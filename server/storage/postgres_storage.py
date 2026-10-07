from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from contextlib import contextmanager, closing
from pathlib import Path
from typing import Any

from server.storage.base import BaseStorage
from server.storage.migration_runner import apply_migrations_dir

import psycopg2
from psycopg2.pool import ThreadedConnectionPool, PoolError
from psycopg2.extras import Json, execute_batch

from server.config import config
from shared.crypto_utils import CryptoConfigError

logger = logging.getLogger("insiedr.storage.postgres")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

class _SQLiteCursorAdapter:
    """Wraps a SQLite cursor to translate psycopg2 %s params → SQLite ? params."""
    def __init__(self, cursor):
        self._cursor = cursor

    def _adapt_sql(self, sql: str) -> str:
        import re
        # %s → ?
        sql = sql.replace("%s", "?")
        # Strip PostgreSQL type casts: ::timestamp, ::text, ::int, etc.
        sql = re.sub(r"::[a-zA-Z_ ]+( with time zone)?", "", sql)
        # Strip RETURNING clauses (not supported by SQLite), set flag
        if " RETURNING " in sql.upper():
            sql = sql[:sql.upper().rfind(" RETURNING ")]
            self._had_returning = True
        else:
            self._had_returning = False
        # Replace PostgreSQL interval: X - INTERVAL '5 minutes' → datetime(X, '-5 minutes')
        sql = re.sub(
            r"(NOW\(\)|CURRENT_TIMESTAMP)\s*-\s*INTERVAL\s*'(\d+)\s+minutes?'",
            r"datetime('now', '-\2 minutes')",
            sql,
            flags=re.IGNORECASE
        )
        return sql

    def _adapt_params(self, params):
        """Serialize psycopg2 Json objects to strings for SQLite."""
        if params is None:
            return None
        try:
            from psycopg2.extras import Json as PgJson
        except ImportError:
            return params
        result = []
        for p in params:
            if isinstance(p, PgJson):
                result.append(json.dumps(p.adapted))
            else:
                result.append(p)
        return tuple(result)

    def execute(self, sql: str, params=None):
        sql = self._adapt_sql(sql)
        if params is None:
            self._cursor.execute(sql)
        else:
            self._cursor.execute(sql, self._adapt_params(params))
        return self

    def executemany(self, sql: str, params_list):
        sql = self._adapt_sql(sql)
        adapted_list = [self._adapt_params(p) for p in params_list]
        self._cursor.executemany(sql, adapted_list)
        return self

    def fetchone(self):
        if getattr(self, "_had_returning", False):
            # RETURNING was stripped — only return a dummy non-None row if a real
            # insert happened (rowcount == 1). If 0, the ON CONFLICT DO NOTHING fired.
            self._had_returning = False
            if self._cursor.rowcount == 1:
                return ("ok",)
            return None
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self):
        return iter(self._cursor)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    def close(self):
        self._cursor.close()


class _SQLiteParamAdapter:
    """Wraps a SQLite connection exposing a psycopg2-compatible cursor() interface."""
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return _SQLiteCursorAdapter(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def execute(self, sql: str, params=None):
        sql = sql.replace("%s", "?")
        if params is None:
            return self._conn.execute(sql)
        return self._conn.execute(sql, params)

    def executescript(self, sql: str):
        return self._conn.executescript(sql)


class PostgresStorage(BaseStorage):
    def __init__(self, dsn: str | None = None, minconn=None, maxconn=None, connection_factory=None) -> None:
        self.connection_factory = connection_factory
        self._is_sqlite = False
        if self.connection_factory:
            self.dsn = dsn
            self.pool = None
            # Detect if we're running against SQLite (for tests)
            try:
                import sqlite3
                test_conn = connection_factory()
                if isinstance(test_conn, sqlite3.Connection):
                    self._is_sqlite = True
                test_conn.close()
            except Exception:
                pass
            return
            
        self.dsn = dsn or os.environ.get("INSIEDR_SERVER_POSTGRES_URI")
        if not self.dsn:
            raise RuntimeError("INSIEDR_SERVER_POSTGRES_URI environment variable or dsn is required for PostgresStorage")
        
        minconn = int(os.environ.get("INSIEDR_PG_POOL_MIN", "2")) if minconn is None else minconn
        maxconn = int(os.environ.get("INSIEDR_PG_POOL_MAX", "32")) if maxconn is None else maxconn
        if not 1 <= minconn <= maxconn:
            raise ValueError("PostgreSQL pool requires 1 <= minconn <= maxconn")
        self._pool_wait_seconds = float(os.environ.get("INSIEDR_PG_POOL_WAIT_SECONDS", "2"))
        statement_ms = int(os.environ.get("INSIEDR_PG_STATEMENT_TIMEOUT_MS", "15000"))
        lock_ms = int(os.environ.get("INSIEDR_PG_LOCK_TIMEOUT_MS", "3000"))
        if self._pool_wait_seconds <= 0 or statement_ms <= 0 or lock_ms <= 0:
            raise ValueError("PostgreSQL wait, statement and lock timeouts must be positive")
        self._pool_slots = threading.BoundedSemaphore(maxconn)
        self._pool_broken = False
        self.pool = ThreadedConnectionPool(
            minconn, maxconn, dsn=self.dsn,
            connect_timeout=5,
            options=f"-c statement_timeout={statement_ms} -c lock_timeout={lock_ms}",
        )

    @contextmanager
    def connection(self):
        if self.connection_factory:
            raw_conn = self.connection_factory()
            try:
                if self._is_sqlite:
                    yield _SQLiteParamAdapter(raw_conn)
                else:
                    yield raw_conn
            finally:
                try:
                    raw_conn.rollback()
                finally:
                    raw_conn.close()
            return
            
        # psycopg2's pool raises immediately at capacity; bound both waiting and
        # ownership so bursts cannot exhaust it or wait indefinitely.
        if self._pool_broken or not self._pool_slots.acquire(timeout=self._pool_wait_seconds):
            raise PoolError("PostgreSQL connection capacity unavailable; retry shortly")
        conn = None
        try:
            conn = self.pool.getconn()
            yield conn
        finally:
            try:
                if conn is not None:
                    discard = bool(conn.closed)
                    if not discard:
                        try:
                            # Also closes read-only/aborted transactions on normal
                            # exits and BaseException cancellation paths.
                            conn.rollback()
                        except Exception:
                            discard = True
                    try:
                        self.pool.putconn(conn, close=discard)
                    except Exception:
                        self._pool_broken = True
                        conn.close()
                        logger.exception("PostgreSQL pool return failed; pool requires restart")
            finally:
                self._pool_slots.release()

    def close(self) -> None:
        if self.pool is not None:
            self.pool.closeall()

    def _sql(self, query: str) -> str:
        """Translate %s → ? when running against SQLite (test mode only)."""
        if self._is_sqlite:
            return query.replace("%s", "?")
        return query

    @staticmethod
    def _stable_json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

    @staticmethod
    def _sha256_hex(value: str | bytes | None) -> str | None:
        if value is None:
            return None
        data = value.encode("utf-8") if isinstance(value, str) else value
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _collector_source_quality(collector_result: dict[str, Any]) -> str:
        if collector_result.get("status") != "success":
            return "low"
        collector_name = str(collector_result.get("collector", "")).lower()
        payload = collector_result.get("payload") or {}
        if collector_name in {"file-feature", "file_feature", "file"}:
            return "heuristic"
        if collector_name in {"devices-feature", "devices_feature", "usb", "usb-monitor"}:
            if any(key in payload for key in ("usb_file_transfer_count", "large_usb_transfer", "bytes_written")):
                return "verify_required"
        if collector_name in {"http-feature", "http_feature", "browser-history"}:
            return "browser_history"
        if collector_name == "network-monitor":
            return "passive_optional"
        return "high"

    @staticmethod
    def _quality_notes(collector_name: str, feature_name: str, quality: str) -> str | None:
        collector = collector_name.lower()
        feature = feature_name.lower()
        if quality == "heuristic":
            return "File activity fields are heuristic user-space observations, not proven copy direction."
        if quality == "verify_required":
            return "USB transfer byte/count fields require verification because current collectors may not populate bytes_written."
        if quality == "browser_history":
            if feature == "upload_count":
                return "HTTP data is browser-history scoped; upload_count may be null and is not full network monitoring."
            return "HTTP data is browser-history scoped and excludes private browsing and non-browser traffic."
        if quality == "passive_optional" or collector == "network-monitor":
            return "Network monitor is optional passive psutil metadata, not packet sniffing or threat-feed classification."
        if quality == "low":
            return "Collector failed; stored as a data-quality record."
        return None

    @staticmethod
    def _feature_rows(decrypted_payload: dict[str, Any], collector_result: dict[str, Any], quality: str) -> list[dict[str, Any]]:
        payload = collector_result.get("payload")
        if not isinstance(payload, dict):
            return []
        rows = []
        for name, value in payload.items():
            if value is None:
                continue
            row = {
                "payload_id": decrypted_payload.get("payload_id"),
                "agent_id": decrypted_payload.get("agent_id"),
                "username": decrypted_payload.get("username"),
                "hostname": decrypted_payload.get("hostname") or collector_result.get("hostname"),
                "collector": collector_result.get("collector"),
                "entity_user": decrypted_payload.get("username"),
                "feature_name": name,
                "feature_value_numeric": None,
                "feature_value_text": None,
                "feature_value_json": None,
                "feature_timestamp": collector_result.get("collected_at") or decrypted_payload.get("collected_at"),
                "source_quality": quality,
                "quality_notes": PostgresStorage._quality_notes(str(collector_result.get("collector", "")), str(name), quality),
            }
            if isinstance(value, bool):
                row["feature_value_numeric"] = float(value)
            elif isinstance(value, (int, float)):
                row["feature_value_numeric"] = float(value)
            elif isinstance(value, str):
                row["feature_value_text"] = value
            elif value is not None:
                row["feature_value_json"] = Json(value)
            rows.append(row)
        return rows

    def ensure_migrations(self) -> None:
        def get_conn():
            return psycopg2.connect(self.dsn)
        apply_migrations_dir(get_conn, MIGRATIONS_DIR)

        # Self-healing partition safeguard for PostgreSQL
        if not self._is_sqlite and self.dsn:
            try:
                conn = get_conn()
                try:
                    with conn.cursor() as cur:
                        cur.execute("CREATE TABLE IF NOT EXISTS raw_payloads_default PARTITION OF raw_payloads DEFAULT;")
                        cur.execute("CREATE TABLE IF NOT EXISTS collector_results_default PARTITION OF collector_results DEFAULT;")
                    conn.commit()
                finally:
                    conn.close()
            except Exception as e:
                logger.warning("Default partition verification note: %s", e)

    def _upsert_agent(self, cursor, decrypted_payload: dict[str, Any]) -> None:
        agent_id = decrypted_payload["agent_id"]
        hostname = decrypted_payload.get("hostname")
        username = decrypted_payload.get("username")
        os_info = decrypted_payload.get("os") or {}
        cursor.execute(
            """
            INSERT INTO agents (
                agent_id, hostname, username_last_seen, os_system, os_release, 
                os_version, os_machine, first_seen_at, last_seen_at, last_payload_id, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s, %s)
            ON CONFLICT (agent_id) DO UPDATE SET
                hostname = COALESCE(EXCLUDED.hostname, agents.hostname),
                username_last_seen = COALESCE(EXCLUDED.username_last_seen, agents.username_last_seen),
                os_system = COALESCE(EXCLUDED.os_system, agents.os_system),
                os_release = COALESCE(EXCLUDED.os_release, agents.os_release),
                os_version = COALESCE(EXCLUDED.os_version, agents.os_version),
                os_machine = COALESCE(EXCLUDED.os_machine, agents.os_machine),
                last_seen_at = EXCLUDED.last_seen_at,
                last_payload_id = EXCLUDED.last_payload_id,
                status = EXCLUDED.status
            """,
            (
                agent_id,
                hostname,
                username,
                os_info.get("system"),
                os_info.get("release"),
                os_info.get("version"),
                os_info.get("machine"),
                decrypted_payload.get("payload_id"),
                "active",
            ),
        )

    def store_raw_payload(self, envelope: dict[str, Any], decrypted_payload: dict[str, Any]) -> bool:
        """Commit telemetry atomically; return False for an already stored payload."""
        payload_id = decrypted_payload.get("payload_id")
        if not payload_id:
            raise ValueError("payload_id is required")
            
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    self._upsert_agent(cursor, decrypted_payload)

                    cursor.execute(
                        """
                        INSERT INTO raw_payloads (
                            payload_id, agent_id, received_at, envelope_created_at, payload_collected_at,
                            hostname, username, crypto_scheme, key_id, nonce_hash, ciphertext_hash, decrypted_payload_hash,
                            encrypted_envelope_json, validation_status
                        ) VALUES (
                            %s, %s, COALESCE(%s::timestamp, CURRENT_TIMESTAMP), %s, %s,
                            %s, %s, %s, %s, %s, %s, %s,
                            %s, %s
                        )
                        ON CONFLICT (payload_id, received_at) DO NOTHING
                        RETURNING payload_id
                        """,
                        (
                            payload_id,
                            decrypted_payload.get("agent_id"),
                            decrypted_payload.get("collected_at"),
                            envelope.get("created_at"),
                            decrypted_payload.get("collected_at"),
                            decrypted_payload.get("hostname"),
                            decrypted_payload.get("username"),
                            envelope.get("scheme"),
                            envelope.get("key_id"),
                            self._sha256_hex(envelope.get("nonce")),
                            self._sha256_hex(envelope.get("ciphertext")),
                            self._sha256_hex(self._stable_json(decrypted_payload)),
                            Json(envelope),
                            "accepted",
                        ),
                    )
                    
                    if not cursor.fetchone():
                        # The payload was a duplicate, ignore it idempotently.
                        conn.commit()
                        return False

                    collector_results_args = []
                    risk_events_args = []
                    normalized_features_args = []

                    for collector_result in decrypted_payload.get("collectors", []):
                        payload = collector_result.get("payload") if isinstance(collector_result, dict) else None
                        error = collector_result.get("error") if isinstance(collector_result, dict) else None
                        source_quality = self._collector_source_quality(collector_result)
                        
                        collector_results_args.append((
                            payload_id,
                            decrypted_payload.get("agent_id"),
                            collector_result.get("collector"),
                            collector_result.get("collected_at"),
                            collector_result.get("hostname"),
                            collector_result.get("status"),
                            Json(payload) if config.store_plaintext_payloads and payload is not None else None,
                            error.get("type") if isinstance(error, dict) else None,
                            error.get("message") if isinstance(error, dict) else None,
                            source_quality,
                        ))
                        
                        if collector_result.get("collector") == "tamper" or collector_result.get("status") == "critical":
                            risk_events_args.append((
                                payload_id,
                                decrypted_payload.get("agent_id"),
                                decrypted_payload.get("username"),
                                100.0,
                                "HIGH",
                                Json({
                                    "collector": "tamper",
                                    "hostname": collector_result.get("hostname"),
                                    "user": decrypted_payload.get("username")
                                }),
                                f"Agent Tamper Alert: Agent termination attempted on {collector_result.get('hostname')} by user {decrypted_payload.get('username')}. Msg: {collector_result.get('msg', 'Agent tried to terminate')}",
                                collector_result.get("collected_at"),
                            ))

                        for feature in self._feature_rows(decrypted_payload, collector_result, source_quality):
                            normalized_features_args.append((
                                feature["payload_id"],
                                feature["agent_id"],
                                feature["username"],
                                feature["hostname"],
                                feature["collector"],
                                feature["entity_user"],
                                feature["feature_name"],
                                feature["feature_value_numeric"],
                                feature["feature_value_text"],
                                feature["feature_value_json"],
                                feature["feature_timestamp"],
                                feature["source_quality"],
                                feature["quality_notes"],
                                decrypted_payload.get("collected_at"),
                            ))
                    
                    is_sqlite = getattr(cursor, "_is_sqlite", False) or hasattr(cursor, "_adapt_sql")

                    if collector_results_args:
                        q = """
                            INSERT INTO collector_results (
                                payload_id, agent_id, collector, collector_collected_at, hostname,
                                status, payload_json, error_type, error_message, source_quality
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """
                        if is_sqlite:
                            cursor.executemany(q, collector_results_args)
                        else:
                            execute_batch(cursor, q, collector_results_args)

                    if risk_events_args:
                        q = """
                            INSERT INTO risk_events (
                                payload_id, agent_id, username, risk_score, risk_level,
                                correlated_signals_json, summary, created_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, COALESCE(%s::timestamp, CURRENT_TIMESTAMP))
                            """
                        if is_sqlite:
                            cursor.executemany(q, risk_events_args)
                        else:
                            execute_batch(cursor, q, risk_events_args)

                    if normalized_features_args:
                        q = """
                            INSERT INTO normalized_features (
                                payload_id, agent_id, username, hostname, collector, entity_user,
                                feature_name, feature_value_numeric, feature_value_text, feature_value_json,
                                feature_timestamp, source_quality, quality_notes, created_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s::timestamp, CURRENT_TIMESTAMP))
                            """
                        if is_sqlite:
                            cursor.executemany(q, normalized_features_args)
                        else:
                            execute_batch(cursor, q, normalized_features_args)

                    # Transactional Outbox: insert into clickhouse_outbox inside same transaction.
                    # Use a SAVEPOINT so that a missing table (partial migration) does NOT abort
                    # the entire transaction — in PostgreSQL a SQL error aborts the whole
                    # transaction; catching the exception alone cannot restore it.
                    try:
                        if not is_sqlite:
                            cursor.execute("SAVEPOINT insiedr_outbox_sp")

                        # Respect store_plaintext_payloads: when False, strip decrypted
                        # payload body from the outbox entry so the outbox table does not
                        # become a plaintext data store that bypasses the privacy policy.
                        # Keep only identifiers needed for routing and deduplication.
                        if config.store_plaintext_payloads:
                            outbox_record = {"envelope": envelope, "payload": decrypted_payload}
                        else:
                            outbox_record = {
                                "envelope": {k: v for k, v in envelope.items() if k != "ciphertext"},
                                "payload": {
                                    "payload_id": decrypted_payload.get("payload_id"),
                                    "agent_id": decrypted_payload.get("agent_id"),
                                    "collected_at": decrypted_payload.get("collected_at"),
                                    "_plaintext_stripped": True,
                                },
                            }

                        cursor.execute(
                            """
                            INSERT INTO clickhouse_outbox (target_table, record_json, status, attempts, created_at)
                            VALUES (%s, %s, 'pending', 0, CURRENT_TIMESTAMP)
                            """,
                            ("raw_payloads", Json(outbox_record)),
                        )
                        if not is_sqlite:
                            cursor.execute("RELEASE SAVEPOINT insiedr_outbox_sp")
                    except Exception as ob_err:
                        err_str = str(ob_err).lower()
                        if "clickhouse_outbox" in err_str and ("does not exist" in err_str or "no such table" in err_str):
                            # Table missing (partial migration) — roll back savepoint only,
                            # preserving the already-executed main data inserts.
                            if not is_sqlite:
                                try:
                                    cursor.execute("ROLLBACK TO SAVEPOINT insiedr_outbox_sp")
                                    cursor.execute("RELEASE SAVEPOINT insiedr_outbox_sp")
                                except Exception:
                                    pass
                            logger.debug("clickhouse_outbox table not present; outbox entry skipped for payload %s", payload_id)
                        else:
                            raise
                    conn.commit()
                    return True
                except Exception as exc:
                    conn.rollback()
                    err_msg = str(exc).lower()
                    if ("no partition" in err_msg or "partition" in err_msg) and not self._is_sqlite and self.dsn:
                        try:
                            with self.connection() as fix_conn:
                                with closing(fix_conn.cursor()) as fix_cur:
                                    fix_cur.execute("CREATE TABLE IF NOT EXISTS raw_payloads_default PARTITION OF raw_payloads DEFAULT;")
                                    fix_cur.execute("CREATE TABLE IF NOT EXISTS collector_results_default PARTITION OF collector_results DEFAULT;")
                                fix_conn.commit()
                            # Retry this insert once after auto-creating the missing default partitions
                            return self.store_raw_payload(envelope, decrypted_payload)
                        except Exception:
                            pass
                    raise

    def get_payload(self, payload_id: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    "SELECT payload_id, agent_id, encrypted_envelope_json, validation_status, ciphertext_hash, decrypted_payload_hash FROM raw_payloads WHERE payload_id = %s",
                    (payload_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return {
                    "payload_id": row[0],
                    "agent_id": row[1],
                    "encrypted_envelope_json": row[2] if isinstance(row[2], dict) else json.loads(row[2]),
                    "validation_status": row[3],
                    "ciphertext_hash": row[4],
                    "decrypted_payload_hash": row[5],
                }

    @staticmethod
    def _rows_to_dicts(cursor) -> list[dict[str, Any]]:
        columns = [column[0] for column in cursor.description or []]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_latest_collector_states(self, agent_id: str) -> list[dict[str, Any]]:
        columns = """agent_id, collector, hostname, status, payload_json,
                     collector_collected_at, payload_id, error_type, error_message,
                     source_quality"""
        # Timestamps belong to the observation, not its delivery time: an older
        # offline replay must never replace a more recently collected state.
        if self._is_sqlite:
            query = f"""
                SELECT {columns} FROM (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY collector
                        ORDER BY collector_collected_at DESC, payload_id DESC, id DESC
                    ) AS state_rank
                    FROM collector_results WHERE agent_id = %s
                ) AS states WHERE state_rank = 1 ORDER BY collector
            """
        else:
            query = f"""
                SELECT DISTINCT ON (collector) {columns}
                FROM collector_results WHERE agent_id = %s
                ORDER BY collector, collector_collected_at DESC NULLS LAST,
                         payload_id DESC, id DESC
            """
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(query, (agent_id,))
                states = self._rows_to_dicts(cursor)
                # Plaintext payload retention is disabled by default. The
                # already persisted normalized features still provide observed
                # metrics without decrypting archived envelopes or inventing 0.
                missing = {(state["payload_id"], state["collector"]): state
                           for state in states if state["payload_json"] is None}
                if missing:
                    payload_ids = sorted({key[0] for key in missing})
                    placeholders = ", ".join(["%s"] * len(payload_ids))
                    cursor.execute(
                        f"""SELECT payload_id, collector, feature_name,
                                   feature_value_numeric, feature_value_text,
                                   feature_value_json
                            FROM normalized_features
                            WHERE agent_id = %s AND payload_id IN ({placeholders})
                            ORDER BY id""",
                        tuple([agent_id] + payload_ids),
                    )
                    for payload_id, collector, name, numeric, text, json_value in cursor.fetchall():
                        state = missing.get((payload_id, collector))
                        if state is None:
                            continue
                        if numeric is not None:
                            value = numeric
                        elif text is not None:
                            value = text
                        elif json_value is not None:
                            value = json.loads(json_value) if isinstance(json_value, str) else json_value
                        else:
                            continue
                        if state["payload_json"] is None:
                            state["payload_json"] = {}
                        state["payload_json"][name] = value
        for state in states:
            if isinstance(state["payload_json"], str):
                state["payload_json"] = json.loads(state["payload_json"])
        return states

    def list_agents(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    """
                    SELECT agent_id, hostname, username_last_seen, os_system, os_release, os_version, os_machine,
                           first_seen_at, last_seen_at, last_payload_id, 
                           CASE WHEN last_seen_at > CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 'active' ELSE 'offline' END as status
                    FROM agents
                    ORDER BY last_seen_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    (limit, offset),
                )
                return self._rows_to_dicts(cursor)

    @property
    def fleet(self):
        if not hasattr(self, "_fleet_repo") or self._fleet_repo is None:
            from server.storage.repositories.fleet_repo import FleetRepository
            self._fleet_repo = FleetRepository(self)
        return self._fleet_repo

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        return self.fleet.get_agent(agent_id)

    def upsert_agent_heartbeat(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str | None = None,
        agent_version: str | None = None,
        status: str = "active",
        metrics: dict[str, Any] | None = None,
        config_version: str | None = None,
    ) -> None:
        self.fleet.upsert_agent_heartbeat(
            agent_id=agent_id,
            hostname=hostname,
            ip_address=ip_address,
            agent_version=agent_version,
            status=status,
            metrics=metrics,
            config_version=config_version,
        )

    def queue_agent_task(
        self,
        agent_id: str,
        command: str,
        params: dict[str, Any] | None = None,
        signature: str | None = None,
        task_id: str | None = None,
        actor_id: str | None = None,
        actor_role: str | None = None,
        ip_address: str | None = None,
    ) -> str:
        return self.fleet.queue_task(
            agent_id=agent_id,
            command=command,
            params=params,
            signature=signature,
            task_id=task_id,
            actor_id=actor_id,
            actor_role=actor_role,
            ip_address=ip_address,
        )

    def get_pending_agent_tasks(self, agent_id: str) -> list[dict[str, Any]]:
        return self.fleet.get_pending_tasks(agent_id)

    def mark_tasks_dispatched(self, task_ids: list[str]) -> None:
        self.fleet.mark_tasks_dispatched(task_ids)

    def acknowledge_agent_task(self, agent_id: str, task_id: str) -> bool:
        return self.fleet.acknowledge_task(agent_id=agent_id, task_id=task_id)

    def enqueue_clickhouse_outbox(self, target_table: str, record_data: dict[str, Any]) -> None:
        """Enqueue an analytics record into the transactional outbox table."""
        with self.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute(
                        """
                        INSERT INTO clickhouse_outbox (target_table, record_json, status, attempts, created_at)
                        VALUES (%s, %s, 'pending', 0, CURRENT_TIMESTAMP)
                        """,
                        (target_table, Json(record_data)),
                    )
                    conn.commit()
                except Exception as exc:
                    logger.debug("clickhouse_outbox insert non-fatal error: %s", exc)

    def get_pending_clickhouse_outbox(self, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch oldest pending outbox records for replication catchup.

        Uses ``FOR UPDATE SKIP LOCKED`` on PostgreSQL so that multiple concurrent
        reconciler workers each claim an exclusive, non-overlapping batch.  The
        caller is responsible for committing (or rolling back) the surrounding
        connection so the row-level locks are released after processing.
        SQLite does not support this syntax; the plain query is used there.
        """
        with self.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    is_sqlite = self._is_sqlite
                    skip_locked = "" if is_sqlite else "FOR UPDATE SKIP LOCKED"
                    cur.execute(
                        f"""
                        SELECT outbox_id, target_table, record_json, attempts
                        FROM clickhouse_outbox
                        WHERE status = 'pending'
                        ORDER BY outbox_id ASC
                        LIMIT %s
                        {skip_locked}
                        """,
                        (limit,),
                    )
                    cols = [col[0] for col in cur.description or []]
                    rows = cur.fetchall()
                    results = []
                    for row in rows:
                        item = dict(zip(cols, row))
                        if isinstance(item.get("record_json"), str):
                            try:
                                item["record_json"] = json.loads(item["record_json"])
                            except Exception:
                                pass
                        results.append(item)
                    return results
                except Exception as exc:
                    logger.debug("Failed querying clickhouse_outbox: %s", exc)
                    return []

    def mark_clickhouse_outbox_completed(self, outbox_ids: list[int]) -> None:
        """Mark outbox records as successfully replicated to ClickHouse."""
        if not outbox_ids:
            return
        with self.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute(
                        """
                        UPDATE clickhouse_outbox
                        SET status = 'completed', processed_at = CURRENT_TIMESTAMP
                        WHERE outbox_id = ANY(%s)
                        """,
                        (outbox_ids,),
                    )
                    conn.commit()
                except Exception:
                    for oid in outbox_ids:
                        try:
                            cur.execute(
                                "UPDATE clickhouse_outbox SET status = 'completed', processed_at = CURRENT_TIMESTAMP WHERE outbox_id = %s",
                                (oid,)
                            )
                        except Exception:
                            pass
                    conn.commit()

    def increment_clickhouse_outbox_attempts(self, outbox_ids: list[int], error_msg: str) -> None:
        """Increment attempt count and update last_error on failed outbox reconciliation."""
        if not outbox_ids:
            return
        with self.connection() as conn:
            with closing(conn.cursor()) as cur:
                for oid in outbox_ids:
                    try:
                        cur.execute(
                            """
                            UPDATE clickhouse_outbox
                            SET attempts = attempts + 1, last_error = %s
                            WHERE outbox_id = %s
                            """,
                            (error_msg[:500], oid),
                        )
                    except Exception:
                        pass
                conn.commit()

    def mark_outbox_completed_by_payload_id(self, payload_id: str) -> None:
        """Mark outbox record completed when direct ClickHouse ingestion succeeded."""
        if not payload_id:
            return
        with self.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute(
                        """
                        UPDATE clickhouse_outbox
                        SET status = 'completed', processed_at = CURRENT_TIMESTAMP
                        WHERE target_table = 'raw_payloads'
                          AND status = 'pending'
                          AND record_json->'payload'->>'payload_id' = %s
                        """,
                        (str(payload_id),),
                    )
                    conn.commit()
                except Exception as exc:
                    logger.debug("Failed updating outbox by payload_id: %s", exc)

    def purge_completed_clickhouse_outbox(self, retention_days: int | None = None) -> int:
        """Delete completed outbox entries older than retention_days.

        Prevents unbounded table growth and limits the window during which
        decrypted payload data (or its metadata stub) sits in the outbox.
        Returns the number of rows deleted, or 0 on error / unsupported backend.

        Uses an interval expression compatible with PostgreSQL.  SQLite is
        skipped because the outbox migration is PostgreSQL-only.
        """
        if self._is_sqlite:
            return 0  # Outbox is PostgreSQL-only in production

        days = retention_days if retention_days is not None else config.payload_retention_days
        days = max(1, int(days))

        with self.connection() as conn:
            with closing(conn.cursor()) as cur:
                try:
                    cur.execute(
                        """
                        DELETE FROM clickhouse_outbox
                        WHERE status = 'completed'
                          AND processed_at < NOW() - INTERVAL '%s days'
                        """,
                        (days,),
                    )
                    deleted = cur.rowcount or 0
                    conn.commit()
                    if deleted:
                        logger.info("Purged %d completed clickhouse_outbox entries older than %d days", deleted, days)
                    return deleted
                except Exception as exc:
                    logger.debug("clickhouse_outbox purge non-fatal: %s", exc)
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    return 0

    def update_agent_task_result(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        exit_code: int,
        message: str,
        completed_at: str | None = None,
    ) -> bool:
        return self.fleet.update_task_result(
            agent_id=agent_id,
            task_id=task_id,
            status=status,
            exit_code=exit_code,
            message=message,
            completed_at=completed_at,
        )

    def list_agent_tasks(self, agent_id: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self.fleet.list_agent_tasks(agent_id=agent_id, limit=limit, offset=offset)


    def list_logs(
        self,
        limit: int = 100,
        offset: int = 0,
        agent_id: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        collector: str | None = None,
        status: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                where = []
                params: list[Any] = []
                if agent_id:
                    where.append("rp.agent_id = %s")
                    params.append(agent_id)
                if hostname:
                    where.append("rp.hostname = %s")
                    params.append(hostname)
                if username:
                    where.append("rp.username = %s")
                    params.append(username)
                if collector:
                    where.append("EXISTS (SELECT 1 FROM collector_results cr WHERE cr.payload_id = rp.payload_id AND cr.collector LIKE %s)")
                    params.append(f"%{collector}%")
                if status:
                    where.append("EXISTS (SELECT 1 FROM collector_results crs WHERE crs.payload_id = rp.payload_id AND crs.status = %s)")
                    params.append(status)
                if start_time:
                    where.append("rp.received_at >= %s")
                    params.append(start_time)
                if end_time:
                    where.append("rp.received_at <= %s")
                    params.append(end_time)
                
                where_sql = "WHERE " + " AND ".join(where) if where else ""
                cursor.execute(
                    f"""
                    SELECT rp.payload_id, rp.agent_id, rp.received_at, rp.envelope_created_at, rp.payload_collected_at,
                           rp.hostname, rp.username, rp.crypto_scheme, rp.key_id, rp.nonce_hash, rp.ciphertext_hash, rp.decrypted_payload_hash,
                           encrypted_envelope_json, validation_status
                    FROM raw_payloads rp
                    {where_sql}
                    ORDER BY rp.received_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params + [limit, offset]),
                )
                return self._rows_to_dicts(cursor)

    def list_collector_results(
        self,
        limit: int = 100,
        offset: int = 0,
        collector: str = None,
        username: str = None,
        start_time: str = None,
        end_time: str = None,
        exact_collector: bool = False,
    ) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                where_parts = []
                params = []
                if collector:
                    if exact_collector:
                        where_parts.append("LOWER(cr.collector) = LOWER(%s)")
                        params.append(collector)
                    else:
                        where_parts.append("cr.collector ILIKE %s")
                        params.append(f"%{collector}%")
                if username:
                    where_parts.append("rp.username ILIKE %s")
                    params.append(f"%{username}%")
                if start_time:
                    where_parts.append("COALESCE(cr.collector_collected_at, rp.received_at) >= %s")
                    params.append(start_time)
                if end_time:
                    where_parts.append("COALESCE(cr.collector_collected_at, rp.received_at) <= %s")
                    params.append(end_time)
                
                where_clause = "WHERE " + " AND ".join(where_parts) if where_parts else ""
                params.extend([limit, offset])
                
                cursor.execute(
                    f"""
                    SELECT cr.payload_id, cr.agent_id, cr.collector, cr.collector_collected_at, cr.hostname,
                           cr.status, cr.payload_json, rp.username, rp.received_at, re.risk_level, re.summary, re.correlated_signals_json, re.risk_score,
                           (
                               SELECT json_object_agg(nf.feature_name, COALESCE(nf.feature_value_text, nf.feature_value_numeric::text))
                               FROM normalized_features nf
                               WHERE nf.payload_id = cr.payload_id
                           ) AS features_json
                    FROM collector_results cr
                    LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id
                    LEFT JOIN risk_events re ON cr.payload_id = re.payload_id
                    {where_clause}
                    ORDER BY cr.collector_collected_at DESC NULLS LAST
                    LIMIT %s OFFSET %s
                    """,
                    tuple(params)
                )
                results = []
                for row in cursor.fetchall():
                    payload = row[6] if isinstance(row[6], dict) else (json.loads(row[6]) if row[6] else {})
                    features_json = row[13] if isinstance(row[13], dict) else (json.loads(row[13]) if row[13] else {})
                    if not payload and features_json:
                        payload = features_json
                        
                    results.append({
                        "payload_id": row[0],
                        "agent_id": row[1],
                        "collector": row[2],
                        "collected_at": row[3],
                        "hostname": row[4],
                        "status": row[5],
                        "payload": payload,
                        "username": row[7],
                        "received_at": row[8],
                        "risk_level": row[9],
                        "summary": row[10],
                        "correlated_signals_json": row[11],
                        "risk_score": row[12]
                    })
                return results

    def get_telemetry_page(self, **filters) -> dict[str, Any]:
        from server.storage.telemetry_queries import telemetry_page
        return telemetry_page(self, **filters)

    def get_distinct_collectors(self) -> list[str]:
        """Return distinct collector names present in collector_results merged with known collectors."""
        default_collectors = [
            "logon", "file", "process", "network", "device", "http",
            "lsass_monitor", "registry", "keystroke-collector",
            "decoy-monitor", "clipboard-monitor", "persistence_monitor",
            "dns_monitor", "driver_monitor", "wmi_activity", "usn_monitor"
        ]
        found = set()
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute("SELECT DISTINCT collector FROM collector_results WHERE collector IS NOT NULL AND collector != '' ORDER BY collector")
                    for row in cursor.fetchall():
                        if row[0]:
                            found.add(str(row[0]).strip().lower())
                except Exception:
                    pass
        # Union and sort
        combined = set(default_collectors) | found
        return sorted(list(combined))

    def get_distinct_usernames(self) -> list[str]:
        """Return distinct usernames recorded across raw_payloads."""
        usernames = set()
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute("SELECT DISTINCT username FROM raw_payloads WHERE username IS NOT NULL AND username != '' ORDER BY username")
                    for row in cursor.fetchall():
                        if row[0]:
                            usernames.add(str(row[0]).strip())
                except Exception:
                    pass
        return sorted(list(usernames))

    def count_collector_results(
        self,
        collector: str = None,
        username: str = None,
        start_time: str = None,
        end_time: str = None,
        exact_collector: bool = False,
    ) -> int:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                where_parts = []
                params = []
                if collector:
                    if exact_collector:
                        where_parts.append("LOWER(cr.collector) = LOWER(%s)")
                        params.append(collector)
                    else:
                        where_parts.append("cr.collector ILIKE %s")
                        params.append(f"%{collector}%")
                if username:
                    where_parts.append("rp.username ILIKE %s")
                    params.append(f"%{username}%")
                if start_time:
                    where_parts.append("COALESCE(cr.collector_collected_at, rp.received_at) >= %s")
                    params.append(start_time)
                if end_time:
                    where_parts.append("COALESCE(cr.collector_collected_at, rp.received_at) <= %s")
                    params.append(end_time)

                where_clause = "WHERE " + " AND ".join(where_parts) if where_parts else ""
                cursor.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM collector_results cr
                    LEFT JOIN raw_payloads rp ON cr.payload_id = rp.payload_id
                    {where_clause}
                    """,
                    tuple(params)
                )
                row = cursor.fetchone()
                return int(row[0]) if row else 0

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT id, payload_id, agent_id, username, anomaly_type, severity, detectors_json,
                               top_features_json, status, created_at, acknowledged_at, acknowledged_by
                        FROM anomalies
                        ORDER BY created_at DESC
                        LIMIT %s OFFSET %s
                        """,
                        (limit, offset),
                    )
                    return self._rows_to_dicts(cursor)
                except Exception:
                    conn.rollback()
                    return []

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT id, payload_id, agent_id, username, risk_score, risk_level,
                               correlated_signals_json, summary, created_at
                        FROM risk_events
                        ORDER BY created_at DESC
                        LIMIT %s OFFSET %s
                        """,
                        (limit, offset),
                    )
                    return self._rows_to_dicts(cursor)
                except Exception:
                    conn.rollback()
                    return []

    def list_baselines(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT id, agent_id, username, feature_name, baseline_scope, window_start, window_end,
                               mean_value, std_value, sample_count, metadata_json, created_at
                        FROM baseline_snapshots
                        ORDER BY window_end DESC
                        LIMIT %s OFFSET %s
                        """,
                        (limit, offset),
                    )
                    return self._rows_to_dicts(cursor)
                except Exception:
                    conn.rollback()
                    return []

    def get_stats(self) -> dict[str, Any]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                stats = {}
                for key, table in (
                    ("agents", "agents"),
                    ("logs", "raw_payloads"),
                    ("collector_results", "collector_results"),
                    ("anomalies", "anomalies"),
                    ("risk_events", "risk_events"),
                    ("baselines", "baseline_snapshots"),
                ):
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        stats[key] = cursor.fetchone()[0]
                    except Exception:
                        stats[key] = 0
                try:
                    cursor.execute("SELECT status, COUNT(*) FROM collector_results GROUP BY status")
                    stats["collector_status"] = {row[0]: row[1] for row in cursor.fetchall()}
                except Exception:
                    stats["collector_status"] = {}
                try:
                    cursor.execute("SELECT collector, COUNT(*) FROM collector_results GROUP BY collector")
                    stats["collector_counts"] = {row[0]: row[1] for row in cursor.fetchall()}
                except Exception:
                    stats["collector_counts"] = {}
                try:
                    cursor.execute("SELECT source_quality, COUNT(*) FROM normalized_features GROUP BY source_quality")
                    stats["source_quality"] = {row[0]: row[1] for row in cursor.fetchall()}
                except Exception:
                    stats["source_quality"] = {}
                return {"ok": True, **stats}

    def get_feature_vector(self, payload_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT feature_name, feature_value_numeric, feature_value_text, feature_value_json
                        FROM normalized_features
                        WHERE payload_id = %s
                        """,
                        (payload_id,),
                    )
                    features: dict[str, Any] = {}
                    for name, numeric, text, json_value in cursor.fetchall():
                        if numeric is not None:
                            features[name] = numeric
                        elif text is not None:
                            features[name] = text
                        elif json_value is not None:
                            if isinstance(json_value, (dict, list)):
                                features[name] = json_value
                            elif isinstance(json_value, str):
                                try:
                                    features[name] = json.loads(json_value)
                                except Exception:
                                    features[name] = json_value
                            else:
                                features[name] = json_value
                        else:
                            features[name] = None

                    return features
                except Exception:
                    conn.rollback()
                    return {}

    def list_normalized_features(
        self,
        limit: int = 1000,
        offset: int = 0,
        agent_id: str | None = None,
        username: str | None = None,
        collector: str | None = None,
        feature_name: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    where = []
                    params: list[Any] = []
                    if agent_id:
                        where.append("agent_id = %s")
                        params.append(agent_id)
                    if username:
                        where.append("username = %s")
                        params.append(username)
                    if collector:
                        where.append("collector = %s")
                        params.append(collector)
                    if feature_name:
                        where.append("feature_name = %s")
                        params.append(feature_name)
                    if start_time:
                        where.append("created_at >= %s")
                        params.append(start_time)
                    if end_time:
                        where.append("created_at <= %s")
                        params.append(end_time)

                    where_sql = "WHERE " + " AND ".join(where) if where else ""
                    cursor.execute(
                        f"""
                        SELECT id, payload_id, agent_id, username, hostname, collector,
                               feature_name, feature_value_numeric, feature_value_text, feature_value_json,
                               feature_timestamp, source_quality, created_at
                        FROM normalized_features
                        {where_sql}
                        ORDER BY created_at DESC
                        LIMIT %s OFFSET %s
                        """,
                        tuple(params + [limit, offset]),
                    )
                    rows = self._rows_to_dicts(cursor)
                    for r in rows:
                        js = r.get("feature_value_json")
                        if js is not None:
                            if isinstance(js, (dict, list)):
                                r["feature_value_json"] = js
                            elif isinstance(js, str):
                                try:
                                    r["feature_value_json"] = json.loads(js)
                                except Exception:
                                    pass
                    return rows
                except Exception:
                    conn.rollback()
                    return []

    def list_daily_feature_vectors(self, username: str | None, hostname: str | None, limit: int = 16) -> list[dict[str, Any]]:

        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    where = []
                    params: list[Any] = []
                    if username:
                        where.append("username = %s")
                        params.append(username)
                    if hostname:
                        where.append("hostname = %s")
                        params.append(hostname)
                    if not where:
                        return []
                    where_sql = " AND ".join(where)
                    cursor.execute(
                        f"""
                        SELECT feature_timestamp, feature_name, feature_value_numeric, feature_value_text, feature_value_json
                        FROM normalized_features
                        WHERE {where_sql}
                        ORDER BY feature_timestamp DESC, id DESC
                        LIMIT %s
                        """,
                        tuple(params + [limit * 128]),
                    )
                    grouped: dict[str, dict[str, Any]] = {}
                    for timestamp, name, numeric, text, json_value in cursor.fetchall():
                        day = str(timestamp or "")[:10]
                        if not day:
                            continue
                        grouped.setdefault(day, {})
                        if numeric is not None:
                            grouped[day][name] = numeric
                        elif text is not None:
                            grouped[day][name] = text
                        elif json_value is not None:
                            if isinstance(json_value, (dict, list)):
                                grouped[day][name] = json_value
                            elif isinstance(json_value, str):
                                try:
                                    grouped[day][name] = json.loads(json_value)
                                except Exception:
                                    grouped[day][name] = json_value
                            else:
                                grouped[day][name] = json_value
                        else:
                            grouped[day][name] = None

                    days = sorted(grouped.keys())[-limit:]
                    return [{"date": day, "features": grouped[day]} for day in days]
                except Exception:
                    conn.rollback()
                    return []

    def save_model_output(self, output: dict[str, Any]) -> None:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        INSERT INTO model_outputs (
                            payload_id, agent_id, username, detector_name, model_version, score,
                            confidence, is_anomaly, feature_contributions_json, reason_summary, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        """,
                        (
                            output.get("payload_id"),
                            output.get("agent_id"),
                            output.get("username"),
                            output.get("detector_name"),
                            output.get("model_version"),
                            output.get("score"),
                            output.get("confidence"),
                            bool(output.get("is_anomaly")),
                            Json(output.get("feature_contributions_json") or {}),
                            output.get("reason_summary"),
                        ),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def save_risk_event(self, event: dict[str, Any]) -> None:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        INSERT INTO risk_events (
                            payload_id, agent_id, username, risk_score, risk_level,
                            correlated_signals_json, summary, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, COALESCE(%s::timestamp, CURRENT_TIMESTAMP))
                        """,
                        (
                            event.get("payload_id"),
                            event.get("agent_id"),
                            event.get("username"),
                            event.get("risk_score"),
                            event.get("risk_level"),
                            Json(event.get("correlated_signals_json") or {}),
                            event.get("summary"),
                            event.get("collected_at"),
                        ),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def list_recent_risk_scores(self, username: str | None, hostname: str | None, limit: int = 7) -> list[dict[str, Any]]:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    where = []
                    params: list[Any] = []
                    if username:
                        where.append("username = %s")
                        params.append(username)
                    if hostname:
                        where.append(
                            "payload_id IN (SELECT payload_id FROM raw_payloads WHERE hostname = %s)"
                        )
                        params.append(hostname)
                    if not where:
                        return []
                    cursor.execute(
                        f"""
                        SELECT payload_id, username, risk_score, risk_level, created_at
                        FROM risk_events
                        WHERE {" AND ".join(where)}
                        ORDER BY created_at DESC
                        LIMIT %s
                        """,
                        tuple(params + [limit]),
                    )
                    return self._rows_to_dicts(cursor)
                except Exception:
                    conn.rollback()
                    return []

    def get_max_risk_score_in_window(self, username: str, hours: int) -> float:
        """Returns the maximum risk score for the given user in the past N hours."""
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT MAX(risk_score)
                        FROM risk_events
                        WHERE username = %s AND created_at >= CURRENT_TIMESTAMP - INTERVAL '%s hours'
                        """,
                        (username, hours),
                    )
                    row = cursor.fetchone()
                    if row and row[0] is not None:
                        return float(row[0])
                    return 0.0
                except Exception:
                    conn.rollback()
                    return 0.0

    def save_baseline(self, baseline: dict[str, Any]) -> None:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        INSERT INTO baseline_snapshots (
                            agent_id, username, feature_name, baseline_scope, window_start, window_end,
                            mean_value, std_value, sample_count, logic_version, metadata_json, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            baseline.get("agent_id"),
                            baseline.get("username"),
                            baseline.get("feature_name"),
                            baseline.get("baseline_scope"),
                            baseline.get("window_start"),
                            baseline.get("window_end"),
                            baseline.get("mean_value"),
                            baseline.get("std_value"),
                            baseline.get("sample_count"),
                            baseline.get("logic_version"),
                            Json(baseline.get("metadata_json") or {}),
                            baseline.get("created_at"),
                        ),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def load_baseline(self, username: str) -> dict[str, Any] | None:
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT agent_id, username, feature_name, baseline_scope, window_start, window_end,
                               mean_value, std_value, sample_count, logic_version, metadata_json, created_at
                        FROM baseline_snapshots
                        WHERE username = %s
                        ORDER BY window_end DESC
                        LIMIT 1
                        """,
                        (username,),
                    )
                    row = cursor.fetchone()
                    if not row:
                        return None
                    return {
                        "agent_id": row[0],
                        "username": row[1],
                        "feature_name": row[2],
                        "baseline_scope": row[3],
                        "window_start": row[4],
                        "window_end": row[5],
                        "mean_value": row[6],
                        "std_value": row[7],
                        "sample_count": row[8],
                        "logic_version": row[9],
                        "created_at": row[11],
                        "metadata_json": row[10],
                    }
                except Exception:
                    conn.rollback()
                    return None

    def get_pc_status(self, seconds_since_online: int = 300) -> dict[str, Any]:
        """Use the fleet repository's shared five-minute presence snapshot."""
        return self.fleet.get_pc_status(seconds_since_online=seconds_since_online)

    def get_user_collectors(self, username: str) -> list[dict[str, Any]]:
        """Returns collector results for a specific user with latest data"""
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT DISTINCT cr.collector, cr.payload_id, cr.collector_collected_at, 
                               cr.status, cr.payload_json, rp.received_at
                        FROM collector_results cr
                        JOIN raw_payloads rp ON cr.payload_id = rp.payload_id
                        WHERE rp.username = %s
                        ORDER BY cr.collector, rp.received_at DESC
                        """,
                        (username,)
                    )
                    results = []
                    seen_collectors = set()
                    for row in cursor.fetchall():
                        collector_name = row[0]
                        if collector_name not in seen_collectors:
                            seen_collectors.add(collector_name)
                            payload = row[4] if isinstance(row[4], dict) else (json.loads(row[4]) if row[4] else {})
                            
                            results.append({
                                "collector": collector_name,
                                "payload_id": row[1],
                                "collected_at": row[2],
                                "status": row[3],
                                "payload": payload,
                                "received_at": row[5]
                            })
                    return results
                except Exception:
                    conn.rollback()
                    return []

    def get_user_risk_scores(self, username: str, limit: int = 30) -> list[dict[str, Any]]:
        """Returns historical risk scores for a user ordered by date"""
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT re.risk_score, re.risk_level, re.created_at, re.summary, re.correlated_signals_json
                        FROM risk_events re
                        WHERE re.username = %s
                        ORDER BY re.created_at DESC
                        LIMIT %s
                        """,
                        (username, limit)
                    )
                    results = []
                    for row in cursor.fetchall():
                        results.append({
                            "risk_score": row[0],
                            "risk_level": row[1],
                            "created_at": row[2],
                            "summary": row[3],
                            "correlated_signals_json": row[4]
                        })
                    return sorted(results, key=lambda x: x["created_at"])
                except Exception:
                    conn.rollback()
                    return []

    def get_user_predictions(self, username: str) -> dict[str, Any] | None:
        """Returns latest model predictions for a user"""
        with self.connection() as conn:
            with closing(conn.cursor()) as cursor:
                try:
                    cursor.execute(
                        """
                        SELECT mo.detector_name, mo.score, mo.confidence, mo.is_anomaly, 
                               mo.feature_contributions_json, mo.reason_summary, mo.created_at
                        FROM model_outputs mo
                        WHERE mo.username = %s
                        ORDER BY mo.created_at DESC
                        LIMIT 2
                        """,
                        (username,)
                    )
                    
                    predictions = {
                        "short_term": None,
                        "long_term": None
                    }
                    
                    for idx, row in enumerate(cursor.fetchall()):
                        detector_type = "short_term" if idx == 0 else "long_term"
                        contributions = row[4] if isinstance(row[4], dict) else (json.loads(row[4]) if row[4] else {})
                        
                        predictions[detector_type] = {
                            "detector": row[0],
                            "score": row[1],
                            "confidence": row[2],
                            "is_anomaly": bool(row[3]),
                            "contributions": contributions,
                            "summary": row[5],
                            "created_at": row[6]
                        }
                    
                    return predictions if predictions["short_term"] or predictions["long_term"] else None
                except Exception:
                    conn.rollback()
                    return None
