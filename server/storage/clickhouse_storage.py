"""
server/storage/clickhouse_storage.py
------------------------------------
ClickHouse High-Performance Columnar Storage Engine for InsiEDR Telemetry.

Architecture & Design:
======================
ClickHouse acts as the high-throughput OLAP layer for:
  - Raw agent payloads, envelopes, and tamper telemetry.
  - Granular collector execution results and source-quality labels.
  - Normalized numerical and categorical feature vectors.
  - Model outputs, detector inferences, and reason summaries.
  - Correlated risk events, anomaly alerts, and behavioral scores.

Security & Hardening:
---------------------
  - TLS / HTTPS secure connection support with certificate verification.
  - Query memory limits (`max_memory_usage=2GB`) and execution timeouts (`30s`)
    to prevent denial-of-service from runaway analytical queries.
  - Query parameter binding strictly enforced (zero string concatenation).
  - Dead-Letter Queue (DLQ) disk spooling via `ClickHouseBatcher`.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from server.config import config
from server.storage.clickhouse_batcher import ClickHouseBatcher

logger = logging.getLogger("insiedr.storage.clickhouse")

SCHEMA_FILE = Path(__file__).resolve().parent / "clickhouse_schema.sql"


def _format_dt(val: Any) -> Optional[datetime]:
    """Parse string or timestamp to UTC datetime for ClickHouse DateTime64."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _json_str(val: Any) -> str:
    """Serialize value to compact JSON string."""
    if val is None:
        return "{}"
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, default=str, separators=(",", ":"))
    except Exception:
        return "{}"


class ClickHouseStorage:
    """
    Dedicated ClickHouse storage engine for high-volume logs,
    telemetry, features, and model detection events.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        database: str = "insiedr_analytics",
        batch_size: int = 500,
        flush_interval: float = 1.0,
        max_buffer_bytes: int = 25 * 1024 * 1024,
        secure: bool = False,
        verify: bool = True,
        ca_cert: str | None = None,
        query_timeout: int = 30,
        max_memory_usage: int = 2000000000,
        dlq_enabled: bool = True,
        dlq_dir: str | Path = "data/dlq",
        client: Any = None,
    ) -> None:
        self.host = host or os.environ.get("CLICKHOUSE_HOST", "localhost")
        self.port = port or int(os.environ.get("CLICKHOUSE_PORT", "8123"))
        self.username = username or os.environ.get("CLICKHOUSE_USER", "default")
        self.password = password or os.environ.get("CLICKHOUSE_PASSWORD", "")
        self.database = database or os.environ.get("CLICKHOUSE_DB", "insiedr_analytics")
        self.secure = secure or (os.environ.get("CLICKHOUSE_SECURE", "false").lower() in ("1", "true", "yes"))
        self.verify = verify
        self.ca_cert = ca_cert or os.environ.get("CLICKHOUSE_CA_CERT")
        self.query_timeout = query_timeout
        self.max_memory_usage = max_memory_usage

        self._client = client
        self._is_connected = False

        if client is not None:
            self._is_connected = True
        else:
            self._init_connection()

        # Initialize asynchronous micro-batcher with Dead-Letter Queue (DLQ)
        self.batcher = ClickHouseBatcher(
            insert_fn=self._raw_batch_insert,
            batch_size=batch_size,
            flush_interval=flush_interval,
            max_buffer_bytes=max_buffer_bytes,
            dlq_enabled=dlq_enabled,
            dlq_dir=dlq_dir,
        )
        if self._is_connected:
            self.batcher.start()

    def _init_connection(self) -> None:
        try:
            import clickhouse_connect
            kwargs: Dict[str, Any] = {
                "host": self.host,
                "port": self.port,
                "username": self.username,
                "password": self.password,
                "database": self.database,
                "connect_timeout": 3,
                "send_receive_timeout": self.query_timeout,
            }
            if self.secure:
                kwargs["secure"] = True
                kwargs["verify"] = self.verify
                if self.ca_cert:
                    kwargs["ca_cert"] = self.ca_cert

            try:
                self._client = clickhouse_connect.get_client(**kwargs)
            except Exception as conn_err:
                err_str = str(conn_err).lower()
                if "does not exist" in err_str or "unknown database" in err_str or "database" in err_str:
                    logger.info("ClickHouse database '%s' not found. Connecting via 'default' to bootstrap...", self.database)
                    boot_kwargs = dict(kwargs)
                    boot_kwargs["database"] = "default"
                    boot_client = clickhouse_connect.get_client(**boot_kwargs)
                    boot_client.command(f"CREATE DATABASE IF NOT EXISTS {self.database}")
                    boot_client.close()
                    self._client = clickhouse_connect.get_client(**kwargs)
                else:
                    raise conn_err

            self._client.command("SELECT 1")
            self._is_connected = True
            logger.info("Connected to ClickHouse database '%s' at %s:%s (secure=%s)",
                        self.database, self.host, self.port, self.secure)
        except Exception as exc:
            self._is_connected = False
            self._client = None
            logger.warning("ClickHouse connection failed (%s). Operating in disabled/fallback mode.", exc)

    def is_connected(self) -> bool:
        return self._is_connected and self._client is not None

    def _query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a parameterized query with server-side memory & execution time quotas."""
        settings = {
            "max_execution_time": self.query_timeout,
            "max_memory_usage": self.max_memory_usage,
        }
        return self._client.query(query, parameters=parameters, settings=settings)

    def ensure_schema(self) -> None:
        """Create ClickHouse database and telemetry tables if not already present."""
        if not self.is_connected():
            self._init_connection()
            if not self.is_connected():
                return
        try:
            self._client.command(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            if SCHEMA_FILE.is_file():
                sql_content = SCHEMA_FILE.read_text(encoding="utf-8")
                # Split statements by semicolon
                statements = [stmt.strip() for stmt in sql_content.split(";") if stmt.strip()]
                for stmt in statements:
                    if stmt.upper().startswith("USE "):
                        continue
                    self._client.command(stmt, settings={"default_database": self.database})
                logger.info("ClickHouse schema verified and up to date in '%s'.", self.database)
        except Exception as exc:
            logger.error("Failed ensuring ClickHouse schema: %s", exc)

    def _raw_batch_insert(self, table: str, rows: List[Dict[str, Any]]) -> None:
        """Low-level batch insert execution via clickhouse-connect."""
        if not self.is_connected() or not rows:
            return

        column_names = list(rows[0].keys())
        data_matrix = []
        for row in rows:
            data_matrix.append([row.get(col) for col in column_names])

        self._client.insert(
            table=table,
            data=data_matrix,
            column_names=column_names,
        )

    def close(self) -> None:
        """Cleanly flush batches and close client."""
        if hasattr(self, "batcher"):
            self.batcher.stop()
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._is_connected = False

    def flush_all(self, raise_on_error: bool = False) -> None:
        """Synchronously flush all pending batches through the batcher."""
        if hasattr(self, "batcher") and self.batcher is not None:
            self.batcher.flush_all(raise_on_error=raise_on_error)

    # --------------------------------------------------------------------------
    # Ingest & Storage APIs (Queued via Batcher)
    # --------------------------------------------------------------------------

    def store_raw_payload(self, envelope: Dict[str, Any], decrypted_payload: Dict[str, Any]) -> None:
        """Queue raw payload, collector results, and normalized features for ClickHouse batching."""
        payload_id = decrypted_payload.get("payload_id")
        agent_id = decrypted_payload.get("agent_id")
        if not payload_id or not self.is_connected():
            return

        now_dt = datetime.now(timezone.utc)
        collected_dt = _format_dt(decrypted_payload.get("collected_at")) or now_dt
        envelope_created_dt = _format_dt(envelope.get("created_at")) or now_dt

        # 1. Raw Payloads Row
        raw_row = {
            "payload_id": str(payload_id),
            "agent_id": str(agent_id or ""),
            "received_at": now_dt,
            "envelope_created_at": envelope_created_dt,
            "payload_collected_at": collected_dt,
            "hostname": str(decrypted_payload.get("hostname") or ""),
            "username": str(decrypted_payload.get("username") or ""),
            "crypto_scheme": str(envelope.get("scheme") or ""),
            "key_id": str(envelope.get("key_id") or ""),
            "nonce_hash": str(envelope.get("nonce_hash") or ""),
            "ciphertext_hash": str(envelope.get("ciphertext_hash") or ""),
            "decrypted_payload_hash": str(envelope.get("decrypted_payload_hash") or ""),
            "encrypted_envelope_json": _json_str(envelope),
            "validation_status": "accepted",
            "duplicate_attempt_count": 0,
        }
        self.batcher.add("raw_payloads", raw_row)

        # 2. Collector Results & Normalized Features
        collector_rows = []
        feature_rows = []
        risk_rows = []

        for cr in decrypted_payload.get("collectors", []):
            if not isinstance(cr, dict):
                continue
            collector_name = str(cr.get("collector") or "")
            col_collected_dt = _format_dt(cr.get("collected_at")) or collected_dt
            status = str(cr.get("status") or "unknown")
            error = cr.get("error") if isinstance(cr.get("error"), dict) else {}
            source_quality = self._derive_source_quality(cr)

            col_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload_id}:col:{collector_name}"))
            col_row = {
                "id": col_id,
                "payload_id": str(payload_id),
                "agent_id": str(agent_id or ""),
                "collector": collector_name,
                "collector_collected_at": col_collected_dt,
                "hostname": str(cr.get("hostname") or decrypted_payload.get("hostname") or ""),
                "status": status,
                "payload_json": _json_str(cr.get("payload") or {}),
                "error_type": error.get("type"),
                "error_message": error.get("message"),
                "source_quality": source_quality,
            }
            collector_rows.append(col_row)

            # Check for tamper alert
            if collector_name == "tamper" or status == "critical":
                risk_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload_id}:risk:{collector_name}"))
                risk_rows.append({
                    "id": risk_id,
                    "payload_id": str(payload_id),
                    "agent_id": str(agent_id or ""),
                    "username": str(decrypted_payload.get("username") or ""),
                    "risk_score": 100.0,
                    "risk_level": "critical",
                    "correlated_signals_json": _json_str({"collector": collector_name, "hostname": cr.get("hostname")}),
                    "summary": f"Agent Tamper Alert: Forced termination or tampering detected on {cr.get('hostname')}.",
                    "created_at": col_collected_dt,
                })

            # Extract features
            payload_data = cr.get("payload")
            if isinstance(payload_data, dict):
                for feat_name, feat_val in payload_data.items():
                    if feat_val is None:
                        continue
                    feat_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload_id}:feat:{collector_name}:{feat_name}"))
                    feat_row = {
                        "id": feat_id,
                        "payload_id": str(payload_id),
                        "agent_id": str(agent_id or ""),
                        "username": str(decrypted_payload.get("username") or ""),
                        "hostname": str(decrypted_payload.get("hostname") or cr.get("hostname") or ""),
                        "collector": collector_name,
                        "entity_user": str(decrypted_payload.get("username") or ""),
                        "feature_name": str(feat_name),
                        "feature_value_numeric": float(feat_val) if isinstance(feat_val, (int, float, bool)) else None,
                        "feature_value_text": str(feat_val) if isinstance(feat_val, str) else None,
                        "feature_value_json": _json_str(feat_val) if isinstance(feat_val, (dict, list)) else None,
                        "feature_timestamp": col_collected_dt,
                        "source_quality": source_quality,
                        "quality_notes": None,
                        "created_at": now_dt,
                    }
                    feature_rows.append(feat_row)

        if collector_rows:
            self.batcher.add_many("collector_results", collector_rows)
        if feature_rows:
            self.batcher.add_many("normalized_features", feature_rows)
        if risk_rows:
            self.batcher.add_many("risk_events", risk_rows)

    @staticmethod
    def _derive_source_quality(collector_result: dict[str, Any]) -> str:
        if collector_result.get("status") != "success":
            return "low"
        collector_name = str(collector_result.get("collector", "")).lower()
        if "file" in collector_name:
            return "heuristic"
        if "device" in collector_name or "usb" in collector_name:
            return "verify_required"
        if "http" in collector_name or "browser" in collector_name:
            return "browser_history"
        if "network" in collector_name:
            return "passive_optional"
        return "high"

    def save_model_output(self, output: Dict[str, Any]) -> None:
        """Queue a model inference detection result to ClickHouse."""
        if not self.is_connected():
            return
        row = {
            "id": str(uuid.uuid4()),
            "payload_id": str(output.get("payload_id") or ""),
            "agent_id": str(output.get("agent_id") or ""),
            "username": str(output.get("username") or ""),
            "detector_name": str(output.get("detector_name") or ""),
            "model_version": str(output.get("model_version") or "v1"),
            "score": float(output["score"]) if output.get("score") is not None else None,
            "confidence": float(output["confidence"]) if output.get("confidence") is not None else None,
            "is_anomaly": 1 if output.get("is_anomaly") else 0,
            "feature_contributions_json": _json_str(output.get("feature_contributions_json") or {}),
            "reason_summary": str(output.get("reason_summary") or ""),
            "created_at": datetime.now(timezone.utc),
        }
        self.batcher.add("model_outputs", row)

    def save_risk_event(self, event: Dict[str, Any]) -> None:
        """Queue a correlated risk event to ClickHouse."""
        if not self.is_connected():
            return
        row = {
            "id": str(uuid.uuid4()),
            "payload_id": str(event.get("payload_id") or ""),
            "agent_id": str(event.get("agent_id") or ""),
            "username": str(event.get("username") or ""),
            "risk_score": float(event.get("risk_score") or 0.0),
            "risk_level": str(event.get("risk_level") or "low").lower(),
            "correlated_signals_json": _json_str(event.get("correlated_signals_json") or {}),
            "summary": str(event.get("summary") or ""),
            "created_at": _format_dt(event.get("collected_at")) or datetime.now(timezone.utc),
        }
        self.batcher.add("risk_events", row)

    def save_anomaly(self, anomaly: Dict[str, Any]) -> None:
        """Queue an anomaly alert to ClickHouse."""
        if not self.is_connected():
            return
        row = {
            "id": str(anomaly.get("id") or uuid.uuid4()),
            "payload_id": str(anomaly.get("payload_id") or ""),
            "agent_id": str(anomaly.get("agent_id") or ""),
            "username": str(anomaly.get("username") or ""),
            "anomaly_type": str(anomaly.get("anomaly_type") or "behavioral"),
            "severity": str(anomaly.get("severity") or "medium"),
            "detectors_json": _json_str(anomaly.get("detectors_json") or {}),
            "top_features_json": _json_str(anomaly.get("top_features_json") or {}),
            "status": str(anomaly.get("status") or "open"),
            "created_at": _format_dt(anomaly.get("created_at")) or datetime.now(timezone.utc),
            "acknowledged_at": None,
            "acknowledged_by": None,
        }
        self.batcher.add("anomalies", row)

    # --------------------------------------------------------------------------
    # Analytical & Query APIs (Guarded with Resource Quotas)
    # --------------------------------------------------------------------------

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
    ) -> List[Dict[str, Any]]:
        """Query raw payload logs with high-performance filtering and resource guards."""
        if not self.is_connected():
            return []

        where_clauses = []
        params: Dict[str, Any] = {}

        if agent_id:
            where_clauses.append("agent_id = %(agent_id)s")
            params["agent_id"] = agent_id
        if hostname:
            where_clauses.append("hostname = %(hostname)s")
            params["hostname"] = hostname
        if username:
            where_clauses.append("username = %(username)s")
            params["username"] = username
        if start_time:
            where_clauses.append("received_at >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            where_clauses.append("received_at <= %(end_time)s")
            params["end_time"] = end_time

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        query = f"""
            SELECT payload_id, agent_id, received_at, envelope_created_at, payload_collected_at,
                   hostname, username, crypto_scheme, key_id, nonce_hash, ciphertext_hash,
                   decrypted_payload_hash, encrypted_envelope_json, validation_status
            FROM raw_payloads
            {where_sql}
            ORDER BY received_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset

        try:
            res = self._query(query, parameters=params)
            cols = res.column_names
            rows = []
            for row in res.result_rows:
                d = dict(zip(cols, row))
                if isinstance(d.get("encrypted_envelope_json"), str):
                    try:
                        d["encrypted_envelope_json"] = json.loads(d["encrypted_envelope_json"])
                    except Exception:
                        pass
                rows.append(d)
            return rows
        except Exception as exc:
            logger.error("ClickHouse list_logs query failed: %s", exc)
            return []

    def get_latest_collector_states(self, agent_id: str) -> List[Dict[str, Any]]:
        """Select one whole observation, so nullable fields cannot mix snapshots."""
        query = """
            SELECT collector,
                   tupleElement(state, 1) AS agent_id,
                   tupleElement(state, 2) AS hostname,
                   tupleElement(state, 3) AS status,
                   tupleElement(state, 4) AS payload_json,
                   tupleElement(state, 5) AS collector_collected_at,
                   tupleElement(state, 6) AS payload_id,
                   tupleElement(state, 7) AS error_type,
                   tupleElement(state, 8) AS error_message,
                   tupleElement(state, 9) AS source_quality
            FROM (
                SELECT collector,
                       argMax(tuple(agent_id, hostname, status, payload_json,
                                    collector_collected_at, payload_id, error_type,
                                    error_message, source_quality),
                              tuple(collector_collected_at, payload_id, id)) AS state
                FROM collector_results WHERE agent_id = %(agent_id)s
                GROUP BY collector
            ) ORDER BY collector
        """
        result = self._query(query, parameters={"agent_id": agent_id})
        states = [dict(zip(result.column_names, row)) for row in result.result_rows]
        for state in states:
            if isinstance(state["payload_json"], str):
                state["payload_json"] = json.loads(state["payload_json"])
        return states

    def list_collector_results(
        self,
        limit: int = 100,
        offset: int = 0,
        collector: str | None = None,
        username: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        exact_collector: bool = False,
    ) -> List[Dict[str, Any]]:
        """Query collector observation history for dashboards and streaming export."""
        if not self.is_connected():
            return []

        where_clauses = []
        params: Dict[str, Any] = {}

        if collector:
            if exact_collector:
                where_clauses.append("lower(collector) = lower(%(collector)s)")
                params["collector"] = collector
            else:
                where_clauses.append("collector ILIKE %(collector)s")
                params["collector"] = f"%{collector}%"
        if username:
            where_clauses.append("payload_id IN (SELECT payload_id FROM raw_payloads WHERE username ILIKE %(username)s)")
            params["username"] = f"%{username}%"
        if start_time:
            where_clauses.append("collector_collected_at >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            where_clauses.append("collector_collected_at <= %(end_time)s")
            params["end_time"] = end_time

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        query = f"""
            SELECT id, payload_id, agent_id, collector, collector_collected_at, hostname,
                   status, payload_json, error_type, error_message, source_quality
            FROM collector_results
            {where_sql}
            ORDER BY collector_collected_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset

        try:
            res = self._query(query, parameters=params)
            cols = res.column_names
            results = []
            for row in res.result_rows:
                d = dict(zip(cols, row))
                payload_str = d.get("payload_json")
                if isinstance(payload_str, str):
                    try:
                        d["payload"] = json.loads(payload_str)
                    except Exception:
                        d["payload"] = {}
                else:
                    d["payload"] = payload_str or {}
                d["collected_at"] = d.get("collector_collected_at")
                results.append(d)
            return results
        except Exception as exc:
            logger.error("ClickHouse list_collector_results failed: %s", exc)
            return []

    def get_distinct_collectors(self) -> List[str]:
        default_collectors = [
            "logon", "file", "process", "network", "device", "http",
            "lsass_monitor", "registry", "keystroke-collector",
            "decoy-monitor", "clipboard-monitor", "persistence_monitor",
            "dns_monitor", "driver_monitor", "wmi_activity", "usn_monitor"
        ]
        if not self.is_connected():
            return sorted(default_collectors)
        try:
            res = self._query("SELECT DISTINCT collector FROM collector_results WHERE collector != ''")
            found = {str(r[0]).strip().lower() for r in res.result_rows if r[0]}
            return sorted(list(set(default_collectors) | found))
        except Exception as exc:
            logger.warning("ClickHouse get_distinct_collectors failed: %s", exc)
            return sorted(default_collectors)

    def get_distinct_usernames(self) -> List[str]:
        if not self.is_connected():
            return []
        try:
            res = self._query("SELECT DISTINCT username FROM raw_payloads WHERE username != ''")
            return sorted([str(r[0]).strip() for r in res.result_rows if r[0]])
        except Exception as exc:
            logger.warning("ClickHouse get_distinct_usernames failed: %s", exc)
            return []

    def count_collector_results(
        self,
        collector: str | None = None,
        username: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        exact_collector: bool = False,
    ) -> int:
        if not self.is_connected():
            return 0
        where_clauses = []
        params = {}
        if collector:
            if exact_collector:
                where_clauses.append("lower(collector) = lower(%(collector)s)")
                params["collector"] = collector
            else:
                where_clauses.append("collector ILIKE %(collector)s")
                params["collector"] = f"%{collector}%"
        if username:
            where_clauses.append("payload_id IN (SELECT payload_id FROM raw_payloads WHERE username ILIKE %(username)s)")
            params["username"] = f"%{username}%"
        if start_time:
            where_clauses.append("collector_collected_at >= %(start_time)s")
            params["start_time"] = start_time
        if end_time:
            where_clauses.append("collector_collected_at <= %(end_time)s")
            params["end_time"] = end_time
        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        query = f"SELECT count() FROM collector_results {where_sql}"
        try:
            res = self._query(query, parameters=params)
            return int(res.result_rows[0][0]) if res.result_rows else 0
        except Exception:
            return 0

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve recent correlated risk scores."""
        if not self.is_connected():
            return []
        query = """
            SELECT id, payload_id, agent_id, username, risk_score, risk_level,
                   correlated_signals_json, summary, created_at
            FROM risk_events
            ORDER BY created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        try:
            res = self._query(query, parameters={"limit": limit, "offset": offset})
            cols = res.column_names
            results = []
            for row in res.result_rows:
                d = dict(zip(cols, row))
                signals = d.get("correlated_signals_json")
                if isinstance(signals, str):
                    try:
                        d["correlated_signals_json"] = json.loads(signals)
                    except Exception:
                        pass
                results.append(d)
            return results
        except Exception as exc:
            logger.error("ClickHouse list_risk_events query failed: %s", exc)
            return []

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve detected anomalies and explanation features."""
        if not self.is_connected():
            return []
        query = """
            SELECT id, payload_id, agent_id, username, anomaly_type, severity,
                   detectors_json, top_features_json, status, created_at,
                   acknowledged_at, acknowledged_by
            FROM anomalies
            ORDER BY created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        try:
            res = self._query(query, parameters={"limit": limit, "offset": offset})
            cols = res.column_names
            results = []
            for row in res.result_rows:
                d = dict(zip(cols, row))
                for json_col in ("detectors_json", "top_features_json"):
                    if isinstance(d.get(json_col), str):
                        try:
                            d[json_col] = json.loads(d[json_col])
                        except Exception:
                            pass
                results.append(d)
            return results
        except Exception as exc:
            logger.error("ClickHouse list_anomalies query failed: %s", exc)
            return []

    def get_feature_vector(self, payload_id: str) -> Dict[str, Any]:
        """Fetch all normalized features for a given payload ID."""
        if not self.is_connected():
            return {}
        query = """
            SELECT feature_name, feature_value_numeric, feature_value_text, feature_value_json
            FROM normalized_features
            WHERE payload_id = %(payload_id)s
        """
        try:
            res = self._query(query, parameters={"payload_id": payload_id})
            features: Dict[str, Any] = {}
            for name, num, txt, js in res.result_rows:
                if num is not None:
                    features[name] = num
                elif txt is not None:
                    features[name] = txt
                elif js is not None:
                    try:
                        features[name] = json.loads(js)
                    except Exception:
                        features[name] = js
                else:
                    features[name] = None
            return features
        except Exception as exc:
            logger.error("ClickHouse get_feature_vector failed: %s", exc)
            return {}

    def get_user_risk_scores(self, username: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Fetch historical risk events for a specific user."""
        if not self.is_connected():
            return []
        query = """
            SELECT risk_score, risk_level, created_at, summary, correlated_signals_json
            FROM risk_events
            WHERE username = %(username)s
            ORDER BY created_at DESC
            LIMIT %(limit)s
        """
        try:
            res = self._query(query, parameters={"username": username, "limit": limit})
            cols = res.column_names
            results = []
            for row in res.result_rows:
                d = dict(zip(cols, row))
                if isinstance(d.get("correlated_signals_json"), str):
                    try:
                        d["correlated_signals_json"] = json.loads(d["correlated_signals_json"])
                    except Exception:
                        pass
                results.append(d)
            return sorted(results, key=lambda x: str(x.get("created_at") or ""))
        except Exception as exc:
            logger.error("ClickHouse get_user_risk_scores failed: %s", exc)
            return []

    def get_telemetry_stats(self) -> Dict[str, Any]:
        """Aggregate telemetry counts and quality distributions via ClickHouse."""
        if not self.is_connected():
            return {"logs": 0, "collector_results": 0, "anomalies": 0, "risk_events": 0}

        stats: Dict[str, Any] = {}
        try:
            for table, key in [
                ("raw_payloads", "logs"),
                ("collector_results", "collector_results"),
                ("anomalies", "anomalies"),
                ("risk_events", "risk_events"),
            ]:
                r = self._query(f"SELECT count() FROM {table}")
                stats[key] = int(r.result_rows[0][0]) if r.result_rows else 0

            # Collector status distribution
            cr_status = self._query("SELECT status, count() FROM collector_results GROUP BY status")
            stats["collector_status"] = {row[0]: int(row[1]) for row in cr_status.result_rows}

            # Collector name distribution
            cr_names = self._query("SELECT collector, count() FROM collector_results GROUP BY collector")
            stats["collector_counts"] = {row[0]: int(row[1]) for row in cr_names.result_rows}

            # Quality distribution
            nf_quality = self._query("SELECT source_quality, count() FROM normalized_features GROUP BY source_quality")
            stats["source_quality"] = {row[0]: int(row[1]) for row in nf_quality.result_rows}
        except Exception as exc:
            logger.debug("ClickHouse telemetry stats query failed: %s", exc)

        return stats
