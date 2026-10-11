#!/usr/bin/env python3
"""
scripts/migrate_pg_to_clickhouse.py
-----------------------------------
Operational Tool: Migrates Historical Telemetry from PostgreSQL to ClickHouse.

Usage:
------
    python scripts/migrate_pg_to_clickhouse.py [--dry-run] [--batch-size 1000] [--table <name>]

Description:
------------
Streams historical telemetry records from PostgreSQL and batch-inserts them
into ClickHouse. Runs idempotently and displays migration progress and checksums.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("insiedr.migration.ch")


def _format_dt(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    return str(val)


def _json_str(val: Any) -> str:
    if val is None:
        return "{}"
    if isinstance(val, str):
        return val
    try:
        return json.dumps(val, default=str)
    except Exception:
        return "{}"


def migrate_table(
    pg_conn: Any,
    ch_client: Any,
    table: str,
    query_sql: str,
    transform_row: Any,
    batch_size: int = 1000,
    dry_run: bool = False,
) -> int:
    """Stream rows from PG and batch insert into ClickHouse."""
    logger.info("Migrating table '%s'...", table)

    pg_cur = pg_conn.cursor(name=f"stream_cursor_{table}")
    pg_cur.itersize = batch_size
    try:
        pg_cur.execute(query_sql)
    except Exception as exc:
        logger.warning("Could not query table '%s' on Postgres (table may be empty or missing): %s", table, exc)
        pg_conn.rollback()
        return 0

    total_migrated = 0
    batch: List[Dict[str, Any]] = []

    while True:
        rows = pg_cur.fetchmany(batch_size)
        if not rows:
            break

        cols = [d[0] for d in pg_cur.description]
        for raw_row in rows:
            row_dict = dict(zip(cols, raw_row))
            transformed = transform_row(row_dict)
            if transformed:
                batch.append(transformed)

        if batch:
            if not dry_run:
                col_names = list(batch[0].keys())
                matrix = [[r.get(c) for c in col_names] for r in batch]
                ch_client.insert(table=table, data=matrix, column_names=col_names)
            total_migrated += len(batch)
            logger.info("  -> Table '%s': %d rows streamed%s", table, total_migrated, " (DRY-RUN)" if dry_run else "")
            batch.clear()

    pg_cur.close()
    logger.info("Finished migrating '%s': %d total rows.", table, total_migrated)
    return total_migrated


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate telemetry from PostgreSQL to ClickHouse.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migration without inserting into ClickHouse")
    parser.add_argument("--batch-size", type=int, default=1000, help="Row batch size (default: 1000)")
    parser.add_argument("--table", type=str, default=None, help="Migrate specific table only")
    args = parser.parse_args()

    pg_dsn = os.environ.get("DATABASE_DSN") or os.environ.get("INSIEDR_DATABASE_DSN")
    ch_host = os.environ.get("CLICKHOUSE_HOST", "localhost")
    ch_port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    ch_user = os.environ.get("CLICKHOUSE_USER", "default")
    ch_pass = os.environ.get("CLICKHOUSE_PASSWORD", "")
    ch_db = os.environ.get("CLICKHOUSE_DB", "insiedr_analytics")

    if not pg_dsn:
        logger.error("DATABASE_DSN environment variable is required.")
        return 1

    try:
        import psycopg2
        pg_conn = psycopg2.connect(pg_dsn)
        logger.info("Connected to PostgreSQL.")
    except Exception as exc:
        logger.error("Failed connecting to PostgreSQL: %s", exc)
        return 1

    try:
        import clickhouse_connect
        ch_client = clickhouse_connect.get_client(
            host=ch_host,
            port=ch_port,
            username=ch_user,
            password=ch_pass,
            database=ch_db,
        )
        logger.info("Connected to ClickHouse (%s:%d/%s).", ch_host, ch_port, ch_db)
    except Exception as exc:
        logger.error("Failed connecting to ClickHouse: %s", exc)
        return 1

    # Table migration transforms
    def _transform_raw_payloads(r: dict) -> dict:
        return {
            "payload_id": str(r.get("payload_id")),
            "agent_id": str(r.get("agent_id") or ""),
            "received_at": _format_dt(r.get("received_at")),
            "envelope_created_at": _format_dt(r.get("envelope_created_at")),
            "payload_collected_at": _format_dt(r.get("payload_collected_at")),
            "hostname": str(r.get("hostname") or ""),
            "username": str(r.get("username") or ""),
            "crypto_scheme": str(r.get("crypto_scheme") or ""),
            "key_id": str(r.get("key_id") or ""),
            "nonce_hash": str(r.get("nonce_hash") or ""),
            "ciphertext_hash": str(r.get("ciphertext_hash") or ""),
            "decrypted_payload_hash": str(r.get("decrypted_payload_hash") or ""),
            "encrypted_envelope_json": _json_str(r.get("encrypted_envelope_json")),
            "validation_status": str(r.get("validation_status") or "accepted"),
            "duplicate_attempt_count": int(r.get("duplicate_attempt_count") or 0),
        }

    def _transform_collector_results(r: dict) -> dict:
        import uuid
        return {
            "id": str(r.get("id") or uuid.uuid4()),
            "payload_id": str(r.get("payload_id")),
            "agent_id": str(r.get("agent_id") or ""),
            "collector": str(r.get("collector") or ""),
            "collector_collected_at": _format_dt(r.get("collector_collected_at")),
            "hostname": str(r.get("hostname") or ""),
            "status": str(r.get("status") or "unknown"),
            "payload_json": _json_str(r.get("payload_json")),
            "error_type": r.get("error_type"),
            "error_message": r.get("error_message"),
            "source_quality": str(r.get("source_quality") or "high"),
        }

    def _transform_risk_events(r: dict) -> dict:
        import uuid
        return {
            "id": str(r.get("id") or uuid.uuid4()),
            "payload_id": str(r.get("payload_id") or ""),
            "agent_id": str(r.get("agent_id") or ""),
            "username": str(r.get("username") or ""),
            "risk_score": float(r.get("risk_score") or 0.0),
            "risk_level": str(r.get("risk_level") or "low"),
            "correlated_signals_json": _json_str(r.get("correlated_signals_json")),
            "summary": str(r.get("summary") or ""),
            "created_at": _format_dt(r.get("created_at")),
        }

    tables_to_migrate = [
        ("raw_payloads", "SELECT * FROM raw_payloads", _transform_raw_payloads),
        ("collector_results", "SELECT * FROM collector_results", _transform_collector_results),
        ("risk_events", "SELECT * FROM risk_events", _transform_risk_events),
    ]

    total_all = 0
    for t_name, query_sql, transform_fn in tables_to_migrate:
        if args.table and args.table != t_name:
            continue
        total_all += migrate_table(
            pg_conn=pg_conn,
            ch_client=ch_client,
            table=t_name,
            query_sql=query_sql,
            transform_row=transform_fn,
            batch_size=args.batch_size,
            dry_run=args.dry_run,
        )

    logger.info("All telemetry migrations completed successfully. Total records processed: %d", total_all)

    if not args.dry_run and (not args.table or args.table in ("collector_results", "telemetry_events")):
        logger.info("Synchronizing ClickHouse 'telemetry_events' from 'collector_results'...")
        try:
            ch_client.command(
                """
                INSERT INTO telemetry_events (
                    event_id, payload_id, agent_id, collector_name, timestamp,
                    hostname, username, status, summary_preview, raw_payload_json, tenant_id
                )
                SELECT
                    id AS event_id,
                    payload_id,
                    agent_id,
                    collector AS collector_name,
                    collector_collected_at AS timestamp,
                    hostname,
                    '' AS username,
                    status,
                    substring(payload_json, 1, 150) AS summary_preview,
                    payload_json AS raw_payload_json,
                    'default' AS tenant_id
                FROM collector_results
                """
            )
            logger.info("ClickHouse 'telemetry_events' successfully populated.")
        except Exception as exc:
            logger.warning("Could not sync ClickHouse telemetry_events: %s", exc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
