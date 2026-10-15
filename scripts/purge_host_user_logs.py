"""Purge telemetry logs for a specific HostName and UserName across PostgreSQL and ClickHouse.

Usage:
    # 1. Dry run (preview count without deleting):
    python scripts/purge_host_user_logs.py --hostname MuMu --username MUMU$ --dry-run

    # 2. Execute deletion:
    python scripts/purge_host_user_logs.py --hostname MuMu --username MUMU$ --execute
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.config import config
from server.storage.postgres_storage import PostgresStorage
from server.storage.clickhouse_storage import ClickHouseStorage

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("insiedr.purge")


def preview_and_purge(hostname: str, username: str, execute: bool = False, remove_agent: bool = False) -> dict[str, int]:
    counts: dict[str, int] = {
        "pg_raw_payloads": 0,
        "pg_collector_results": 0,
        "pg_normalized_features": 0,
        "pg_risk_events": 0,
        "pg_agents": 0,
        "ch_raw_payloads": 0,
        "ch_collector_results": 0,
        "ch_collector_events_v2": 0,
    }

    clean_host = hostname.strip()
    clean_user = username.strip()

    logger.info("Scanning database records for HostName='%s', UserName='%s'...", clean_host, clean_user)

    # --------------------------------------------------------------------------
    # 1. PostgreSQL Scan & Purge
    # --------------------------------------------------------------------------
    if config.database_dsn:
        try:
            pg = PostgresStorage(config.database_dsn, minconn=1, maxconn=2)
            with pg.connection() as conn:
                with conn.cursor() as cur:
                    # Count matching raw_payloads
                    cur.execute(
                        """
                        SELECT payload_id FROM raw_payloads
                        WHERE LOWER(hostname) = LOWER(%s) AND LOWER(username) = LOWER(%s)
                        """,
                        (clean_host, clean_user),
                    )
                    matching_payload_ids = [row[0] for row in cur.fetchall()]
                    counts["pg_raw_payloads"] = len(matching_payload_ids)

                    if matching_payload_ids:
                        cur.execute(
                            "SELECT count(*) FROM collector_results WHERE payload_id = ANY(%s)",
                            (matching_payload_ids,),
                        )
                        counts["pg_collector_results"] = cur.fetchone()[0]

                        cur.execute(
                            "SELECT count(*) FROM normalized_features WHERE payload_id = ANY(%s)",
                            (matching_payload_ids,),
                        )
                        counts["pg_normalized_features"] = cur.fetchone()[0]

                    # Count risk_events
                    cur.execute(
                        "SELECT count(*) FROM risk_events WHERE LOWER(username) = LOWER(%s)",
                        (clean_user,),
                    )
                    counts["pg_risk_events"] = cur.fetchone()[0]

                    # Count agents
                    cur.execute(
                        "SELECT count(*) FROM agents WHERE LOWER(hostname) = LOWER(%s)",
                        (clean_host,),
                    )
                    counts["pg_agents"] = cur.fetchone()[0]

                    if execute:
                        logger.info("Executing deletion in PostgreSQL...")
                        # Delete raw_payloads (cascades to collector_results & normalized_features)
                        if matching_payload_ids:
                            cur.execute(
                                "DELETE FROM raw_payloads WHERE payload_id = ANY(%s)",
                                (matching_payload_ids,),
                            )
                            # Fallback direct delete for orphaned collector results if any
                            cur.execute(
                                "DELETE FROM collector_results WHERE LOWER(hostname) = LOWER(%s)",
                                (clean_host,),
                            )

                        # Delete risk_events
                        cur.execute(
                            "DELETE FROM risk_events WHERE LOWER(username) = LOWER(%s)",
                            (clean_user,),
                        )

                        if remove_agent:
                            cur.execute(
                                "DELETE FROM agents WHERE LOWER(hostname) = LOWER(%s)",
                                (clean_host,),
                            )
                        conn.commit()
                        logger.info("PostgreSQL deletion committed successfully.")
            pg.close()
        except Exception as exc:
            logger.error("PostgreSQL operation failed: %s", exc)

    # --------------------------------------------------------------------------
    # 2. ClickHouse Scan & Purge
    # --------------------------------------------------------------------------
    if config.clickhouse_enabled:
        try:
            ch = ClickHouseStorage(
                host=config.clickhouse_host,
                port=config.clickhouse_port,
                username=config.clickhouse_user,
                password=config.clickhouse_password,
                database=config.clickhouse_db,
                secure=config.clickhouse_secure,
                ca_cert=config.clickhouse_ca_cert,
            )
            if ch.is_connected():
                # Count ClickHouse raw_payloads
                try:
                    res = ch._query(
                        "SELECT count() FROM raw_payloads WHERE lower(hostname) = lower(%(host)s) AND lower(username) = lower(%(user)s)",
                        {"host": clean_host, "user": clean_user},
                    )
                    counts["ch_raw_payloads"] = res.result_rows[0][0] if res.result_rows else 0
                except Exception:
                    pass

                # Count ClickHouse collector_results
                try:
                    res = ch._query(
                        "SELECT count() FROM collector_results WHERE lower(hostname) = lower(%(host)s)",
                        {"host": clean_host},
                    )
                    counts["ch_collector_results"] = res.result_rows[0][0] if res.result_rows else 0
                except Exception:
                    pass

                # Count ClickHouse collector_events_v2
                try:
                    res = ch._query(
                        "SELECT count() FROM collector_events_v2 WHERE lower(hostname) = lower(%(host)s) AND lower(username) = lower(%(user)s)",
                        {"host": clean_host, "user": clean_user},
                    )
                    counts["ch_collector_events_v2"] = res.result_rows[0][0] if res.result_rows else 0
                except Exception:
                    pass

                if execute:
                    logger.info("Executing mutation deletes in ClickHouse...")
                    try:
                        ch._client.command(
                            f"ALTER TABLE raw_payloads DELETE WHERE lower(hostname) = lower('{clean_host}') AND lower(username) = lower('{clean_user}')"
                        )
                    except Exception as e:
                        logger.warning("ClickHouse raw_payloads delete mutation: %s", e)

                    try:
                        ch._client.command(
                            f"ALTER TABLE collector_results DELETE WHERE lower(hostname) = lower('{clean_host}')"
                        )
                    except Exception as e:
                        logger.warning("ClickHouse collector_results delete mutation: %s", e)

                    try:
                        ch._client.command(
                            f"ALTER TABLE collector_events_v2 DELETE WHERE lower(hostname) = lower('{clean_host}') AND lower(username) = lower('{clean_user}')"
                        )
                    except Exception as e:
                        logger.warning("ClickHouse collector_events_v2 delete mutation: %s", e)

                    logger.info("ClickHouse deletion mutations submitted.")
            ch.close()
        except Exception as exc:
            logger.warning("ClickHouse connection/operation note: %s", exc)

    return counts


def main():
    parser = argparse.ArgumentParser(description="Purge logs for a specific HostName and UserName")
    parser.add_argument("--hostname", required=True, help="Target HostName (e.g. MuMu)")
    parser.add_argument("--username", required=True, help="Target UserName (e.g. MUMU$)")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Preview records without deleting")
    parser.add_argument("--execute", action="store_true", default=False, help="Actually perform deletion")
    parser.add_argument("--remove-agent", action="store_true", default=False, help="Also remove the agent registration entry")

    args = parser.parse_args()

    if not args.execute and not args.dry_run:
        print("[!] Defaulting to --dry-run mode to prevent accidental data loss.")
        args.dry_run = True

    is_execute = args.execute and not args.dry_run

    results = preview_and_purge(
        hostname=args.hostname,
        username=args.username,
        execute=is_execute,
        remove_agent=args.remove_agent,
    )

    action = "DELETED" if is_execute else "FOUND (Dry Run)"
    print("\n" + "=" * 60)
    print(f"Purge Summary for HostName='{args.hostname}', UserName='{args.username}'")
    print("=" * 60)
    for table, count in results.items():
        print(f"  {table:26}: {count:>8} records {action}")
    print("=" * 60)

    if not is_execute:
        print("\nTo actually delete these records, run with `--execute`:")
        print(f"python scripts/purge_host_user_logs.py --hostname {args.hostname} --username {args.username} --execute\n")


if __name__ == "__main__":
    main()
