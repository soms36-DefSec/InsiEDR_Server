"""Print read-only collector coverage evidence for one completed UTC day."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.config import config
from server.risk.daily40_source_inventory import inventory_daily40_sources


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only Model V3 source inventory")
    parser.add_argument("--as-of", type=date.fromisoformat,
                        default=datetime.now(timezone.utc).date() - timedelta(days=1))
    parser.add_argument("--collector-schema-version", type=int, choices=(1, 2), default=1)
    args = parser.parse_args()
    import clickhouse_connect
    client = clickhouse_connect.get_client(
        host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure,
        ca_cert=config.clickhouse_ca_cert, send_receive_timeout=config.clickhouse_query_timeout,
    )
    try:
        rows = inventory_daily40_sources(client, args.as_of,
                                          args.collector_schema_version)
        print(json.dumps(rows, indent=2))
    finally:
        client.close()


if __name__ == "__main__":
    main()
