"""Run once at 01:00 UTC for the preceding completed UTC day.

Schedule this script with the deployment's single-instance scheduler. It does
not create attested daily40 rows; the collector rollup producer must do that.
"""
from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.config import config
from server.risk.daily_rollup import run_daily_model_pipeline
from server.risk.ml_cache import _redis_client
from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.postgres_storage import PostgresStorage
from server.storage.repositories.model_repo import ModelReviewRepository


def main() -> None:
    parser = argparse.ArgumentParser(description="Model V3 completed-day shadow batch")
    parser.add_argument("--as-of", type=date.fromisoformat)
    parser.add_argument("--max-reviews", type=int, default=20)
    args = parser.parse_args()
    pg = PostgresStorage(config.database_dsn, minconn=1, maxconn=2)
    ch = ClickHouseStorage(
        host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure,
        ca_cert=config.clickhouse_ca_cert, query_timeout=config.clickhouse_query_timeout,
    )
    try:
        if not ch.is_connected():
            raise RuntimeError("ClickHouse is unavailable")
        redis_client = _redis_client(config.redis_url) if config.redis_url else None
        result = run_daily_model_pipeline(ch, ModelReviewRepository(pg), redis_client,
                                          as_of=args.as_of, max_reviews=args.max_reviews)
        print(json.dumps(result, sort_keys=True))
    finally:
        ch.close()
        pg.close()


if __name__ == "__main__":
    main()
