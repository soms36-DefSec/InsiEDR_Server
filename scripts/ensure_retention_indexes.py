"""Ensure PostgreSQL retention indexes exist and are valid.

Executes CREATE INDEX CONCURRENTLY outside transaction blocks with autocommit,
and automatically cleans up any invalid indexes left behind by interrupted builds.

Usage:
    python scripts/ensure_retention_indexes.py          # Build missing indexes concurrently
    python scripts/ensure_retention_indexes.py --check  # Inspect without modifying
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.config import config
from server.storage.postgres_storage import PostgresStorage

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("insiedr.retention_indexes")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Inspect index status only, do not build")
    args = parser.parse_args()

    if not config.database_dsn:
        logger.error("INSIEDR_DATABASE_DSN is not configured.")
        sys.exit(1)

    logger.info("Connecting to PostgreSQL to verify retention indexes...")
    storage = PostgresStorage(config.database_dsn, minconn=1, maxconn=2)
    try:
        report = storage.ensure_retention_indexes(check_only=args.check)
        print("\n=== Retention Indexes Status ===")
        print(json.dumps(report, indent=2))
        all_ok = all(v in ("valid", "created") for v in report.values())
        if all_ok:
            logger.info("All retention indexes are verified and ready.")
            sys.exit(0)
        elif args.check:
            logger.warning("One or more retention indexes are missing or invalid.")
            sys.exit(2)
        else:
            logger.warning("Retention index status completed with notes.")
            sys.exit(0)
    finally:
        storage.close()


if __name__ == "__main__":
    main()
