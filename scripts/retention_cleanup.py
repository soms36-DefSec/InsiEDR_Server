"""Run the same bounded, serialized retention used by the server scheduler."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.config import config
from server.storage.postgres_storage import PostgresStorage
from server.storage.maintenance import MaintenanceWorker


def run_retention_cleanup(batch_size=5000, max_run_seconds=120, ensure_indexes=False):
    storage = PostgresStorage(config.database_dsn, minconn=1, maxconn=2)
    try:
        if ensure_indexes:
            storage.ensure_retention_indexes()
        return MaintenanceWorker(storage, batch_size=batch_size,
                                 max_run_seconds=max_run_seconds).run_once(force=True)
    finally:
        storage.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch-size', type=int, default=5000)
    parser.add_argument('--max-run-seconds', type=int, default=120)
    parser.add_argument('--ensure-indexes', action='store_true',
                        help='Verify or build concurrent retention indexes before cleanup')
    args = parser.parse_args()
    result = run_retention_cleanup(args.batch_size, args.max_run_seconds, args.ensure_indexes)
    print(json.dumps(result, default=str))
    sys.exit(0 if result['status'] == 'ok' else 1)
