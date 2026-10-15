"""Build minute summaries in bounded, restartable slices; no reader switch.

Run off peak inside the backend image. The live materialized view is installed
BEFORE backfill so concurrent inserts and late arrivals are included. Repeating
a slice cannot double-count an observation ID. Source events must be immutable.
"""
import argparse
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.config import config
from server.storage.dashboard_rollups import names, projection, schema


def prepare(client, version, start, end, minutes=60, pause=1):
    source, table, _ = names(version)
    for statement in schema(version):
        client.command(statement)
    lower = start
    settings = {'max_threads': 1, 'max_memory_usage': 268435456,
                'max_execution_time': 30, 'timeout_before_checking_execution_speed': 0,
                'max_bytes_before_external_group_by': 0, 'max_bytes_before_external_sort': 0}
    while lower < end:
        upper = min(end, lower + timedelta(minutes=minutes))
        params = {'start': lower, 'end': upper}
        where = 'WHERE collector_collected_at >= %(start)s AND collector_collected_at < %(end)s'
        client.command(f'INSERT INTO {table} ' + projection(source, where), parameters=params, settings=settings)
        # Lower-bound validation tolerates new arrivals after the backfill query.
        # A final exact verification requires a quiet source interval.
        expected = client.query(f'SELECT uniqExact(id) FROM {source} {where}', parameters=params, settings=settings).result_rows[0][0]
        actual = client.query(f'SELECT uniqExactMerge(event_ids) FROM {table} WHERE bucket >= %(start)s AND bucket < %(end)s', parameters=params, settings=settings).result_rows[0][0]
        if actual < expected:
            raise RuntimeError(f'Summary incomplete at {lower.isoformat()}; rerun from this slice')
        print(f'Completed through {upper.isoformat()} (source={expected}, summary={actual})', flush=True)
        lower = upper
        time.sleep(pause)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-date', required=True, help='UTC minute boundary, inclusive')
    parser.add_argument('--until-date', required=True, help='UTC minute boundary, exclusive')
    parser.add_argument('--schema-version', type=int, choices=(1, 2), default=1)
    parser.add_argument('--slice-minutes', type=int, default=60)
    parser.add_argument('--pause-seconds', type=float, default=1)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    def parse(value):
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date.astimezone(timezone.utc)
    start, end = parse(args.from_date), parse(args.until_date)
    if (end <= start or any(d.second or d.microsecond for d in (start, end))
            or not 1 <= args.slice_minutes <= 1440 or args.pause_seconds < .25):
        parser.error('Use increasing UTC minute boundaries, 1..1440 minute slices and pause >= 0.25s')
    if not args.apply:
        print('Dry run: schema + bounded backfill planned; add --apply to execute. Readers remain unchanged.')
        return
    import clickhouse_connect
    client = clickhouse_connect.get_client(host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure,
        connect_timeout=3, send_receive_timeout=45)
    try:
        prepare(client, args.schema_version, start, end, args.slice_minutes, args.pause_seconds)
    finally:
        client.close()


if __name__ == '__main__':
    main()
