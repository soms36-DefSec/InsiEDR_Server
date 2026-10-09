"""Copy a bounded time range into collector_events_v2; never switch readers.

Stop ingestion/reconciliation during final catch-up. Requires explicit UTC date
bounds and --apply. Re-running is logically idempotent through FINAL/versioned
identity; physical duplicate rows may exist until merges finish.
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.config import config
from server.storage.clickhouse_storage import ClickHouseStorage


COLUMNS = ('id', 'payload_id', 'agent_id', 'collector', 'collector_collected_at',
           'hostname', 'status', 'payload_json', 'error_type', 'error_message', 'source_quality')


def backfill(storage, start, end, batch_rows=1000):
    copied = missing_metadata = 0
    day = start
    while day < end:
        upper = min(end, day + timedelta(minutes=15))
        params = {'start': day, 'end': upper, 'limit': batch_rows}
        interval = 'collector_collected_at >= %(start)s AND collector_collected_at < %(end)s'
        # An identity collision needs a human data decision, not arbitrary loss.
        conflict = storage._query('''SELECT id FROM collector_results WHERE ''' + interval + '''
            GROUP BY collector_collected_at, id
            HAVING uniqExact(SHA256(toJSONString(tuple(payload_id, agent_id, collector, hostname, status,
                payload_json, error_type, error_message, source_quality)))) > 1 LIMIT 1''', params)
        if conflict.result_rows:
            raise RuntimeError(f'Conflicting legacy event identity in {day.date()}; backfill stopped')
        position = ''
        while True:
            result = storage._query('SELECT ' + ', '.join(COLUMNS)
                + ' FROM collector_results WHERE ' + interval + position
                + ' ORDER BY collector_collected_at, id LIMIT %(limit)s', params)
            rows = [dict(zip(result.column_names, row)) for row in result.result_rows]
            if not rows:
                break
            ids = tuple({row['payload_id'] for row in rows})
            raw = storage._query('''SELECT payload_id, argMin(username, received_at), min(received_at)
                FROM raw_payloads WHERE payload_id IN %(ids)s GROUP BY payload_id''', {'ids': ids})
            metadata = {r[0]: (r[1], r[2]) for r in raw.result_rows}
            for row in rows:
                info = metadata.get(row['payload_id'])
                if info is None:
                    missing_metadata += 1
                    info = ('', row['collector_collected_at'])
                received = info[1]
                if received.tzinfo is None:
                    received = received.replace(tzinfo=timezone.utc)
                row.update(username=info[0] or '', received_at=received,
                           version=max(0, int(received.timestamp() * 1000000)))
            storage._raw_batch_insert('collector_events_v2', rows)
            copied += len(rows)
            params.update(cursor_time=rows[-1]['collector_collected_at'], cursor_id=str(rows[-1]['id']))
            position = ' AND (collector_collected_at, id) > (%(cursor_time)s, toUUID(%(cursor_id)s))'
        # Validate each bounded time slice instead of aggregating a whole archive.
        where = ' WHERE collector_collected_at >= %(start)s AND collector_collected_at < %(end)s'
        source = storage._query('SELECT uniqExact(tuple(collector_collected_at, id)) FROM collector_results' + where, params).result_rows[0][0]
        target = storage._query('SELECT count() FROM collector_events_v2 FINAL' + where, params).result_rows[0][0]
        if source != target:
            raise RuntimeError(f'Logical count mismatch in {day}: source={source}, target={target}; keep legacy readers')
        day = upper
    return {'copied_rows': copied, 'range_counts_verified': True, 'rows_missing_username_history': missing_metadata}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-date', required=True)
    parser.add_argument('--until-date', required=True, help='Exclusive end date')
    parser.add_argument('--batch-rows', type=int, default=1000)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    start = datetime.fromisoformat(args.from_date).replace(tzinfo=timezone.utc)
    end = datetime.fromisoformat(args.until_date).replace(tzinfo=timezone.utc)
    if end <= start or not 1 <= args.batch_rows <= 10000:
        parser.error('Use a positive date range and 1..10000 batch rows')
    if not args.apply:
        print('No writes. Re-run with --apply after backup and free-space review.')
        sys.exit(0)
    storage = ClickHouseStorage(host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password, database=config.clickhouse_db,
        secure=config.clickhouse_secure, ca_cert=config.clickhouse_ca_cert,
        query_timeout=config.clickhouse_query_timeout, max_memory_usage=config.clickhouse_max_memory,
        collector_schema_version=1)
    try:
        storage.ensure_schema()
        print(backfill(storage, start, end, args.batch_rows))
    finally:
        storage.close()
