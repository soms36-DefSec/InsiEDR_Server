"""Optional minute summaries. Identity states make replay/backfill idempotent.

Enable readers only after completing the bounded backfill. Observations must
have immutable IDs, timestamps and dimensions (as the telemetry outbox does).
"""
from __future__ import annotations

import os


def enabled():
    return os.environ.get('INSIEDR_CH_ROLLUPS_ENABLED', 'false').lower() == 'true'


def names(version):
    if version not in (1, 2):
        raise ValueError('Collector schema must be 1 or 2')
    return ('collector_results' if version == 1 else 'collector_events_v2',
            f'dashboard_minutes_v{version}', f'dashboard_minutes_mv_v{version}')


def projection(source, where=''):
    return ("SELECT toStartOfMinute(collector_collected_at) AS bucket, "
            "lower(collector) AS collector, lower(status) AS status, agent_id, "
            f"uniqExactState(id) AS event_ids FROM {source} {where} "
            "GROUP BY bucket, collector, status, agent_id")


def schema(version):
    source, table, view = names(version)
    return [f"""CREATE TABLE IF NOT EXISTS {table} (
        bucket DateTime('UTC'), collector LowCardinality(String),
        status LowCardinality(String), agent_id String,
        event_ids AggregateFunction(uniqExact, UUID)
    ) ENGINE = AggregatingMergeTree()
    PARTITION BY toYYYYMM(bucket) ORDER BY (bucket, collector, status, agent_id)
    TTL bucket + INTERVAL 95 DAY""",
        f'CREATE MATERIALIZED VIEW IF NOT EXISTS {view} TO {table} AS ' + projection(source)]
