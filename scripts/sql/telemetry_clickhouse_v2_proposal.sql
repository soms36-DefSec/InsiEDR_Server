-- DESIGN / STAGING ONLY: no application writer targets this table yet.
-- Backfill username/received_at while raw_payloads still exist. Reconcile IDs,
-- duplicates and privacy policy before changing the reader/writer together.
-- Use the configured analytics database if it differs from this name.
CREATE TABLE IF NOT EXISTS insiedr_analytics.collector_results_v2 (
    id UUID,
    payload_id String,
    agent_id String,
    collector LowCardinality(String),
    collector_collected_at DateTime64(3, 'UTC'),
    received_at DateTime64(3, 'UTC'),
    hostname LowCardinality(String),
    username LowCardinality(String),
    status LowCardinality(String),
    process_name String,
    payload_json String CODEC(ZSTD(1)),
    version UInt64,
    INDEX idx_collector collector TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_hostname hostname TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_username username TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_process process_name TYPE bloom_filter(0.01) GRANULARITY 1
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toDate(collector_collected_at)
ORDER BY (collector_collected_at, id)
TTL collector_collected_at + INTERVAL 2 DAY DELETE
SETTINGS ttl_only_drop_parts = 1;
-- Two days is a capacity example, not a policy for existing evidence.
-- Pin event time and ID on replay; versions must be monotonic per event.
-- ReplacingMergeTree is eventual: use FINAL (benchmark its cost) or explicit
-- deduplication until merges finish. Bloom filters help equality/IN predicates,
-- not arbitrary case-insensitive substring searches. Add only measured winners.
-- TTL is asynchronous. Monitor bytes/free space and TTL merge lag.
