-- Optional PostgreSQL 16 maintenance-window changes, NOT a startup migration.
-- Parent tables may already be partitioned (migration 004). CREATE INDEX on a
-- partitioned parent builds child indexes and is not concurrent. For online
-- rollout, build indexes CONCURRENTLY on each leaf and attach them separately.
-- Run selectively after EXPLAIN (ANALYZE, BUFFERS); GIN adds ingestion writes.
SET lock_timeout = '3s';
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_collectors_host_trgm
    ON collector_results USING gin (LOWER(hostname) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_collectors_name_trgm
    ON collector_results USING gin (LOWER(collector) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_raw_user_trgm
    ON raw_payloads USING gin (LOWER(username) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_risk_payload_latest
    ON risk_events (payload_id, created_at DESC, id DESC);
-- The ordered telemetry index already exists in migration 013.
-- JSONB path indexes do not accelerate CAST(payload_json AS TEXT) LIKE.
-- Cross-table OR searches may still use a scan despite these indexes.
