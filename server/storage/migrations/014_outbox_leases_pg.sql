-- Fenced claims survive the short claiming transaction and expire after crashes.
ALTER TABLE clickhouse_outbox ADD COLUMN IF NOT EXISTS claim_token TEXT;
ALTER TABLE clickhouse_outbox ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE clickhouse_outbox ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_outbox_expired_claims
    ON clickhouse_outbox (lease_expires_at, outbox_id) WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS idx_outbox_completed_retention
    ON clickhouse_outbox (processed_at, outbox_id) WHERE status = 'completed';

CREATE TABLE IF NOT EXISTS maintenance_runs (
    name TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb
);
