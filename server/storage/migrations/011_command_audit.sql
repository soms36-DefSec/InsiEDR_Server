-- Migration 011: Command Audit Logging, Delivery Leases & Outbox Replication
-- Creates immutable command_audit_log, delivery lease metadata on agent_tasks,
-- and clickhouse_outbox for transactional outbox replication.

CREATE TABLE IF NOT EXISTS command_audit_log (
    audit_id      BIGSERIAL PRIMARY KEY,
    task_id       TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    command       TEXT NOT NULL,
    params_json   JSONB NOT NULL DEFAULT '{}',
    actor_id      TEXT NOT NULL,
    actor_role    TEXT,
    ip_address    TEXT,
    status        TEXT NOT NULL DEFAULT 'queued',
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_command_audit_task
    ON command_audit_log (task_id);

CREATE INDEX IF NOT EXISTS idx_command_audit_agent_created
    ON command_audit_log (agent_id, created_at);

ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS dispatch_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS lease_token TEXT;
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP WITH TIME ZONE;

CREATE TABLE IF NOT EXISTS clickhouse_outbox (
    outbox_id     BIGSERIAL PRIMARY KEY,
    target_table  TEXT NOT NULL,
    record_json   JSONB NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_at  TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_ch_outbox_status_id
    ON clickhouse_outbox (status, outbox_id);
