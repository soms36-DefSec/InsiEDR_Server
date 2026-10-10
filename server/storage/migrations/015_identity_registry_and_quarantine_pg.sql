-- Migration 015: Identity Registry and Outbox Quarantine
-- Resolves Findings I03, I05, and I09

-- 1. Dedicated unpartitioned authoritative identity registry (I03, I05)
-- Enforces global payload uniqueness and prevents duplicate replay race conditions.
CREATE TABLE IF NOT EXISTS payload_registry (
    payload_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ciphertext_hash TEXT,
    decrypted_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payload_registry_agent_received
    ON payload_registry (agent_id, received_at DESC);

-- 2. Durable poison-record quarantine for replication outbox (I09)
-- Prevents malformed or oversized records from permanently blocking replication batches.
CREATE TABLE IF NOT EXISTS clickhouse_outbox_quarantine (
    quarantine_id BIGSERIAL PRIMARY KEY,
    outbox_id BIGINT,
    target_table TEXT NOT NULL,
    record_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_reason TEXT,
    attempts INT DEFAULT 0,
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outbox_quarantine_time
    ON clickhouse_outbox_quarantine (quarantined_at DESC);
