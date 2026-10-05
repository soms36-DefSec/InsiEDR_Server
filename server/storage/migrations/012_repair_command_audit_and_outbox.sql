-- ==============================================================================
-- Migration 012: Corrective Schema Repair for command_audit_log and clickhouse_outbox
-- ==============================================================================
-- Ensures existing installations that ran the legacy 011 migration are seamlessly
-- upgraded with exact column parity matching production repository queries.

-- 1. Ensure command_audit_log exists with standard schema
CREATE TABLE IF NOT EXISTS command_audit_log (
    audit_id    BIGSERIAL PRIMARY KEY,
    task_id     TEXT,
    agent_id    TEXT,
    command     TEXT,
    params_json JSONB,
    actor_id    TEXT,
    actor_role  TEXT,
    ip_address  TEXT,
    status      TEXT,
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Retrofit legacy column names if migrating from early 011
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'command_audit_log') THEN
        -- Rename legacy 'actor' to 'actor_id'
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_audit_log' AND column_name = 'actor')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_audit_log' AND column_name = 'actor_id') THEN
            ALTER TABLE command_audit_log RENAME COLUMN actor TO actor_id;
        END IF;

        -- Rename legacy 'client_ip' to 'ip_address'
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_audit_log' AND column_name = 'client_ip')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_audit_log' AND column_name = 'ip_address') THEN
            ALTER TABLE command_audit_log RENAME COLUMN client_ip TO ip_address;
        END IF;

        -- Add missing columns
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_audit_log' AND column_name = 'actor_role') THEN
            ALTER TABLE command_audit_log ADD COLUMN actor_role TEXT DEFAULT 'operator';
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'command_audit_log' AND column_name = 'status') THEN
            ALTER TABLE command_audit_log ADD COLUMN status TEXT DEFAULT 'queued';
        END IF;
    END IF;
END $$;

-- 3. Ensure clickhouse_outbox exists with standard schema
CREATE TABLE IF NOT EXISTS clickhouse_outbox (
    outbox_id     BIGSERIAL PRIMARY KEY,
    target_table  TEXT NOT NULL,
    record_json   JSONB NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempts      INT NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    processed_at  TIMESTAMPTZ
);

-- 4. Retrofit legacy clickhouse_outbox columns if migrating from early 011
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'clickhouse_outbox') THEN
        -- Rename legacy 'id' to 'outbox_id'
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'id')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'outbox_id') THEN
            ALTER TABLE clickhouse_outbox RENAME COLUMN id TO outbox_id;
        END IF;

        -- Rename legacy 'table_name' to 'target_table'
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'table_name')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'target_table') THEN
            ALTER TABLE clickhouse_outbox RENAME COLUMN table_name TO target_table;
        END IF;

        -- Rename legacy 'data_json' to 'record_json'
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'data_json')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'record_json') THEN
            ALTER TABLE clickhouse_outbox RENAME COLUMN data_json TO record_json;
        END IF;

        -- Add missing columns
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'attempts') THEN
            ALTER TABLE clickhouse_outbox ADD COLUMN attempts INT DEFAULT 0;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'last_error') THEN
            ALTER TABLE clickhouse_outbox ADD COLUMN last_error TEXT;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'processed_at') THEN
            ALTER TABLE clickhouse_outbox ADD COLUMN processed_at TIMESTAMPTZ;
        END IF;

        -- Drop legacy payload_id column if present — current inserts omit it and
        -- the NOT NULL constraint causes every ingestion transaction to fail on
        -- deployments that ran an early version of this migration.
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'clickhouse_outbox' AND column_name = 'payload_id') THEN
            ALTER TABLE clickhouse_outbox DROP COLUMN payload_id;
        END IF;

        -- Ensure target_table and record_json are NOT NULL (fill any NULLs from legacy rows first)
        UPDATE clickhouse_outbox SET target_table = 'raw_payloads' WHERE target_table IS NULL;
        UPDATE clickhouse_outbox SET record_json = '{}' WHERE record_json IS NULL;
        ALTER TABLE clickhouse_outbox ALTER COLUMN target_table SET NOT NULL;
        ALTER TABLE clickhouse_outbox ALTER COLUMN record_json SET NOT NULL;
    END IF;
END $$;

-- 5. Safe indexes
CREATE INDEX IF NOT EXISTS idx_command_audit_agent ON command_audit_log (agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_clickhouse_outbox_status ON clickhouse_outbox (status, outbox_id ASC);
