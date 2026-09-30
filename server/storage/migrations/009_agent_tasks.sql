-- Migration 009: Agent Downlink Tasks & Remote Fleet Control
-- Stores remote containment, termination, lock, and rollback commands for agent downlink dispatch,
-- as well as historical agent health metrics and heartbeats.

CREATE TABLE IF NOT EXISTS agent_tasks (
    task_id       TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    command       TEXT NOT NULL,
    params_json   JSONB NOT NULL DEFAULT '{}',
    signature     TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    exit_code     INTEGER,
    message       TEXT,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    dispatched_at TIMESTAMP WITH TIME ZONE,
    completed_at  TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_agent_status
    ON agent_tasks (agent_id, status);

CREATE INDEX IF NOT EXISTS idx_agent_tasks_created
    ON agent_tasks (created_at DESC);

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id       TEXT NOT NULL,
    hostname       TEXT,
    ip_address     TEXT,
    agent_version  TEXT,
    status         TEXT,
    metrics_json   JSONB NOT NULL DEFAULT '{}',
    config_version TEXT,
    received_at    TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agent_hb_agent_received
    ON agent_heartbeats (agent_id, received_at DESC);
