-- Migration 008: Additive performance indexes for FastAPI, Streaming Export, and SSE lookups
-- Strictly non-destructive: uses IF NOT EXISTS with zero table locks or column changes.

-- Accelerate risk event lookups and streaming export sorting
CREATE INDEX IF NOT EXISTS idx_risk_events_created_at_desc
    ON risk_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_risk_events_level_score
    ON risk_events (risk_level, risk_score);

CREATE INDEX IF NOT EXISTS idx_risk_events_user_time
    ON risk_events (username, created_at DESC);

-- Accelerate collector results streaming export and drilldowns
CREATE INDEX IF NOT EXISTS idx_collector_results_agent_time
    ON collector_results (agent_id, collector_collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_collector_results_time_desc
    ON collector_results (collector_collected_at DESC);

-- Accelerate agent fleet overview and health checks
CREATE INDEX IF NOT EXISTS idx_agents_last_seen_desc
    ON agents (last_seen_at DESC);

-- Accelerate raw payloads audit queries
CREATE INDEX IF NOT EXISTS idx_raw_payloads_received_desc
    ON raw_payloads (received_at DESC);

-- Accelerate task queue recovery and failure queries
CREATE INDEX IF NOT EXISTS idx_task_queue_status_attempts
    ON task_queue (status, attempts);
