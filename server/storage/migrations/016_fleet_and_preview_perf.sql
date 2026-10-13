-- Migration 016: High-performance composite indexes for fleet discovery, collector previews, and streaming exports.
-- Strictly non-destructive and additive with lock timeouts.
SET LOCAL lock_timeout = '3s';

-- Accelerate collector preview and dataset export queries
CREATE INDEX IF NOT EXISTS idx_collectors_name_time_nulls_last
    ON collector_results (LOWER(collector), collector_collected_at DESC NULLS LAST, id DESC);

CREATE INDEX IF NOT EXISTS idx_collectors_page_order_nulls_last
    ON collector_results (collector_collected_at DESC NULLS LAST, id DESC);

-- Accelerate foreign key joins on payload_id
CREATE INDEX IF NOT EXISTS idx_collector_results_payload_id
    ON collector_results (payload_id);

CREATE INDEX IF NOT EXISTS idx_risk_events_payload_id
    ON risk_events (payload_id);

-- Accelerate fleet hostname discovery
CREATE INDEX IF NOT EXISTS idx_raw_payloads_hostname_collected
    ON raw_payloads (hostname, payload_collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_collector_results_hostname_collected
    ON collector_results (hostname, collector_collected_at DESC);
