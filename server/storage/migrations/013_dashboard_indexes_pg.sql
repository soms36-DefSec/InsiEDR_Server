-- Additive indexes. Normal CREATE INDEX takes locks: apply during a maintenance
-- window on existing large tables; this migration is not advertised as lock-free.
SET LOCAL lock_timeout = '3s';
CREATE INDEX IF NOT EXISTS idx_agents_hostname_seen
    ON agents (hostname, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_agents_trimmed_hostname_seen
    ON agents (TRIM(hostname, E' \t\r\n\f\013'), last_seen_at DESC)
    WHERE hostname IS NOT NULL AND TRIM(hostname, E' \t\r\n\f\013') != '';
CREATE INDEX IF NOT EXISTS idx_collectors_page_order
    ON collector_results (collector_collected_at DESC NULLS LAST, id DESC);
CREATE INDEX IF NOT EXISTS idx_collectors_status_time
    ON collector_results (LOWER(status), collector_collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_collectors_name_time
    ON collector_results (LOWER(collector), collector_collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_raw_payload_username_time
    ON raw_payloads (username, received_at DESC);
