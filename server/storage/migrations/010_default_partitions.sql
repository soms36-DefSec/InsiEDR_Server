-- Migration 010: Ensure DEFAULT catch-all partitions exist for partitioned tables.
-- Prevents PostgreSQL from throwing 'no partition found for row' error when
-- timestamps fall outside the pre-generated weekly partition window.

CREATE TABLE IF NOT EXISTS raw_payloads_default PARTITION OF raw_payloads DEFAULT;
CREATE TABLE IF NOT EXISTS collector_results_default PARTITION OF collector_results DEFAULT;
