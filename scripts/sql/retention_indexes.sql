-- Run against the application database in autocommit mode, outside migrations.
-- Check pg_index.indisvalid after an interrupted concurrent build before retrying.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_features_retention ON normalized_features (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_models_retention ON model_outputs (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_risk_retention ON risk_events (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_anomalies_retention ON anomalies (created_at);
