-- ==============================================================================
-- InsiEDR High-Throughput Telemetry Schema for ClickHouse
-- Database: insiedr_analytics
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS insiedr_analytics;

USE insiedr_analytics;

-- Opt-in collector schema. Populate and validate before selecting schema v2.
CREATE TABLE IF NOT EXISTS collector_events_v2 (
    id UUID,
    payload_id String,
    agent_id String,
    collector LowCardinality(String),
    collector_collected_at DateTime64(3, 'UTC'),
    hostname LowCardinality(String),
    status LowCardinality(String),
    payload_json String CODEC(ZSTD(1)),
    error_type LowCardinality(Nullable(String)),
    error_message Nullable(String),
    source_quality LowCardinality(String),
    agent_quality_json String DEFAULT '',
    feature_quality_json String DEFAULT '',
    username LowCardinality(String),
    received_at DateTime64(3, 'UTC'),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(collector_collected_at)
ORDER BY (collector_collected_at, id)
TTL toDateTime(collector_collected_at) + INTERVAL 90 DAY
SETTINGS non_replicated_deduplication_window = 10000;

-- 1. Raw Payloads: High-cardinality envelope and transmission metadata
CREATE TABLE IF NOT EXISTS raw_payloads (
    payload_id              String,
    agent_id                String,
    received_at             DateTime64(3, 'UTC'),
    envelope_created_at     Nullable(DateTime64(3, 'UTC')),
    payload_collected_at    Nullable(DateTime64(3, 'UTC')),
    hostname                LowCardinality(String),
    username                LowCardinality(String),
    crypto_scheme           LowCardinality(String),
    key_id                  String,
    nonce_hash              String,
    ciphertext_hash         String,
    decrypted_payload_hash  String,
    encrypted_envelope_json String CODEC(ZSTD(1)),
    validation_status       LowCardinality(String),
    duplicate_attempt_count UInt32 DEFAULT 0
) ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(received_at)
ORDER BY (received_at, hostname, username, payload_id)
TTL toDateTime(received_at) + INTERVAL 30 DAY;

-- 2. Collector Results: Endpoint sensor observations and execution status
CREATE TABLE IF NOT EXISTS collector_results (
    id                      UUID DEFAULT generateUUIDv4(),
    payload_id              String,
    agent_id                String,
    collector               LowCardinality(String),
    collector_collected_at  DateTime64(3, 'UTC'),
    hostname                LowCardinality(String),
    status                  LowCardinality(String),
    payload_json            String CODEC(ZSTD(1)),
    error_type              LowCardinality(Nullable(String)),
    error_message           Nullable(String),
    source_quality          LowCardinality(String),
    agent_quality_json      String DEFAULT '',
    feature_quality_json    String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(collector_collected_at)
ORDER BY (collector, collector_collected_at, hostname, payload_id)
TTL toDateTime(collector_collected_at) + INTERVAL 90 DAY;

-- 3. Normalized Features: Vectorized feature metrics extracted for detection models
CREATE TABLE IF NOT EXISTS normalized_features (
    id                      UUID DEFAULT generateUUIDv4(),
    payload_id              String,
    agent_id                String,
    username                LowCardinality(String),
    hostname                LowCardinality(String),
    collector               LowCardinality(String),
    entity_user             LowCardinality(String),
    feature_name            LowCardinality(String),
    feature_value_numeric   Nullable(Float64),
    feature_value_text      Nullable(String),
    feature_value_json      Nullable(String) CODEC(ZSTD(1)),
    feature_timestamp       DateTime64(3, 'UTC'),
    source_quality          LowCardinality(String),
    quality_notes           Nullable(String),
    created_at              DateTime64(3, 'UTC')
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(feature_timestamp)
ORDER BY (feature_name, username, feature_timestamp, payload_id)
TTL toDateTime(feature_timestamp) + INTERVAL 90 DAY;

-- 4. Model Outputs: ML Inference detector scores and explanations
CREATE TABLE IF NOT EXISTS model_outputs (
    id                          UUID DEFAULT generateUUIDv4(),
    payload_id                  String,
    agent_id                    String,
    username                    LowCardinality(String),
    detector_name               LowCardinality(String),
    model_version               LowCardinality(String),
    score                       Nullable(Float64),
    confidence                  Nullable(Float64),
    is_anomaly                  UInt8,
    feature_contributions_json  String CODEC(ZSTD(1)),
    reason_summary              String,
    created_at                  DateTime64(3, 'UTC')
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (detector_name, created_at, username, payload_id)
TTL toDateTime(created_at) + INTERVAL 180 DAY;

-- 5. Risk Events: Correlated behavioral risk scores and alerts
CREATE TABLE IF NOT EXISTS risk_events (
    id                      UUID DEFAULT generateUUIDv4(),
    payload_id              String,
    agent_id                String,
    username                LowCardinality(String),
    risk_score              Float64,
    risk_level              LowCardinality(String),
    correlated_signals_json String CODEC(ZSTD(1)),
    summary                 String,
    created_at              DateTime64(3, 'UTC')
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, risk_level, username, payload_id)
TTL toDateTime(created_at) + INTERVAL 180 DAY;

-- 6. Anomalies: Operational security alerts for SOC analyst review
CREATE TABLE IF NOT EXISTS anomalies (
    id                  UUID DEFAULT generateUUIDv4(),
    payload_id          String,
    agent_id            String,
    username            LowCardinality(String),
    anomaly_type        LowCardinality(String),
    severity            LowCardinality(String),
    detectors_json      String CODEC(ZSTD(1)),
    top_features_json   String CODEC(ZSTD(1)),
    status              LowCardinality(String),
    created_at          DateTime64(3, 'UTC'),
    acknowledged_at     Nullable(DateTime64(3, 'UTC')),
    acknowledged_by     Nullable(String)
) ENGINE = ReplacingMergeTree(created_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (created_at, agent_id, id)
TTL toDateTime(created_at) + INTERVAL 365 DAY;

-- 7. Telemetry Events: High-throughput flattened telemetry logs with sparse primary index
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id                UUID DEFAULT generateUUIDv4(),
    payload_id              String,
    agent_id                String,
    collector_name          LowCardinality(String),
    timestamp               DateTime64(3, 'UTC'),
    hostname                LowCardinality(String),
    username                LowCardinality(String),
    status                  LowCardinality(String),
    summary_preview         String,
    raw_payload_json        String CODEC(ZSTD(1)),
    tenant_id               LowCardinality(String) DEFAULT 'default'
) ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (agent_id, collector_name, toUnixTimestamp64Milli(timestamp), event_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- Daily40 cache contract. Null means unavailable, never measured zero.
-- The adapter populates this only after source and window verification.
CREATE TABLE IF NOT EXISTS endpoint_daily_feature_rollups (
    agent_id String,
    hostname String,
    review_date Date,
    observation_complete UInt8,
    journal_gap_detected UInt8,
    feature_contract_verified UInt8,
    sensor_coverage_verified UInt8,
    timezone_verified UInt8,
    source_kind LowCardinality(String),
    missing_sensors_json String,
    coverage_details_json String,
    feature_contract_version String,
    successful_logons Nullable(Float64),
    failed_logons Nullable(Float64),
    after_hours_logon_ratio Nullable(Float64),
    unique_pc_count Nullable(Float64),
    pc_access_entropy Nullable(Float64),
    interactive_duration_seconds Nullable(Float64),
    mean_session_duration_seconds Nullable(Float64),
    weekend_activity Nullable(Float64),
    usb_connect_count Nullable(Float64),
    usb_disconnect_count Nullable(Float64),
    after_hours_usb_ratio Nullable(Float64),
    distinct_usb_devices Nullable(Float64),
    file_access_count Nullable(Float64),
    unique_filename_count Nullable(Float64),
    new_filename_count Nullable(Float64),
    file_delete_count Nullable(Float64),
    file_access_entropy Nullable(Float64),
    protected_file_touch_count Nullable(Float64),
    http_request_count Nullable(Float64),
    unique_domain_count Nullable(Float64),
    new_domain_count Nullable(Float64),
    external_domain_ratio Nullable(Float64),
    domain_access_entropy Nullable(Float64),
    file_sharing_visit_count Nullable(Float64),
    mean_process_count Nullable(Float64),
    peak_process_count Nullable(Float64),
    admin_process_count Nullable(Float64),
    temp_exec_count Nullable(Float64),
    bytes_sent Nullable(Float64),
    bytes_received Nullable(Float64),
    external_connection_count Nullable(Float64),
    unique_remote_ip_count Nullable(Float64),
    clipboard_copy_count Nullable(Float64),
    lsass_handle_request_count Nullable(Float64),
    memory_dump_attempt_count Nullable(Float64),
    decoy_access_count Nullable(Float64),
    wmi_query_count Nullable(Float64),
    named_pipe_event_count Nullable(Float64),
    dns_query_count Nullable(Float64),
    outbound_attachment_count Nullable(Float64),
    version UInt64
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(review_date)
ORDER BY (agent_id, review_date);

-- 8. Process Events: Dedicated process sensor telemetry
CREATE TABLE IF NOT EXISTS process_events (
    event_id                UUID DEFAULT generateUUIDv4(),
    payload_id              String,
    agent_id                String,
    collector_name          LowCardinality(String) DEFAULT 'process',
    timestamp               DateTime64(3, 'UTC'),
    hostname                LowCardinality(String),
    username                LowCardinality(String),
    status                  LowCardinality(String),
    summary_preview         String,
    process_name            String,
    process_pid             UInt32 DEFAULT 0,
    parent_pid              UInt32 DEFAULT 0,
    command_line            String,
    raw_payload_json        String CODEC(ZSTD(1)),
    tenant_id               LowCardinality(String) DEFAULT 'default'
) ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (agent_id, collector_name, toUnixTimestamp64Milli(timestamp), event_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

-- 9. Network Events: Dedicated network sensor telemetry
CREATE TABLE IF NOT EXISTS network_events (
    event_id                UUID DEFAULT generateUUIDv4(),
    payload_id              String,
    agent_id                String,
    collector_name          LowCardinality(String) DEFAULT 'network',
    timestamp               DateTime64(3, 'UTC'),
    hostname                LowCardinality(String),
    username                LowCardinality(String),
    status                  LowCardinality(String),
    summary_preview         String,
    dest_ip                 String,
    dest_port               UInt16 DEFAULT 0,
    proto                   LowCardinality(String) DEFAULT 'TCP',
    domain                  String,
    raw_payload_json        String CODEC(ZSTD(1)),
    tenant_id               LowCardinality(String) DEFAULT 'default'
) ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (agent_id, collector_name, toUnixTimestamp64Milli(timestamp), event_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;
