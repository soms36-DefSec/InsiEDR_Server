-- Model V3 is host scoped. Never mix these rows with user_daily_rvfl_risk.
CREATE TABLE IF NOT EXISTS endpoint_daily_model_scores (
    agent_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    review_date DATE NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('observed_unlabeled', 'observed_labeled')),
    observation_complete BOOLEAN NOT NULL DEFAULT FALSE,
    selection_status TEXT NOT NULL,
    missing_sensors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    coverage_details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    feature_contract_version TEXT,
    model_version TEXT,
    threat_probability DOUBLE PRECISION,
    if_risk DOUBLE PRECISION,
    fused_risk DOUBLE PRECISION,
    forecasted_risk DOUBLE PRECISION,
    drift_error DOUBLE PRECISION,
    pair_threat_score DOUBLE PRECISION,
    predicted_scenario TEXT,
    scenario_probabilities_json JSONB,
    behavior_heads_json JSONB,
    scored_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, review_date),
    CHECK (threat_probability IS NULL OR threat_probability BETWEEN 0 AND 1),
    CHECK (if_risk IS NULL OR if_risk BETWEEN 0 AND 1),
    CHECK (fused_risk IS NULL OR fused_risk BETWEEN 0 AND 1),
    CHECK (pair_threat_score IS NULL OR pair_threat_score >= 0),
    CHECK (observation_complete OR scored_at IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_daily_model_scores_date
    ON endpoint_daily_model_scores (review_date DESC, agent_id);

CREATE TABLE IF NOT EXISTS model_v3_review_queue (
    as_of_date DATE NOT NULL,
    rank INTEGER NOT NULL CHECK (rank BETWEEN 1 AND 20),
    agent_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    pair_threat_score DOUBLE PRECISION NOT NULL CHECK (pair_threat_score >= 0),
    primary_hypothesis TEXT NOT NULL,
    scenario_probabilities_json JSONB NOT NULL,
    evidence_dates_json JSONB NOT NULL,
    selection_status TEXT NOT NULL DEFAULT 'review_candidate',
    analyst_status TEXT NOT NULL DEFAULT 'needs_investigation'
        CHECK (analyst_status IN ('needs_investigation', 'benign_context',
            'confirmed_incident', 'acknowledged_suppressed')),
    analyst_note TEXT,
    reviewed_by TEXT,
    reviewed_at TIMESTAMPTZ,
    model_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (as_of_date, rank),
    UNIQUE (as_of_date, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_model_v3_review_queue_agent_date
    ON model_v3_review_queue (agent_id, as_of_date DESC);

CREATE TABLE IF NOT EXISTS model_v3_review_feedback_audit (
    id BIGSERIAL PRIMARY KEY,
    as_of_date DATE NOT NULL,
    agent_id TEXT NOT NULL,
    previous_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    analyst_note TEXT,
    reviewed_by TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_v3_feedback_audit_agent_date
    ON model_v3_review_feedback_audit (agent_id, as_of_date DESC);
