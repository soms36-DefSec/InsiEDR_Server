"""Contract checks for isolated dataset replay without database dependencies."""
from datetime import date, datetime, timezone
import json

from scripts.scenario_replay import _envelope, _utc, _vector, BASELINE, SCENARIOS
from server.crypto.aesgcm_plugin import AESGCMPlugin
from server.api.ingest import validate_collector_results, validate_envelope_shape
from server.config import config
from server.api.scenario_replay import _evidence_dates, _score
from shared.protocol import validate_telemetry_payload


def test_timestamp_normalization_preserves_offset():
    assert _utc("2026-10-12T05:30:00+05:30") == datetime(2026, 10, 12, tzinfo=timezone.utc)


def test_generated_vector_respects_feature_contract():
    from server.risk.daily_adapter import RAW_FEATURES, RATIOS, SUBSETS

    scenario, agent = SCENARIOS[0]
    empty = {agent: {name: [] for name in RAW_FEATURES}}
    row = dict(zip(RAW_FEATURES, _vector(agent, scenario, date(2026, 10, 20), 21, empty, empty)))
    assert len(row) == 40
    assert all(value >= 0 for value in row.values())
    assert all(0 <= row[name] <= 1 for name in RATIOS)
    assert all(row[child] <= row[total] for child, total in SUBSETS)
    assert row["peak_process_count"] >= row["mean_process_count"]
    assert row["file_access_count"] >= BASELINE["file_access_count"]


def test_replay_envelope_decrypts_and_retains_original_timestamp():
    key = bytes(range(32))
    row = {"timestamp": "2026-10-12T09:00:00", "agent_id": "AGENT-SOCL4-61",
           "hostname": "SOCL4-61", "status": "success", "threat_triggered": "true"}
    envelope, headers = _envelope("AGENT-SOCL4-61", "SOCL4-61", "admin",
                                  {"decoy-monitor": row}, "test-run", key, "secret-token")
    validate_envelope_shape(envelope)
    payload = json.loads(AESGCMPlugin(key).decrypt(envelope))
    validate_telemetry_payload(payload)
    validate_collector_results(payload)
    assert payload["collectors"][0]["quality"]["original_timestamp"] == row["timestamp"]
    assert payload["collectors"][0]["quality"]["source_kind"] == "synthetic"
    assert headers["X-Agent-Token"] == "secret-token"
    assert payload["collected_at"] != row["timestamp"]


def test_local_mirror_can_open_operator_stream_and_enforce_agent_tokens(monkeypatch):
    monkeypatch.setenv("INSIEDR_ENVIRONMENT", "staging")
    monkeypatch.setenv("INSIEDR_AUTH_ENFORCED", "false")
    monkeypatch.setenv("INSIEDR_AGENT_AUTH_ENFORCED", "true")
    assert not config.auth_enforced
    assert config.agent_auth_enforced


def test_incomplete_day_and_structured_evidence_remain_distinct():
    score = _score({"date": "2026-10-20", "observation_complete": "0",
                    "threat_probability": "0.1", "predicted_scenario": "BENIGN"})
    assert score["observation_complete"] is False
    assert score["selection_status"] == "incomplete"
    assert _evidence_dates('[{"date":"2026-10-20","threat_score":0.7}]')[0]["date"] == "2026-10-20"
    assert _evidence_dates("nan") == []
