"""
tests/test_risk_heuristics_pipeline.py
---------------------------------------
Focused behavior tests for InsiEDR non-ML detection layer:
- Direct heuristic detections (LSASS cred dumping, unbacked memory, tunneling, honeytokens, persistence)
- Telemetry feature extraction, flattening, and canonical alias mapping
- Authentication burst signal detection (positive, negative, sparse)
- Baseline engine updates, dual variance floors, and deviation vectors
- Baseline update gating (Risk < 40)
- End-to-end risk pipeline evaluation and persistence
"""
from __future__ import annotations

import pytest
from typing import Any, Dict

from heuristics.detector import detect_insider_threat, calculate_overall_severity
from server.risk.signals import detect_auth_burst, score_zscore
from server.risk.aggregator import RiskAggregator
from server.risk.pipeline import extract_features_from_payload, process_telemetry_risk
from server.baseline.engine import (
    BaselineEngine,
    UserBaseline,
    HostBaselineEngine,
    HostBaseline,
    DEFAULT_HOST_FEATURE_PRIORS,
)


class InMemoryRiskStorage:
    """Mock storage adapter for baseline and risk event persistence."""

    def __init__(self):
        self.baselines: dict[str, dict[str, Any]] = {}
        self.host_baselines: dict[str, dict[str, Any]] = {}
        self.risk_events: list[dict[str, Any]] = []

    def load_baseline(self, username: str) -> dict[str, Any] | None:
        return self.baselines.get(username)

    def save_baseline(self, baseline: dict[str, Any]) -> None:
        username = baseline.get("username")
        if username:
            self.baselines[username] = dict(baseline)

    def load_host_baseline(self, agent_id: str) -> dict[str, Any] | None:
        return self.host_baselines.get(agent_id)

    def save_host_baseline(self, baseline: dict[str, Any]) -> None:
        agent_id = baseline.get("agent_id")
        if agent_id:
            self.host_baselines[agent_id] = dict(baseline)

    def save_risk_event(self, event: dict[str, Any]) -> None:
        self.risk_events.append(event)

    def get_max_risk_score_in_window(self, username: str, hours: int = 4) -> float:
        scores = [float(e.get("risk_score", 0.0)) for e in self.risk_events if e.get("username") == username]
        return max(scores, default=0.0)

    def get_recent_risk_events_in_window(self, username: str, hours: int = 4, limit: int = 50) -> list[dict[str, Any]]:
        return [
            e for e in reversed(self.risk_events)
            if e.get("username") == username
        ][:limit]


def test_temporal_risk_memory_stays_on_the_same_agent():
    storage = InMemoryRiskStorage()
    storage.risk_events.append({"username": "admin", "agent_id": "AGENT-A", "risk_score": 94.0})
    aggregator = RiskAggregator(storage)
    harmless = {"process_count": 40}

    other_host = aggregator.aggregate_detectors([], username="admin", agent_id="AGENT-B",
                                                raw_features=harmless)
    same_host = aggregator.aggregate_detectors([], username="admin", agent_id="AGENT-A",
                                               raw_features=harmless)

    assert other_host["risk_score"] == 0.0
    assert same_host["risk_score"] > 0.0


# ==============================================================================
# 1. Direct Heuristic Detections
# ==============================================================================

def test_heuristic_lsass_credential_dumping():
    """Verify suspected LSASS credential dumping triggers S1_CRED_DUMP (CRITICAL, score 100)."""
    # Boolean True
    res1 = detect_insider_threat({"credential_dumping_suspected": True})
    scenarios1 = {d["scenario_id"]: d for d in res1["detections"]}
    assert "S1_CRED_DUMP" in scenarios1
    assert scenarios1["S1_CRED_DUMP"]["severity"] == "CRITICAL"
    assert scenarios1["S1_CRED_DUMP"]["score"] == 100
    assert res1["overall_score"] >= 95.0
    assert res1["overall_severity"] == "CRITICAL"
    assert "CREDENTIAL" in res1["active_domains"]

    developer_res = detect_insider_threat(
        {"credential_dumping_suspected": True}, system_profile="DEVELOPER"
    )
    assert developer_res["overall_score"] >= 95.0
    assert developer_res["overall_severity"] == "CRITICAL"

    # String "1"
    res2 = detect_insider_threat({"credential_dumping_suspected": "1"})
    assert any(d["scenario_id"] == "S1_CRED_DUMP" for d in res2["detections"])


def test_heuristic_unbacked_executable_memory():
    """Verify unbacked executable memory triggers S1_INJECTION (HIGH, score 85)."""
    res1 = detect_insider_threat({"unbacked_executable_regions": 3})
    scenarios = {d["scenario_id"]: d for d in res1["detections"]}
    assert "S1_INJECTION" in scenarios
    assert scenarios["S1_INJECTION"]["severity"] == "HIGH"
    assert scenarios["S1_INJECTION"]["score"] == 85
    assert "3 unbacked executable region(s)" in scenarios["S1_INJECTION"]["reasons"][0]

    # Via threats_detected boolean flag
    res2 = detect_insider_threat({"threats_detected": True})
    assert any(d["scenario_id"] == "S1_INJECTION" for d in res2["detections"])


def test_heuristic_network_tunneling():
    """Verify network tunneling triggers NETWORK_TUNNELING (HIGH, score 80)."""
    res1 = detect_insider_threat({"tunneling_process_count": 2})
    scenarios = {d["scenario_id"]: d for d in res1["detections"]}
    assert "NETWORK_TUNNELING" in scenarios
    assert scenarios["NETWORK_TUNNELING"]["severity"] == "HIGH"
    assert scenarios["NETWORK_TUNNELING"]["score"] == 80

    # Via tunneling_detected boolean flag
    res2 = detect_insider_threat({"tunneling_detected": "true"})
    assert any(d["scenario_id"] == "NETWORK_TUNNELING" for d in res2["detections"])


def test_heuristic_honeytoken_access():
    """Verify honeytoken access triggers HONEYTOKEN (CRITICAL, score 100)."""
    res = detect_insider_threat({"threat_triggered": True})
    scenarios = {d["scenario_id"]: d for d in res["detections"]}
    assert "HONEYTOKEN" in scenarios
    assert scenarios["HONEYTOKEN"]["severity"] == "CRITICAL"
    assert scenarios["HONEYTOKEN"]["score"] == 100


def test_heuristic_persistence_tampering_correlation():
    """Verify persistence modification correlated with after-hours logon triggers S1."""
    # modifications_detected with after_hours >= 2
    res = detect_insider_threat({
        "modifications_detected": True,
        "after_hours_logon": 3,
    })
    scenarios = {d["scenario_id"]: d for d in res["detections"]}
    assert "S1" in scenarios
    assert scenarios["S1"]["severity"] == "HIGH"
    assert scenarios["S1"]["score"] == 85

    # Clean persistence alone without anomaly should not trigger S1
    clean_res = detect_insider_threat({
        "modifications_detected": False,
        "after_hours_logon": 0,
    })
    assert not any(d["scenario_id"] == "S1" for d in clean_res["detections"])


def test_heuristic_clean_and_empty_telemetry():
    """Verify benign and empty telemetry produces zero score and LOW severity."""
    # Empty dictionary
    empty_res = detect_insider_threat({})
    assert empty_res["overall_score"] == 0.0
    assert empty_res["overall_severity"] == "LOW"
    assert empty_res["detections"] == []

    # Clean telemetry
    clean_features = {
        "file_access_count": 5,
        "daily_http_request_count": 20,
        "after_hours_logon": 0,
        "credential_dumping_suspected": False,
        "unbacked_executable_regions": 0,
        "tunneling_process_count": 0,
        "threats_detected": False,
        "modifications_detected": False,
    }
    clean_res = detect_insider_threat(clean_features)
    assert clean_res["overall_score"] == 0.0
    assert clean_res["overall_severity"] == "LOW"
    assert len(clean_res["detections"]) == 0


def test_calculate_overall_severity_thresholds():
    """Verify severity boundary classification."""
    assert calculate_overall_severity(95.0) == "CRITICAL"
    assert calculate_overall_severity(90.0) == "CRITICAL"
    assert calculate_overall_severity(89.9) == "HIGH"
    assert calculate_overall_severity(70.0) == "HIGH"
    assert calculate_overall_severity(69.9) == "MEDIUM"
    assert calculate_overall_severity(40.0) == "MEDIUM"
    assert calculate_overall_severity(39.9) == "LOW"
    assert calculate_overall_severity(0.0) == "LOW"


# ==============================================================================
# 2. Telemetry Extraction and Canonical Aliasing
# ==============================================================================

def test_extract_features_from_payload():
    """Verify flattening of collector array and alias resolution."""
    raw_payload = {
        "agent_id": "agent-007",
        "hostname": "WORKSTATION-X",
        "username": "alice",
        "collected_at": "2026-10-16T12:00:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "process_monitor",
                "status": "success",
                "payload": {
                    "unbacked_executable_regions": 2,
                    "tunneling_process_count": 1,
                },
            },
            {
                "collector": "persistence_monitor",
                "status": "success",
                "payload": {
                    "modifications_detected": True,
                },
            },
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {
                    "daily_file_open_count": 15,
                    "daily_file_write_count": 5,
                    "daily_file_delete_count": 2,
                },
            },
            {
                "collector": "failed_collector",
                "status": "error",
                "payload": {"ignored_metric": 999},
            },
        ],
    }

    features = extract_features_from_payload(raw_payload)

    # Base metadata preserved
    assert features["agent_id"] == "agent-007"
    assert features["username"] == "alice"
    assert features["hostname"] == "WORKSTATION-X"

    # Extracted collector metrics
    assert features["unbacked_executable_regions"] == 2
    assert features["tunneling_process_count"] == 1
    assert features["modifications_detected"] is True

    # Canonical alias mapping: persistence_modification_count aliased from modifications_detected
    assert features.get("persistence_modification_count") is True

    # Composite feature computed: file_access_count = open + write + delete = 22
    assert features["file_access_count"] == 22.0

    # Failed collector omitted
    assert "ignored_metric" not in features


# ==============================================================================
# 3. Authentication Burst Detector
# ==============================================================================

def test_auth_burst_detection_positive():
    """Verify auth burst detection triggers on high failed ratio and volume."""
    features = {
        "edr_failed_auth_ratio_window": 0.85,
        "edr_failed_auth_events_per_minute_window": 2.0,  # 2.0 * 5 = 10 failed events
        "edr_auth_event_count_window": 12,
    }
    burst = detect_auth_burst(features)
    assert burst["detector_name"] == "auth_burst"
    assert burst["is_anomaly"] is True
    assert burst["score"] == 85.0
    assert burst["severity"] == "HIGH"
    assert "failed_auth_ratio=0.850" in burst["reason"]


def test_auth_burst_detection_negative():
    """Verify normal authentication traffic triggers no burst anomaly."""
    features = {
        "edr_failed_auth_ratio_window": 0.05,
        "edr_failed_auth_events_per_minute_window": 0.1,
        "edr_auth_event_count_window": 10,
    }
    burst = detect_auth_burst(features)
    assert burst["is_anomaly"] is False
    assert burst["score"] == 0.0
    assert burst["severity"] == "LOW"
    assert burst["attack_pattern"] is None
    assert burst["mitre_technique"] is None


def test_auth_burst_password_spray():
    """Verify multi-workstation failed authentication triggers MULTI_WORKSTATION_BURST."""
    features = {
        "unique_workstations_300s": 4.0,
        "edr_failed_auth_events_per_minute_window": 1.0,  # 5 failed events
        "edr_failed_auth_ratio_window": 0.70,
        "edr_auth_event_count_window": 7,
    }
    burst = detect_auth_burst(features)
    assert burst["is_anomaly"] is True
    assert burst["score"] >= 80.0
    assert burst["severity"] == "HIGH"
    assert burst["burst_type"] == "MULTI_WORKSTATION_BURST"
    assert burst["scope"] == "host"
    assert "burst across 4 workstations" in burst["reason"].lower()


def test_auth_burst_brute_force():
    """Verify concentrated endpoint failed authentication triggers HIGH_FAILURE_BURST."""
    features = {
        "unique_workstations_300s": 1.0,
        "edr_failed_auth_events_per_minute_window": 1.6,  # 8 failed events
        "edr_failed_auth_ratio_window": 0.88,
        "edr_auth_event_count_window": 9,
    }
    burst = detect_auth_burst(features)
    assert burst["is_anomaly"] is True
    assert burst["score"] == 85.0
    assert burst["severity"] == "HIGH"
    assert burst["burst_type"] == "HIGH_FAILURE_BURST"
    assert burst["scope"] == "host"


def test_auth_burst_zero_successes_with_explicit_failure_rate():
    """A zero-success window still detects failures when the failure rate gives volume."""
    burst = detect_auth_burst({
        "edr_auth_event_count_window": 0,
        "edr_failed_auth_events_per_minute_window": 2.0,
        "edr_failed_auth_ratio_window": 1.0,
    })
    assert burst["is_anomaly"] is True
    assert burst["burst_type"] == "HIGH_FAILURE_BURST"
    assert burst["evidence"]["failed_auth_events_5m_estimate"] == 10.0
    assert burst["score"] >= 80.0


def test_auth_burst_ratio_without_denominator_does_not_invent_failure_volume():
    """A 100% ratio alone has no denominator and must not fabricate an attack count."""
    burst = detect_auth_burst({
        "edr_auth_event_count_window": 0,
        "edr_failed_auth_ratio_window": 1.0,
    })
    assert burst["is_anomaly"] is False
    assert burst["evidence"]["failed_auth_events_5m_estimate"] == 0.0


def test_cert_sabotage_correlates_sampled_deletes_with_system_change():
    """Ten or more sampled deletes plus a system change trigger daytime S1."""
    aggregator = RiskAggregator(InMemoryRiskStorage())
    scenarios = aggregator._map_cert_scenarios(
        detector_results=[],
        raw_features={"file_delete_count": 13, "persistence_modification_count": 1},
        heur_result={"detections": []},
    )
    s1 = next(scenario for scenario in scenarios if scenario["id"] == "S1")
    assert s1["severity"] == "HIGH"

    # Collector normalization can preserve a boolean as either True or "True".
    string_bool_scenarios = aggregator._map_cert_scenarios(
        detector_results=[],
        raw_features={"file_delete_count": 13, "persistence_modification_count": "True"},
        heur_result={"detections": []},
    )
    assert any(scenario["id"] == "S1" for scenario in string_bool_scenarios)


def test_cloud_upload_without_file_correlation_is_reported_as_precursor():
    result = detect_insider_threat({
        "file_sharing_site_visits": 5,
        "cloud_storage_uploads": 4,
        "large_uploads": 3,
    })
    upload = next(d for d in result["detections"] if d["scenario_id"] == "S4_PRECURSOR")
    assert upload["scenario"] == "Cloud Upload Without File Correlation"
    assert "upload_activity=4" in upload["reasons"][0]
    assert "correlation unavailable" in upload["reasons"][0]


def test_auth_burst_lateral_movement():
    """Verify multi-workstation traversal with active logons triggers MULTI_WORKSTATION_BURST."""
    features = {
        "unique_workstations_300s": 4.0,
        "edr_auth_event_count_window": 6,
        "edr_failed_auth_ratio_window": 0.0,
    }
    burst = detect_auth_burst(features)
    assert burst["is_anomaly"] is True
    assert burst["score"] >= 70.0
    assert burst["severity"] == "HIGH"
    assert burst["burst_type"] == "MULTI_WORKSTATION_BURST"
    assert "activity across 4 workstations" in burst["reason"].lower()


def test_auth_burst_velocity_spike():
    """Verify a high successful-logon rate with few failures triggers VELOCITY_BURST."""
    features = {
        "edr_auth_events_per_minute_window": 5.5,  # Successful logons/minute
        "edr_failed_auth_ratio_window": 0.10,
        "unique_workstations_300s": 1.0,
    }
    burst = detect_auth_burst(features)
    assert burst["is_anomaly"] is True
    assert burst["score"] == 60.0
    assert burst["severity"] == "MEDIUM"
    assert burst["burst_type"] == "VELOCITY_BURST"


def test_auth_burst_off_hours():
    """Verify after-hours authentication burst triggers OFF_HOURS_BURST."""
    features = {
        "off_hours_auth_count": 3,
        "edr_auth_event_count_window": 4,
        "unique_workstations_300s": 1.0,
    }
    burst = detect_auth_burst(features)
    assert burst["is_anomaly"] is True
    assert burst["score"] == 35.0
    assert burst["severity"] == "MEDIUM"
    assert burst["burst_type"] == "OFF_HOURS_BURST"


# ==============================================================================
# 4. Baseline Engine & Z-Score Scoring
# ==============================================================================

def test_baseline_engine_update_and_deviation():
    """Verify BaselineEngine computes deviations with variance floors."""
    storage = InMemoryRiskStorage()
    engine = BaselineEngine(storage, window_days=14)

    # 1. Initialize user baseline with observations over several days
    for day in range(1, 10):
        engine.update_baseline(
            "bob",
            {"file_access_count": 20.0, "daily_http_request_count": 50.0},
            observed_at=f"2026-10-0{day}T10:00:00Z",
        )

    baseline = engine.get_baseline("bob")
    assert baseline is not None
    assert baseline.sample_count >= 1
    assert "file_access_count" in baseline.feature_means

    # 2. Normal observation: deviations should be small (z-score near 0)
    normal_devs = engine.get_deviation_vector(
        "bob",
        {"file_access_count": 22.0, "daily_http_request_count": 52.0},
    )
    assert all(z < 2.0 for z in normal_devs.values())

    # 3. Anomalous observation (10x spike): deviations should exceed threshold
    spike_devs = engine.get_deviation_vector(
        "bob",
        {"file_access_count": 300.0, "daily_http_request_count": 500.0},
    )
    assert spike_devs.get("file_access_count", 0.0) > 3.0

    # 4. Score z-score
    z_result = score_zscore(spike_devs, {}, calibration_threshold=8.0)
    assert z_result["detector_name"] == "z_score"
    assert z_result["score"] > 0.0


# ==============================================================================
# 5. End-to-End Risk Pipeline & Baseline Update Gating
# ==============================================================================

def test_risk_pipeline_benign_payload_updates_baseline():
    """Verify low-risk payload (Risk < 40) updates the user baseline."""
    storage = InMemoryRiskStorage()

    benign_payload = {
        "payload_id": "p-benign-001",
        "agent_id": "agent-01",
        "username": "carol",
        "collected_at": "2026-10-16T10:00:00Z",
        "user_role": "OFFICE_WORKER",
        "collectors": [
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {"daily_file_open_count": 5},
            }
        ],
    }

    result = process_telemetry_risk(storage, benign_payload)
    assert result["risk_score"] < 40.0
    assert result["risk_level"] == "low"
    assert len(storage.risk_events) == 1

    # Carol's baseline was updated because risk < 40
    baseline = storage.load_baseline("carol")
    assert baseline is not None
    assert baseline["sample_count"] >= 1


def test_risk_pipeline_critical_threat_skips_baseline_poisoning():
    """Verify high-risk threat payload (Risk >= 40) does NOT update the baseline."""
    storage = InMemoryRiskStorage()

    malicious_payload = {
        "payload_id": "p-malicious-001",
        "agent_id": "agent-01",
        "username": "attacker",
        "collected_at": "2026-10-16T11:00:00Z",
        "user_role": "OFFICE_WORKER",
        "collectors": [
            {
                "collector": "lsass_monitor",
                "status": "success",
                "payload": {"credential_dumping_suspected": True},
            }
        ],
    }

    result = process_telemetry_risk(storage, malicious_payload)
    assert result["risk_score"] >= 80.0
    assert result["risk_level"] in ("high", "critical")
    assert len(storage.risk_events) == 1

    # Attacker's baseline should NOT be updated because risk >= 40 (poisoning guard)
    baseline = storage.load_baseline("attacker")
    assert baseline is None


# ==============================================================================
# 6. Role Cohort Unthrottled Updating & Cold-Start Priors
# ==============================================================================

def test_role_cohort_unthrottled_across_distinct_users():
    """Verify distinct users in the same role cohort do not throttle each other."""
    storage = InMemoryRiskStorage()
    engine = BaselineEngine(storage, window_days=14)

    # 1. User Alice in role 'engineering' updates at 10:00
    res_alice1 = engine.update_baseline(
        "alice",
        {"file_access_count": 25.0, "daily_http_request_count": 40.0},
        observed_at="2026-10-16T10:00:00Z",
        role="engineering",
    )
    assert not res_alice1.get("skipped", False)
    cohort1 = storage.load_baseline("__role_engineering__")
    assert cohort1 is not None
    assert cohort1["sample_count"] == 1

    # 2. User Bob in role 'engineering' updates at 10:05 (only 5m later)
    # Bob must NOT be throttled by Alice's prior observation!
    res_bob1 = engine.update_baseline(
        "bob",
        {"file_access_count": 30.0, "daily_http_request_count": 45.0},
        observed_at="2026-10-16T10:05:00Z",
        role="engineering",
    )
    assert not res_bob1.get("skipped", False)
    cohort2 = storage.load_baseline("__role_engineering__")
    assert cohort2 is not None
    assert cohort2["sample_count"] == 2  # Both Alice and Bob contributed!

    # 3. User Bob tries to update again at 10:15 (within 1 hour of Bob's last observation)
    res_bob2 = engine.update_baseline(
        "bob",
        {"file_access_count": 35.0, "daily_http_request_count": 50.0},
        observed_at="2026-10-16T10:15:00Z",
        role="engineering",
    )
    assert res_bob2.get("skipped", False) is True
    cohort3 = storage.load_baseline("__role_engineering__")
    assert cohort3["sample_count"] == 2  # Throttled per-user, sample count remains 2

    # 4. User Alice updates after >1 hour (11:05) -> accepted
    res_alice2 = engine.update_baseline(
        "alice",
        {"file_access_count": 22.0, "daily_http_request_count": 38.0},
        observed_at="2026-10-16T11:05:00Z",
        role="engineering",
    )
    assert not res_alice2.get("skipped", False)
    cohort4 = storage.load_baseline("__role_engineering__")
    assert cohort4["sample_count"] == 3


def test_cold_start_organizational_priors_and_rogue_detection():
    """Verify cold-start accounts with 0 samples safely use priors: benign work gets z<=0, rogue bursts spike."""
    storage = InMemoryRiskStorage()
    engine = BaselineEngine(storage, window_days=14)

    # 1. Brand new user with 0 history performs normal work
    normal_features = {
        "unique_workstations_300s": 1.0,
        "daily_unique_pc_count": 1.0,
        "daily_device_connect_count": 0.0,
        "edr_failed_auth_ratio_window": 0.0,
        "file_access_count": 20.0,
        "daily_http_request_count": 50.0,
    }
    normal_devs = engine.get_deviation_vector("brand_new_user", normal_features)
    # All deviations should be <= 0.0 (no false positives during cold start)
    assert all(dev <= 0.0 for dev in normal_devs.values())
    normal_z = score_zscore(normal_devs, normal_features)
    assert normal_z["score"] == 0.0
    assert not normal_z["is_anomaly"]

    # 2. Brand new user with 0 history performs rogue attack burst
    rogue_features = {
        "daily_device_connect_count": 4.0,        # Device domain: Prior mean=0.0, std=0.5 -> dev=8.0
        "file_access_count": 500.0,               # File domain: Prior mean=30.0, std=50.0 -> dev=9.4
        "daily_http_request_count": 800.0,        # Network domain: Prior mean=60.0, std=80.0 -> dev=9.25
    }
    rogue_devs = engine.get_deviation_vector("brand_new_rogue", rogue_features)
    assert rogue_devs["daily_device_connect_count"] >= 4.0
    assert rogue_devs["file_access_count"] >= 8.0
    assert rogue_devs["daily_http_request_count"] >= 8.0

    rogue_z = score_zscore(rogue_devs, rogue_features)
    assert rogue_z["score"] >= 85.0
    assert rogue_z["is_anomaly"] is True
    assert rogue_z["compound_domains_count"] >= 2
    assert rogue_z["severity"] in ("HIGH", "CRITICAL")


def test_cohort_concurrent_updates_are_thread_safe():
    """Verify concurrent updates to the same cohort baseline do not lose samples or cause race conditions."""
    import concurrent.futures

    storage = InMemoryRiskStorage()
    engine = BaselineEngine(storage, window_days=14)

    def worker(user_id: int):
        user_name = f"engineer_{user_id}"
        engine.update_baseline(
            user_name,
            {"file_access_count": 20.0 + user_id, "daily_http_request_count": 50.0},
            observed_at="2026-10-16T12:00:00Z",
            role="engineering",
        )

    # 10 distinct users reporting concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker, i) for i in range(10)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    cohort = storage.load_baseline("__role_engineering__")
    assert cohort is not None
    assert cohort["sample_count"] == 10
    recency = cohort.get("metadata_json", {}).get("cohort_member_last_seen", {})
    assert len(recency) == 10


def test_cohort_member_recency_pruning():
    """Verify that cohort member recency records older than 48 hours are automatically pruned."""
    storage = InMemoryRiskStorage()
    engine = BaselineEngine(storage, window_days=14)

    # User Alice reported on Day 1
    engine.update_baseline(
        "alice",
        {"file_access_count": 20.0},
        observed_at="2026-10-10T10:00:00Z",
        role="engineering",
    )

    cohort = storage.load_baseline("__role_engineering__")
    assert "alice" in cohort["metadata_json"]["cohort_member_last_seen"]

    # User Bob reports 3 days later (> 48 hours)
    engine.update_baseline(
        "bob",
        {"file_access_count": 25.0},
        observed_at="2026-10-13T10:00:00Z",
        role="engineering",
    )

    cohort2 = storage.load_baseline("__role_engineering__")
    recency = cohort2["metadata_json"]["cohort_member_last_seen"]
    assert "bob" in recency
    # Alice's 3-day-old entry was pruned
    assert "alice" not in recency


def test_score_zscore_multi_domain_deconstruction_and_compounding():
    """Verify multi-domain deconstruction computes domain Z-scores and compounds orthogonal anomalies."""
    features = {}

    # Case 1: Single domain elevated (File)
    single_domain_devs = {
        "file_access_count": 3.8,
    }
    single_res = score_zscore(single_domain_devs, features, calibration_threshold=8.0)
    assert single_res["domain_z_scores"]["file"] == 3.8
    assert single_res["domain_z_scores"]["logon"] == 0.0
    assert single_res["compound_domains_count"] == 1
    assert single_res["score"] == 52.0  # piecewise calibration maps 3σ→40 and 5σ→70

    # Case 2: Compound multi-domain elevated (Logon 3.5, File 3.8, Network 3.2)
    compound_devs = {
        "unique_workstations_300s": 3.5,
        "file_access_count": 3.8,
        "daily_http_request_count": 3.2,
    }
    compound_res = score_zscore(compound_devs, features, calibration_threshold=8.0)
    assert compound_res["domain_z_scores"]["logon"] == 3.5
    assert compound_res["domain_z_scores"]["file"] == 3.8
    assert compound_res["domain_z_scores"]["network"] == 3.2
    assert compound_res["compound_domains_count"] == 3
    # Compound score elevates beyond the single-feature 30.0 into MEDIUM/HIGH (> 50)
    assert compound_res["score"] > 50.0
    assert compound_res["confidence"] > single_res["confidence"]
    assert "Compound baseline anomaly across 3 domains" in compound_res["reason"]


def test_score_zscore_piecewise_calibration_and_compound_domain_boundary():
    """Moderate deviations become visible and each domain activates above 2σ."""
    z35 = score_zscore({"file_access_count": 3.5}, {}, calibration_threshold=8.0)
    assert z35["score"] == 47.5
    assert z35["is_anomaly"] is True
    assert z35["severity"] == "MEDIUM"

    z5 = score_zscore({"file_access_count": 5.0}, {}, calibration_threshold=8.0)
    assert z5["score"] == 70.0
    z7 = score_zscore({"file_access_count": 7.0}, {}, calibration_threshold=8.0)
    assert z7["score"] == 95.0

    low_and_slow = score_zscore({
        "file_access_count": 2.4,
        "daily_http_request_count": 2.4,
        "daily_device_connect_count": 2.4,
    }, {}, calibration_threshold=8.0)
    assert low_and_slow["compound_domains_count"] == 3
    assert low_and_slow["score"] == 16.0  # recognized across domains, but below alert threshold


# ==============================================================================
# 7. Stateful Multi-Stage Kill-Chain Sequence Tracking
# ==============================================================================

def test_kill_chain_single_stage_no_progression():
    """Verify that a single tactical stage does not trigger a kill-chain progression floor."""
    storage = InMemoryRiskStorage()
    single_stage_payload = {
        "payload_id": "kc-01",
        "agent_id": "agent-kc1",
        "username": "david",
        "collected_at": "2026-10-16T10:00:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {
                    "daily_unique_filename_count": 150,  # S2 collection
                },
            }
        ],
    }
    result = process_telemetry_risk(storage, single_stage_payload)
    kc = result["correlated_signals_json"].get("kill_chain", {})
    assert kc.get("kill_chain_progression_detected") is False
    assert kc.get("stage_count") == 1
    assert "COLLECTION_STAGING" in kc.get("stages_present", [])


def test_kill_chain_two_stages_progression_elevates_to_high():
    """Verify that 2 tactical stages across the rolling window elevate score to HIGH (>= 85.0)."""
    storage = InMemoryRiskStorage()

    # Stage 1: Credential Access at 10:00
    p1 = {
        "payload_id": "kc-p1",
        "agent_id": "agent-kc2",
        "username": "eve",
        "collected_at": "2026-10-16T10:00:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "lsass_monitor",
                "status": "success",
                "payload": {"credential_dumping_suspected": True},
            }
        ],
    }
    r1 = process_telemetry_risk(storage, p1)
    assert r1["risk_score"] >= 90.0

    # Stage 2: Collection / Staging at 10:30 (30 min later)
    p2 = {
        "payload_id": "kc-p2",
        "agent_id": "agent-kc2",
        "username": "eve",
        "collected_at": "2026-10-16T10:30:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {
                    "daily_unique_filename_count": 120,  # S2 collection
                },
            }
        ],
    }
    r2 = process_telemetry_risk(storage, p2)
    kc2 = r2["correlated_signals_json"].get("kill_chain", {})
    assert kc2.get("kill_chain_progression_detected") is True
    assert kc2.get("stage_count") == 2
    assert kc2.get("progression_severity") == "HIGH"
    assert r2["risk_score"] >= 85.0
    assert r2["risk_level"] in ("high", "critical")
    assert "Tactical kill chain progression" in r2["summary"]


def test_kill_chain_three_stages_progression_elevates_to_critical():
    """Verify that 3 tactical stages across the rolling window elevate score to CRITICAL (>= 95.0)."""
    storage = InMemoryRiskStorage()

    # Stage 1: Credential Access at 10:00
    p1 = {
        "payload_id": "kc-p1",
        "agent_id": "agent-kc3",
        "username": "frank",
        "collected_at": "2026-10-16T10:00:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "auth_monitor",
                "status": "success",
                "payload": {
                    "unique_workstations_300s": 4.0,
                    "edr_failed_auth_events_per_minute_window": 1.2,
                    "edr_failed_auth_ratio_window": 0.75,
                    "edr_auth_event_count_window": 8,
                },
            }
        ],
    }
    process_telemetry_risk(storage, p1)

    # Stage 2: Collection at 10:20
    p2 = {
        "payload_id": "kc-p2",
        "agent_id": "agent-kc3",
        "username": "frank",
        "collected_at": "2026-10-16T10:20:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {"daily_unique_filename_count": 150},
            }
        ],
    }
    process_telemetry_risk(storage, p2)

    # Stage 3: Exfiltration / Tunneling at 10:45
    p3 = {
        "payload_id": "kc-p3",
        "agent_id": "agent-kc3",
        "username": "frank",
        "collected_at": "2026-10-16T10:45:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "process_monitor",
                "status": "success",
                "payload": {"tunneling_process_count": 1},
            }
        ],
    }
    r3 = process_telemetry_risk(storage, p3)
    kc3 = r3["correlated_signals_json"].get("kill_chain", {})
    assert kc3.get("kill_chain_progression_detected") is True
    assert kc3.get("stage_count") >= 3
    assert kc3.get("progression_severity") == "CRITICAL"
    assert r3["risk_score"] >= 95.0
    assert r3["risk_level"] == "critical"
    assert "Confirmed multi-stage kill chain" in r3["summary"]


def test_kill_chain_benign_subsequent_event_not_elevated():
    """Verify that a subsequent benign heartbeat after an attack is not artificially spiked."""
    storage = InMemoryRiskStorage()

    # Past attack event
    p1 = {
        "payload_id": "kc-p1",
        "agent_id": "agent-kc4",
        "username": "grace",
        "collected_at": "2026-10-16T10:00:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "lsass_monitor",
                "status": "success",
                "payload": {"credential_dumping_suspected": True},
            }
        ],
    }
    process_telemetry_risk(storage, p1)

    # Subsequent completely benign heartbeat
    p_benign = {
        "payload_id": "kc-benign",
        "agent_id": "agent-kc4",
        "username": "grace",
        "collected_at": "2026-10-16T10:30:00Z",
        "user_role": "DEVELOPER",
        "collectors": [
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {
                    "daily_file_open_count": 2,
                    "daily_unique_filename_count": 1,
                },
            }
        ],
    }
    r_benign = process_telemetry_risk(storage, p_benign)
    kc_benign = r_benign["correlated_signals_json"].get("kill_chain", {})
    # No progression detected in benign observation
    assert kc_benign.get("kill_chain_progression_detected") is False
    assert len(kc_benign.get("stages_present", [])) == 0
    assert r_benign["risk_score"] < 40.0


# ==============================================================================
# 8. Attribution Scope & Single-Domain Compatibility Verification
# ==============================================================================

def test_score_zscore_single_domain_agent_only_compatibility():
    """Agent velocity uses the same graduated calibration as baseline deviations."""
    features = {
        "logon_velocity_zscore": 4.5,
    }
    # No server baseline deviations (agent-only input)
    result = score_zscore({}, features, calibration_threshold=8.0)
    assert result["detector_name"] == "z_score"
    # Piecewise calibration interpolates between 3σ→40 and 5σ→70.
    assert result["score"] == 62.5
    assert result["severity"] == "MEDIUM"
    assert result["compound_domains_count"] <= 1
    # Confidence uses effective max_z = 4.5
    assert result["confidence"] > 0.60


def test_user_baseline_isolates_host_scoped_auth_metrics():
    """Verify that host-scoped authentication event log metrics are excluded from the user baseline."""
    from server.risk.pipeline import _user_baseline_features

    mixed_collector_features = {
        # Host-scoped aggregates from Windows Event Log
        "auth_rate_300s": 2.5,
        "auth_rate_3600s": 1.2,
        "auth_fail_rate_300s": 0.8,
        "edr_auth_events_per_minute_window": 5.0,
        "edr_failed_auth_events_per_minute_window": 2.0,
        "edr_failed_auth_ratio_window": 0.40,
        "unique_workstations_300s": 4.0,
        "off_hours_auth_count": 3.0,
        # User-scoped metrics
        "file_access_count": 45.0,
        "daily_http_request_count": 120.0,
        "bytes_sent": 2500000.0,
    }

    user_features = _user_baseline_features(mixed_collector_features)

    # User metrics retained
    assert user_features["file_access_count"] == 45.0
    assert user_features["daily_http_request_count"] == 120.0
    assert user_features["bytes_sent"] == 2500000.0

    # Host-scoped metrics stripped from user baseline to prevent contamination
    assert "auth_rate_300s" not in user_features
    assert "auth_fail_rate_300s" not in user_features
    assert "edr_failed_auth_ratio_window" not in user_features
    assert "unique_workstations_300s" not in user_features
    assert "off_hours_auth_count" not in user_features


def test_storage_acquire_entity_lock_invoked_by_baseline_engine():
    """Verify that BaselineEngine invokes storage.acquire_entity_lock for multi-process safety."""
    from unittest.mock import MagicMock
    from contextlib import contextmanager

    lock_called = []

    class MockLockStorage(InMemoryRiskStorage):
        @contextmanager
        def acquire_entity_lock(self, entity_id: str):
            lock_called.append(entity_id)
            yield

    mock_storage = MockLockStorage()
    engine = BaselineEngine(mock_storage, window_days=14)

    engine.update_baseline(
        "worker_user",
        {"file_access_count": 15.0},
        observed_at="2026-10-16T12:00:00Z",
        role="engineering",
    )

    assert "worker_user" in lock_called
    assert "__role_engineering__" in lock_called


# ==============================================================================
# 11. Agent-Scoped Host Baseline Tests
# ==============================================================================

def test_host_baseline_feature_extraction():
    """Verify that _host_baseline_features extracts only host-scoped features."""
    from server.risk.pipeline import _host_baseline_features

    mixed_features = {
        # Host-scoped features
        "unique_workstations_300s": 3.0,
        "auth_rate_300s": 1.5,
        "edr_auth_events_per_minute_window": 2.0,
        "edr_auth_event_count_window": 10.0,
        "off_hours_auth_count": 1.0,
        "daily_unique_pc_count": 2.0,
        "daily_device_connect_count": 0.0,
        # User-scoped features
        "file_access_count": 50.0,
        "daily_unique_filename_count": 20.0,
        "bytes_sent": 5000000.0,
        # Invalid / none features
        "unknown_metric": 999.0,
        "auth_rate_3600s": 0.5,
    }

    host_features = _host_baseline_features(mixed_features)

    assert host_features["unique_workstations_300s"] == 3.0
    assert host_features["auth_rate_300s"] == 1.5
    assert host_features["edr_auth_events_per_minute_window"] == 2.0
    assert host_features["edr_auth_event_count_window"] == 10.0
    assert host_features["off_hours_auth_count"] == 1.0
    assert host_features["daily_unique_pc_count"] == 2.0
    assert host_features["daily_device_connect_count"] == 0.0

    # User-only features excluded
    assert "file_access_count" not in host_features
    assert "daily_unique_filename_count" not in host_features
    assert "bytes_sent" not in host_features
    assert "unknown_metric" not in host_features


def test_host_baseline_cold_start_and_deviation():
    """Verify cold-start host priors and calibrated deviations for uninitialized agents."""
    storage = InMemoryRiskStorage()
    engine = HostBaselineEngine(storage, window_days=14)

    assert engine.get_baseline("agent-001") is None

    # Normal activity matches priors -> deviation 0.0
    devs_normal = engine.get_deviation_vector("agent-001", {
        "unique_workstations_300s": 1.0,  # prior: mean=1.0, std=0.5
        "auth_rate_300s": 0.2,            # prior: mean=0.2, std=0.5
        "off_hours_auth_count": 0.0,      # prior: mean=0.0, std=0.5
    })
    assert devs_normal["unique_workstations_300s"] == 0.0
    assert devs_normal["auth_rate_300s"] == 0.0
    assert devs_normal["off_hours_auth_count"] == 0.0

    # Spikes produce calibrated positive deviations
    devs_spike = engine.get_deviation_vector("agent-001", {
        "unique_workstations_300s": 5.0,  # (5.0 - 1.0) / 0.5 = 8.0
        "auth_rate_300s": 1.2,            # (1.2 - 0.2) / 0.5 = 2.0
    })
    assert devs_spike["unique_workstations_300s"] == 8.0
    assert devs_spike["auth_rate_300s"] == 2.0


def test_host_baseline_jump_box_suppresses_multi_workstation_false_positive():
    """Verify jump box host baseline suppresses benign multi-workstation bursts while detecting attacks."""
    storage = InMemoryRiskStorage()
    engine = HostBaselineEngine(storage, window_days=14)

    # Mature jump box baseline with regular access to ~8 workstations
    storage.save_host_baseline({
        "agent_id": "agent-jumpbox-01",
        "sample_count": 10,
        "metadata_json": {
            "feature_means": {"unique_workstations_300s": 8.0, "auth_rate_300s": 2.0},
            "feature_stds": {"unique_workstations_300s": 1.5, "auth_rate_300s": 0.5},
            "feature_sample_counts": {"unique_workstations_300s": 10, "auth_rate_300s": 10},
        },
        "created_at": "2026-10-16T12:00:00Z",
    })

    benign_jumpbox_features = {
        "unique_workstations_300s": 8.0,
        "edr_auth_event_count_window": 10.0,
        "auth_fail_rate_300s": 0.0,
    }

    # 1. Jump box evaluation: Z-score is 0.0 < 2.0 -> suppressed
    jumpbox_devs = engine.get_deviation_vector("agent-jumpbox-01", benign_jumpbox_features)
    res_jumpbox = detect_auth_burst(benign_jumpbox_features, host_deviations=jumpbox_devs)
    assert not res_jumpbox["is_anomaly"]
    assert res_jumpbox["score"] == 0.0

    # 2. Ordinary workstation evaluation: cold start / standard prior -> triggers MULTI_WORKSTATION_BURST
    workstation_devs = engine.get_deviation_vector("agent-workstation-01", benign_jumpbox_features)
    res_workstation = detect_auth_burst(benign_jumpbox_features, host_deviations=workstation_devs)
    assert res_workstation["is_anomaly"]
    assert res_workstation["score"] == 75.0
    assert res_workstation["burst_type"] == "MULTI_WORKSTATION_BURST"

    # 3. Malicious burst on jump box: high failures -> triggers regardless of baseline
    attack_jumpbox_features = {
        "unique_workstations_300s": 8.0,
        "edr_auth_event_count_window": 10.0,
        "edr_failed_auth_events_per_minute_window": 5.0,
        "auth_fail_rate_300s": 0.80,
    }
    res_jumpbox_attack = detect_auth_burst(attack_jumpbox_features, host_deviations=jumpbox_devs)
    assert res_jumpbox_attack["is_anomaly"]
    assert res_jumpbox_attack["score"] == 85.0
    assert res_jumpbox_attack["burst_type"] == "MULTI_WORKSTATION_BURST"


def test_host_baseline_anti_poisoning_rejection_on_attack():
    """Verify that attack telemetry and auth anomalies do not train/poison the host baseline."""
    storage = InMemoryRiskStorage()

    # 1. Clean observation trains the host baseline
    payload_clean = {
        "payload_id": "p-clean-1",
        "agent_id": "agent-host-100",
        "username": "alice",
        "collected_at": "2026-10-16T10:00:00Z",
        "collectors": [
            {
                "collector": "auth_monitor",
                "status": "success",
                "payload": {
                    "unique_workstations_300s": 1.0,
                    "auth_rate_300s": 0.2,
                },
            },
            {
                "collector": "file_monitor",
                "status": "success",
                "payload": {
                    "file_access_count": 5.0,
                },
            },
        ],
    }
    res1 = process_telemetry_risk(storage, payload_clean)
    assert res1["risk_score"] < 40.0
    host_b1 = storage.load_host_baseline("agent-host-100")
    assert host_b1 is not None
    assert host_b1["sample_count"] == 1

    # 2. Attack payload arrives 2 hours later (credential dumping)
    payload_attack = {
        "payload_id": "p-attack-1",
        "agent_id": "agent-host-100",
        "username": "alice",
        "collected_at": "2026-10-16T12:00:00Z",
        "collectors": [
            {
                "collector": "lsass_monitor",
                "status": "success",
                "payload": {
                    "credential_dumping_suspected": True,
                },
            },
            {
                "collector": "auth_monitor",
                "status": "success",
                "payload": {
                    "unique_workstations_300s": 25.0,
                    "auth_rate_300s": 15.0,
                },
            },
        ],
    }
    res2 = process_telemetry_risk(storage, payload_attack)
    assert res2["risk_score"] >= 95.0
    host_b2 = storage.load_host_baseline("agent-host-100")
    # Anti-poisoning policy rejected the update: sample_count remains 1
    assert host_b2["sample_count"] == 1

    # 3. Clean observation 2 hours after the attack trains normally
    payload_clean_2 = {
        "payload_id": "p-clean-2",
        "agent_id": "agent-host-100",
        "username": "alice",
        "collected_at": "2026-10-16T14:00:00Z",
        "collectors": [
            {
                "collector": "auth_monitor",
                "status": "success",
                "payload": {
                    "unique_workstations_300s": 1.0,
                    "auth_rate_300s": 0.2,
                },
            },
        ],
    }
    res3 = process_telemetry_risk(storage, payload_clean_2)
    assert res3["risk_score"] < 40.0
    host_b3 = storage.load_host_baseline("agent-host-100")
    assert host_b3["sample_count"] == 2


def test_host_baseline_bounded_winsorization():
    """Verify observations > mu + 3*sigma are clamped before short-term accumulation."""
    storage = InMemoryRiskStorage()
    engine = HostBaselineEngine(storage, window_days=14)

    # Mature baseline: mu = 2.0, sigma = 1.0 -> clamp ceiling = 2.0 + 3.0 = 5.0
    storage.save_host_baseline({
        "agent_id": "agent-win-01",
        "sample_count": 10,
        "metadata_json": {
            "feature_means": {"unique_workstations_300s": 2.0},
            "feature_stds": {"unique_workstations_300s": 1.0},
            "feature_sample_counts": {"unique_workstations_300s": 10},
            "short_term_sums": {},
            "short_term_counts": {},
            "last_merge_date": "2026-10-16",
            "last_observation_at": "2026-10-16T10:00:00Z",
        },
        "created_at": "2026-10-16T10:00:00Z",
    })

    # Observe an extreme surge of 50.0
    engine.update_baseline(
        "agent-win-01",
        {"unique_workstations_300s": 50.0},
        observed_at="2026-10-16T12:00:00Z",
    )

    saved = storage.load_host_baseline("agent-win-01")
    # Winsorized value is clamped to 5.0
    assert saved["metadata_json"]["short_term_sums"]["unique_workstations_300s"] == 5.0
    assert saved["metadata_json"]["short_term_counts"]["unique_workstations_300s"] == 1


def test_host_baseline_stale_and_hourly_throttling():
    """Verify stale or sub-hourly snapshots are throttled for host baselines."""
    storage = InMemoryRiskStorage()
    engine = HostBaselineEngine(storage, window_days=14)

    # First update
    res1 = engine.update_baseline(
        "agent-th-01",
        {"unique_workstations_300s": 1.0},
        observed_at="2026-10-16T12:00:00Z",
    )
    assert not res1.get("skipped")
    assert res1["sample_count"] == 1

    # Stale observation (earlier than last seen) -> skipped
    res_stale = engine.update_baseline(
        "agent-th-01",
        {"unique_workstations_300s": 1.0},
        observed_at="2026-10-16T11:00:00Z",
    )
    assert res_stale.get("skipped") is True
    assert res_stale["reason"] == "host throttled"

    # Rapid observation within 30 minutes (< 3600s) -> skipped
    res_fast = engine.update_baseline(
        "agent-th-01",
        {"unique_workstations_300s": 1.0},
        observed_at="2026-10-16T12:30:00Z",
    )
    assert res_fast.get("skipped") is True
    assert res_fast["reason"] == "host throttled"

    # Eligible observation after 65 minutes -> accepted
    res_ok = engine.update_baseline(
        "agent-th-01",
        {"unique_workstations_300s": 1.0},
        observed_at="2026-10-16T13:05:00Z",
    )
    assert not res_ok.get("skipped")
    assert res_ok["sample_count"] == 2


def test_host_baseline_suppressed_multi_workstation_does_not_mask_subsequent_rules():
    """Verify that suppressing an expected multi-workstation pattern does not mask velocity or off-hours alerts."""
    # Mature jump box baseline where 8 workstations is expected
    host_deviations = {
        "unique_workstations_300s": 0.5,  # Z < 2.0 -> expected multi-workstation
        "auth_rate_300s": 3.5,            # Z >= 2.0 -> unexpected velocity spike
        "off_hours_auth_count": 4.0,      # Z >= 2.0 -> unexpected off-hours burst
    }

    # 1. Expected multi-workstation + unexpected velocity spike
    features_velocity = {
        "unique_workstations_300s": 8.0,
        "edr_auth_event_count_window": 10.0,
        "edr_auth_events_per_minute_window": 5.5,
        "auth_fail_rate_300s": 0.0,
    }
    res_vel = detect_auth_burst(features_velocity, host_deviations=host_deviations)
    assert res_vel["is_anomaly"] is True
    assert res_vel["score"] == 60.0
    assert res_vel["burst_type"] == "VELOCITY_BURST"

    # 2. Expected multi-workstation + unexpected off-hours burst
    features_off_hours = {
        "unique_workstations_300s": 8.0,
        "edr_auth_event_count_window": 5.0,
        "off_hours_auth_count": 3.0,
        "auth_fail_rate_300s": 0.0,
    }
    # Rate deviation is normal (not spiking), but off-hours deviation is unexpected
    host_devs_day = {
        "unique_workstations_300s": 0.5,
        "auth_rate_300s": 0.0,
        "off_hours_auth_count": 3.5,
    }
    res_off = detect_auth_burst(features_off_hours, host_deviations=host_devs_day)
    assert res_off["is_anomaly"] is True
    assert res_off["score"] == 35.0
    assert res_off["burst_type"] == "OFF_HOURS_BURST"


def test_host_baseline_anti_poisoning_rejection_on_off_hours_burst():
    """Verify that even a low-risk off-hours burst anomaly (score 35) blocks host baseline training."""
    storage = InMemoryRiskStorage()

    # 1. Clean observation trains the host baseline
    payload_clean = {
        "payload_id": "p-clean-1",
        "agent_id": "agent-host-200",
        "username": "bob",
        "collected_at": "2026-10-16T10:00:00Z",
        "collectors": [
            {
                "collector": "auth_monitor",
                "status": "success",
                "payload": {
                    "unique_workstations_300s": 1.0,
                    "auth_rate_300s": 0.2,
                },
            },
        ],
    }
    res1 = process_telemetry_risk(storage, payload_clean)
    assert res1["risk_score"] < 40.0
    host_b1 = storage.load_host_baseline("agent-host-200")
    assert host_b1 is not None
    assert host_b1["sample_count"] == 1

    # 2. Observation 2 hours later has off-hours burst (score 35.0, overall risk < 40)
    payload_off_hours = {
        "payload_id": "p-off-1",
        "agent_id": "agent-host-200",
        "username": "bob",
        "collected_at": "2026-10-16T12:00:00Z",
        "collectors": [
            {
                "collector": "auth_monitor",
                "status": "success",
                "payload": {
                    "off_hours_auth_count": 3.0,
                    "edr_auth_event_count_window": 4.0,
                },
            },
        ],
    }
    res2 = process_telemetry_risk(storage, payload_off_hours)
    # Risk score may be moderate (e.g. 35.0), but auth anomaly must block host baseline update
    assert res2["correlated_signals_json"].get("auth_burst", {}).get("is_anomaly") is True
    host_b2 = storage.load_host_baseline("agent-host-200")
    # Sample count must remain 1 (not updated)
    assert host_b2["sample_count"] == 1


def test_host_baseline_auth_rate_zero_deviation_not_overridden():
    """Verify that a valid 0.0 auth_rate_300s deviation is not treated as falsy/missing."""
    features = {
        "auth_rate_300s": 5.0,
        "edr_auth_events_per_minute_window": 5.0,
        "auth_fail_rate_300s": 0.05,
    }

    # Host has an established baseline where auth_rate_300s deviation is exactly 0.0 (rate_expected is True).
    # edr_auth_events_per_minute_window has a legacy or fallback deviation of 4.5.
    # An explicit 'is not None' check ensures 0.0 is used, keeping rate_expected == True.
    host_deviations = {
        "auth_rate_300s": 0.0,
        "edr_auth_events_per_minute_window": 4.5,
    }

    res = detect_auth_burst(features, host_deviations=host_deviations)
    # Because rate_expected is True (Z = 0.0 < 2.0) and fail_ratio < 0.20, velocity burst is suppressed
    assert res["score"] == 0.0
    assert not res["is_anomaly"]

