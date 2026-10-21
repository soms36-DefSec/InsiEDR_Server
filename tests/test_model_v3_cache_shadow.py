import json

from server.risk.aggregator import RiskAggregator
from server.risk.ml_cache import detector_from_cached_prior


def _prior():
    classes = (
        "BENIGN", "CLOUD_EXFILTRATION_PRECURSOR", "CREDENTIAL_DUMP",
        "DATA_HOARDING", "IT_SABOTAGE", "USB_EXFILTRATION_PRECURSOR",
        "HONEYTOKEN_TRIP", "KILL_CHAIN_APT",
    )
    return dict(as_of="2026-10-20", history_days="22", threat_probability="0.8",
                fused_risk="0.7", drift_error="0.4", pair_threat="0.6",
                predicted_scenario="DATA_HOARDING",
                scenario_probabilities_json=json.dumps({name: (1 if name == "DATA_HOARDING" else 0)
                                                        for name in classes}))


def test_stale_or_warming_prior_abstains():
    assert detector_from_cached_prior(_prior(), "2026-10-19", shadow=True) is None
    warming = _prior()
    warming["history_days"] = "21"
    assert detector_from_cached_prior(warming, "2026-10-20", shadow=True) is None


def test_shadow_prior_has_no_risk_or_stage_effect():
    model = detector_from_cached_prior(_prior(), "2026-10-20", shadow=True)
    assert model is not None
    aggregator = RiskAggregator(object())
    base = [{"detector_name": "auth_burst", "score": 60.0, "confidence": .8,
             "is_anomaly": True, "reason": "auth burst"}]
    without = aggregator.aggregate_detectors(base, raw_features={})
    with_shadow = aggregator.aggregate_detectors(base + [model], raw_features={})
    assert with_shadow["risk_score"] == without["risk_score"]
    assert with_shadow["risk_level"] == without["risk_level"]
    assert "ml_pipeline" not in with_shadow["correlated_signals_json"]
    assert with_shadow["correlated_signals_json"] == without["correlated_signals_json"]
