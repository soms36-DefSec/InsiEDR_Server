from __future__ import annotations

from math import isnan


def _number(features, name, default=0.0):
    value = features.get(name, default)
    try:
        result = float(value)
        return default if isnan(result) else result
    except (TypeError, ValueError):
        return default


def _detection(name, scenario_id, severity, score, confidence, reasons):
    return {"scenario": name, "scenario_id": scenario_id, "severity": severity,
            "score": score, "confidence": confidence, "reasons": reasons}


def detect_logon_scenarios(features):
    detections = []
    logons = _number(features, "successful_logons", _number(features, "logon_count"))
    after_hours = _number(features, "after_hours_logon")
    after_ratio = _number(features, "daily_after_hours_logon_ratio")
    unique_pcs = max(_number(features, "daily_unique_pc_count"), _number(features, "unique_pc_count"))
    failed = _number(features, "failed_logons")
    failed_ratio = _number(features, "edr_failed_auth_ratio_window", _number(features, "auth_fail_rate_300s"))

    # After-hours activity is a weak precursor by itself; require a meaningful
    # share of the user's logons or a second abnormal access signal.
    if after_hours >= 2 and after_ratio >= 0.5 and logons >= 3:
        detections.append(_detection(
            "After-Hours Logon Anomaly", "S1_PRECURSOR", "MEDIUM", 40, "MEDIUM",
            [f"after_hours_logon={after_hours:g}", f"after_hours_ratio={after_ratio:.3f}", f"successful_logons={logons:g}"],
        ))

    if unique_pcs >= 3 and logons >= 3:
        detections.append(_detection(
            "Multi-PC Access Anomaly", "AUTH_LATERAL", "MEDIUM", 40, "MEDIUM",
            [f"distinct_pcs={unique_pcs:g}", f"successful_logons={logons:g}"],
        ))

    if failed >= 5 and failed_ratio >= 0.5:
        detections.append(_detection(
            "Failed Authentication Activity", "AUTH_BURST", "MEDIUM", 45, "MEDIUM",
            [f"failed_logons={failed:g}", f"failed_auth_ratio={failed_ratio:.3f}"],
        ))

    return detections
