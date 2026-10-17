from __future__ import annotations

import math
from typing import Any, Dict


def _number(features: Dict[str, Any], *names: str) -> float | None:
    for name in names:
        value = features.get(name)
        if value is None:
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if number == number:  # reject NaN
            return number
    return None


def detect_auth_burst(features: Dict[str, Any]) -> Dict[str, Any]:
    """Score host-scoped short-window authentication burst indicators."""
    successes = _number(features, "edr_auth_event_count_window")
    fail_rate = _number(features, "edr_failed_auth_events_per_minute_window")
    fail_ratio = _number(features, "edr_failed_auth_ratio_window", "auth_fail_rate_300s")
    # The agent currently defines these rates from successful logons only;
    # estimate successes from that rate when the exact five-minute count is absent.
    events_per_minute = _number(features, "edr_auth_events_per_minute_window", "auth_rate_300s")
    # Do not substitute daily logon/PC counters into this five-minute detector.
    if successes is None and events_per_minute is not None:
        successes = max(0.0, events_per_minute * 5.0)
    workstations = _number(features, "unique_workstations_300s")
    off_hours = _number(features, "off_hours_auth_count")

    failed_count = max(0.0, (fail_rate or 0.0) * 5.0)
    # Some agent versions export the ratio and total but not a failed-event count.
    if failed_count == 0.0 and fail_ratio is not None and successes is not None:
        failed_count = (max(0.0, fail_ratio) * max(0.0, successes)) / max(0.01, 1.0 - fail_ratio)

    ws_count = workstations or 0.0
    total_attempts = (successes or 0.0) + failed_count
    if fail_ratio is None and total_attempts > 0:
        fail_ratio = failed_count / total_attempts

    score = 0.0
    severity = "LOW"
    reasons: list[str] = []
    confidence = 0.0
    burst_type: str | None = None
    attack_pattern: str | None = None
    # The current telemetry is host-scoped and lacks account/source
    # attribution, so emit factual burst labels without assigning ATT&CK
    # techniques or tactics that the evidence cannot substantiate.
    tactical_category: str | None = None

    ws_count = workstations or 0.0

    # 1. Multi-workstation burst with high failure ratio
    if ws_count >= 3.0 and failed_count >= 4.0 and (fail_ratio is not None and fail_ratio >= 0.50):
        score, severity, confidence = 85.0, "HIGH", 0.90
        burst_type = "MULTI_WORKSTATION_BURST"
        tactical_category = "AUTHENTICATION_ACTIVITY"
        reasons.extend((
            f"failed_auth_ratio={fail_ratio:.3f}",
            f"failed_auth_events_5m~={failed_count:.1f}",
            f"unique_workstations_5m={ws_count:g}",
            f"Host authentication burst across {ws_count:g} workstations with elevated failures",
        ))
    # 2. Concentrated high failure burst
    elif (fail_ratio is not None and fail_ratio >= 0.75 and failed_count >= 5.0):
        score, severity, confidence = 85.0, "HIGH", 0.90
        burst_type = "HIGH_FAILURE_BURST"
        tactical_category = "AUTHENTICATION_ACTIVITY"
        reasons.extend((
            f"failed_auth_ratio={fail_ratio:.3f}",
            f"failed_auth_events_5m~={failed_count:.1f}",
            "Host authentication burst with high failure volume",
        ))
    # 3. Multi-workstation activity with active/successful logons
    elif ws_count >= 3.0 and (total_attempts >= 4.0 or (events_per_minute is not None and events_per_minute >= 1.0)) and (fail_ratio is None or fail_ratio < 0.50):
        score, severity, confidence = 75.0, "HIGH", 0.85
        burst_type = "MULTI_WORKSTATION_BURST"
        tactical_category = "AUTHENTICATION_ACTIVITY"
        reasons.extend((
            f"unique_workstations_5m={ws_count:g}",
            f"auth_events_5m~={total_attempts:.1f}",
            f"Host authentication activity across {ws_count:g} workstations in 5-minute window",
        ))
    # 4. Secondary volume threshold
    elif failed_count >= 8.0 or (ws_count >= 4.0 and total_attempts >= 8.0):
        score, severity, confidence = 70.0, "HIGH", 0.82
        burst_type = "MULTI_WORKSTATION_BURST" if ws_count >= 4.0 else "HIGH_FAILURE_BURST"
        tactical_category = "AUTHENTICATION_ACTIVITY"
        reasons.extend((
            f"failed_auth_events_5m~={failed_count:.1f}",
            f"unique_workstations_5m={ws_count:g}",
        ))
    # 5. Velocity Spike
    elif (events_per_minute is not None and events_per_minute >= 3.0 and (fail_ratio or 0.0) >= 0.50) or (events_per_minute is not None and events_per_minute >= 5.0):
        score, severity, confidence = 60.0, "MEDIUM", 0.75
        burst_type = "VELOCITY_BURST"
        tactical_category = "AUTHENTICATION_ACTIVITY"
        reasons.extend((
            f"auth_events_per_minute={events_per_minute:.2f}",
            f"failed_auth_ratio={fail_ratio or 0.0:.3f}",
            f"Host authentication velocity spike ({events_per_minute:.2f} events/min)",
        ))
    # 6. Off-Hours Burst
    elif (off_hours or 0.0) >= 2.0 and total_attempts >= 3.0:
        score, severity, confidence = 35.0, "MEDIUM", 0.60
        burst_type = "OFF_HOURS_BURST"
        tactical_category = "AUTHENTICATION_ACTIVITY"
        reasons.extend((
            f"off_hours_auth_count={off_hours:g}",
            f"auth_events_5m~={total_attempts:.1f}",
            "Host off-hours authentication burst",
        ))

    return {
        "detector_name": "auth_burst",
        "score": score,
        "confidence": confidence,
        "severity": severity,
        "is_anomaly": score > 0,
        "reason": "; ".join(reasons),
        "burst_type": burst_type,
        "attack_pattern": burst_type,
        "mitre_technique": None,
        "mitre_hypothesis": None,
        "tactical_category": tactical_category,
        "scope": "host",
        "account_attributed": False,
        "evidence": {
            "failed_auth_events_5m_estimate": round(failed_count, 3),
            "failed_auth_ratio": fail_ratio,
            "auth_events_per_minute": events_per_minute,
            "unique_workstations_5m": workstations,
            "off_hours_auth_count": off_hours,
            "burst_type": burst_type,
            "mitre_technique": None,
            "mitre_hypothesis": None,
            "tactical_category": tactical_category,
            "scope": "host",
            "account_attributed": False,
        },
    }


def _classify_domain(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("auth", "logon", "workstation", "pc", "session", "after_hours")):
        return "logon"
    if any(k in n for k in ("file", "filename", "delete", "sensitive")):
        return "file"
    if any(k in n for k in ("http", "domain", "upload", "sent", "network", "sharing", "traffic")):
        return "network"
    if any(k in n for k in ("usb", "device", "removable", "drive")):
        return "device"
    return "other"


def score_zscore(
    deviations: Dict[str, float],
    features: Dict[str, Any],
    calibration_threshold: float = 8.0,
) -> Dict[str, Any]:
    """Turn user-baseline deviations and the agent velocity z-score into risk with multi-domain deconstruction."""
    candidates: dict[str, float] = {}
    domain_deviations: dict[str, dict[str, float]] = {
        "logon": {},
        "file": {},
        "network": {},
        "device": {},
    }

    for name, value in deviations.items():
        try:
            z = float(value)
        except (TypeError, ValueError):
            continue
        if z == z and z > 0:
            candidates[name] = z
            dom = _classify_domain(name)
            if dom in domain_deviations:
                domain_deviations[dom][name] = z

    # Agent velocity z-score contributes to the logon domain
    agent_z = _number(features, "logon_velocity_zscore") or 0.0
    if agent_z > 0:
        domain_deviations["logon"]["logon_velocity_zscore"] = max(
            domain_deviations["logon"].get("logon_velocity_zscore", 0.0), agent_z
        )

    # Compute max deviation per domain
    domain_z: dict[str, float] = {
        dom: max(devs.values(), default=0.0)
        for dom, devs in domain_deviations.items()
    }

    threshold = max(3.0, float(calibration_threshold))
    max_name, max_z = max(candidates.items(), key=lambda item: item[1], default=("", 0.0))
    baseline_score = min(100.0, max(0.0, (max_z - 2.0) * (100.0 / (threshold - 2.0))))

    # The agent's exported velocity z-score uses a fixed low-volume baseline.
    agent_score = min(50.0, max(0.0, (agent_z - 2.0) * 10.0))
    if agent_z >= 4.0 and (_number(features, "auth_rate_300s") or 0.0) >= 2.0 and (_number(features, "unique_workstations_300s") or 0.0) >= 2.0:
        agent_score = min(65.0, max(agent_score, (agent_z - 2.0) * 12.0))
    if agent_score > baseline_score:
        max_name, max_z = "logon_velocity_zscore", agent_z

    # Multi-Domain Compound Anomaly Norm
    excess_by_domain = {dom: max(0.0, z_val - 2.0) for dom, z_val in domain_z.items()}
    active_compound_domains = [dom for dom, excess in excess_by_domain.items() if excess > 0.5]  # >= 2.5 sigma
    k_domains = len(active_compound_domains)

    # Compound norm only applies when multiple orthogonal domains are elevated (k >= 2)
    if k_domains >= 2:
        compound_excess = math.sqrt(sum(e * e for e in excess_by_domain.values()))
        multi_domain_boost = 1.0 + (0.15 * (k_domains - 1))
        compound_score = min(100.0, compound_excess * (100.0 / (threshold - 2.0)) * multi_domain_boost)
        score = max(baseline_score, agent_score, compound_score)
    else:
        compound_score = 0.0
        score = max(baseline_score, agent_score)

    # Confidence calculation: accurately accounts for effective max z-score and multi-domain corroboration
    effective_max_z = max_z if max_z > 0 else (agent_z if agent_score > 0 else 0.0)
    confidence = 0.0
    if score > 0:
        confidence = min(0.95, 0.45 + (0.05 * effective_max_z) + (0.08 * max(0, k_domains - 1)))

    severity = "CRITICAL" if score >= 90.0 else "HIGH" if score >= 70.0 else "MEDIUM" if score >= 40.0 else "LOW"
    is_anomaly = score >= 35.0

    reason_parts = []
    if score >= 35.0:
        if k_domains >= 2:
            domain_strs = [f"{dom.capitalize()} ({domain_z[dom]:.1f}σ)" for dom in active_compound_domains]
            reason_parts.append(f"Compound baseline anomaly across {k_domains} domains: {', '.join(domain_strs)}")
        elif max_name:
            reason_parts.append(f"{max_name} is {max_z:.2f} standard deviations above baseline")

    return {
        "detector_name": "z_score",
        "score": round(score, 2),
        "confidence": round(confidence, 3),
        "severity": severity,
        "is_anomaly": is_anomaly,
        "reason": "; ".join(reason_parts),
        "max_z_score": round(max_z, 3),
        "domain_z_scores": {dom: round(val, 3) for dom, val in domain_z.items()},
        "active_anomaly_domains": [dom for dom, val in domain_z.items() if val >= 2.0],
        "compound_domains_count": k_domains,
        "feature_deviations": {name: round(value, 3) for name, value in candidates.items() if value >= 2.0},
    }
