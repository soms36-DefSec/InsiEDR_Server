from math import isnan


def safe_get(features, key, default=0):
    value = features.get(key, default)
    if value is None:
        return default
    try:
        if isinstance(value, float) and isnan(value):
            return default
    except Exception:
        pass
    return value


# ==============================================================
# Threshold Revision — v0.5 Hardening  (all thresholds ×5)
#
# Original → New
#   After-Hours Midnight Access : after_hours > 0   → >= 5
#                                 logon_count >= 3   → >= 15
#                                 first_logon <= 5   → <= 3
#   Multi-PC Lateral Movement   : unique_pc >= 4     → >= 20
#                                 daily_pc >= 4       → >= 20
#                                 pc_entropy >= 1.5   → >= 3.0
#   Short Repeated Sessions     : logon/logoff >= 10 → >= 50
#   Possible Account Sharing    : logon >= 2         → >= 10
#                                 unique_pc >= 2      → >= 10
#                                 ratio > 0.3         → > 0.75
# ==============================================================

def detect_logon_scenarios(features):

    detections = []

    def add_detection(name, severity, score, confidence, reasons):
        detections.append({
            "scenario": name,
            "severity": severity,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    logon_count          = safe_get(features, "logon_count")
    logoff_count         = safe_get(features, "logoff_count")
    unique_pc_count      = safe_get(features, "unique_pc_count")
    daily_unique_pc_count= safe_get(features, "daily_unique_pc_count")
    after_hours_logon    = safe_get(features, "after_hours_logon")
    after_hours_ratio    = safe_get(features, "daily_after_hours_logon_ratio")
    first_logon_time     = safe_get(features, "first_logon_time")
    last_logoff_time     = safe_get(features, "last_logoff_time")
    weekend_logon        = safe_get(features, "weekend_logon")
    pc_entropy           = safe_get(features, "daily_pc_access_entropy")

    # ----------------------------------------------------------
    # Scenario 1 — After-Hours Midnight Access (High Threshold)
    # Thresholds: after_hours >= 50 AND (first_logon <= 2 OR logon >= 100)
    # ----------------------------------------------------------
    midnight_flag = (first_logon_time <= 2 if first_logon_time is not None else False)

    if (after_hours_logon >= 50 and (midnight_flag or logon_count >= 100)):
        add_detection(
            name="After-Hours Midnight Access",
            severity="MEDIUM",
            score=10,
            confidence="MEDIUM",
            reasons=[
                f"after_hours_logon={after_hours_logon} (threshold >=50)",
                f"first_logon_time={first_logon_time} (threshold <=2)",
                f"logon_count={logon_count} (threshold >=100)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 2 — Multi-PC Lateral Movement
    # Thresholds: unique_pc >= 100 OR (daily_pc >= 100 AND entropy >= 5.5)
    # ----------------------------------------------------------
    if (unique_pc_count >= 100 or (daily_unique_pc_count >= 100 and pc_entropy >= 5.5)):
        add_detection(
            name="Multi-PC Lateral Movement",
            severity="HIGH",
            score=20,
            confidence="HIGH",
            reasons=[
                f"unique_pc_count={unique_pc_count} (threshold >=100)",
                f"daily_unique_pc_count={daily_unique_pc_count} (threshold >=100)",
                f"pc_entropy={pc_entropy} (threshold >=5.5)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 3 — Normal Daily Login (Broad Benign Baseline)
    # ----------------------------------------------------------
    if (logon_count <= 50 and unique_pc_count <= 10
            and after_hours_logon <= 25 and weekend_logon <= 25):
        add_detection(
            name="Normal Daily Login",
            severity="LOW",
            score=0,
            confidence="HIGH",
            reasons=["routine user session", "within operational parameters"]
        )

    # ----------------------------------------------------------
    # Scenario 4 — Short Repeated Sessions
    # Thresholds: logon_count >= 300, logoff_count >= 300
    # ----------------------------------------------------------
    mismatch = abs(logon_count - logoff_count)

    if (logon_count >= 300 and logoff_count >= 300 and mismatch <= 20):
        add_detection(
            name="Short Repeated Sessions",
            severity="MEDIUM",
            score=10,
            confidence="MEDIUM",
            reasons=[
                f"logon_count={logon_count} (threshold >=300)",
                f"logoff_count={logoff_count} (threshold >=300)",
                f"mismatch={mismatch} (threshold <=20)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 5 — Possible Account Sharing
    # Thresholds: logon >= 100, unique_pc >= 50, ratio > 0.95
    # ----------------------------------------------------------
    if (logon_count >= 100 and unique_pc_count >= 50 and after_hours_ratio > 0.95):
        add_detection(
            name="Possible Account Sharing",
            severity="MEDIUM",
            score=10,
            confidence="LOW",
            reasons=[
                f"logon_count={logon_count} (threshold >=100)",
                f"unique_pc_count={unique_pc_count} (threshold >=50)",
                f"after_hours_ratio={after_hours_ratio} (threshold >0.95)"
            ]
        )

    return detections
