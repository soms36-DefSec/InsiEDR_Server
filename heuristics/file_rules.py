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
#   Bulk File Collection        : acc >= 500, unique >= 100
#                               → acc >= 2500, unique >= 500
#   Anomalous File Access       : entropy >= 2.5
#                                 new_files >= 50, repeat <= 0.2
#                               → entropy >= 4.5 (bounded near max)
#                                 new_files >= 250, repeat <= 0.05
#   Credential File Hunting     : new >= 75, unique >= 75, repeat <= 0.15
#                               → new >= 375, unique >= 375, repeat <= 0.04
#   After-Hours File Activity   : after_hours > 0, acc >= 100
#                               → after_hours >= 5, acc >= 500
#   Weekend File Collection     : weekend > 0, acc >= 50
#                               → weekend >= 5, acc >= 250
# ==============================================================

def detect_file_scenarios(features):

    detections = []

    def add_detection(name, severity, score, confidence, reasons):
        detections.append({
            "scenario": name,
            "severity": severity,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    file_access_count = safe_get(features, "file_access_count")
    unique_files      = safe_get(features, "daily_unique_filename_count")
    new_files         = safe_get(features, "daily_new_filename_count")
    file_entropy      = safe_get(features, "daily_file_access_entropy")
    after_hours       = safe_get(features, "after_hours_file_access")
    weekend_access    = safe_get(features, "weekend_file_access")
    repeat_count      = safe_get(features, "daily_repeat_file_access_count")
    repeat_ratio      = safe_get(features, "daily_repeat_file_ratio")
    first_access      = safe_get(features, "first_file_access_time")
    last_access       = safe_get(features, "last_file_access_time")

    # ----------------------------------------------------------
    # Scenario 1 — Bulk File Collection (Mass Exfil Scale)
    # Thresholds: acc >= 20000, unique >= 5000
    # ----------------------------------------------------------
    if (file_access_count >= 20000 and unique_files >= 5000):
        add_detection(
            name="Bulk File Collection",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"file_access_count={file_access_count} (threshold >=20000)",
                f"unique_files={unique_files} (threshold >=5000)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 2 — Normal Document Editing (Broad Benign Baseline)
    # ----------------------------------------------------------
    if (file_access_count > 0
            and unique_files > 0
            and file_access_count <= 2500
            and unique_files <= 2500
            and after_hours <= 50
            and weekend_access <= 50):
        add_detection(
            name="Normal Document Editing",
            severity="LOW",
            score=0,
            confidence="HIGH",
            reasons=["normal file activity within safe limits"]
        )

    # ----------------------------------------------------------
    # Scenario 3 — Anomalous File Access Pattern (Scripted Scans)
    # Thresholds: entropy >= 6.5 AND new >= 2500 AND acc >= 5000
    # ----------------------------------------------------------
    if (file_entropy >= 6.5
            and new_files >= 2500
            and repeat_ratio <= 0.005
            and file_access_count >= 5000):
        add_detection(
            name="Anomalous File Access Pattern",
            severity="MEDIUM",
            score=10,
            confidence="MEDIUM",
            reasons=[
                f"file_entropy={file_entropy} (threshold >=6.5)",
                f"new_files={new_files} (threshold >=2500)",
                f"repeat_ratio={repeat_ratio} (threshold <=0.005)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 4 — Credential File Hunting
    # Thresholds: new >= 3000, unique >= 3000, repeat <= 0.005
    # ----------------------------------------------------------
    if (new_files >= 3000 and repeat_ratio <= 0.005 and unique_files >= 3000):
        add_detection(
            name="Credential File Hunting",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"new_files={new_files} (threshold >=3000)",
                f"unique_files={unique_files} (threshold >=3000)",
                f"repeat_ratio={repeat_ratio} (threshold <=0.005)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 5 — New Employee Onboarding / Normal Project Exploration
    # ----------------------------------------------------------
    if (10 <= file_access_count <= 10000
            and 10 <= unique_files <= 10000
            and after_hours <= 50
            and weekend_access <= 50
            and repeat_ratio < 0.85):
        add_detection(
            name="Possible New Employee Onboarding",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[
                f"file_access_count={file_access_count}",
                f"unique_files={unique_files}"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 6 — After-Hours File Activity (Large Volume Off-Hours)
    # Thresholds: after_hours >= 100, acc >= 5000
    # ----------------------------------------------------------
    if (after_hours >= 100 and file_access_count >= 5000):
        add_detection(
            name="After-Hours File Activity",
            severity="MEDIUM",
            score=10,
            confidence="MEDIUM",
            reasons=[
                f"after_hours_file_access={after_hours} (threshold >=100)",
                f"file_access_count={file_access_count} (threshold >=5000)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 7 — Weekend File Collection Activity
    # Thresholds: weekend >= 100, acc >= 5000
    # ----------------------------------------------------------
    if (weekend_access >= 100 and file_access_count >= 5000):
        add_detection(
            name="Weekend File Collection Activity",
            severity="MEDIUM",
            score=10,
            confidence="MEDIUM",
            reasons=[
                f"weekend_file_access={weekend_access} (threshold >=100)",
                f"file_access_count={file_access_count} (threshold >=5000)"
            ]
        )

    return detections
