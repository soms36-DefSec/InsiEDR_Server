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


def detect_file_scenarios(features):
    detections = []
    accesses = _number(features, "file_access_count")
    unique_files = max(_number(features, "daily_unique_filename_count"), _number(features, "unique_filename_count"))
    new_files = _number(features, "daily_new_filename_count")
    deletes = max(_number(features, "daily_file_delete_count"), _number(features, "file_delete_count"))
    sensitive = _number(features, "sensitive_file_access")
    to_removable = sum(_number(features, name) for name in (
        "daily_files_to_removable_count", "external_drive_file_copy", "usb_file_transfer_count"
    ))

    # Collection needs volume and breadth. A few accesses or an ordinary audit
    # event must not be interpreted as hoarding.
    if accesses >= 500 and unique_files >= 100:
        detections.append(_detection(
            "Bulk File Collection", "S2", "HIGH", 75, "HIGH",
            [f"file_access_count={accesses:g}", f"distinct_files={unique_files:g}"],
        ))
    elif unique_files >= 50 and new_files >= 25:
        detections.append(_detection(
            "Broad File Collection", "S2", "MEDIUM", 45, "MEDIUM",
            [f"distinct_files={unique_files:g}", f"new_files={new_files:g}"],
        ))

    if sensitive > 0 and (accesses >= 50 or unique_files >= 20):
        detections.append(_detection(
            "Sensitive File Collection", "S2", "HIGH", 70, "HIGH",
            [f"sensitive_file_access={sensitive:g}", f"file_access_count={accesses:g}", f"distinct_files={unique_files:g}"],
        ))

    if deletes >= 10:
        detections.append(_detection(
            "Mass File Deletion", "FILE_DELETE", "MEDIUM", 50, "MEDIUM", [f"file_delete_count={deletes:g}"]
        ))

    if to_removable > 0:
        detections.append(_detection(
            "File Transfer to Removable Media", "S3", "HIGH", 80, "HIGH",
            [f"files_to_removable={to_removable:g}"],
        ))

    return detections
