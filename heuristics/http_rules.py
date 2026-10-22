from __future__ import annotations

from math import isnan


def _number(features, name, default=0.0):
    value = features.get(name, default)
    try:
        result = float(value)
        return default if isnan(result) else result
    except (TypeError, ValueError):
        return default


def detect_http_scenarios(features):
    detections = []
    sharing_visits = _number(features, "file_sharing_site_visits")
    uploads = max(
        _number(features, "cloud_storage_uploads"),
        _number(features, "large_uploads"),
        _number(features, "upload_bytes"),
        _number(features, "cloud_upload_bytes"),
        _number(features, "large_upload_bytes"),
    )
    upload_count = max(_number(features, "cloud_storage_uploads"), _number(features, "large_uploads"))
    sensitive_files = _number(features, "sensitive_file_access")
    file_burst = max(_number(features, "daily_unique_filename_count"), _number(features, "daily_new_filename_count")) >= 50

    # A visit to Drive/Dropbox is context, not evidence of exfiltration.
    if (uploads > 0 or upload_count > 0) and (sensitive_files > 0 or file_burst):
        detections.append({
            "scenario": "Cloud Upload Correlated with File Collection",
            "scenario_id": "S4",
            "severity": "HIGH",
            "score": 80,
            "confidence": "HIGH",
            "reasons": [f"upload_activity={max(uploads, upload_count):g}", f"sensitive_file_access={sensitive_files:g}", f"file_burst={file_burst}"],
        })
    elif uploads > 0 or upload_count > 0:
        detections.append({
            "scenario": "Cloud Upload Without File Correlation",
            "scenario_id": "S4_PRECURSOR",
            "severity": "LOW",
            "score": 25,
            "confidence": "MEDIUM",
            "reasons": [f"upload_activity={max(uploads, upload_count):g}; sensitive-file correlation unavailable"],
        })
    elif sharing_visits > 0:
        detections.append({
            "scenario": "File-Sharing Site Visit",
            "scenario_id": "S4_PRECURSOR",
            "severity": "LOW",
            "score": 10,
            "confidence": "LOW",
            "reasons": [f"file_sharing_site_visits={sharing_visits:g}; upload activity was not reported"],
        })

    return detections
