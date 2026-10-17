from __future__ import annotations

from math import isnan


def _number(features, name, default=0.0):
    value = features.get(name, default)
    try:
        result = float(value)
        return default if isnan(result) else result
    except (TypeError, ValueError):
        return default


def detect_device_scenarios(features):
    detections = []
    transfer_count = max(
        _number(features, "daily_files_to_removable_count"),
        _number(features, "external_drive_file_copy"),
        _number(features, "usb_file_transfer_count"),
        _number(features, "large_usb_transfer"),
    )
    connects = max(_number(features, "usb_connect_count"), _number(features, "daily_device_connect_count"))
    unauthorized = features.get("unauthorized_usb_detected") is True

    if transfer_count > 0:
        severity = "HIGH" if transfer_count >= 20 else "MEDIUM"
        detections.append({
            "scenario": "Bulk USB File Transfer",
            "scenario_id": "S3",
            "severity": severity,
            "score": 80 if transfer_count >= 20 else 60,
            "confidence": "HIGH",
            "reasons": [f"files_or_transfer_units={transfer_count:g}"],
        })
    elif unauthorized:
        detections.append({
            "scenario": "Unapproved USB Device",
            "scenario_id": "S3_PRECURSOR",
            "severity": "MEDIUM",
            "score": 40,
            "confidence": "MEDIUM",
            "reasons": ["unauthorized_usb_detected=true; no transfer evidence"],
        })
    elif connects > 0:
        detections.append({
            "scenario": "USB Device Activity",
            "scenario_id": "S3_PRECURSOR",
            "severity": "LOW",
            "score": 10,
            "confidence": "LOW",
            "reasons": [f"device_connect_count={connects:g}; transfer evidence is unavailable"],
        })

    return detections
