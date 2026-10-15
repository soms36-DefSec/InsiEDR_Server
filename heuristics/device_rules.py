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
#   Repeated Short USB Connects : connect >= 10, disconnect >= 10
#                               → connect >= 50, disconnect >= 50
# ==============================================================

def detect_device_scenarios(features):

    detections = []

    def add_detection(name, severity, score, confidence, reasons):
        detections.append({
            "scenario": name,
            "severity": severity,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    usb_connect_count       = safe_get(features, "usb_connect_count")
    usb_disconnect_count    = safe_get(features, "usb_disconnect_count")
    after_hours_usb_usage   = safe_get(features, "after_hours_usb_usage")
    daily_device_connect    = safe_get(features, "daily_device_connect_count")
    daily_device_flag       = safe_get(features, "daily_device_usage_flag")
    first_usb_usage_time    = safe_get(features, "first_usb_usage_time")
    last_usb_usage_time     = safe_get(features, "last_usb_usage_time")

    # ----------------------------------------------------------
    # Scenario 1 — Repeated Short USB Connects (Extreme Rapid Insertion Burst)
    # Thresholds: connect >= 300, disconnect >= 300
    # ----------------------------------------------------------
    if (usb_connect_count >= 300 and usb_disconnect_count >= 300):
        add_detection(
            name="Repeated Short USB Connects",
            severity="MEDIUM",
            score=10,
            confidence="HIGH",
            reasons=[
                f"usb_connect_count={usb_connect_count} (threshold >=300)",
                f"usb_disconnect_count={usb_disconnect_count} (threshold >=300)"
            ]
        )

    return detections
