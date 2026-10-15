from __future__ import annotations

import logging
from typing import Any, Dict
from server.risk.aggregator import RiskAggregator

logger = logging.getLogger("insiedr.risk.pipeline")

FEATURE_ALIASES = {
    "first_usb_usage_time": ("first_usb_time",),
    "daily_unique_filename_count": ("unique_filename_count",),
    "daily_new_filename_count": ("new_filename_count",),
    "daily_http_request_count": ("http_request_count", "http_count"),
    "daily_unique_domain_count": ("unique_domain_count",),
    "daily_new_domain_count": ("new_domain_count",),
    "daily_external_domain_ratio": ("external_domain_ratio",),
    "daily_device_connect_count": ("usb_connect_count",),
    "daily_unique_pc_count": ("unique_pc_count",),
    "suspicious_url_count": ("watchlisted_url_count",),
}


def _numeric(val: Any) -> float:
    if val is None:
        return 0.0
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)):
        return float(val)
    try:
        return float(val)
    except (TypeError, ValueError):
        text = str(val).strip()
        if ":" in text:
            # Time string e.g. "08:30"
            parts = text.split(":")
            try:
                return float(parts[0]) + (float(parts[1]) / 60.0)
            except Exception:
                return 0.0
        return 0.0


def extract_features_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flattens hierarchical collector payloads into a flat feature dictionary
    suitable for the Heuristics Engine and Risk Aggregator.
    """
    features: Dict[str, Any] = {}

    # 1. Base Metadata
    for k in ("agent_id", "hostname", "username", "collected_at", "user_role", "system_profile"):
        if k in payload:
            features[k] = payload[k]

    # 2. Extract from collectors array
    collectors = payload.get("collectors", [])
    if isinstance(collectors, list):
        for col in collectors:
            if not isinstance(col, dict) or col.get("status") != "success":
                continue
            col_payload = col.get("payload")
            if not isinstance(col_payload, dict):
                continue
            for k, v in col_payload.items():
                if isinstance(v, dict):
                    for sub_k, sub_v in v.items():
                        if isinstance(sub_v, dict):
                            for leaf_k, leaf_v in sub_v.items():
                                features.setdefault(leaf_k, leaf_v)
                        else:
                            features.setdefault(sub_k, sub_v)
                else:
                    features.setdefault(k, v)

    # 3. Apply canonical aliases
    for canonical, aliases in FEATURE_ALIASES.items():
        if canonical not in features or features[canonical] is None:
            for alias in aliases:
                if alias in features and features[alias] is not None:
                    features[canonical] = features[alias]
                    break

    # 4. Computed composite features
    if "file_access_count" not in features:
        open_c = _numeric(features.get("daily_file_open_count", features.get("file_open_count", 0)))
        write_c = _numeric(features.get("daily_file_write_count", features.get("file_write_count", 0)))
        del_c = _numeric(features.get("daily_file_delete_count", features.get("file_delete_count", 0)))
        features["file_access_count"] = open_c + write_c + del_c

    return features


def process_telemetry_risk(storage, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes the Heuristics Detection Engine and Risk Aggregator on an ingested payload.
    Persists risk event to storage and dispatches real-time SSE threat notifications.
    """
    payload_id = str(payload.get("payload_id", ""))
    agent_id = str(payload.get("agent_id", ""))
    username = str(payload.get("username", "unknown"))

    try:
        raw_features = extract_features_from_payload(payload)

        # Execute Risk Aggregator (evaluates Heuristics and CERT scenarios)
        aggregator = RiskAggregator(storage)
        risk_result = aggregator.aggregate_detectors([], username=username, raw_features=raw_features)

        event_dict = {
            "payload_id": payload_id,
            "agent_id": agent_id,
            "username": username,
            "risk_score": float(risk_result.get("risk_score", 0.0)),
            "risk_level": str(risk_result.get("risk_level", "low")),
            "correlated_signals_json": risk_result.get("correlated_signals_json", {}),
            "summary": str(risk_result.get("summary", "Normal behavior.")),
            "collected_at": payload.get("collected_at"),
        }

        # Persist to storage (both Postgres and ClickHouse support save_risk_event)
        risk_saver = getattr(storage, "save_risk_event", None)
        if callable(risk_saver):
            try:
                risk_saver(event_dict)
            except Exception as save_err:
                logger.warning("Failed to persist risk event: %s", save_err)

        # Dispatch real-time threat event to connected SSE clients
        try:
            from server.api.events import dispatch_threat_event
            dispatch_threat_event(event_dict)
        except Exception:
            pass

        return event_dict

    except Exception as exc:
        logger.error("Heuristics and risk pipeline evaluation failed for payload %s: %s", payload_id, exc)
        return {
            "payload_id": payload_id,
            "agent_id": agent_id,
            "username": username,
            "risk_score": 0.0,
            "risk_level": "low",
            "summary": "Error evaluating risk.",
            "correlated_signals_json": {},
        }
