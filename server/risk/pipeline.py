from __future__ import annotations

import logging
from typing import Any, Dict
from server.risk.aggregator import RiskAggregator
from server.risk.signals import detect_auth_burst, score_zscore
from server.baseline.engine import BaselineEngine, HostBaselineEngine
from server.config import config

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
    # Persistence monitor currently emits a boolean instead of a count. A true
    # value remains usable by the existing numeric evidence checks as 1.
    "persistence_modification_count": ("modifications_detected",),
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

    # 2. Extract from collectors array. Keep root identity authoritative: most
    # SYSTEM collectors are host-scoped and intentionally omit username.
    collectors = payload.get("collectors", [])
    if isinstance(collectors, list):
        for col in collectors:
            if not isinstance(col, dict) or col.get("status") != "success":
                continue
            col_payload = col.get("payload")
            if not isinstance(col_payload, dict):
                continue
            _flatten_features(col_payload, features, features.get("username"))

    # 3. Apply canonical aliases
    for canonical, aliases in FEATURE_ALIASES.items():
        if canonical not in features or features[canonical] is None:
            for alias in aliases:
                if alias in features and features[alias] is not None:
                    features[canonical] = features[alias]
                    break

    # 4. Derive file deletion counts from confirmed sampled integrity event operations
    # Note: This reflects the count of explicitly sampled DELETE operations in the
    # telemetry batch, not necessarily the total number of deletions on the endpoint.
    if "file_delete_count" not in features and "daily_file_delete_count" not in features:
        delete_ops = [
            str(v).strip().upper() for k, v in features.items()
            if k.startswith("integrity_events_") and k.endswith("_op") and v
        ]
        if delete_ops:
            features["file_delete_count"] = float(sum(1 for op in delete_ops if op in ("DELETE", "DELETION")))


    # 5. Computed composite features
    if "file_access_count" not in features and any(
        name in features for name in ("daily_file_open_count", "file_open_count", "daily_file_write_count", "file_write_count", "daily_file_delete_count", "file_delete_count")
    ):
        open_c = _numeric(features.get("daily_file_open_count", features.get("file_open_count", 0)))
        write_c = _numeric(features.get("daily_file_write_count", features.get("file_write_count", 0)))
        del_c = _numeric(features.get("daily_file_delete_count", features.get("file_delete_count", 0)))
        features["file_access_count"] = open_c + write_c + del_c

    return features


def _flatten_features(source: Dict[str, Any], target: Dict[str, Any], username: Any = None) -> None:
    clean_user = str(username or "").strip().casefold()
    user_metric_hints = {
        "logon_count", "logoff_count", "failed_logons", "successful_logons",
        "after_hours_logon", "interactive_duration_seconds", "daily_unique_pc_count",
    }
    for key, value in source.items():
        if isinstance(value, dict):
            if clean_user and value and all(isinstance(item, dict) for item in value.values()):
                user_entry = next((item for user, item in value.items() if str(user).strip().casefold() == clean_user), None)
                if user_entry is not None:
                    _flatten_features(user_entry, target, username)
                    continue
                if any(user_metric_hints.intersection(item) for item in value.values()):
                    # Do not combine another user's logon counters into this
                    # payload if the active root user cannot be matched.
                    continue
            _flatten_features(value, target, username)
        else:
            target.setdefault(str(key), value)


def process_telemetry_risk(storage, payload: Dict[str, Any], *, emit: bool = True) -> Dict[str, Any]:
    """
    Executes the Heuristics Detection Engine and Risk Aggregator on an ingested payload.
    Persists risk event to storage and dispatches real-time SSE threat notifications.
    """
    payload_id = str(payload.get("payload_id", ""))
    agent_id = str(payload.get("agent_id", ""))
    username_value = str(payload.get("username") or "").strip()
    username = username_value or "unknown"

    if not config.enable_detection_pipeline:
        logger.debug("Detection pipeline is disabled; skipping evaluation for payload %s", payload_id)
        return {
            "payload_id": payload_id,
            "agent_id": agent_id,
            "username": username,
            "risk_score": 0.0,
            "risk_level": "low",
            "summary": "Detection pipeline is disabled.",
            "correlated_signals_json": {},
            "collected_at": payload.get("collected_at"),
        }

    try:
        raw_features = extract_features_from_payload(payload)

        # Score against the user's prior baseline and the agent's host baseline before updating.
        # Ingested snapshots are sampled hourly and only eligible, non-alerting observations train them.
        detector_results = []
        baseline_engine = None
        host_engine = None
        deviations: Dict[str, float] = {}
        host_deviations: Dict[str, float] = {}
        baseline_features = _user_baseline_features(raw_features)
        host_features = _host_baseline_features(raw_features)

        if username_value and hasattr(storage, "load_baseline") and hasattr(storage, "save_baseline"):
            try:
                baseline_engine = BaselineEngine(storage, window_days=config.baseline_window_days)
                role = raw_features.get("user_role")
                deviations = baseline_engine.get_deviation_vector(username_value, baseline_features, role=role)
            except Exception as baseline_err:
                logger.debug("User baseline unavailable for %s: %s", username_value, baseline_err)

        if agent_id and hasattr(storage, "load_host_baseline") and hasattr(storage, "save_host_baseline"):
            try:
                host_engine = HostBaselineEngine(storage, window_days=config.baseline_window_days)
                host_deviations = host_engine.get_deviation_vector(agent_id, host_features)
            except Exception as host_err:
                logger.debug("Host baseline unavailable for %s: %s", agent_id, host_err)

        auth_burst_result = detect_auth_burst(raw_features, host_deviations=host_deviations)
        detector_results.extend((
            auth_burst_result,
            # Only user-baseline features enter the user z-score path. In
            # particular, do not let the host-wide agent logon velocity score
            # leak back into a per-user anomaly score.
            score_zscore(deviations, baseline_features, config.zscore_calibration_threshold),
        ))

        # The model is scored in an isolated daily worker. This bounded Redis
        # lookup only adds fresh, fully warmed endpoint context.
        from server.risk.ml_cache import get_cached_ml_detector
        ml_result = get_cached_ml_detector(agent_id)
        if ml_result is not None:
            detector_results.append(ml_result)

        # Execute deterministic heuristics plus auth-burst and user-baseline
        # detectors. Model inference remains an external detector integration.
        aggregator = RiskAggregator(storage)
        risk_result = aggregator.aggregate_detectors(detector_results, username=username_value or None,
                                                      raw_features=raw_features, agent_id=agent_id)

        if baseline_engine is not None and risk_result.get("risk_score", 0.0) < 40.0:
            try:
                baseline_engine.update_baseline(
                    username_value,
                    _user_baseline_features(raw_features),
                    observed_at=payload.get("collected_at"),
                    role=raw_features.get("user_role"),
                )
            except Exception as baseline_err:
                logger.debug("User baseline update skipped for %s: %s", username_value, baseline_err)

        # Host baseline anti-poisoning policy:
        # Update host baseline only from eligible, non-alerting observations.
        # Prevent active auth anomalies (any is_anomaly) or elevated overall threat states from teaching the baseline.
        if host_engine is not None and agent_id:
            risk_val = float(risk_result.get("risk_score", 0.0))
            auth_anomaly = bool(auth_burst_result.get("is_anomaly"))
            has_critical = any(
                raw_features.get(k) is True or str(raw_features.get(k, "")).strip().lower() in ("1", "true", "yes")
                for k in ("credential_dumping_suspected", "threats_detected", "threat_triggered")
            )
            if risk_val < 40.0 and not auth_anomaly and not has_critical:
                try:
                    host_engine.update_baseline(
                        agent_id,
                        host_features,
                        observed_at=payload.get("collected_at"),
                    )
                except Exception as host_err:
                    logger.debug("Host baseline update skipped for %s: %s", agent_id, host_err)

        correlated_signals = dict(risk_result.get("correlated_signals_json") or {})
        if payload.get("hostname"):
            correlated_signals["hostname"] = str(payload["hostname"])
        if agent_id in config.test_agent_ids:
            correlated_signals["source_kind"] = "synthetic_test"
        # Keep the matched process details with a tunneling finding so an analyst
        # can inspect the exact process instead of a count-only assertion.
        processes = raw_features.get("processes")
        try:
            tunneling_process_count = float(raw_features.get("tunneling_process_count") or 0)
        except (TypeError, ValueError):
            tunneling_process_count = 0
        if tunneling_process_count > 0 and isinstance(processes, list):
            indicators = ("ngrok", "ssh", "plink", "localtunnel", "chisel", "frpc")
            evidence = []
            for process in processes:
                if not isinstance(process, dict):
                    continue
                name = str(process.get("name") or "")
                command = str(process.get("cmd") or "")
                if not any(indicator in f"{name} {command}".lower() for indicator in indicators):
                    continue
                evidence.append({
                    "pid": process.get("pid"),
                    "name": name[:260],
                    "command_line": command[:512],
                    "source": str(process.get("source") or "")[:80],
                    "observed_at": payload.get("collected_at"),
                })
                if len(evidence) == 5:
                    break
            if evidence:
                correlated_signals["process_evidence"] = evidence

        event_dict = {
            "payload_id": payload_id,
            "agent_id": agent_id,
            "username": username,
            "risk_score": float(risk_result.get("risk_score", 0.0)),
            "risk_level": str(risk_result.get("risk_level", "low")),
            "correlated_signals_json": correlated_signals,
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
        if emit:
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


def _user_baseline_features(features: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract baseline inputs associated with the active root session.

    Host-scoped authentication event-log metrics are excluded. Other flattened
    collector counters may still reflect host activity; the current telemetry
    does not provide kernel-enforced SID attribution for every collector.
    """
    user_feature_names = (
        "daily_unique_filename_count",
        "daily_new_filename_count",
        "file_access_count",
        "file_sharing_site_visits",
        "daily_http_request_count",
        "daily_external_domain_ratio",
        "daily_device_connect_count",
        "bytes_sent",
    )
    result: Dict[str, float] = {}
    for name in user_feature_names:
        if name not in features or features[name] is None:
            continue
        try:
            value = float(features[name])
        except (TypeError, ValueError):
            continue
        if value == value:
            result[name] = value
    return result


def _host_baseline_features(features: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract baseline inputs associated with the endpoint host/machine.

    Covers host-wide authentication, workstation traversal, and hardware velocity.
    """
    host_feature_names = (
        "unique_workstations_300s",
        "auth_rate_300s",
        "edr_auth_events_per_minute_window",
        "edr_auth_event_count_window",
        "off_hours_auth_count",
        "daily_unique_pc_count",
        "daily_device_connect_count",
    )
    result: Dict[str, float] = {}
    for name in host_feature_names:
        if name not in features or features[name] is None:
            continue
        try:
            value = float(features[name])
        except (TypeError, ValueError):
            continue
        if value == value:
            result[name] = value
    return result


def _baseline_features(features: Dict[str, Any]) -> Dict[str, float]:
    """Backward compatible alias."""
    return _user_baseline_features(features)
