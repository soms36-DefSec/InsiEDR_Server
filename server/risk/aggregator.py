from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from heuristics.detector import detect_insider_threat

logger = logging.getLogger("InsiEDR.RiskAggregator")


class RiskAggregator:
    """
    Centralized Risk Aggregation and Evidence Fusion Engine for InsiEDR.
    Combines ML Pipeline, Z-Score baseline, AuthBurst anomalies, and Workload-Adaptive Heuristics.
    Enforces Certainty-Gated dynamic ensembling, Leaky-Bucket EMA temporal smoothing,
    and a Critical Corroboration Guard.
    """

    def __init__(self, storage) -> None:
        self.storage = storage
        self.base_weights = {
            "ml_pipeline": 0.70,
            "z_score": 0.10,
            "auth_burst": 0.05,
            "heuristics": 0.15
        }

    def summary(self) -> Dict[str, Any]:
        """Provides a statistical summary for dashboard metrics."""
        stats = self.storage.get_stats() if hasattr(self.storage, "get_stats") else {}
        return {
            "ok": True,
            "agents": stats.get("agents", 0),
            "logs": stats.get("logs", 0),
            "collector_results": stats.get("collector_results", 0),
            "anomalies": stats.get("anomalies", 0),
            "baselines": stats.get("baselines", 0),
        }

    def aggregate_detectors(
        self, 
        detector_results: List[Dict[str, Any]], 
        username: str = None, 
        raw_features: dict = None
    ) -> Dict[str, Any]:
        """
        Fuses multiple detector outputs and heuristic signals into a single calibrated risk assessment.
        """
        if not detector_results and not raw_features:
            return {
                "risk_score": 0.0,
                "risk_level": "low",
                "summary": "No active detectors.",
                "correlated_signals_json": {}
            }

        correlated_signals = {}
        reasons = []
        anomalies_flagged = 0

        # 1. Evaluate Heuristics Engine with Workload Profile Context
        h_result = {"short_term_risk": 0.0, "overall_score": 0.0, "overall_severity": "LOW", "detections": []}
        profile = "DEFAULT"
        if raw_features:
            profile = str(raw_features.get("system_profile") or raw_features.get("user_role") or "DEFAULT").upper()
            h_result = detect_insider_threat(raw_features, system_profile=profile)
            correlated_signals["heuristics"] = h_result

        # 2. Extract Individual Detector Scores & Confidences
        scores = {
            "ml_pipeline": 0.0,
            "z_score": 0.0,
            "auth_burst": 0.0,
            "heuristics": float(h_result.get("short_term_risk", 0.0))
        }
        confidences = {
            "ml_pipeline": 0.75,
            "z_score": 0.85,
            "auth_burst": 0.80,
            "heuristics": 0.85 if h_result.get("scenario_count", 0) > 0 else 0.40
        }

        for result in detector_results or []:
            name = result.get("detector_name", "unknown").lower()
            score = float(result.get("score", 0.0))
            conf = float(result.get("confidence", 0.70))
            correlated_signals[name] = result

            if result.get("is_anomaly"):
                anomalies_flagged += 1
                if result.get("reason"):
                    reasons.append(result["reason"])

            if "pipeline" in name or "model" in name or "random_forest" in name or "isolation_forest" in name or "advanced" in name:
                scores["ml_pipeline"] = max(scores["ml_pipeline"], score)
                confidences["ml_pipeline"] = max(confidences["ml_pipeline"], conf)
            elif "zscore" in name or "z_score" in name:
                scores["z_score"] = max(scores["z_score"], score)
                confidences["z_score"] = max(confidences["z_score"], conf)
            elif "auth" in name:
                scores["auth_burst"] = max(scores["auth_burst"], score)
                confidences["auth_burst"] = max(confidences["auth_burst"], conf)

        # 3. Dynamic Certainty-Gated Weight Calculation
        # Only true high-severity signals scale up conviction
        dynamic_weights = {}
        for source, base_w in self.base_weights.items():
            s = scores[source]
            c = confidences[source]
            conviction_boost = 1.0
            if s >= 40.0:
                conviction_boost = 1.0 + (2.0 * (((s - 40.0) / 60.0) ** 2) * c)
            dynamic_weights[source] = base_w * conviction_boost

        total_weight = sum(dynamic_weights.values())
        raw_aggregated_score = sum(scores[k] * dynamic_weights[k] for k in scores) / max(0.001, total_weight)

        # 4. Leaky-Bucket EMA Temporal Smoothing
        final_score = raw_aggregated_score
        if username and hasattr(self.storage, "get_max_risk_score_in_window"):
            try:
                past_max_score = float(self.storage.get_max_risk_score_in_window(username, 4) or 0.0)
                if past_max_score > 0.0:
                    final_score = (0.85 * raw_aggregated_score) + (0.15 * min(100.0, past_max_score))
                    if past_max_score >= 50.0 and raw_aggregated_score >= 50.0:
                        reasons.append(f"Sustained anomaly pattern in 4h window (Past Max: {past_max_score:.1f})")
            except Exception as e:
                logger.debug(f"Temporal memory fetch skipped: {e}")

        # 5. CERT Scenario Evaluation (Multi-Stage Kill Chain)
        cert_scenarios = self._map_cert_scenarios(detector_results, raw_features, h_result)
        correlated_signals["cert_scenarios"] = cert_scenarios

        # 6. High & Medium Threshold Protection Safeguard
        # Requires multi-paradigm corroboration for any score >= 35.0 (MEDIUM / HIGH / CRITICAL)
        critical_safeguard_applied = False
        if final_score >= 35.0:
            is_corroborated = self._verify_critical_corroboration(
                scores=scores,
                confidences=confidences,
                heur_result=h_result,
                cert_scenarios=cert_scenarios,
                profile=profile
            )
            if not is_corroborated:
                # Cap uncorroborated single-signal anomaly safely at 10.0 (LOW)
                final_score = min(final_score, 10.0)
                critical_safeguard_applied = True
                correlated_signals["critical_safeguard_applied"] = True

        # Cap bounds strictly [0.0, 100.0] with high floating-point precision
        final_score = max(0.0, min(100.0, round(final_score, 6)))

        # 7. Centralized Severity Mapping (Raised high-threshold scale)
        risk_level = "low"
        if final_score >= 85.0:
            risk_level = "critical"
        elif final_score >= 60.0:
            risk_level = "high"
        elif final_score >= 35.0:
            risk_level = "medium"

        # 8. Construct Human-Readable Summary
        summary = "Normal behavior."
        summary_parts = []
        if h_result.get("scenario_count", 0) > 0:
            h_scenarios = " | ".join(d["scenario"] for d in h_result.get("detections", []))
            summary_parts.append(f"Heuristics: {h_scenarios}")

        if reasons:
            summary_parts.append(" | ".join(reasons))

        if cert_scenarios:
            cert_desc = " | ".join(s["description"] for s in cert_scenarios if "description" in s)
            if cert_desc:
                summary_parts.append(cert_desc)

        if summary_parts:
            summary = " | ".join(summary_parts)

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "summary": summary,
            "correlated_signals_json": correlated_signals
        }

    def _verify_critical_corroboration(
        self,
        scores: Dict[str, float],
        confidences: Dict[str, float],
        heur_result: Dict[str, Any],
        cert_scenarios: List[Dict[str, str]],
        profile: str
    ) -> bool:
        """
        Corroboration Matrix: Requires multi-source validation before confirming CRITICAL or HIGH.
        """
        # Condition 1: Cross-Paradigm Agreement (High ML + Heuristics or Z-Score or CERT)
        if scores["ml_pipeline"] >= 75.0 and confidences["ml_pipeline"] >= 0.80:
            if scores["heuristics"] >= 10.0 or scores["z_score"] >= 25.0 or len(cert_scenarios) >= 1:
                return True

        # Condition 2: High-Severity Multi-Domain Heuristic Breach
        active_domains = heur_result.get("active_domains", [])
        if scores["heuristics"] >= 50.0 and len(active_domains) >= 2:
            return True

        # Condition 3: Strong ML Anomaly Conviction
        if scores["ml_pipeline"] >= 85.0 and confidences["ml_pipeline"] >= 0.85:
            return True

        # Condition 4: Confirmed Multi-Vector High-Severity CERT Exfiltration Kill Chain
        if any(s.get("severity") in ("CRITICAL", "HIGH") for s in cert_scenarios):
            return True

        return False

    def _map_cert_scenarios(
        self, 
        detector_results: List[Dict[str, Any]], 
        raw_features: Optional[dict] = None,
        heur_result: Optional[dict] = None
    ) -> List[Dict[str, str]]:
        scenarios = []
        anomalous_features = set()

        for result in detector_results or []:
            if result.get("is_anomaly"):
                for feat_name in result.get("feature_contributions", {}).keys():
                    anomalous_features.add(feat_name)

        # Only add features from raw_features that cross genuine attack thresholds
        ATTACK_HIGH_WATERMARKS = {
            "file_access_count": 10000,
            "sensitive_file_access": 100,
            "unusual_file_access_ratio": 0.75,
            "file_delete_count": 500,
            "daily_file_delete_count": 500,
            "file_sharing_site_visits": 100,
            "job_search_site_visits": 50,
            "usb_connect_count": 100,
            "daily_files_to_removable_count": 200,
            "external_drive_file_copy": 100,
            "large_usb_transfer": 50,
            "usb_file_transfer_count": 100,
            "after_hours_logon": 50,
            "daily_failed_login_ratio": 0.75,
            "edr_failed_auth_ratio_window": 0.75,
            "edr_auth_burst_score": 75.0
        }

        if raw_features:
            for k, v in raw_features.items():
                thresh = ATTACK_HIGH_WATERMARKS.get(k)
                if thresh is not None and isinstance(v, (int, float)) and v >= thresh:
                    anomalous_features.add(k)

        # S1 & S2: IP Theft / USB Exfiltration
        s1_s2_device = {"usb_connect_count", "daily_files_to_removable_count", "external_drive_file_copy", "large_usb_transfer", "usb_file_transfer_count"}
        s1_s2_http = {"job_search_site_visits"}
        
        intersect_s1_device = anomalous_features.intersection(s1_s2_device)
        intersect_s1_http = anomalous_features.intersection(s1_s2_http)

        if len(intersect_s1_device) >= 1 and len(intersect_s1_http) >= 1:
            scenarios.append({
                "id": "S1_S2", 
                "severity": "CRITICAL",
                "description": f"CERT S1/S2: WikiLeaks/IP Theft - USB Activity + Job Search (Correlated: {', '.join(intersect_s1_device.union(intersect_s1_http))})"
            })
        elif len(intersect_s1_device) >= 1:
            scenarios.append({
                "id": "S1_S2_Partial", 
                "severity": "LOW",
                "description": f"CERT S1/S2: USB Data Transfer Activity (Correlated: {', '.join(intersect_s1_device)})"
            })

        # S3: IT Sabotage
        s3_file = {"file_delete_count", "daily_file_delete_count"}
        s3_auth = {"after_hours_logon", "daily_failed_login_ratio", "edr_failed_auth_ratio_window", "edr_auth_burst_score"}
        intersect_s3_file = anomalous_features.intersection(s3_file)
        intersect_s3_auth = anomalous_features.intersection(s3_auth)

        if len(intersect_s3_file) >= 1 and len(intersect_s3_auth) >= 1:
            scenarios.append({
                "id": "S3", 
                "severity": "CRITICAL",
                "description": f"CERT S3: IT Sabotage - Mass Delete + Auth Spikes (Correlated: {', '.join(intersect_s3_file.union(intersect_s3_auth))})"
            })
        elif len(intersect_s3_file) >= 1:
            scenarios.append({
                "id": "S3_Partial", 
                "severity": "LOW",
                "description": f"CERT S3: File Deletion Activity (Correlated: {', '.join(intersect_s3_file)})"
            })

        # S5: Cloud Storage Upload (Precursor vs Confirmed Exfiltration)
        s5_http = {"file_sharing_site_visits"}
        s5_file = {"sensitive_file_access", "unusual_file_access_ratio"}
        intersect_s5_http = anomalous_features.intersection(s5_http)
        intersect_s5_file = anomalous_features.intersection(s5_file)

        heur_groups = (heur_result or {}).get("active_groups", [])
        has_file_exfil_group = "FILE_EXFIL_GROUP" in heur_groups

        if len(intersect_s5_http) >= 1 and (len(intersect_s5_file) >= 1 or has_file_exfil_group):
            scenarios.append({
                "id": "S5_CONFIRMED", 
                "severity": "HIGH",
                "description": f"CERT S5: Sensitive File Access + Cloud Storage Upload (Correlated: {', '.join(intersect_s5_http.union(intersect_s5_file))})"
            })
        elif len(intersect_s5_http) >= 1:
            scenarios.append({
                "id": "S5_PRECURSOR", 
                "severity": "LOW",
                "description": f"CERT S5: Cloud Storage Browsing [VERIFY_REQUIRED]"
            })

        return scenarios

