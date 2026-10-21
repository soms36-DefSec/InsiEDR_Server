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

        # 2. Extract Individual Detector Scores & Confidences. A detector that
        # did not run must not dilute the scores of detectors that did run.
        scores = {
            "ml_pipeline": 0.0,
            "z_score": 0.0,
            "auth_burst": 0.0,
            "heuristics": float(h_result.get("short_term_risk", 0.0))
        }
        confidences = {
            "ml_pipeline": 0.75,
            "z_score": 0.0,
            "auth_burst": 0.0,
            "heuristics": 0.90 if h_result.get("scenario_count", 0) > 0 else 0.0
        }

        active_detector_results = [r for r in detector_results or [] if not r.get("is_shadow")]
        for result in active_detector_results:
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

        # 3. Dynamic certainty-gated ensemble over available detectors only.
        dynamic_weights = {}
        for source, base_w in self.base_weights.items():
            s = scores[source]
            c = confidences[source]
            if c <= 0.0 or (source == "ml_pipeline" and not any(
                any(tag in str(result.get("detector_name", "")).lower() for tag in ("pipeline", "model", "random_forest", "isolation_forest", "advanced"))
                for result in active_detector_results
            )):
                dynamic_weights[source] = 0.0
                continue
            conviction_boost = 1.0
            if s >= 40.0:
                conviction_boost = 1.0 + (2.0 * (((s - 40.0) / 60.0) ** 2) * c)
            dynamic_weights[source] = base_w * conviction_boost

        total_weight = sum(dynamic_weights.values())
        raw_aggregated_score = (
            sum(scores[k] * dynamic_weights[k] for k in scores) / total_weight
            if total_weight > 0
            else 0.0
        )
        # Deterministic heuristics are a risk floor. A strong, explainable rule
        # must not be washed out by absent or lower-confidence model outputs.
        raw_aggregated_score = max(raw_aggregated_score, scores["heuristics"])

        # 4. Leaky-Bucket EMA Temporal Smoothing & Rolling History Fetch
        final_score = raw_aggregated_score
        past_events: List[Dict[str, Any]] = []
        if username and hasattr(self.storage, "get_recent_risk_events_in_window"):
            try:
                past_events = self.storage.get_recent_risk_events_in_window(username, hours=4)
            except Exception as e:
                logger.debug("Recent risk events fetch skipped: %s", e)

        past_max_score = 0.0
        if past_events:
            past_max_score = max((float(e.get("risk_score", 0.0) or 0.0) for e in past_events), default=0.0)
        elif username and hasattr(self.storage, "get_max_risk_score_in_window"):
            try:
                past_max_score = float(self.storage.get_max_risk_score_in_window(username, 4) or 0.0)
            except Exception as e:
                logger.debug(f"Temporal memory fetch skipped: {e}")

        if past_max_score > 0.0:
            final_score = max(
                raw_aggregated_score,
                (0.85 * raw_aggregated_score) + (0.15 * min(100.0, past_max_score)),
            )
            if past_max_score >= 50.0 and raw_aggregated_score >= 50.0:
                reasons.append(f"Sustained anomaly pattern in 4h window (Past Max: {past_max_score:.1f})")

        # 5. CERT Scenario Evaluation
        cert_scenarios = self._map_cert_scenarios(active_detector_results, raw_features, h_result)
        correlated_signals["cert_scenarios"] = cert_scenarios
        scenario_floors = {"LOW": 0.0, "MEDIUM": 40.0, "HIGH": 70.0, "CRITICAL": 90.0}
        final_score = max(final_score, max((scenario_floors.get(s.get("severity", "LOW"), 0.0) for s in cert_scenarios), default=0.0))

        # 6. Stateful Multi-Stage Kill-Chain Sequence Tracking
        current_stages = self._map_tactical_stages(active_detector_results, raw_features, h_result, cert_scenarios)
        current_agent_id = str((raw_features or {}).get("agent_id") or "").strip()
        # The current auth/endpoint indicators are host-scoped. Do not build a
        # sequence by joining two different agents that happen to share a user.
        kill_chain_history = [
            event for event in past_events
            if current_agent_id and str(event.get("agent_id") or "").strip() == current_agent_id
        ]
        kill_chain = self._evaluate_kill_chain(current_stages, kill_chain_history)
        correlated_signals["kill_chain"] = kill_chain
        if kill_chain.get("kill_chain_progression_detected"):
            final_score = max(final_score, float(kill_chain.get("floor_score", 0.0)))
            if kill_chain.get("reason"):
                reasons.append(kill_chain["reason"])

        # 7. Corroboration guard for high scores. Confirmed strong evidence from
        # an individual deterministic detector or kill-chain progression can stand on its own.
        critical_safeguard_applied = False
        if final_score >= 70.0:
            is_corroborated = self._verify_critical_corroboration(
                scores=scores,
                confidences=confidences,
                heur_result=h_result,
                cert_scenarios=cert_scenarios,
                profile=profile,
                kill_chain=kill_chain,
            )
            if not is_corroborated:
                # Cap uncorroborated single-signal anomaly safely at 10.0 (LOW)
                final_score = min(final_score, 10.0)
                critical_safeguard_applied = True
                correlated_signals["critical_safeguard_applied"] = True

        # Cap bounds strictly [0.0, 100.0] with high floating-point precision
        final_score = max(0.0, min(100.0, round(final_score, 6)))

        # 8. Severity thresholds match DETECTION_PIPELINE.md.
        risk_level = "low"
        if final_score >= 90.0:
            risk_level = "critical"
        elif final_score >= 70.0:
            risk_level = "high"
        elif final_score >= 40.0:
            risk_level = "medium"

        # 9. Construct Human-Readable Summary
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
        profile: str,
        kill_chain: Optional[Dict[str, Any]] = None,
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
        if scores["heuristics"] >= 60.0 and len(active_domains) >= 2:
            return True

        # Condition 3: Strong ML Anomaly Conviction
        if scores["ml_pipeline"] >= 85.0 and confidences["ml_pipeline"] >= 0.85:
            return True

        # Strong, high-confidence auth burst or baseline deviation is actionable
        # even when the ML service is absent.
        if scores["auth_burst"] >= 85.0 and confidences["auth_burst"] >= 0.85:
            return True
        if scores["z_score"] >= 85.0 and confidences["z_score"] >= 0.85:
            return True

        # Condition 4: Confirmed Multi-Vector High-Severity CERT Exfiltration Kill Chain
        if any(s.get("severity") in ("CRITICAL", "HIGH") for s in cert_scenarios):
            return True

        # Condition 5: Multi-Stage Tactical Kill-Chain Progression across rolling window
        if kill_chain and kill_chain.get("kill_chain_progression_detected"):
            return True

        return False

    @staticmethod
    def _map_tactical_stages(
        detector_results: List[Dict[str, Any]],
        raw_features: Optional[dict] = None,
        heur_result: Optional[dict] = None,
        cert_scenarios: Optional[List[Dict[str, str]]] = None,
    ) -> set[str]:
        stages: set[str] = set()
        raw = raw_features or {}
        cert_ids = {s.get("id") for s in (cert_scenarios or []) if s.get("id")}
        heur_ids = {d.get("scenario_id") for d in (heur_result or {}).get("detections", []) if d.get("scenario_id")}
        all_ids = cert_ids | heur_ids

        # A snapshot is an observation, not a sequence. Map each host-level
        # burst to at most one stage; do not infer credential access from
        # workstation breadth alone.
        if "S1_CRED_DUMP" in all_ids or "HONEYTOKEN" in all_ids:
            stages.add("CREDENTIAL_ACCESS")
        for res in detector_results or []:
            name = str(res.get("detector_name", "")).lower()
            if "auth" in name:
                pat = res.get("burst_type") or res.get("attack_pattern")
                cat = res.get("tactical_category")
                if pat in ("HIGH_FAILURE_BURST", "VELOCITY_BURST"):
                    stages.add("CREDENTIAL_ACCESS")
                elif cat == "LATERAL_MOVEMENT" or pat in ("LATERAL_MOVEMENT", "MULTI_WORKSTATION_BURST"):
                    stages.add("LATERAL_MOVEMENT")
            elif "z_score" in name or "zscore" in name:
                domain_z = res.get("domain_z_scores", {})
                if isinstance(domain_z, dict) and domain_z.get("logon", 0.0) >= 3.0:
                    stages.add("CREDENTIAL_ACCESS")

        # 2. LATERAL_MOVEMENT
        # Aggregation Inference: detect_auth_burst labels multi-endpoint activity as
        # MULTI_WORKSTATION_BURST under AUTHENTICATION_ACTIVITY. Mapping this activity
        # (or raw unique_workstations_300s >= 3.0) to LATERAL_MOVEMENT is an aggregation inference,
        # treating rapid cross-workstation auth as indicative of lateral progression.
        try:
            ws_count = float(raw.get("unique_workstations_300s") or 0.0)
            if ws_count >= 3.0:
                stages.add("LATERAL_MOVEMENT")
        except (TypeError, ValueError):
            pass

        # 3. EXECUTION_PERSISTENCE
        if "S1_INJECTION" in all_ids:
            stages.add("EXECUTION_PERSISTENCE")
        for k in ("modifications_detected", "threats_detected"):
            val = raw.get(k)
            if val is True or str(val or "").strip().lower() in ("1", "true", "yes"):
                stages.add("EXECUTION_PERSISTENCE")
        for k in ("service_modification_count", "privilege_change_count", "persistence_modification_count", "driver_modification_count", "unbacked_executable_regions"):
            try:
                if float(raw.get(k) or 0.0) > 0.0:
                    stages.add("EXECUTION_PERSISTENCE")
            except (TypeError, ValueError):
                pass

        # 4. COLLECTION_STAGING
        if "S2" in all_ids or "S1_PRECURSOR" in all_ids:
            stages.add("COLLECTION_STAGING")
        for k in ("sensitive_file_access", "file_sharing_site_visits"):
            try:
                if float(raw.get(k) or 0.0) > 0.0:
                    stages.add("COLLECTION_STAGING")
            except (TypeError, ValueError):
                pass
        for res in detector_results or []:
            name = str(res.get("detector_name", "")).lower()
            if "z_score" in name or "zscore" in name:
                domain_z = res.get("domain_z_scores", {})
                if isinstance(domain_z, dict) and domain_z.get("file", 0.0) >= 3.0:
                    stages.add("COLLECTION_STAGING")

        # 5. EXFILTRATION_SABOTAGE
        if any(sid in all_ids for sid in ("S1", "S3", "S4", "NETWORK_TUNNELING")):
            stages.add("EXFILTRATION_SABOTAGE")
        for k in ("tunneling_detected",):
            val = raw.get(k)
            if val is True or str(val or "").strip().lower() in ("1", "true", "yes"):
                stages.add("EXFILTRATION_SABOTAGE")
        for k in ("tunneling_process_count", "daily_files_to_removable_count", "usb_file_transfer_count", "cloud_upload_bytes", "large_usb_transfer"):
            try:
                if float(raw.get(k) or 0.0) > 0.0:
                    stages.add("EXFILTRATION_SABOTAGE")
            except (TypeError, ValueError):
                pass
        for res in detector_results or []:
            name = str(res.get("detector_name", "")).lower()
            if "z_score" in name or "zscore" in name:
                domain_z = res.get("domain_z_scores", {})
                if isinstance(domain_z, dict) and (domain_z.get("network", 0.0) >= 3.5 or domain_z.get("device", 0.0) >= 3.5):
                    stages.add("EXFILTRATION_SABOTAGE")

        return stages

    def _evaluate_kill_chain(
        self,
        current_stages: set[str],
        past_events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Correlates tactical kill-chain progression across a 4-hour temporal rolling window.
        """
        historical_stages: set[str] = set()
        for ev in past_events:
            signals = ev.get("correlated_signals_json")
            if isinstance(signals, str):
                try:
                    import json
                    signals = json.loads(signals)
                except Exception:
                    signals = {}
            if not isinstance(signals, dict):
                continue

            # Recompute old stages with the current one-event/one-stage rules.
            # This also prevents kill_chain.stages_present written by an older
            # version from carrying forward inflated single-snapshot stages.
            saved_auth = signals.get("auth_burst", {})
            history_raw: dict[str, Any] = {}
            history_evidence = saved_auth.get("evidence", {}) if isinstance(saved_auth, dict) else {}
            if isinstance(history_evidence, dict) and history_evidence.get("unique_workstations_5m") is not None:
                history_raw["unique_workstations_300s"] = history_evidence["unique_workstations_5m"]

            history_detectors = [
                detector for key in ("auth_burst", "z_score", "zscore")
                if isinstance((detector := signals.get(key)), dict)
            ]
            historical_stages.update(self._map_tactical_stages(
                history_detectors,
                raw_features=history_raw,
                heur_result=signals.get("heuristics") if isinstance(signals.get("heuristics"), dict) else {},
                cert_scenarios=signals.get("cert_scenarios") if isinstance(signals.get("cert_scenarios"), list) else [],
            ))

        all_stages = current_stages | historical_stages
        k_count = len(all_stages)
        # Require a stage in an earlier event and a different stage appearing
        # now. Stages co-reported in one snapshot cannot establish sequence.
        newly_observed_stages = current_stages - historical_stages
        is_progression = bool(historical_stages and newly_observed_stages and k_count >= 2)

        progression_severity = "NONE"
        stage_floor = 0.0
        reason_text = ""
        if is_progression:
            if k_count >= 3:
                progression_severity = "CRITICAL"
                stage_floor = 95.0
                reason_text = f"Confirmed multi-stage kill chain across 4h window: {' -> '.join(sorted(all_stages))}"
            else:
                progression_severity = "HIGH"
                stage_floor = 85.0
                reason_text = f"Tactical kill chain progression across 4h window: {' -> '.join(sorted(all_stages))}"

        return {
            "stages_present": sorted(list(current_stages)),
            "stages_in_window": sorted(list(all_stages)),
            "stage_count": k_count,
            "kill_chain_progression_detected": is_progression,
            "progression_severity": progression_severity,
            "floor_score": stage_floor,
            "reason": reason_text,
        }

    def _map_cert_scenarios(
        self, 
        detector_results: List[Dict[str, Any]], 
        raw_features: Optional[dict] = None,
        heur_result: Optional[dict] = None
    ) -> List[Dict[str, str]]:
        scenarios = []
        # Canonical IDs and meanings: S1 sabotage, S2 hoarding, S3 removable
        # media exfiltration, S4 cloud exfiltration. Require behavior evidence;
        # browsing a site or inserting a USB alone is only a precursor.
        raw = raw_features or {}
        heur_detections = (heur_result or {}).get("detections", [])
        ids = {d.get("scenario_id") for d in heur_detections if d.get("scenario_id")}
        detector_names = {str(r.get("detector_name", "")).lower() for r in detector_results or []}
        auth_burst = "auth_burst" in detector_names and any(r.get("score", 0) >= 60 for r in detector_results or [] if str(r.get("detector_name", "")).lower() == "auth_burst")
        z_result = next((r for r in detector_results or [] if str(r.get("detector_name", "")).lower() in {"z_score", "zscore"}), {})
        deviations = z_result.get("feature_deviations", {}) if isinstance(z_result.get("feature_deviations", {}), dict) else {}
        auth_deviation = float(z_result.get("score", 0) or 0) >= 60 and any("auth" in name for name in deviations)
        file_baseline_anomaly = float(z_result.get("score", 0) or 0) >= 35 and any(
            any(token in name for token in ("file", "filename", "sensitive")) for name in deviations
        )
        auth_burst = auth_burst or auth_deviation

        def add_scenario(scenario_id: str, severity: str, description: str) -> None:
            scenarios.append({"id": scenario_id, "severity": severity, "description": description})

        if raw.get("threat_triggered") is True or str(raw.get("threat_triggered", "")).strip().lower() in {"1", "true", "yes"}:
            add_scenario("HONEYTOKEN", "CRITICAL", "Honeytoken interaction reported by the decoy monitor")

        def truthy(name: str) -> bool:
            value = raw.get(name)
            return value is True or str(value or "").strip().lower() in {"1", "true", "yes"}

        def number(name: str) -> float:
            try:
                value = float(raw.get(name) or 0)
                return value if value == value else 0.0
            except (TypeError, ValueError):
                return 0.0

        if truthy("credential_dumping_suspected"):
            add_scenario("S1_CRED_DUMP", "CRITICAL", "LSASS monitor reported suspected credential dumping")
        if number("unbacked_executable_regions") > 0 or truthy("threats_detected"):
            add_scenario("S1_INJECTION", "HIGH", "Memory scanner reported unbacked executable memory or a threat")
        if number("tunneling_process_count") > 0 or truthy("tunneling_detected"):
            # This network indicator does not mean CERT S4 cloud upload.
            add_scenario("NETWORK_TUNNELING", "HIGH", "Process or DNS monitor reported network tunneling activity")

        delete_count = max(number("daily_file_delete_count"), number("file_delete_count"))
        sabotage_action = any(number(name) > 0 for name in ("service_modification_count", "privilege_change_count", "persistence_modification_count", "driver_modification_count"))
        after_hours_access = number("after_hours_logon") >= 2 or "S1_PRECURSOR" in ids
        # A batch of confirmed sampled deletions plus a system/persistence change
        # is sufficient sabotage evidence, even during daytime and without an
        # accompanying authentication anomaly.
        corroborated_delete_sabotage = delete_count >= 10 and sabotage_action
        if "S1" in ids or corroborated_delete_sabotage or (sabotage_action and (after_hours_access or auth_burst)):
            add_scenario("S1", "HIGH", "IT sabotage indicators: destructive file activity with authentication or system-change evidence")
        elif delete_count >= 20:
            add_scenario("S1_PRECURSOR", "LOW", "Mass file deletion observed without supporting sabotage evidence")

        file_burst = "S2" in ids or file_baseline_anomaly or any(number(name) >= 100 for name in ("daily_unique_filename_count", "sensitive_file_access", "daily_new_filename_count"))
        if file_burst:
            add_scenario("S2", "MEDIUM", "Unusual broad file collection; confirm sensitivity and user baseline deviation")

        usb_transfer = any(number(name) > 0 for name in ("daily_files_to_removable_count", "external_drive_file_copy", "large_usb_transfer", "usb_file_transfer_count"))
        if usb_transfer:
            add_scenario("S3", "HIGH", "File transfer to removable media detected")
        elif number("usb_connect_count") or number("daily_device_connect_count"):
            add_scenario("S3_PRECURSOR", "LOW", "Removable media activity observed; transfer evidence is unavailable")

        upload_evidence = max(number("cloud_upload_bytes"), number("upload_bytes"), number("large_upload_bytes"), number("cloud_storage_uploads"), number("large_uploads"))
        if upload_evidence > 0 and (number("sensitive_file_access") > 0 or file_burst):
            add_scenario("S4", "HIGH", "Outbound cloud upload correlated with sensitive or unusual file access")
        elif number("file_sharing_site_visits") > 0:
            add_scenario("S4_PRECURSOR", "LOW", "File-sharing site visit observed; upload evidence is unavailable")

        return scenarios

