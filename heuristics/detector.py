from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from heuristics.logon_rules import detect_logon_scenarios
from heuristics.file_rules import detect_file_scenarios
from heuristics.http_rules import detect_http_scenarios
from heuristics.device_rules import detect_device_scenarios

# ==============================================================================
# Correlation Groups: Clusters related rules to prevent linear score stacking
# ==============================================================================
CORRELATION_GROUPS = {
    # File Exfiltration & Access
    "Bulk File Collection": "FILE_EXFIL_GROUP",
    "Anomalous File Access": "FILE_EXFIL_GROUP",
    "Credential File Hunting": "FILE_EXFIL_GROUP",
    "After-Hours File Activity": "FILE_EXFIL_GROUP",
    "Weekend File Collection": "FILE_EXFIL_GROUP",
    "Rapid File Modification": "FILE_RANSOM_GROUP",
    
    # Network / HTTP
    "Cloud Storage Upload": "HTTP_EXFIL_GROUP",
    "Restricted Domain Access": "SUSPICIOUS_HTTP_GROUP",
    "High Network Traffic": "HTTP_EXFIL_GROUP",
    "After-Hours Browsing": "SUSPICIOUS_HTTP_GROUP",
    
    # Logon & Authentication
    "After-Hours Midnight Access": "LOGON_TIME_GROUP",
    "Multi-PC Lateral Movement": "LOGON_ASSET_GROUP",
    "Short Repeated Sessions": "LOGON_SESSION_GROUP",
    "Possible Account Sharing": "LOGON_ASSET_GROUP",
    "Weekend Logon Activity": "LOGON_TIME_GROUP",
    "Failed Authentication Burst": "LOGON_AUTH_GROUP",
    
    # Removable Media / USB
    "USB Storage Device Inserted": "DEVICE_USB_GROUP",
    "Unapproved USB Device": "DEVICE_USB_GROUP",
    "Bulk USB File Transfer": "DEVICE_USB_GROUP",
}

# Domain Priority Weights
DOMAIN_BASE_WEIGHTS = {
    "FILE": 0.35,
    "DEVICE": 0.30,
    "LOGON": 0.20,
    "HTTP": 0.15
}

# Rule Confidence Value Mappings
CONFIDENCE_MAP = {
    "VERY_HIGH": 0.95,
    "HIGH": 0.90,
    "MEDIUM": 0.70,
    "LOW": 0.40
}

# Workload Sensitivity Multipliers by Endpoint Profile
PROFILE_SENSITIVITY = {
    "OFFICE_WORKER": {"FILE": 1.00, "HTTP": 1.00, "LOGON": 1.00, "DEVICE": 1.00},
    "DEVELOPER":     {"FILE": 0.35, "HTTP": 0.60, "LOGON": 0.70, "DEVICE": 0.80},
    "SYSADMIN":      {"FILE": 0.60, "HTTP": 0.70, "LOGON": 0.30, "DEVICE": 0.70},
    "DATA_ENGINEER": {"FILE": 0.40, "HTTP": 0.30, "LOGON": 0.60, "DEVICE": 0.70},
    "MEDIA_CREATOR": {"FILE": 0.40, "HTTP": 0.50, "LOGON": 0.80, "DEVICE": 0.30},
    "DEFAULT":       {"FILE": 0.80, "HTTP": 0.80, "LOGON": 0.80, "DEVICE": 0.80}
}

# Known Trusted Developer & Build Toolchains
TRUSTED_BUILD_PROCESSES = {
    "git.exe", "cargo.exe", "rustc.exe", "msbuild.exe", "cl.exe", "javac.exe",
    "npm.cmd", "node.exe", "yarn.cmd", "pnpm.cmd", "docker.exe", "dockerd.exe",
    "mvn.cmd", "gradlew.bat", "python.exe", "pytest.exe", "go.exe", "code.exe"
}

# Benign High-I/O Path Regex Patterns
BENIGN_PATH_PATTERNS = [
    r"[\\/]node_modules[\\/]",
    r"[\\/]\.git[\\/]",
    r"[\\/]target[\\/]",
    r"[\\/]build[\\/]",
    r"[\\/]dist[\\/]",
    r"[\\/]\.m2[\\/]",
    r"[\\/]\.cargo[\\/]",
    r"[\\/]\.cache[\\/]",
    r"[\\/]AppData[\\/]Local[\\/]Temp[\\/]"
]

_COMPILED_PATH_REGEXES = [re.compile(p, re.IGNORECASE) for p in BENIGN_PATH_PATTERNS]


def calculate_overall_severity(score: float) -> str:
    """Calculates unified heuristic severity based on normalized 0-100 score."""
    if score >= 85.0:
        return "CRITICAL"
    if score >= 60.0:
        return "HIGH"
    if score >= 35.0:
        return "MEDIUM"
    return "LOW"


def _infer_domain(scenario_name: str) -> str:
    """Infers the domain (LOGON, FILE, HTTP, DEVICE) from scenario name."""
    s = scenario_name.lower()
    if "file" in s or "credential" in s:
        return "FILE"
    if "usb" in s or "device" in s:
        return "DEVICE"
    if "logon" in s or "session" in s or "pc" in s or "account" in s or "auth" in s:
        return "LOGON"
    if "http" in s or "cloud" in s or "domain" in s or "network" in s or "browsing" in s:
        return "HTTP"
    return "FILE"


def detect_insider_threat(features: Dict[str, Any], system_profile: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates heuristic detections using non-linear correlation grouping,
    workload context sensitivity, and cross-domain superposition.
    """
    if not features:
        return {
            "overall_score": 0.0,
            "short_term_risk": 0.0,
            "overall_severity": "LOW",
            "scenario_count": 0,
            "detections": [],
            "evidence_summary": [],
            "active_domains": [],
            "active_groups": []
        }

    # Resolve system profile
    profile = (system_profile or features.get("system_profile") or features.get("user_role") or "DEFAULT").upper()
    sensitivity = PROFILE_SENSITIVITY.get(profile, PROFILE_SENSITIVITY["DEFAULT"])

    # 1. Run all rule modules
    logon_results = detect_logon_scenarios(features)
    file_results = detect_file_scenarios(features)
    http_results = detect_http_scenarios(features)
    device_results = detect_device_scenarios(features)

    raw_detections: List[Dict[str, Any]] = []
    raw_detections.extend(logon_results)
    raw_detections.extend(file_results)
    raw_detections.extend(http_results)
    raw_detections.extend(device_results)

    if not raw_detections:
        return {
            "overall_score": 0.0,
            "short_term_risk": 0.0,
            "overall_severity": "LOW",
            "scenario_count": 0,
            "detections": [],
            "evidence_summary": [],
            "active_domains": [],
            "active_groups": []
        }

    # Extract process & path context if available
    proc = str(features.get("process_name") or features.get("active_process") or "").lower()
    path = str(features.get("target_path") or features.get("file_path") or "")

    # 2. Contextual Discounting & Domain Sensitivity Scaling
    processed_detections: List[Dict[str, Any]] = []
    for d in raw_detections:
        scenario = d.get("scenario", "")
        domain = _infer_domain(scenario)
        raw_score = float(d.get("score", 0.0))
        conf_str = d.get("confidence", "MEDIUM")

        discount_factor = 1.0
        if proc in TRUSTED_BUILD_PROCESSES:
            if domain == "FILE":
                discount_factor *= 0.20
            elif domain == "HTTP" and "HTTP_EXFIL" in CORRELATION_GROUPS.get(scenario, ""):
                discount_factor *= 0.50

        if path and any(rgx.search(path) for rgx in _COMPILED_PATH_REGEXES):
            discount_factor *= 0.25

        dom_sens = sensitivity.get(domain, 0.8)
        effective_score = raw_score * discount_factor * dom_sens

        d_copy = dict(d)
        d_copy["domain"] = domain
        d_copy["effective_score"] = effective_score
        d_copy["confidence_weight"] = CONFIDENCE_MAP.get(conf_str, 0.70)
        d_copy["group_id"] = CORRELATION_GROUPS.get(scenario, f"GROUP_{scenario}")
        processed_detections.append(d_copy)

    # 3. Group by Correlation Clusters & Apply Sub-linear Decay
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for d in processed_detections:
        grouped.setdefault(d["group_id"], []).append(d)

    group_scores: Dict[str, float] = {}
    group_domains: Dict[str, str] = {}
    evidence_summary = []

    for group_id, items in grouped.items():
        sorted_items = sorted(
            items,
            key=lambda x: (x["effective_score"] * x["confidence_weight"]),
            reverse=True
        )
        primary = sorted_items[0]
        primary_score = primary["effective_score"] * primary["confidence_weight"]

        # Sublinear decay on secondary rules within same correlation cluster
        supporting_sum = sum(
            (item["effective_score"] * item["confidence_weight"]) * (0.20 ** (idx + 1))
            for idx, item in enumerate(sorted_items[1:])
        )

        g_score = min(100.0, primary_score + supporting_sum)
        group_scores[group_id] = g_score
        group_domains[group_id] = primary["domain"]

        evidence_summary.append({
            "group_id": group_id,
            "primary_scenario": primary.get("scenario"),
            "domain": primary["domain"],
            "group_score": round(g_score, 2),
            "rule_count": len(items)
        })

    # 4. Cross-Domain Superposition
    domain_peaks: Dict[str, float] = {}
    for group_id, g_score in group_scores.items():
        dom = group_domains[group_id]
        domain_peaks[dom] = max(domain_peaks.get(dom, 0.0), g_score)

    active_domains = list(domain_peaks.keys())

    if not active_domains:
        final_risk = 0.0
    elif len(active_domains) == 1:
        # Single isolated domain activity is scaled down to prevent false positive spikes
        final_risk = domain_peaks[active_domains[0]] * 0.40
    else:
        total_w = sum(DOMAIN_BASE_WEIGHTS.get(d, 0.25) for d in active_domains)
        weighted_val = sum(domain_peaks[d] * DOMAIN_BASE_WEIGHTS.get(d, 0.25) for d in active_domains)
        base_risk = weighted_val / max(0.01, total_w)
        
        # Diversity Bonus: Only applied if 3+ distinct domains have genuine malicious activity
        diversity_bonus = 0.0
        if len(active_domains) >= 3 and base_risk >= 35.0:
            diversity_bonus = min(10.0, (len(active_domains) - 2) * 5.0)
            
        final_risk = min(100.0, base_risk + diversity_bonus)

    bounded_risk = max(0.0, min(100.0, final_risk))
    severity = calculate_overall_severity(bounded_risk)

    # Sort detections highest severity/score first
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    processed_detections.sort(
        key=lambda x: (
            severity_order.get(x.get("severity", "LOW"), 0),
            x.get("effective_score", 0.0)
        ),
        reverse=True
    )

    return {
        "overall_score": round(bounded_risk, 2),
        "short_term_risk": round(bounded_risk, 2),
        "overall_severity": severity,
        "scenario_count": len(processed_detections),
        "detections": processed_detections,
        "evidence_summary": evidence_summary,
        "active_domains": active_domains,
        "active_groups": list(grouped.keys()),
        "system_profile": profile
    }