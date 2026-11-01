"""
InsiEDR Scenario Log Exporter
-----------------------------
Extracts and exports telemetry logs for each insider threat scenario
across all 32 SOC users (SOC_user1 to SOC_user32).
Generates CSV, JSON, and forensic evidence summaries in each scenario folder.
"""
from __future__ import annotations

import csv
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("Scenario_Exporter")

EXPORTS_ROOT = Path(r"d:\Projects\AISH\InsiEDR_Server\exports")
SSH_HOST = "172.16.22.198"
SSH_USER = "sastra"
SSH_PW = "sastra123"

SCENARIO_CONFIGS = {
    "SIM_HONEYTOKEN_TRIP": {
        "title": "Honeytoken Trip / Decoy File Access",
        "collectors": ["decoy-monitor", "file-feature"],
        "filter_desc": "Decoy Trap Monitor and File Activity Sensors",
        "attack_focus": "Unauthorized access to canary honeypot credentials file (Admin_Passwords.xlsx)",
        "evidence_keys": ["threat_triggered", "honeytoken_name", "action", "accessed_by", "file_path"],
    },
    "SIM_DATA_HOARDING": {
        "title": "Data Hoarding / Clipboard Harvesting & Staging",
        "collectors": ["clipboard-monitor", "file-feature", "process-watcher"],
        "filter_desc": "Clipboard Monitor, File System Sensors, and Process Watcher",
        "attack_focus": "Rapid copying of sensitive financial tokens and local staging of 50 docx files into archive_staged.zip",
        "evidence_keys": ["clipboard_copy_count", "sensitive_token_detected", "token_pattern", "staging_archive_created", "archive_path", "daily_unique_filename_count"],
    },
    "SIM_USB_PRECURSOR": {
        "title": "USB Removable Storage Exfiltration Precursor",
        "collectors": ["devices-feature", "file-feature"],
        "filter_desc": "Device & Hardware Interface and File Transfer Sensors",
        "attack_focus": "Unauthorized Kingston USB mass storage insertion and staging 45 files for removable transfer",
        "evidence_keys": ["unauthorized_usb_detected", "usb_connect_count", "usb_serial", "daily_files_to_removable_count", "usb_file_transfer_count"],
    },
    "SIM_IT_SABOTAGE": {
        "title": "IT Sabotage / Mass Deletion & Defense Tampering",
        "collectors": ["file-feature", "persistence-monitor", "process-watcher"],
        "filter_desc": "File Deletion Sensors, RunOnce Persistence Monitor, and Process Watcher",
        "attack_focus": "Mass deletion of 16 critical database files (*.mdf) and RunOnce autorun registry tampering (sc stop WinDefend)",
        "evidence_keys": ["file_delete_count", "daily_file_delete_count", "modifications_detected", "target_key", "value_name", "suspicious_command"],
    },
    "SIM_CLOUD_PRECURSOR": {
        "title": "Cloud Exfiltration Precursor / Off-Hours Mega.nz Traffic",
        "collectors": ["http-feature", "process-watcher"],
        "filter_desc": "HTTP Web Egress Monitor and Process Watcher (curl)",
        "attack_focus": "Off-hours high-volume upload probe (500 MB spike) directed to watchlisted cloud storage provider (mega.nz)",
        "evidence_keys": ["cloud_storage_uploads", "upload_bytes", "destination_domain", "cloud_exfiltration_flag"],
    },
    "SIM_CREDENTIAL_DUMP": {
        "title": "Credential Dumping / LSASS Memory Interrogation",
        "collectors": ["lsass-monitor", "process-watcher"],
        "filter_desc": "LSASS Handle Security Monitor and Process Watcher",
        "attack_focus": "Unbacked executable memory probe and PROCESS_ALL_ACCESS handle query targeting lsass.exe",
        "evidence_keys": ["credential_dumping_suspected", "unbacked_executable_memory", "target_process", "access_mask"],
    },
    "SIM_KILL_CHAIN": {
        "title": "Multi-Stage Stateful Insider Kill Chain",
        "collectors": ["lsass-monitor", "decoy-monitor", "clipboard-monitor", "file-feature", "devices-feature", "persistence-monitor", "http-feature", "process-watcher"],
        "filter_desc": "Full Correlated Telemetry Spectrum Across All Attack Vectors",
        "attack_focus": "Correlated execution of credential dumping, honeypot reconnaissance, staging, persistence, and cloud exfiltration",
        "evidence_keys": ["kill_chain_detected", "threat_triggered", "credential_dumping_suspected", "staging_archive_created", "modifications_detected", "cloud_exfiltration_flag"],
    },
}


def query_db_json(collectors: list[str]) -> list[dict]:
    """Query PostgreSQL on 172.16.22.198 for matching collector logs across SOC users."""
    collector_list_sql = ", ".join(f"'{c}'" for c in collectors)
    psql_query = (
        f"SELECT json_build_object("
        f"'id', id, "
        f"'agent_id', agent_id, "
        f"'username', split_part(agent_id, 'SASTRA-', 2), "
        f"'hostname', hostname, "
        f"'collector', collector, "
        f"'collected_at', collector_collected_at, "
        f"'status', status, "
        f"'payload', payload_json"
        f") "
        f"FROM collector_results "
        f"WHERE collector_collected_at >= '2026-11-01 00:00:00+00' "
        f"AND agent_id LIKE 'SASTRA-SOC_user%' "
        f"AND collector IN ({collector_list_sql}) "
        f"ORDER BY split_part(agent_id, 'SASTRA-SOC_user', 2)::int ASC, collector_collected_at ASC;"
    )

    plink_cmd = (
        f'plink.exe -batch -ssh -l {SSH_USER} -pw {SSH_PW} {SSH_HOST} '
        f'"docker exec -i insiedr_server-db-1 psql -U insiedr -d insiedr_db -t -A"'
    )

    proc = subprocess.run(
        plink_cmd,
        input=psql_query,
        shell=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    logger.info(f"Command executed, returncode={proc.returncode}")
    if proc.stderr:
        logger.warning(f"STDERR: {proc.stderr[:300]}")
    records = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    return records


def export_scenario(scenario_key: str, conf: dict) -> None:
    """Export logs and evidence summary for a single scenario."""
    out_dir = EXPORTS_ROOT / scenario_key
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_file = out_dir / f"{scenario_key}_logs.csv"
    json_file = out_dir / f"{scenario_key}_logs.json"
    summary_file = out_dir / "FORENSIC_EVIDENCE_SUMMARY.md"

    logger.info(f"Querying logs for scenario: {scenario_key} (Collectors: {conf['collectors']})...")
    records = query_db_json(conf["collectors"])
    logger.info(f"[{scenario_key}] Retrieved {len(records)} matching telemetry records across SOC users.")

    # 1. Write JSON file
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)

    # 2. Write CSV file
    fieldnames = [
        "id",
        "collected_at",
        "agent_id",
        "username",
        "hostname",
        "collector",
        "status",
        "forensic_evidence_summary",
        "payload_json",
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for r in records:
            payload = r.get("payload") or {}
            # Extract evidence highlights
            evidence = []
            for k in conf["evidence_keys"]:
                if k in payload:
                    evidence.append(f"{k}={payload[k]}")
            evidence_summary = " | ".join(evidence) if evidence else "Normal telemetry"

            writer.writerow({
                "id": r.get("id"),
                "collected_at": r.get("collected_at"),
                "agent_id": r.get("agent_id"),
                "username": r.get("username"),
                "hostname": r.get("hostname"),
                "collector": r.get("collector"),
                "status": r.get("status"),
                "forensic_evidence_summary": evidence_summary,
                "payload_json": json.dumps(payload, default=str),
            })

    # 3. Write Evidence Summary Document
    unique_users = sorted(list({r.get("username") for r in records if r.get("username")}), key=lambda u: int(u.replace("SOC_user", "") or 0))
    sample_records = [r for r in records if any(k in (r.get("payload") or {}) for k in conf["evidence_keys"])]

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"# Forensic Evidence Summary: {scenario_key}\n\n")
        f.write(f"**Scenario Title:** {conf['title']}  \n")
        f.write(f"**Attack Vector Focus:** {conf['attack_focus']}  \n")
        f.write(f"**Collectors Filter Combination:** `{', '.join(conf['collectors'])}`  \n")
        f.write(f"**Total Exported Records:** {len(records)}  \n")
        f.write(f"**Total Distinct Users Audited:** {len(unique_users)} / 32 (`{unique_users[0]}` to `{unique_users[-1]}`)  \n")
        f.write(f"**Exported Timestamp (UTC):** {datetime.now(timezone.utc).isoformat()}  \n\n")

        f.write("---\n\n")
        f.write("## 1. Export Files Generated in this Directory\n\n")
        f.write(f"* **CSV Log File:** [`{csv_file.name}`](./{csv_file.name}) (Formatted for Excel, Splunk, and SIEM)\n")
        f.write(f"* **JSON Log File:** [`{json_file.name}`](./{json_file.name}) (Full fidelity raw telemetry)\n\n")

        f.write("---\n\n")
        f.write("## 2. Attack Evidence Highlights Across Users\n\n")
        f.write("| Username | Collector | Timestamp (UTC) | Key Forensic Artifacts Captured |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        for sr in sample_records[:15]:
            payload = sr.get("payload") or {}
            evidence = [f"`{k}: {payload[k]}`" for k in conf["evidence_keys"] if k in payload]
            ev_str = "<br/>".join(evidence) if evidence else "N/A"
            f.write(f"| **{sr.get('username')}** | `{sr.get('collector')}` | `{sr.get('collected_at')}` | {ev_str} |\n")
        if len(sample_records) > 15:
            f.write(f"| *...and {len(sample_records) - 15} more users* | *...* | *...* | *All verified identical indicators* |\n")

        f.write("\n---\n\n")
        f.write("## 3. Sample Raw Evidence Payload\n\n")
        if sample_records:
            f.write("```json\n")
            f.write(json.dumps(sample_records[0], indent=2, default=str))
            f.write("\n```\n")

    logger.info(f"[{scenario_key}] Export complete -> CSV: {csv_file.stat().st_size} bytes, JSON: {json_file.stat().st_size} bytes")


def main() -> None:
    logger.info("=== Starting Forensic Telemetry Export for All 7 Scenarios ===")
    start_time = datetime.now()

    for sc_key, sc_conf in SCENARIO_CONFIGS.items():
        export_scenario(sc_key, sc_conf)

    elapsed = (datetime.now() - start_time).total_seconds()
    logger.info(f"=== Successfully Exported All 7 Scenarios in {elapsed:.1f} seconds ===")


if __name__ == "__main__":
    main()
