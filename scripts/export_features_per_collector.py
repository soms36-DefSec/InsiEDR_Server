"""
InsiEDR Exporter: Scenario-based Collector Feature CSVs (Live Sensed Telemetry)
------------------------------------------------------------------------------
Exports live natively sensed telemetry into scenario directories:
  exports/<scenario_name>/<collector_name>.csv
Columns:
  username, <collector_feature_1>, <collector_feature_2>, ..., collected_at
"""
from __future__ import annotations

import csv
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("CollectorFeatureExporter")

EXPORTS_ROOT = Path(r"d:\Projects\AISH\InsiEDR_Server\exports")
SSH_HOST = "172.16.22.198"
SSH_USER = "sastra"
SSH_PW = "sastra123"

# Mapping each scenario to the collectors relevant to that attack
SCENARIO_COLLECTORS = {
    "SIM_HONEYTOKEN_TRIP": ["decoy-monitor", "file-feature"],
    "SIM_DATA_HOARDING": ["clipboard-monitor", "file-feature"],
    "SIM_USB_PRECURSOR": ["devices-feature", "file-feature"],
    "SIM_IT_SABOTAGE": ["file-feature", "persistence-monitor"],
    "SIM_CLOUD_PRECURSOR": ["http-feature"],
    "SIM_CREDENTIAL_DUMP": ["lsass-monitor"],
    "SIM_KILL_CHAIN": [
        "decoy-monitor",
        "clipboard-monitor",
        "devices-feature",
        "file-feature",
        "http-feature",
        "lsass-monitor",
        "persistence-monitor",
    ],
}

# Preferred feature column order per collector
COLLECTOR_FEATURE_ORDER = {
    "decoy-monitor": [
        "threat_triggered",
        "events_recorded",
        "events",
        "monitored_decoys",
    ],
    "clipboard-monitor": [
        "clipboard_copy_count",
        "formats_involved",
        "monitor_active",
    ],
    "file-feature": [
        "file_delete_count",
        "sensitive_file_access",
        "file_copy_count",
        "file_write_count",
        "file_access_count",
        "staging_archive_count",
        "total_staged_bytes",
        "daily_file_delete_count",
        "daily_file_write_count",
        "daily_unique_filename_count",
        "daily_new_filename_count",
        "daily_file_open_count",
        "file_open_count",
        "weekend_file_access",
        "daily_file_access_entropy",
        "unusual_file_access_ratio",
    ],
    "persistence-monitor": [
        "modifications_detected",
        "added_keys",
        "entry_count",
        "deleted_keys",
        "modified_keys",
        "total_monitored_keys",
    ],
    "http-feature": [
        "http_count",
        "visited_domains",
        "watchlisted_url_count",
        "file_sharing_site_visits",
        "upload_count",
        "download_count",
        "http_after_hours",
        "unique_url_count",
        "daily_http_request_count",
        "daily_unique_domain_count",
    ],
    "devices-feature": [
        "usb_connect_count",
        "large_usb_transfer",
        "unique_usb_devices",
        "usb_file_transfer_count",
        "daily_device_connect_count",
        "usb_disconnect_count",
        "usb_usage_duration",
        "after_hours_usb_usage",
        "daily_device_usage_flag",
        "daily_removable_bytes_written",
    ],
    "lsass-monitor": [
        "status",
        "event_count",
        "target_process",
        "quality",
        "lsass_access_events",
        "error",
    ],
}


def user_sort_key(username: str) -> int:
    """Sort SOC_user1, SOC_user2, ..., SOC_user32 numerically."""
    match = re.search(r"\d+", username)
    return int(match.group()) if match else 999


def fetch_database_records() -> list[dict]:
    """Retrieve all collector telemetry for the live run across SOC users."""
    psql_query = (
        "SELECT json_build_object("
        "'id', id, "
        "'agent_id', agent_id, "
        "'username', split_part(agent_id, 'SASTRA-', 2), "
        "'hostname', hostname, "
        "'collector', collector, "
        "'collected_at', collector_collected_at, "
        "'status', status, "
        "'payload', payload_json, "
        "'error_type', error_type, "
        "'error_message', error_message"
        ") "
        "FROM collector_results "
        "WHERE collector_collected_at >= '2026-11-01 14:00:00+00' "
        "AND agent_id LIKE 'SASTRA-SOC_user%' "
        "ORDER BY split_part(agent_id, 'SASTRA-SOC_user', 2)::int ASC, collector_collected_at ASC;"
    )

    plink_cmd = [
        "plink.exe",
        "-batch",
        "-ssh",
        "-l",
        SSH_USER,
        "-pw",
        SSH_PW,
        SSH_HOST,
        "docker exec -i insiedr_server-db-1 psql -U insiedr -d insiedr_db -t -A",
    ]

    logger.info("Executing database query on remote server...")
    proc = subprocess.run(
        plink_cmd,
        input=psql_query,
        text=True,
        capture_output=True,
        timeout=60,
    )

    if proc.returncode != 0:
        logger.error(f"Database query failed: {proc.stderr}")
        raise RuntimeError(f"Database query failed: {proc.stderr}")

    records = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            pass

    logger.info(f"Retrieved {len(records)} total live records from database.")
    return records


def build_collector_rows(collector: str, records: list[dict]) -> tuple[list[str], list[dict]]:
    """
    Extract and flatten collector features for all users into a clean tabular structure.
    Returns (columns, list_of_row_dicts).
    """
    col_records = [r for r in records if r.get("collector") == collector]

    rows = []
    for r in col_records:
        username = r.get("username", "")
        collected_at = r.get("collected_at", "")
        payload = r.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        # Convert complex objects (dicts, lists) into clean JSON strings for CSV cells
        clean_payload = {}
        for k, v in payload.items():
            if isinstance(v, (dict, list)):
                clean_payload[k] = json.dumps(v, ensure_ascii=False)
            else:
                clean_payload[k] = v

        # If error was stored on the record level
        if r.get("status") != "success" and "status" not in clean_payload:
            clean_payload["status"] = r.get("status")
        if r.get("error_message") and "error" not in clean_payload:
            clean_payload["error"] = r.get("error_message")

        # Remove payload-level username/collected_at so they do not override the agent's true identity
        clean_payload.pop("username", None)
        clean_payload.pop("collected_at", None)

        row_dict = {
            "username": username,
            **clean_payload,
            "collected_at": collected_at,
        }
        rows.append(row_dict)

    # Sort rows by user number and then collection time
    rows.sort(key=lambda x: (user_sort_key(x["username"]), str(x.get("collected_at", ""))))

    # Determine columns: username FIRST, then ordered features, then collected_at
    all_keys = set()
    for row in rows:
        all_keys.update(row.keys())

    all_keys.discard("username")
    all_keys.discard("collected_at")
    all_keys.discard("host")
    all_keys.discard("hostname")

    preferred_order = COLLECTOR_FEATURE_ORDER.get(collector, [])
    ordered_features = [f for f in preferred_order if f in all_keys]
    remaining_features = sorted(list(all_keys - set(ordered_features)))
    final_features = ordered_features + remaining_features

    fieldnames = ["username"] + final_features + ["collected_at"]
    return fieldnames, rows


def main():
    # 1. Clear out exports directory completely
    if EXPORTS_ROOT.exists():
        shutil.rmtree(EXPORTS_ROOT, ignore_errors=True)
    EXPORTS_ROOT.mkdir(parents=True, exist_ok=True)

    records = fetch_database_records()
    total_files_written = 0

    for scenario_name, collectors in SCENARIO_COLLECTORS.items():
        scenario_dir = EXPORTS_ROOT / scenario_name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Processing Scenario: {scenario_name}")

        for col in collectors:
            fieldnames, rows = build_collector_rows(col, records)
            if not rows:
                logger.warning(f"  No records found for collector '{col}' in scenario '{scenario_name}'")
                continue

            csv_path = scenario_dir / f"{col}.csv"
            with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for r in rows:
                    writer.writerow(r)

            logger.info(f"  -> Wrote {csv_path.name} ({len(rows)} rows, {len(fieldnames)} columns)")
            total_files_written += 1

    print("\n" + "=" * 60)
    print(f"SUCCESS: Exported {total_files_written} live collector CSV files across 7 scenarios.")
    print(f"Directory: {EXPORTS_ROOT}")
    print("=" * 60)


if __name__ == "__main__":
    main()
