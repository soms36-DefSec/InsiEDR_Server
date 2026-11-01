"""
Build Progressive 7-Day Insider Attack Dataset in exports/
---------------------------------------------------------
Restructures d:\Projects\AISH\InsiEDR_Server\exports to match D:\Projects\AISH\Dataset_RealTime.
Replicates all 32 SOC users (SOC_user1 to SOC_user32, hostname SANDY).
Uses exact dates and times from Dataset_RealTime across the 7 days (2026-10-06 to 2026-10-12).
Applies a progressive threat escalation curve:
  Day 1 (2026-10-06): 0%   (Pure Baseline)
  Day 2 (2026-10-07): 10%  (Initial Recon / Subtle Footprinting)
  Day 3 (2026-10-08): 25%  (Discovery & Staging Setup)
  Day 4 (2026-10-09): 45%  (Privilege Escalation & Handle Probes)
  Day 5 (2026-10-10): 70%  (Active Data Hoarding & Stage Expansion)
  Day 6 (2026-10-11): 85%  (Exfiltration Precursors & Persistence Hook)
  Day 7 (2026-10-12): 100% (Complete Attack Spike across All Scenarios)
"""
from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, date, time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DatasetBuilder")

RT_DIR = Path(r"D:\Projects\AISH\Dataset_RealTime")
EXPORTS_DIR = Path(r"d:\Projects\AISH\InsiEDR_Server\exports")

USERS = [f"SOC_user{i}" for i in range(1, 33)]
HOSTNAME = "SANDY"

DATES = [
    date(2026, 10, 6),   # Day 1 - Baseline
    date(2026, 10, 7),   # Day 2 - Subtle Footprinting
    date(2026, 10, 8),   # Day 3 - Discovery / Staging
    date(2026, 10, 9),   # Day 4 - Privilege Probe
    date(2026, 10, 10),  # Day 5 - Active Data Hoarding
    date(2026, 10, 11),  # Day 6 - Exfil Precursor
    date(2026, 10, 12),  # Day 7 - Peak Attack Spike
]

PROGRESSION_FACTORS = {
    date(2026, 10, 6): 0.00,
    date(2026, 10, 7): 0.10,
    date(2026, 10, 8): 0.25,
    date(2026, 10, 9): 0.45,
    date(2026, 10, 10): 0.70,
    date(2026, 10, 11): 0.85,
    date(2026, 10, 12): 1.00,
}

# Observation sample times for each day during lab hours
DAILY_SAMPLE_TIMES = [
    time(9, 15, 0),
    time(11, 30, 0),
    time(14, 10, 0),
    time(16, 45, 0),
    time(18, 20, 0),
]

SCENARIO_COLLECTOR_MAP = {
    "SIM_HONEYTOKEN_TRIP": ["decoy-monitor", "file-integrity-monitor"],
    "SIM_DATA_HOARDING": ["clipboard-monitor", "file-integrity-monitor", "activity-monitor"],
    "SIM_USB_PRECURSOR": ["devices", "file-integrity-monitor", "usn-monitor"],
    "SIM_IT_SABOTAGE": ["file-integrity-monitor", "persistence-monitor", "process-watcher"],
    "SIM_CLOUD_PRECURSOR": ["http", "network"],
    "SIM_CREDENTIAL_DUMP": ["lsass-monitor", "memory-scanner", "process-watcher"],
    "SIM_KILL_CHAIN": [
        "clipboard-monitor",
        "decoy-monitor",
        "devices",
        "file-integrity-monitor",
        "http",
        "lsass-monitor",
        "memory-scanner",
        "network",
        "persistence-monitor",
        "process-watcher",
        "wmi-activity",
    ],
}


def lerp(a: float, b: float, alpha: float) -> float:
    return a + (b - a) * alpha


def generate_row(collector: str, schema: list[str], dt: datetime, user: str, alpha: float) -> dict[str, object]:
    """Generate a feature dictionary for a given collector, user, and escalation factor."""
    ts_str = dt.isoformat()
    # Initialize all schema fields with empty string
    row = {col: "" for col in schema}
    
    # Common headers
    if "timestamp" in row: row["timestamp"] = ts_str
    if "username" in row: row["username"] = user
    if "hostname" in row: row["hostname"] = HOSTNAME
    if "agent_id" in row: row["agent_id"] = f"SASTRA-{user}"
    if "status" in row: row["status"] = "success"

    # Specific collector generators
    if collector == "activity-monitor":
        if "is_user_active" in row: row["is_user_active"] = True if alpha > 0.4 else False
        if "last_input_tick" in row: row["last_input_tick"] = int(15000000 + alpha * 500000)
        if "user_idle_seconds" in row: row["user_idle_seconds"] = round(max(5.0, lerp(1200.0, 15.0, alpha)), 2)

    elif collector == "clipboard-monitor":
        # Baseline: 0 copies -> Day 7: 35 copies
        copy_count = int(round(lerp(0.0, 35.0, alpha)))
        if "clipboard_copy_count" in row: row["clipboard_copy_count"] = copy_count
        if "clipboard_sequence" in row: row["clipboard_sequence"] = copy_count
        if "monitor_active" in row: row["monitor_active"] = True

    elif collector == "decoy-monitor":
        # Honeytoken: untouched until Day 6 (event recorded) and Day 7 (threat triggered)
        if "monitored_decoys" in row: row["monitored_decoys"] = r"C:\Users\Public\Admin_Passwords.xlsx"
        if "current_size" in row: row["current_size"] = int(lerp(2181, 2239, alpha))
        if "events_recorded" in row: row["events_recorded"] = True if alpha >= 0.85 else False
        if "threat_triggered" in row: row["threat_triggered"] = True if alpha >= 1.0 else False

    elif collector == "devices":
        # Baseline: 0 USB -> Day 7: 2 connects, unauthorized USB, 240MB written
        connects = int(round(lerp(0.0, 3.0, alpha))) if alpha >= 0.25 else 0
        disconnects = connects if alpha < 1.0 else max(0, connects - 1)
        if "usb_connect_count" in row: row["usb_connect_count"] = float(connects)
        if "usb_disconnect_count" in row: row["usb_disconnect_count"] = float(disconnects)
        if "usb_devices_count" in row: row["usb_devices_count"] = 1 if connects > 0 else 0
        if "daily_device_connect_count" in row: row["daily_device_connect_count"] = float(connects)
        if "daily_device_usage_flag" in row: row["daily_device_usage_flag"] = 1.0 if connects > 0 else 0.0
        if "after_hours_usb_usage" in row: row["after_hours_usb_usage"] = 1.0 if alpha >= 0.70 else 0.0
        if "unauthorized_usb_detected" in row: row["unauthorized_usb_detected"] = True if alpha >= 0.85 else False
        if "usb_device_names" in row: row["usb_device_names"] = r"Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00" if connects > 0 else ""
        if "first_usb_usage_time" in row: row["first_usb_usage_time"] = dt.strftime("%H:%M:%S") if connects > 0 else "0.0"

    elif collector == "dns-monitor":
        if "channel" in row: row["channel"] = "Microsoft-Windows-DNS-Client/Operational"
        if "etw_realtime_active" in row: row["etw_realtime_active"] = True
        if "suspicious_queries_count" in row: row["suspicious_queries_count"] = int(round(lerp(0.0, 18.0, alpha)))
        if "total_queries_captured" in row: row["total_queries_captured"] = int(round(lerp(12.0, 85.0, alpha)))
        if "tunneling_detected" in row: row["tunneling_detected"] = True if alpha >= 0.95 else False

    elif collector == "driver-monitor":
        if "driver_count" in row: row["driver_count"] = 142
        if "running_drivers" in row: row["running_drivers"] = 142
        if "drivers_sample" in row: row["drivers_sample"] = "fltmgr.sys,ntfs.sys,ksecdd.sys"

    elif collector == "email-monitor":
        if "monitor_active" in row: row["monitor_active"] = True
        if "email_clients_installed" in row: row["email_clients_installed"] = "outlook.exe"
        if "external_recipient_ratio" in row: row["external_recipient_ratio"] = round(lerp(0.0, 0.92, alpha), 2)
        if "outbound_attachment_count" in row: row["outbound_attachment_count"] = int(round(lerp(0.0, 14.0, alpha)))

    elif collector == "file-integrity-monitor":
        # Baseline: 13 accesses, 0 deletes -> Day 7: 850 accesses, 39 deletes
        access_cnt = int(round(lerp(13.0, 850.0, alpha)))
        unique_cnt = int(round(lerp(13.0, 420.0, alpha)))
        new_cnt = int(round(lerp(0.0, 65.0, alpha)))
        if "file_access_count" in row: row["file_access_count"] = float(access_cnt)
        if "event_count" in row: row["event_count"] = access_cnt
        if "daily_unique_filename_count" in row: row["daily_unique_filename_count"] = float(unique_cnt)
        if "daily_new_filename_count" in row: row["daily_new_filename_count"] = float(new_cnt)
        if "daily_file_access_entropy" in row: row["daily_file_access_entropy"] = round(lerp(0.0, 5.85, alpha), 4)
        if "monitor_active" in row: row["monitor_active"] = True
        if "integrity_events_0_op" in row: row["integrity_events_0_op"] = "WRITE" if alpha >= 0.4 else "AUDIT"
        if "integrity_events_0_path" in row: row["integrity_events_0_path"] = r"C:\Users\SOMS\Documents\ProductionDB\database_1.mdf" if alpha >= 0.7 else r"C:\WINDOWS\System32\drivers\etc\hosts"
        if "integrity_events_0_target_type" in row: row["integrity_events_0_target_type"] = "user_document"
        if "integrity_events_0_sha256" in row: row["integrity_events_0_sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    elif collector == "http":
        # Baseline: 0 watchlisted, 0 file sharing -> Day 7: 14 watchlisted, 119 file sharing
        req_cnt = int(round(lerp(50.0, 1760.0, alpha)))
        watch_cnt = int(round(lerp(0.0, 14.0, alpha)))
        sharing_cnt = int(round(lerp(0.0, 119.0, alpha)))
        uploads = int(round(lerp(0.0, 28.0, alpha))) if alpha >= 0.4 else 0
        if "browser_db_found" in row: row["browser_db_found"] = True
        if "http_count" in row: row["http_count"] = float(req_cnt)
        if "url_access_count" in row: row["url_access_count"] = req_cnt
        if "daily_http_request_count" in row: row["daily_http_request_count"] = float(req_cnt)
        if "unique_url_count" in row: row["unique_url_count"] = float(int(round(req_cnt * 0.75)))
        if "daily_unique_domain_count" in row: row["daily_unique_domain_count"] = float(int(round(lerp(5.0, 48.0, alpha))))
        if "daily_new_domain_count" in row: row["daily_new_domain_count"] = float(int(round(lerp(0.0, 12.0, alpha))))
        if "watchlisted_domain_hits" in row: row["watchlisted_domain_hits"] = watch_cnt
        if "suspicious_url_count" in row: row["suspicious_url_count"] = float(watch_cnt)
        if "file_sharing_site_visits" in row: row["file_sharing_site_visits"] = float(sharing_cnt)
        if "cloud_storage_uploads" in row: row["cloud_storage_uploads"] = uploads
        if "job_search_site_visits" in row: row["job_search_site_visits"] = float(int(round(lerp(0.0, 5.0, alpha))))
        if "http_after_hours" in row: row["http_after_hours"] = float(int(round(lerp(0.0, 18.0, alpha))))
        if "external_url_ratio" in row: row["external_url_ratio"] = round(lerp(0.1, 0.95, alpha), 4)
        if "daily_external_domain_ratio" in row: row["daily_external_domain_ratio"] = round(lerp(0.1, 0.95, alpha), 4)
        if "domain_entropy" in row: row["domain_entropy"] = round(lerp(0.5, 4.2, alpha), 4)
        if "daily_domain_access_entropy" in row: row["daily_domain_access_entropy"] = round(lerp(0.5, 4.2, alpha), 4)

    elif collector == "keystroke-collector":
        if "total_keys_sampled" in row: row["total_keys_sampled"] = int(round(lerp(180.0, 650.0, alpha)))
        if "typing_speed_cpm" in row: row["typing_speed_cpm"] = round(lerp(160.0, 240.0, alpha), 1)
        if "mean_dwell_time_ms" in row: row["mean_dwell_time_ms"] = round(lerp(110.0, 75.0, alpha), 2)
        if "mean_flight_time_ms" in row: row["mean_flight_time_ms"] = round(lerp(330.0, 180.0, alpha), 2)
        if "backspace_ratio" in row: row["backspace_ratio"] = round(lerp(0.15, 0.42, alpha), 3)

    elif collector == "logon":
        if "successful_logons" in row: row["successful_logons"] = int(round(lerp(2.0, 8.0, alpha)))
        if "failed_logons" in row: row["failed_logons"] = int(round(lerp(0.0, 8.0, alpha)))
        if "logon_count" in row: row["logon_count"] = int(round(lerp(2.0, 16.0, alpha)))
        if "concurrent_sessions" in row: row["concurrent_sessions"] = 2 if alpha >= 0.85 else 1
        if "after_hours_logon" in row: row["after_hours_logon"] = 1.0 if alpha >= 0.70 else 0.0
        if "daily_after_hours_logon_ratio" in row: row["daily_after_hours_logon_ratio"] = round(lerp(0.0, 0.65, alpha), 2)
        if "daily_unique_pc_count" in row: row["daily_unique_pc_count"] = 1.0
        if "unique_pc_count" in row: row["unique_pc_count"] = 1
        if "interactive_duration_seconds" in row: row["interactive_duration_seconds"] = int(lerp(28800, 36000, alpha))
        if "session_duration_avg" in row: row["session_duration_avg"] = float(int(lerp(14400, 18000, alpha)))

    elif collector == "lsass-monitor":
        # Baseline: 0 events -> Day 7: 6 events, suspected dumping, 28 handle requests
        handles = int(round(lerp(0.0, 28.0, alpha))) if alpha >= 0.45 else 0
        events = int(round(lerp(0.0, 6.0, alpha))) if alpha >= 0.70 else 0
        if "target_process" in row: row["target_process"] = "lsass.exe"
        if "handle_requests" in row: row["handle_requests"] = float(handles) if handles > 0 else 0.0
        if "event_count" in row: row["event_count"] = events
        if "memory_dump_attempts" in row: row["memory_dump_attempts"] = float(int(round(lerp(0.0, 4.0, alpha)))) if alpha >= 0.85 else 0.0
        if "mimikatz_signatures" in row: row["mimikatz_signatures"] = float(1.0) if alpha >= 1.0 else 0.0
        if "credential_dumping_suspected" in row: row["credential_dumping_suspected"] = True if alpha >= 0.85 else False
        if "suspicious_access_mask" in row: row["suspicious_access_mask"] = "0x1010" if alpha >= 0.85 else ("0x1000" if alpha >= 0.45 else "")

    elif collector == "memory-scanner":
        if "unbacked_executable_regions" in row: row["unbacked_executable_regions"] = int(round(lerp(0.0, 4.0, alpha)))
        if "threats_detected" in row: row["threats_detected"] = 1 if alpha >= 0.85 else 0
        if "reflective_pe_injections" in row: row["reflective_pe_injections"] = 1 if alpha >= 0.85 else 0
        if "target_processes_scanned" in row: row["target_processes_scanned"] = int(round(lerp(40.0, 120.0, alpha)))

    elif collector == "named-pipe-monitor":
        pipes = int(round(lerp(4.0, 22.0, alpha)))
        if "pipe_count" in row: row["pipe_count"] = pipes
        if "named_pipes_sample" in row: row["named_pipes_sample"] = r"\\.\pipe\InsiEDR_IPC,\\.\pipe\lsass_query" if alpha >= 0.7 else r"\\.\pipe\crashpad_pipe"

    elif collector == "network":
        # Baseline: 2.5MB sent -> Day 7: 650MB sent (exfil spike)
        sent = int(round(lerp(2500000.0, 650000000.0, alpha)))
        recv = int(round(lerp(12000000.0, 45000000.0, alpha)))
        conns = int(round(lerp(15.0, 120.0, alpha)))
        remote_ips = int(round(lerp(8.0, 45.0, alpha)))
        if "bytes_sent" in row: row["bytes_sent"] = float(sent)
        if "bytes_received" in row: row["bytes_received"] = float(recv)
        if "active_connections_count" in row: row["active_connections_count"] = conns
        if "connection_count" in row: row["connection_count"] = conns
        if "outbound_connections" in row: row["outbound_connections"] = float(conns)
        if "inbound_connections" in row: row["inbound_connections"] = float(max(1, conns // 4))
        if "unique_remote_ips" in row: row["unique_remote_ips"] = float(remote_ips)
        if "failed_connections" in row: row["failed_connections"] = float(int(round(lerp(0.0, 12.0, alpha))))
        if "high_port_traffic" in row: row["high_port_traffic"] = float(int(round(lerp(2.0, 68.0, alpha))))

    elif collector == "persistence-monitor":
        # RunOnce persistence key installed on Day 6, active on Day 7
        keys = int(865 + round(lerp(0.0, 2.0, alpha)))
        mod_detected = True if alpha >= 0.85 else False
        if "total_monitored_keys" in row: row["total_monitored_keys"] = keys
        if "entry_count" in row: row["entry_count"] = keys
        if "modifications_detected" in row: row["modifications_detected"] = mod_detected
        if "persistence_entries_0_name" in row: row["persistence_entries_0_name"] = f"InsiAudit_{user}" if mod_detected else "ClassicStartMenu"
        if "persistence_entries_0_command" in row: row["persistence_entries_0_command"] = "cmd.exe /c echo InsiEDR_Audit" if mod_detected else r'"C:\Program Files\Classic Shell\ClassicStartMenu.exe" -autorun'
        if "persistence_entries_0_path" in row: row["persistence_entries_0_path"] = r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" if mod_detected else r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

    elif collector == "process-watcher":
        # Baseline: 40 processes -> Day 7: 135 processes, 18 admin, 8 temp folder execs
        procs = int(round(lerp(40.0, 135.0, alpha)))
        admin_procs = int(round(lerp(0.0, 18.0, alpha)))
        temp_exec = int(round(lerp(0.0, 8.0, alpha)))
        if "process_count" in row: row["process_count"] = procs
        if "daily_unique_process_count" in row: row["daily_unique_process_count"] = procs
        if "admin_process_count" in row: row["admin_process_count"] = admin_procs
        if "executables_from_temp_folder" in row: row["executables_from_temp_folder"] = temp_exec
        if "tunneling_process_count" in row: row["tunneling_process_count"] = 1 if alpha >= 0.85 else 0
        if "etw_realtime_active" in row: row["etw_realtime_active"] = True

    elif collector == "short-term_edr_feature":
        if "auth_rate_300s" in row: row["auth_rate_300s"] = round(lerp(0.0, 12.0, alpha), 2)
        if "auth_rate_3600s" in row: row["auth_rate_3600s"] = round(lerp(2.0, 45.0, alpha), 2)
        if "logon_velocity_zscore" in row: row["logon_velocity_zscore"] = round(lerp(-0.5, 4.8, alpha), 2)
        if "off_hours_auth_count" in row: row["off_hours_auth_count"] = int(round(lerp(0.0, 8.0, alpha)))
        if "edr_auth_event_count_window" in row: row["edr_auth_event_count_window"] = int(round(lerp(0.0, 32.0, alpha)))

    elif collector == "usn-monitor":
        # File deletions recorded by USN journal
        deletes = int(round(lerp(0.0, 1200.0, alpha))) if alpha >= 0.70 else 0
        if "usn_records_captured" in row: row["usn_records_captured"] = deletes
        if "note" in row: row["note"] = f"USN journal captured {deletes} records" if deletes > 0 else "Normal baseline volume activity"

    elif collector == "wmi-activity":
        queries = int(round(lerp(0.0, 35.0, alpha)))
        if "channel" in row: row["channel"] = "Microsoft-Windows-WMI-Activity/Operational"
        if "total_queries_captured" in row: row["total_queries_captured"] = queries
        if "lateral_movement_suspected" in row: row["lateral_movement_suspected"] = True if alpha >= 0.85 else False

    # Strictly filter row so only keys present in schema are returned in the exact order
    return {k: row.get(k, "") for k in schema}


def main():
    logger.info("==============================================================")
    logger.info(" INSIEDR RESTRUCTURE EXPORTS AS DATASET_REALTIME (7-DAY SPIKE)")
    logger.info("==============================================================")

    # 1. Load schemas for all 20 collectors from Dataset_RealTime
    schemas = {}
    csv_files = sorted(list(RT_DIR.glob("*_dataset_*.csv")))
    logger.info(f"Discovered {len(csv_files)} source schema files in {RT_DIR}")

    for file_path in csv_files:
        collector = file_path.name.split("_dataset_")[0]
        with file_path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader)
            schemas[file_path.name] = (collector, header)

    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Generate 20 top-level collector dataset files matching Dataset_RealTime
    generated_rows_by_collector = {}
    for filename, (collector, schema) in schemas.items():
        dest_file = EXPORTS_DIR / filename
        logger.info(f"Building top-level dataset: {filename} ({collector})...")

        rows = []
        for day in DATES:
            alpha = PROGRESSION_FACTORS[day]
            for sample_time in DAILY_SAMPLE_TIMES:
                dt = datetime.combine(day, sample_time)
                for user in USERS:
                    row = generate_row(collector, schema, dt, user, alpha)
                    rows.append(row)

        # Write CSV
        with dest_file.open("w", newline="", encoding="utf-8") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=schema)
            writer.writeheader()
            writer.writerows(rows)

        generated_rows_by_collector[collector] = (schema, rows)
        logger.info(f"  [+] Wrote {len(rows)} rows to {filename}")

    # 3. Populate scenario subfolders matching the 7 insider threat scenarios
    logger.info("\nBuilding progressive scenario subfolders...")
    for scenario, collectors in SCENARIO_COLLECTOR_MAP.items():
        scenario_dir = EXPORTS_DIR / scenario
        scenario_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Processing Scenario Folder: {scenario}")

        for col in collectors:
            if col in generated_rows_by_collector:
                schema, rows = generated_rows_by_collector[col]
                # Write collector CSV inside scenario folder
                scenario_csv = scenario_dir / f"{col}.csv"
                with scenario_csv.open("w", newline="", encoding="utf-8") as sc_f:
                    writer = csv.DictWriter(sc_f, fieldnames=schema)
                    writer.writeheader()
                    writer.writerows(rows)
                logger.info(f"  -> Wrote {scenario}/{col}.csv ({len(rows)} rows)")

    logger.info("==============================================================")
    logger.info(" SUCCESS: All 20 dataset files and 7 scenario folders updated! ")
    logger.info(f" Output Location: {EXPORTS_DIR}")
    logger.info("==============================================================")


if __name__ == "__main__":
    main()
