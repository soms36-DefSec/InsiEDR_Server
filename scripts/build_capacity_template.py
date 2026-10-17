"""Build a sanitized, benign multi-collector payload template for capacity tests.

The output contains synthetic data only. It is a size/shape fixture for
scripts/validate_ingest_capacity.py, not an agent-generated golden payload and
not suitable for ML training. Validate collector names and fields against the
staging server version before using it for a load run.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_template(processes: int, network_events: int, file_events: int) -> dict:
    process_rows = [
        {
            "pid": 4000 + i,
            "parent_pid": 900 + (i % 8),
            "name": ("explorer.exe", "svchost.exe", "RuntimeBroker.exe", "SearchHost.exe")[i % 4],
            "path": rf"C:\Windows\System32\{( 'svchost.exe' if i % 4 == 1 else 'RuntimeBroker.exe' if i % 4 == 2 else 'SearchHost.exe' if i % 4 == 3 else 'explorer.exe')}",
            "user": "LOADTEST\\synthetic-user",
            "integrity_level": "medium",
            "signature_status": "valid",
            "command_line": f"{('svchost.exe -k netsvcs', 'RuntimeBroker.exe -Embedding', 'SearchHost.exe', 'explorer.exe')[i % 4]}",
        }
        for i in range(processes)
    ]
    network_rows = [
        {
            "protocol": "TCP",
            "local_port": 51000 + i,
            "dest_ip": f"192.0.2.{10 + (i % 200)}",  # RFC 5737 TEST-NET-1
            "dest_port": (443, 80, 53)[i % 3],
            "bytes_sent": 1200 + (i % 7) * 311,
            "bytes_received": 2400 + (i % 11) * 197,
            "state": "ESTABLISHED",
            "process_name": process_rows[i % len(process_rows)]["name"] if process_rows else "svchost.exe",
        }
        for i in range(network_events)
    ]
    file_rows = [
        {
            "path": rf"C:\Users\loadtest\Documents\SyntheticReport-{i:03d}.txt",
            "operation": "read",
            "process_name": "explorer.exe" if i % 2 == 0 else "SearchHost.exe",
            "file_size_bytes": 2048 + (i % 9) * 1024,
            "result": "success",
        }
        for i in range(file_events)
    ]
    dns_rows = [
        {"query_name": f"service-{i % 8}.example.invalid", "query_type": "A", "response_count": 1}
        for i in range(max(8, network_events // 2))
    ]
    http_rows = [
        {
            "method": "GET",
            "url_host": f"service-{i % 5}.example.invalid",
            "url_path": f"/health/check/{i % 12}",
            "status_code": 200,
            "bytes_sent": 512 + i * 13,
            "bytes_received": 4096 + i * 29,
        }
        for i in range(max(6, network_events // 3))
    ]
    usn_rows = [
        {
            "path": rf"C:\Users\loadtest\Documents\SyntheticReport-{i:03d}.txt",
            "reason": "DATA_OVERWRITE",
            "file_size_bytes": 2048 + (i % 9) * 1024,
        }
        for i in range(file_events)
    ]

    collectors = [
        ("activity-monitor", {"active_window_count": 1, "idle_seconds": 0, "foreground_app": "explorer.exe"}),
        ("clipboard-monitor", {"clipboard_event_count": 0, "sensitive_content_detected": False}),
        ("decoy-monitor", {"decoy_file_access_count": 0, "threat_triggered": False}),
        ("devices", {"usb_connect_count": 0, "daily_device_connect_count": 0, "devices": []}),
        ("dns-monitor", {"query_count": len(dns_rows), "queries": dns_rows}),
        ("driver-monitor", {"loaded_driver_count": 42, "unsigned_driver_count": 0, "drivers_changed": False}),
        ("email-monitor", {"email_event_count": 0, "attachments_opened": 0, "external_recipients": []}),
        ("file-integrity-monitor", {"integrity_event_count": len(file_rows), "integrity_events": file_rows, "integrity_events_delete_op": 0}),
        ("http", {"request_count": len(http_rows), "requests": http_rows, "http_post_count": 0}),
        ("keystroke-collector", {"keystroke_event_count": 0, "raw_keystrokes_collected": False}),
        ("logon", {"successful_logons_5m": 1, "failed_logons_5m": 0, "unique_workstations_300s": 1, "logons": []}),
        ("lsass-monitor", {"lsass_handle_request_count": 0, "mimikatz_signatures": 0, "credential_dumping_suspected": False}),
        ("memory-scanner", {"unbacked_executable_regions": 0, "suspicious_memory_regions": 0}),
        ("named-pipe-monitor", {"pipe_open_count": 2, "named_pipes": [r"\Device\NamedPipe\spoolss", r"\Device\NamedPipe\wkssvc"]}),
        ("network", {"connection_count": len(network_rows), "connections": network_rows, "daily_unique_pc_count": 1}),
        ("persistence-monitor", {"modifications_detected": False, "persistence_changes": []}),
        ("process-watcher", {"process_count": len(process_rows), "processes": process_rows, "tunneling_process_count": 0}),
        ("short-term_edr_feature", {
            "edr_auth_event_count_window": 1,
            "edr_auth_events_per_minute_window": 0.2,
            "edr_failed_auth_events_per_minute_window": 0.0,
            "edr_failed_auth_ratio_window": 0.0,
            "unique_workstations_300s": 1,
            "auth_rate_300s": 0.2,
            "off_hours_auth_count": 0,
            "daily_device_connect_count": 0,
        }),
        ("usn-monitor", {"change_count": len(usn_rows), "changes": usn_rows}),
        ("wmi-activity", {"query_count": 2, "queries": [
            {"namespace": r"root\cimv2", "operation": "SELECT", "class": "Win32_OperatingSystem"},
            {"namespace": r"root\cimv2", "operation": "SELECT", "class": "Win32_ComputerSystem"},
        ]}),
    ]

    return {
        "schema": "insiedr.agent.telemetry.v1",
        "protocol_version": "2.0",
        "payload_id": "REPLACED-BY-CAPACITY-HARNESS",
        "agent_id": "REPLACED-BY-CAPACITY-HARNESS",
        "hostname": "REPLACED-BY-CAPACITY-HARNESS",
        "username": "loadtest-user",
        "collected_at": "2026-10-17T00:00:00Z",
        "collectors": [
            {"collector": name, "status": "success", "collected_at": "2026-10-17T00:00:00Z", "hostname": "REPLACED-BY-CAPACITY-HARNESS", "payload": data}
            for name, data in collectors
        ],
        "summary": {"collector_count": len(collectors), "success_count": len(collectors), "failed_count": 0},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="scripts/templates/loadtest_payload.json")
    parser.add_argument("--processes", type=int, default=45)
    parser.add_argument("--network-events", type=int, default=20)
    parser.add_argument("--file-events", type=int, default=28)
    args = parser.parse_args()
    if min(args.processes, args.network_events, args.file_events) < 0:
        parser.error("event counts must be non-negative")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    template = build_template(args.processes, args.network_events, args.file_events)
    content = json.dumps(template, indent=2) + "\n"
    output.write_text(content, encoding="utf-8")
    compact_bytes = len(json.dumps(template, separators=(",", ":")).encode("utf-8"))
    print(
        f"Wrote synthetic benign template: {output} "
        f"(pretty file {len(content.encode('utf-8')):,} bytes; "
        f"serialized payload {compact_bytes:,} bytes before encryption)"
    )
    print("Synthetic only; validate it against the isolated staging server before load testing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
