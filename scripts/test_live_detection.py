#!/usr/bin/env python3
"""
Trigger a live scenario detection through the InsiEDR risk pipeline.
Dispatches real-time SSE threat notifications to the live dashboard.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[1]
for candidate in ["/app", str(ROOT)]:
    if candidate not in sys.path and Path(candidate).exists():
        sys.path.insert(0, candidate)

from server.db import get_storage
from server.risk.pipeline import process_telemetry_risk

SCENARIO_PAYLOADS = {
    "credential_dump": {
        "title": "Credential Dumping (LSASS Memory Attack)",
        "collectors": [
            {
                "collector": "memory",
                "status": "success",
                "payload": {
                    "credential_dumping_suspected": True,
                    "unbacked_executable_memory": True,
                    "target_process": "lsass.exe",
                },
            }
        ],
    },
    "honeytoken": {
        "title": "Honeytoken Trip / Decoy File Access",
        "collectors": [
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "honeytoken_access": True,
                    "honeytoken_filename": "passwords_backup.xlsx",
                    "file_read_count": 1,
                },
            }
        ],
    },
    "usb_exfiltration": {
        "title": "Bulk USB Data Exfiltration Precursor",
        "collectors": [
            {
                "collector": "device",
                "status": "success",
                "payload": {
                    "usb_inserted": True,
                    "unapproved_device": True,
                    "usb_serial": "USB-SANDISK-09823",
                },
            },
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "bulk_file_write": True,
                    "daily_file_write_count": 150,
                    "usb_file_transfer": True,
                },
            },
        ],
    },
    "it_sabotage": {
        "title": "IT Sabotage (Mass Deletion + Persistence)",
        "collectors": [
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "daily_file_delete_count": 450,
                    "mass_deletion": True,
                },
            },
            {
                "collector": "integrity",
                "status": "success",
                "payload": {
                    "persistence_tampering": True,
                    "modifications_detected": True,
                },
            },
        ],
    },
    "cloud_upload": {
        "title": "Cloud Exfiltration Precursor (Archive + Spike)",
        "collectors": [
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "bulk_file_access": True,
                    "daily_file_open_count": 200,
                },
            },
            {
                "collector": "http",
                "status": "success",
                "payload": {
                    "cloud_upload_spike": True,
                    "bytes_sent": 524288000,
                    "destination_domain": "mega.nz",
                },
            },
        ],
    },
}


def main():
    parser = argparse.ArgumentParser(description="Trigger a live threat scenario in InsiEDR pipeline.")
    parser.add_argument("--scenario", choices=list(SCENARIO_PAYLOADS.keys()), default="credential_dump",
                        help="Attack scenario type (default: credential_dump)")
    parser.add_argument("--hostname", default="DEMO-PC-01",
                        help="Target hostname to flag on dashboard (default: DEMO-PC-01)")
    parser.add_argument("--agent-id", default=None,
                        help="Agent ID (default: AGENT-<hostname>)")
    parser.add_argument("--username", default="demo_user",
                        help="Username on the target system (default: demo_user)")
    args = parser.parse_args()

    agent_id = args.agent_id or f"AGENT-{args.hostname}"
    scenario_info = SCENARIO_PAYLOADS[args.scenario]
    payload_id = f"demo-sim-{uuid.uuid4().hex[:12]}"

    payload = {
        "payload_id": payload_id,
        "agent_id": agent_id,
        "hostname": args.hostname,
        "username": args.username,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collectors": scenario_info["collectors"],
    }

    storage = get_storage()
    print(f"\n=======================================================")
    print(f" InsiEDR Live Detection Pipeline - Simulation Trigger")
    print(f"=======================================================")
    print(f" Scenario  : {scenario_info['title']}")
    print(f" Hostname  : {args.hostname}")
    print(f" Agent ID  : {agent_id}")
    print(f" Username  : {args.username}")
    print(f" Payload ID: {payload_id}")
    print(f"-------------------------------------------------------")
    print(f" Executing heuristics detection engine and risk aggregator...")

    result = process_telemetry_risk(storage, payload, emit=True)

    risk_score = result.get("risk_score", 0.0)
    risk_level = str(result.get("risk_level", "low")).upper()
    summary = result.get("summary", "Normal")

    print(f"\n >>> DETECTION PIPELINE RESULT <<<")
    print(f" Calculated Risk Score : {risk_score:.1f} / 100")
    print(f" Severity Level        : {risk_level}")
    print(f" Pipeline Summary      : {summary}")
    print(f"-------------------------------------------------------")
    print(f" [OK] Threat dispatched via SSE stream to active dashboards!")
    print(f" Open http://172.16.22.198/dashboard/ to see the live alert card.")
    print(f"=======================================================\n")


if __name__ == "__main__":
    main()
