#!/usr/bin/env python3
"""
InsiEDR Agent Simulator (insiedr_sim_agent.py)
---------------------------------------------
Simulates endpoint telemetry and threat scenarios through the InsiEDR pipeline.
Enables auditing of named fleet records and validating detections before cleanup or sending.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[1]
for candidate in ["/app", str(ROOT)]:
    if candidate not in sys.path and Path(candidate).exists():
        sys.path.insert(0, candidate)

from server.config import config
from server.storage.postgres_storage import PostgresStorage
from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.hybrid_storage import HybridStorage
from server.risk.pipeline import process_telemetry_risk
from server.api.events import broadcaster, dispatch_telemetry_event

# Supported threat scenarios with validated heuristics signatures
SIMULATED_SCENARIOS = {
    "benign": {
        "title": "Nominal Baseline / Benign Endpoint Heartbeat",
        "severity": "LOW",
        "collectors": [
            {
                "collector": "process-watcher",
                "status": "success",
                "payload": {
                    "running_processes": ["explorer.exe", "svchost.exe", "chrome.exe"],
                    "process_count": 42,
                    "suspicious_processes": 0,
                },
            },
            {
                "collector": "activity-monitor",
                "status": "success",
                "payload": {
                    "active_window": "Document.docx - Word",
                    "idle_seconds": 12,
                },
            },
        ],
    },
    "credential_dump": {
        "title": "Credential Dumping (LSASS Memory Attack)",
        "severity": "CRITICAL",
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
        "severity": "CRITICAL",
        "collectors": [
            {
                "collector": "decoy-monitor",
                "status": "success",
                "payload": {
                    "threat_triggered": True,
                    "honeytoken_name": "passwords_backup.xlsx",
                    "action": "read",
                },
            }
        ],
    },
    "usb_exfiltration": {
        "title": "Bulk USB Data Exfiltration",
        "severity": "HIGH",
        "collectors": [
            {
                "collector": "device",
                "status": "success",
                "payload": {
                    "unauthorized_usb_detected": True,
                    "usb_connect_count": 1,
                    "usb_serial": "USB-SANDISK-09823",
                },
            },
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "daily_files_to_removable_count": 45,
                    "usb_file_transfer_count": 45,
                },
            },
        ],
    },
    "it_sabotage": {
        "title": "IT Sabotage (Mass Deletion + Persistence)",
        "severity": "HIGH",
        "collectors": [
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "file_delete_count": 120,
                    "daily_file_delete_count": 120,
                },
            },
            {
                "collector": "integrity",
                "status": "success",
                "payload": {
                    "modifications_detected": True,
                    "after_hours_logon": 3,
                },
            },
        ],
    },
    "cloud_upload": {
        "title": "Cloud Exfiltration (Sensitive File Archive + Spike)",
        "severity": "HIGH",
        "collectors": [
            {
                "collector": "file",
                "status": "success",
                "payload": {
                    "sensitive_file_access": 15,
                    "file_access_count": 80,
                    "daily_unique_filename_count": 60,
                },
            },
            {
                "collector": "http",
                "status": "success",
                "payload": {
                    "cloud_storage_uploads": 5,
                    "upload_bytes": 524288000,
                    "destination_domain": "mega.nz",
                },
            },
        ],
    },
    "network_tunneling": {
        "title": "C2 Network Tunneling (DNS / Process Tunnel)",
        "severity": "HIGH",
        "collectors": [
            {
                "collector": "process-watcher",
                "status": "success",
                "payload": {
                    "tunneling_process_count": 1,
                    "tunneling_detected": True,
                    "process_name": "chisel.exe",
                },
            }
        ],
    },
}


def init_storage() -> HybridStorage:
    pg = PostgresStorage(config.database_dsn, minconn=1, maxconn=4)
    ch = None
    try:
        ch = ClickHouseStorage(
            host=config.clickhouse_host,
            port=config.clickhouse_port,
            username=config.clickhouse_user,
            password=config.clickhouse_password,
            database=config.clickhouse_db,
            secure=config.clickhouse_secure,
            ca_cert=config.clickhouse_ca_cert,
            query_timeout=config.clickhouse_query_timeout,
        )
        if not ch.is_connected():
            ch = None
    except Exception:
        ch = None
    return HybridStorage(postgres_storage=pg, clickhouse_storage=ch)


def run_agent_simulation(scenario: str, hostname: str, agent_id: str | None = None,
                         username: str = "demo_user", emit_sse: bool = True) -> dict:
    effective_agent_id = agent_id or f"AGENT-{hostname}"
    scenario_info = SIMULATED_SCENARIOS.get(scenario, SIMULATED_SCENARIOS["credential_dump"])
    payload_id = f"sim-{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    collectors = []
    for c in scenario_info["collectors"]:
        c_copy = dict(c)
        c_copy.setdefault("collected_at", now_iso)
        collectors.append(c_copy)

    payload = {
        "payload_id": payload_id,
        "agent_id": effective_agent_id,
        "hostname": hostname,
        "username": username,
        "collected_at": now_iso,
        "os": {
            "system": "Windows",
            "release": "10",
            "version": "10.0.19045",
            "machine": "AMD64",
        },
        "collectors": collectors,
    }

    envelope = {
        "agent_id": effective_agent_id,
        "hostname": hostname,
        "timestamp": now_iso,
        "payload_id": payload_id,
    }

    if emit_sse:
        broadcaster.start()

    storage = init_storage()
    print(f"\n=======================================================", flush=True)
    print(f" InsiEDR Agent Simulator (insiedr_sim_agent.py)", flush=True)
    print(f"=======================================================", flush=True)
    print(f" Scenario  : {scenario_info['title']}", flush=True)
    print(f" Hostname  : {hostname}", flush=True)
    print(f" Agent ID  : {effective_agent_id}", flush=True)
    print(f" Username  : {username}", flush=True)
    print(f" Payload ID: {payload_id}", flush=True)
    print(f"-------------------------------------------------------", flush=True)

    try:
        storage.store_raw_payload(envelope, payload)
        print(f" [OK] Telemetry ingested and agent '{hostname}' registered/updated.", flush=True)
    except Exception as store_err:
        print(f" [!] Storage note: {store_err}", flush=True)

    print(f" Evaluating detection engine and risk scoring...", flush=True)
    result = process_telemetry_risk(storage, payload, emit=emit_sse)

    if emit_sse:
        try:
            dispatch_telemetry_event(payload_id)
        except Exception:
            pass
        time.sleep(1.0)

    storage.close()

    risk_score = result.get("risk_score", 0.0)
    risk_level = str(result.get("risk_level", "low")).upper()
    summary = result.get("summary", "Normal behavior.")

    print(f"\n >>> SIMULATOR PIPELINE OUTPUT <<<", flush=True)
    print(f" Risk Score   : {risk_score:.1f} / 100", flush=True)
    print(f" Risk Level   : {risk_level}", flush=True)
    print(f" Summary      : {summary}", flush=True)
    print(f"-------------------------------------------------------", flush=True)
    if emit_sse:
        print(f" [OK] Real-time SSE alert dispatched to SOC dashboard!", flush=True)
    print(f"=======================================================\n", flush=True)
    return result


def audit_fleet() -> None:
    storage = init_storage()
    agents = storage.list_agents(limit=500)
    print(f"\n=======================================================")
    print(f" InsiEDR Fleet Audit Summary")
    print(f"=======================================================")
    print(f" Total Registered Agents in DB: {len(agents)}")
    print(f"-------------------------------------------------------")
    print(f"{'HOSTNAME':<25} {'AGENT ID':<25} {'USER':<15} {'STATUS':<10}")
    print(f"{'-'*25} {'-'*25} {'-'*15} {'-'*10}")
    for a in agents[:20]:
        h = str(a.get('hostname') or '')[:24]
        aid = str(a.get('agent_id') or '')[:24]
        u = str(a.get('username_last_seen') or 'N/A')[:14]
        s = str(a.get('status') or 'unknown')[:9]
        print(f"{h:<25} {aid:<25} {u:<15} {s:<10}")
    if len(agents) > 20:
        print(f"... and {len(agents) - 20} more endpoints (see fleet.csv for complete audit)")
    print(f"=======================================================\n")
    storage.close()


def main():
    parser = argparse.ArgumentParser(description="InsiEDR Agent Simulator")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Simulate attack or benign
    sim_parser = subparsers.add_parser("simulate", help="Simulate agent telemetry / threat scenario")
    sim_parser.add_argument("--scenario", choices=list(SIMULATED_SCENARIOS.keys()), default="credential_dump",
                           help="Scenario type (default: credential_dump)")
    sim_parser.add_argument("--hostname", default="DEMO-PC-01",
                           help="Target hostname (default: DEMO-PC-01)")
    sim_parser.add_argument("--agent-id", default=None,
                           help="Custom Agent ID (default: AGENT-<hostname>)")
    sim_parser.add_argument("--username", default="demo_user",
                           help="Username (default: demo_user)")
    sim_parser.add_argument("--no-sse", action="store_true",
                           help="Disable SSE dispatch")

    # Audit command
    subparsers.add_parser("audit", help="Audit registered fleet records in database")

    # List scenarios
    subparsers.add_parser("list-scenarios", help="List available threat and benign simulation scenarios")

    args = parser.parse_args()

    if args.command == "audit":
        audit_fleet()
    elif args.command == "list-scenarios":
        print("\nAvailable InsiEDR Simulation Scenarios:")
        print(f"{'SCENARIO':<20} {'SEVERITY':<10} {'DESCRIPTION'}")
        print(f"{'-'*20} {'-'*10} {'-'*45}")
        for key, info in SIMULATED_SCENARIOS.items():
            print(f"{key:<20} {info['severity']:<10} {info['title']}")
        print()
    else:
        # Default to simulate if no subcommand provided (backward-compatible flags)
        scenario = getattr(args, "scenario", "credential_dump")
        hostname = getattr(args, "hostname", "DEMO-PC-01")
        agent_id = getattr(args, "agent_id", None)
        username = getattr(args, "username", "demo_user")
        no_sse = getattr(args, "no_sse", False)
        run_agent_simulation(scenario=scenario, hostname=hostname, agent_id=agent_id,
                             username=username, emit_sse=not no_sse)


if __name__ == "__main__":
    main()
