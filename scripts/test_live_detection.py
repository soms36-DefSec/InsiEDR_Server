#!/usr/bin/env python3
"""
Trigger a live scenario detection through the InsiEDR risk pipeline.
Dispatches real-time SSE threat notifications to the live dashboard.
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
    now_iso = datetime.now(timezone.utc).isoformat()

    collectors = []
    for c in scenario_info["collectors"]:
        c_copy = dict(c)
        c_copy.setdefault("collected_at", now_iso)
        collectors.append(c_copy)

    payload = {
        "payload_id": payload_id,
        "agent_id": agent_id,
        "hostname": args.hostname,
        "username": args.username,
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
        "agent_id": agent_id,
        "hostname": args.hostname,
        "timestamp": now_iso,
        "payload_id": payload_id,
    }

    # Start the SSE event broadcaster so Redis pub/sub bridges across containers
    broadcaster.start()

    storage = init_storage()
    print(f"\n=======================================================", flush=True)
    print(f" InsiEDR Live Detection Pipeline - Simulation Trigger", flush=True)
    print(f"=======================================================", flush=True)
    print(f" Scenario  : {scenario_info['title']}", flush=True)
    print(f" Hostname  : {args.hostname}", flush=True)
    print(f" Agent ID  : {agent_id}", flush=True)
    print(f" Username  : {args.username}", flush=True)
    print(f" Payload ID: {payload_id}", flush=True)
    print(f"-------------------------------------------------------", flush=True)

    # 1. Store raw payload and register/update agent in fleet
    try:
        storage.store_raw_payload(envelope, payload)
        print(f" [OK] Telemetry ingested and agent '{args.hostname}' recorded.", flush=True)
    except Exception as store_err:
        print(f" [!] Telemetry store notice: {store_err}", flush=True)

    # 2. Execute heuristics detection engine and risk aggregator
    print(f" Executing heuristics detection engine and risk aggregator...", flush=True)
    result = process_telemetry_risk(storage, payload, emit=True)

    # 3. Notify telemetry change
    try:
        dispatch_telemetry_event(payload_id)
    except Exception:
        pass

    risk_score = result.get("risk_score", 0.0)
    risk_level = str(result.get("risk_level", "low")).upper()
    summary = result.get("summary", "Normal")

    # Allow background Redis publisher thread to flush message to socket
    time.sleep(1.0)
    storage.close()

    print(f"\n >>> DETECTION PIPELINE RESULT <<<", flush=True)
    print(f" Calculated Risk Score : {risk_score:.1f} / 100", flush=True)
    print(f" Severity Level        : {risk_level}", flush=True)
    print(f" Pipeline Summary      : {summary}", flush=True)
    print(f"-------------------------------------------------------", flush=True)
    print(f" [OK] Threat dispatched via SSE stream to active dashboards!", flush=True)
    print(f" Open http://172.16.22.198/dashboard/ to see the live alert card.", flush=True)
    print(f"=======================================================\n", flush=True)


if __name__ == "__main__":
    main()
