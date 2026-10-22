"""
Demo Simulation Tool for InsiEDR Model V3 Review Queue & SOC Dashboard
----------------------------------------------------------------------
Simulates 22 consecutive completed UTC days of endpoint activity, bypassing the 22-day
real-time wait so you can immediately demonstrate the Model V3 Review Queue and the main
SOC Dashboard (Risk Breakdown, Detection Engine, Threat Stream, Attack Surface, Fleet Matrix).

Dynamically binds to existing fleet hostnames in your database (e.g. SOCL8-39, SOCL8-44...)
so that actual monitored machines light up in the dashboard rather than generic placeholders.

Supported modes:
  1. direct   (Default/Fastest): Directly populates PostgreSQL review queue & endpoint trajectory.
                                 Works instantly with zero external dependencies.
  2. pipeline (Full ML Model):  Populates ClickHouse endpoint_daily_feature_rollups and runs the
                                 actual frozen Model V3 (predict.py) inference batch.
  3. clean    (Reset):           Removes simulated demo records from PostgreSQL and ClickHouse.

Usage:
  python scripts/demo_simulate_model_v3.py --mode direct
  python scripts/demo_simulate_model_v3.py --mode pipeline
  python scripts/demo_simulate_model_v3.py --mode clean
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import uuid

# Ensure repository root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.config import config
from server.storage.postgres_storage import PostgresStorage
from server.storage.repositories.model_repo import ModelReviewRepository

CONTRACT_VERSION = "v3_daily40_observed_v1"
RAW_FEATURES: tuple[str, ...] = (
    "successful_logons", "failed_logons", "after_hours_logon_ratio", "unique_pc_count",
    "pc_access_entropy", "interactive_duration_seconds", "mean_session_duration_seconds",
    "weekend_activity", "usb_connect_count", "usb_disconnect_count", "after_hours_usb_ratio",
    "distinct_usb_devices", "file_access_count", "unique_filename_count", "new_filename_count",
    "file_delete_count", "file_access_entropy", "protected_file_touch_count", "http_request_count",
    "unique_domain_count", "new_domain_count", "external_domain_ratio", "domain_access_entropy",
    "file_sharing_visit_count", "mean_process_count", "peak_process_count", "admin_process_count",
    "temp_exec_count", "bytes_sent", "bytes_received", "external_connection_count",
    "unique_remote_ip_count", "clipboard_copy_count", "lsass_handle_request_count",
    "memory_dump_attempt_count", "decoy_access_count", "wmi_query_count", "named_pipe_event_count",
    "dns_query_count", "outbound_attachment_count",
)


def get_pg_dsn() -> str:
    if config.database_dsn:
        return config.database_dsn
    if os.environ.get("INSIEDR_SERVER_POSTGRES_URI"):
        return os.environ["INSIEDR_SERVER_POSTGRES_URI"]
    user = os.environ.get("POSTGRES_USER", "insiedr")
    pwd = os.environ.get("POSTGRES_PASSWORD", "insiedr_pass")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "insiedr_db")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


SCENARIO_TEMPLATES = [
    {
        "scenario": "DATA_HOARDING",
        "pair_threat": 0.9706,
        "threat_prob": 0.9837,
        "if_risk": 0.9418,
        "fused_risk": 0.9774,
        "forecasted_risk": 0.1393,
        "drift_error": 0.8381,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.012, "DATA_HOARDING": 0.915, "CLOUD_EXFILTRATION_PRECURSOR": 0.041,
            "CREDENTIAL_DUMP": 0.010, "IT_SABOTAGE": 0.008, "USB_EXFILTRATION_PRECURSOR": 0.007,
            "HONEYTOKEN_TRIP": 0.004, "KILL_CHAIN_APT": 0.003,
        },
        "risk_score": 97.1,
        "risk_level": "CRITICAL",
        "summary": "Heuristics: Broad File Collection | Mass file touch across network shares after-hours followed by archive staging",
        "domain_scores": {"FILE": 96.0, "LOGON": 85.0, "DEVICE": 40.0, "HTTP": 62.0},
        "cert_scenarios": [{"id": "DATA_HOARDING", "description": "Mass Data Collection"}],
    },
    {
        "scenario": "CREDENTIAL_DUMP",
        "pair_threat": 0.8842,
        "threat_prob": 0.9120,
        "if_risk": 0.8650,
        "fused_risk": 0.9050,
        "forecasted_risk": 0.1520,
        "drift_error": 0.7530,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.025, "CREDENTIAL_DUMP": 0.872, "KILL_CHAIN_APT": 0.051,
            "DATA_HOARDING": 0.018, "IT_SABOTAGE": 0.014, "CLOUD_EXFILTRATION_PRECURSOR": 0.009,
            "USB_EXFILTRATION_PRECURSOR": 0.006, "HONEYTOKEN_TRIP": 0.005,
        },
        "risk_score": 88.4,
        "risk_level": "CRITICAL",
        "summary": "Heuristics: LSASS Credential Dumping Suspected | Unbacked Executable Memory",
        "domain_scores": {"FILE": 35.0, "LOGON": 72.0, "DEVICE": 20.0, "HTTP": 45.0},
        "cert_scenarios": [{"id": "CREDENTIAL_DUMP", "description": "Credential Access"}],
    },
    {
        "scenario": "USB_EXFILTRATION_PRECURSOR",
        "pair_threat": 0.7655,
        "threat_prob": 0.8140,
        "if_risk": 0.7920,
        "fused_risk": 0.8105,
        "forecasted_risk": 0.1180,
        "drift_error": 0.6925,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.048, "USB_EXFILTRATION_PRECURSOR": 0.805, "CLOUD_EXFILTRATION_PRECURSOR": 0.072,
            "DATA_HOARDING": 0.035, "CREDENTIAL_DUMP": 0.015, "IT_SABOTAGE": 0.012,
            "HONEYTOKEN_TRIP": 0.008, "KILL_CHAIN_APT": 0.005,
        },
        "risk_score": 76.5,
        "risk_level": "HIGH",
        "summary": "Heuristics: USB Device Activity | Removable media activity observed with sensitive document staging",
        "domain_scores": {"FILE": 62.0, "LOGON": 45.0, "DEVICE": 88.0, "HTTP": 38.0},
        "cert_scenarios": [{"id": "USB_EXFILTRATION_PRECURSOR", "description": "Removable Media Exfiltration Precursor"}],
    },
    {
        "scenario": "KILL_CHAIN_APT",
        "pair_threat": 0.9400,
        "threat_prob": 0.9500,
        "if_risk": 0.9200,
        "fused_risk": 0.9450,
        "forecasted_risk": 0.1200,
        "drift_error": 0.8250,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.010, "KILL_CHAIN_APT": 0.930, "CREDENTIAL_DUMP": 0.030,
            "DATA_HOARDING": 0.015, "IT_SABOTAGE": 0.010, "USB_EXFILTRATION_PRECURSOR": 0.005,
        },
        "risk_score": 94.0,
        "risk_level": "CRITICAL",
        "summary": "Heuristics: Honeytoken Access | Lateral Movement Attempt detected across fleet workstations",
        "domain_scores": {"FILE": 78.0, "LOGON": 92.0, "DEVICE": 10.0, "HTTP": 85.0},
        "cert_scenarios": [{"id": "KILL_CHAIN_APT", "description": "Multi-Stage Attack Chain"}],
    },
    {
        "scenario": "IT_SABOTAGE",
        "pair_threat": 0.8200,
        "threat_prob": 0.8500,
        "if_risk": 0.8000,
        "fused_risk": 0.8300,
        "forecasted_risk": 0.1400,
        "drift_error": 0.6900,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.030, "IT_SABOTAGE": 0.880, "DATA_HOARDING": 0.050,
            "CREDENTIAL_DUMP": 0.020, "USB_EXFILTRATION_PRECURSOR": 0.010,
        },
        "risk_score": 82.0,
        "risk_level": "HIGH",
        "summary": "Heuristics: Mass File Deletion | Suspicious administrative activity on sensitive volume",
        "domain_scores": {"FILE": 88.0, "LOGON": 55.0, "DEVICE": 15.0, "HTTP": 30.0},
        "cert_scenarios": [{"id": "IT_SABOTAGE", "description": "System Sabotage Attempt"}],
    },
]

FALLBACK_AGENTS = [
    {"agent_id": "AGENT-FINANCE-01", "hostname": "DESKTOP-FIN-01", "username": "fin_admin"},
    {"agent_id": "AGENT-ADMIN-03", "hostname": "WS-SYSADMIN-03", "username": "sys_admin"},
    {"agent_id": "AGENT-HR-07", "hostname": "LAPTOP-HR-07", "username": "hr_user"},
    {"agent_id": "AGENT-DEV-12", "hostname": "WS-DEV-12", "username": "dev_user"},
    {"agent_id": "AGENT-BENIGN-01", "hostname": "DESKTOP-STAFF-01", "username": "staff_user"},
]


def resolve_fleet_endpoints(pg: PostgresStorage) -> list[dict]:
    """Inspect PostgreSQL agents table to bind threat scenarios directly to real fleet hostnames."""
    with pg.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT agent_id, hostname, username_last_seen
                FROM agents
                WHERE hostname IS NOT NULL AND BTRIM(hostname) != ''
                ORDER BY last_seen_at DESC NULLS LAST, hostname ASC
            """)
            fleet = cur.fetchall()

    if not fleet:
        print("[*] No registered fleet agents found; using reference fallback hostnames.")
        hosts_to_use = FALLBACK_AGENTS
    else:
        print(f"[*] Discovered {len(fleet)} registered fleet endpoints in PostgreSQL.")
        hosts_to_use = [{"agent_id": r[0], "hostname": r[1], "username": r[2] or "user"} for r in fleet]

    resolved = []
    for i, h_info in enumerate(hosts_to_use):
        if i < len(SCENARIO_TEMPLATES):
            tmpl = SCENARIO_TEMPLATES[i]
            resolved.append({
                **h_info,
                **tmpl,
            })
        else:
            # Baseline nominal host
            resolved.append({
                **h_info,
                "scenario": "BENIGN",
                "pair_threat": 0.0421,
                "threat_prob": 0.0380,
                "if_risk": 0.0610,
                "fused_risk": 0.0415,
                "forecasted_risk": 0.0390,
                "drift_error": 0.0025,
                "evidence_dates": [],
                "scenario_probs": {"BENIGN": 0.965, "DATA_HOARDING": 0.008},
                "risk_score": 12.0,
                "risk_level": "LOW",
                "summary": "Nominal baseline activity",
                "domain_scores": {"FILE": 10.0, "LOGON": 12.0, "DEVICE": 2.0, "HTTP": 8.0},
                "cert_scenarios": [],
            })

    return resolved


def generate_feature_vector(agent_cfg: dict, day_offset: int, is_anomaly_day: bool) -> dict[str, float]:
    """Generate 40 realistic features compliant with the Model V3 schema and validation constraints."""
    scenario = agent_cfg["scenario"]
    vec: dict[str, float] = {f: 0.0 for f in RAW_FEATURES}

    # Baseline daily activity
    vec["successful_logons"] = 4.0
    vec["failed_logons"] = 0.0
    vec["after_hours_logon_ratio"] = 0.0
    vec["unique_pc_count"] = 1.0
    vec["pc_access_entropy"] = 0.0
    vec["interactive_duration_seconds"] = 28800.0  # 8 hours
    vec["mean_session_duration_seconds"] = 14400.0
    vec["weekend_activity"] = 0.0
    vec["file_access_count"] = 150.0
    vec["unique_filename_count"] = 45.0
    vec["new_filename_count"] = 10.0
    vec["file_delete_count"] = 5.0
    vec["file_access_entropy"] = 1.2
    vec["protected_file_touch_count"] = 0.0
    vec["http_request_count"] = 350.0
    vec["unique_domain_count"] = 25.0
    vec["new_domain_count"] = 3.0
    vec["external_domain_ratio"] = 0.2
    vec["domain_access_entropy"] = 1.3
    vec["file_sharing_visit_count"] = 0.0
    vec["mean_process_count"] = 40.0
    vec["peak_process_count"] = 65.0
    vec["admin_process_count"] = 1.0
    vec["temp_exec_count"] = 0.0
    vec["bytes_sent"] = 2500000.0
    vec["bytes_received"] = 12000000.0
    vec["external_connection_count"] = 25.0
    vec["unique_remote_ip_count"] = 12.0
    vec["clipboard_copy_count"] = 8.0
    vec["lsass_handle_request_count"] = 0.0
    vec["memory_dump_attempt_count"] = 0.0
    vec["decoy_access_count"] = 0.0
    vec["wmi_query_count"] = 0.0
    vec["named_pipe_event_count"] = 0.0
    vec["dns_query_count"] = 120.0
    vec["outbound_attachment_count"] = 0.0

    if is_anomaly_day and scenario == "DATA_HOARDING":
        vec["successful_logons"] = 22.0
        vec["after_hours_logon_ratio"] = 0.85
        vec["file_access_count"] = 9800.0
        vec["unique_filename_count"] = 4200.0
        vec["new_filename_count"] = 3900.0
        vec["file_delete_count"] = 1200.0
        vec["file_access_entropy"] = 4.6
        vec["protected_file_touch_count"] = 35.0
        vec["temp_exec_count"] = 24.0
        vec["bytes_sent"] = 650000000.0
        vec["file_sharing_visit_count"] = 40.0

    elif is_anomaly_day and scenario == "CREDENTIAL_DUMP":
        vec["admin_process_count"] = 42.0
        vec["lsass_handle_request_count"] = 28.0
        vec["memory_dump_attempt_count"] = 4.0
        vec["wmi_query_count"] = 35.0
        vec["named_pipe_event_count"] = 18.0
        vec["temp_exec_count"] = 15.0
        vec["decoy_access_count"] = 2.0

    elif is_anomaly_day and scenario == "USB_EXFILTRATION_PRECURSOR":
        vec["usb_connect_count"] = 12.0
        vec["usb_disconnect_count"] = 12.0
        vec["after_hours_usb_ratio"] = 0.80
        vec["distinct_usb_devices"] = 3.0
        vec["file_access_count"] = 3500.0
        vec["unique_filename_count"] = 1200.0
        vec["bytes_sent"] = 450000000.0
        vec["clipboard_copy_count"] = 95.0

    elif is_anomaly_day and scenario == "KILL_CHAIN_APT":
        vec["successful_logons"] = 18.0
        vec["unique_pc_count"] = 4.0
        vec["admin_process_count"] = 25.0
        vec["wmi_query_count"] = 40.0
        vec["named_pipe_event_count"] = 22.0
        vec["decoy_access_count"] = 1.0
        vec["file_sharing_visit_count"] = 6.0
        vec["bytes_sent"] = 320000000.0

    elif is_anomaly_day and scenario == "IT_SABOTAGE":
        vec["file_delete_count"] = 4500.0
        vec["file_access_count"] = 5200.0
        vec["after_hours_logon_ratio"] = 0.90
        vec["admin_process_count"] = 15.0
        vec["temp_exec_count"] = 10.0

    return vec


def inject_soc_dashboard_threats(pg: PostgresStorage, endpoints: list[dict]) -> None:
    """Inject active risk events, agent registrations, and domain vectors for the main SOC dashboard."""
    print("\n[*] Populating main SOC Dashboard (Risk Severity, Threat Stream, Attack Surface, Fleet Risk Matrix)...")
    anomaly_endpoints = [ep for ep in endpoints if ep.get("scenario") != "BENIGN"]
    resolved_threats = []

    with pg.connection() as conn:
        with conn.cursor() as cur:
            for idx, item in enumerate(anomaly_endpoints):
                agent_id = item["agent_id"]
                hostname = item["hostname"]
                username = item["username"]
                payload_id = f"payload-{agent_id}-live"
                # Stagger event times within the last 15 minutes (active threat window, avoiding 30m decay)
                event_time = datetime.now(timezone.utc) - timedelta(minutes=idx * 3 + 1)

                resolved_threats.append({
                    **item,
                    "payload_id": payload_id,
                    "event_time": event_time,
                })

                # 1. Ensure agent is registered, marked active and online
                cur.execute("""
                    INSERT INTO agents (agent_id, hostname, username_last_seen, status, last_seen_at)
                    VALUES (%s, %s, %s, 'active', NOW())
                    ON CONFLICT (agent_id) DO UPDATE SET
                        last_seen_at = NOW(),
                        status = 'active',
                        username_last_seen = COALESCE(agents.username_last_seen, EXCLUDED.username_last_seen)
                """, (agent_id, hostname, username))

                # 2. Insert into raw_payloads (required foreign key for risk_events)
                cur.execute("""
                    INSERT INTO raw_payloads (payload_id, agent_id, hostname, username, received_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (payload_id, agent_id, hostname, username, event_time))

                # 3. Build correlated_signals_json explicitly including hostname
                signals = {
                    "hostname": hostname,
                    "cert_scenarios": item["cert_scenarios"],
                    "heuristics": {
                        "detections": [{"scenario": item["scenario"]}],
                        "domain_scores": item["domain_scores"],
                        "detected_scenarios": [item["scenario"]],
                    },
                    "predicted_scenario": {"scenario": item["scenario"]},
                    "logon_risk": item["domain_scores"]["LOGON"],
                    "file_risk": item["domain_scores"]["FILE"],
                    "device_risk": item["domain_scores"]["DEVICE"],
                    "http_risk": item["domain_scores"]["HTTP"],
                }

                # 4. Remove previous live event for this payload to avoid duplicate feed entries
                cur.execute("DELETE FROM risk_events WHERE payload_id = %s", (payload_id,))

                # 5. Insert active risk event
                cur.execute("""
                    INSERT INTO risk_events (
                        payload_id, agent_id, username, risk_score, risk_level,
                        correlated_signals_json, summary, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                """, (
                    payload_id, agent_id, username,
                    item["risk_score"], item["risk_level"],
                    json.dumps(signals), item["summary"], event_time
                ))

            # Mark all benign hosts active as well so they show green in the matrix
            for b_ep in endpoints:
                if b_ep.get("scenario") == "BENIGN":
                    cur.execute("""
                        UPDATE agents SET last_seen_at = NOW(), status = 'active'
                        WHERE agent_id = %s
                    """, (b_ep["agent_id"],))

        conn.commit()

    # Also insert into ClickHouse risk_events if ClickHouse is accessible
    try:
        from server.storage.clickhouse_storage import ClickHouseStorage
        ch = ClickHouseStorage(
            host=config.clickhouse_host, port=config.clickhouse_port,
            username=config.clickhouse_user, password=config.clickhouse_password,
            database=config.clickhouse_db,
        )
        if ch.is_connected():
            client = getattr(ch, "_client", ch)
            ch_rows = []
            for item in resolved_threats:
                signals = {
                    "hostname": item["hostname"],
                    "cert_scenarios": item["cert_scenarios"],
                    "heuristics": {
                        "detections": [{"scenario": item["scenario"]}],
                        "domain_scores": item["domain_scores"],
                        "detected_scenarios": [item["scenario"]],
                    },
                    "predicted_scenario": {"scenario": item["scenario"]},
                    "logon_risk": item["domain_scores"]["LOGON"],
                    "file_risk": item["domain_scores"]["FILE"],
                    "device_risk": item["domain_scores"]["DEVICE"],
                    "http_risk": item["domain_scores"]["HTTP"],
                }
                ch_rows.append((
                    str(uuid.uuid4()), item["payload_id"], item["agent_id"], item["username"],
                    float(item["risk_score"]), item["risk_level"].lower(),
                    json.dumps(signals), item["summary"], item["event_time"]
                ))
            client.insert("risk_events", ch_rows, column_names=(
                "id", "payload_id", "agent_id", "username", "risk_score",
                "risk_level", "correlated_signals_json", "summary", "created_at"
            ))
            ch.close()
            print("[+] Injected live risk events into ClickHouse.")
    except Exception as exc:
        print(f"[-] ClickHouse sync skipped (PostgreSQL active): {exc}")

    # Invalidate cached dashboard summary in Redis so UI immediately displays new data
    try:
        import redis
        if config.redis_url:
            r = redis.Redis.from_url(config.redis_url, decode_responses=True)
            keys = r.keys("snapshot:v2:*")
            if keys:
                r.delete(*keys)
                print(f"[+] Invalidated {len(keys)} cached dashboard summary keys in Redis.")
    except Exception as exc:
        print(f"[-] Redis cache invalidate skipped: {exc}")

    print(f"[+] Successfully injected {len(resolved_threats)} active risk events into SOC dashboard!")


def run_direct_simulation(as_of: date) -> None:
    """Directly populate PostgreSQL scores and review queue table (Fast, 100% reliable)."""
    pg = PostgresStorage(get_pg_dsn(), minconn=1, maxconn=2)
    repo = ModelReviewRepository(pg)
    start_date = as_of - timedelta(days=21)

    print(f"\n[*] Mode: DIRECT DATABASE SIMULATION")
    print(f"[*] Window: 22 completed UTC days from {start_date.isoformat()} to {as_of.isoformat()}")

    endpoints = resolve_fleet_endpoints(pg)

    t_as_of_str = as_of.isoformat()
    t_minus_1_str = (as_of - timedelta(days=1)).isoformat()

    queue_items = []
    rank = 1

    for agent_cfg in endpoints:
        agent_id = agent_cfg["agent_id"]
        hostname = agent_cfg["hostname"]
        scenario = agent_cfg["scenario"]

        print(f"  -> Simulating 22 consecutive days for Hostname: {hostname} ({agent_id}) [{scenario}]...")

        for offset in range(22):
            review_day = start_date + timedelta(days=offset)
            is_anomaly = (offset >= 20) and (scenario != "BENIGN")

            threat_prob = agent_cfg["threat_prob"] if is_anomaly else 0.02
            if_risk = agent_cfg["if_risk"] if is_anomaly else 0.04
            fused_risk = agent_cfg["fused_risk"] if is_anomaly else 0.03
            forecasted = agent_cfg["forecasted_risk"] if is_anomaly else (None if offset < 7 else 0.03)
            drift = agent_cfg["drift_error"] if is_anomaly else (None if offset < 7 else 0.005)
            pair = agent_cfg["pair_threat"] if (offset == 21 and is_anomaly) else (0.02 if offset == 21 else None)
            cur_scenario = scenario if is_anomaly else "BENIGN"
            scenario_probs = agent_cfg["scenario_probs"] if is_anomaly else {"BENIGN": 0.98}

            score_row = {
                "agent_id": agent_id,
                "hostname": hostname,
                "review_date": review_day,
                "source_kind": "observed_unlabeled",
                "observation_complete": True,
                "selection_status": "complete" if offset >= 7 else "temporal_warmup",
                "missing_sensors": [],
                "coverage_details": {"sensor_count": 8, "intervals_covered": 1},
                "feature_contract_version": CONTRACT_VERSION,
                "model_version": "Model V3",
                "threat_probability": threat_prob,
                "if_risk": if_risk,
                "fused_risk": fused_risk,
                "forecasted_risk": forecasted,
                "drift_error": drift,
                "pair_threat_score": pair,
                "predicted_scenario": cur_scenario,
                "scenario_probabilities": scenario_probs,
                "behavior_heads": None,
            }
            repo.save_endpoint_score(score_row)

        # If eligible anomaly candidate, add to review queue
        if agent_cfg["pair_threat"] >= 0.4103:  # frozen supervised cutoff
            evidence_dates = [d.format(t_as_of=t_as_of_str, t_minus_1=t_minus_1_str)
                              for d in agent_cfg["evidence_dates"]]
            queue_items.append({
                "agent_id": agent_id,
                "hostname": hostname,
                "pair_threat_score": agent_cfg["pair_threat"],
                "primary_hypothesis": agent_cfg["scenario"],
                "scenario_probabilities": agent_cfg["scenario_probs"],
                "evidence_dates": evidence_dates,
                "model_version": "Model V3",
            })
            rank += 1

    # Save to review queue
    repo.save_review_queue(as_of, queue_items)
    print(f"\n[+] Successfully injected {len(queue_items)} candidates into model_v3_review_queue!")
    print(f"[+] Successfully saved 22 daily scores for all {len(endpoints)} endpoints into endpoint_daily_model_scores.")
    inject_soc_dashboard_threats(pg, endpoints)
    pg.close()


def run_pipeline_simulation(as_of: date) -> None:
    """Populate ClickHouse endpoint_daily_feature_rollups and run real run_daily_model_pipeline.py."""
    from server.storage.clickhouse_storage import ClickHouseStorage
    from server.risk.daily_rollup import COLUMNS, run_daily_model_pipeline

    ch = ClickHouseStorage(
        host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure,
        ca_cert=config.clickhouse_ca_cert, query_timeout=config.clickhouse_query_timeout,
    )
    if not ch.is_connected():
        raise RuntimeError("ClickHouse is not available at configured host/port.")

    pg = PostgresStorage(get_pg_dsn(), minconn=1, maxconn=2)
    endpoints = resolve_fleet_endpoints(pg)

    start_date = as_of - timedelta(days=21)
    print(f"\n[*] Mode: PIPELINE WITH FROZEN MODEL V3")
    print(f"[*] Populating ClickHouse endpoint_daily_feature_rollups ({start_date} to {as_of})...")

    client = getattr(ch, "_client", ch)
    insert_rows = []

    for agent_cfg in endpoints:
        agent_id = agent_cfg["agent_id"]
        hostname = agent_cfg["hostname"]
        for offset in range(22):
            review_day = start_date + timedelta(days=offset)
            is_anomaly = (offset >= 20) and (agent_cfg["scenario"] != "BENIGN")
            features = generate_feature_vector(agent_cfg, offset, is_anomaly)

            row_dict = {
                "agent_id": agent_id,
                "hostname": hostname,
                "review_date": review_day,
                "observation_complete": 1,
                "journal_gap_detected": 0,
                "feature_contract_verified": 1,
                "sensor_coverage_verified": 1,
                "timezone_verified": 1,
                "source_kind": "observed_unlabeled",
                "missing_sensors_json": "[]",
                "coverage_details_json": "{}",
                "feature_contract_version": CONTRACT_VERSION,
                **features,
                "version": int(datetime.now(timezone.utc).timestamp()),
            }
            insert_rows.append(row_dict)

    # Insert into ClickHouse
    col_names = list(insert_rows[0].keys())
    data = [[r[c] for c in col_names] for r in insert_rows]
    client.insert("endpoint_daily_feature_rollups", data, column_names=col_names)
    print(f"[+] Inserted {len(insert_rows)} daily40 rows into ClickHouse.")

    print(f"[*] Running Model V3 daily batch worker...")
    repo = ModelReviewRepository(pg)
    redis_client = None
    try:
        import redis
        if config.redis_url:
            redis_client = redis.Redis.from_url(config.redis_url, decode_responses=True)
    except Exception:
        pass

    result = run_daily_model_pipeline(ch, repo, redis_client, as_of=as_of, max_reviews=20)
    print(f"[+] Model V3 Batch Result:\n{json.dumps(result, indent=2)}")

    inject_soc_dashboard_threats(pg, endpoints)
    ch.close()
    pg.close()


def clean_simulation() -> None:
    """Clean demo endpoints from PostgreSQL, ClickHouse, and Redis."""
    pg = PostgresStorage(get_pg_dsn(), minconn=1, maxconn=2)
    with pg.connection() as conn:
        with conn.cursor() as cur:
            # Clean live risk events & payloads
            cur.execute("DELETE FROM risk_events WHERE payload_id LIKE 'payload-%-live'")
            cur.execute("DELETE FROM raw_payloads WHERE payload_id LIKE 'payload-%-live'")

            # Delete only synthetic placeholder demo agents if created
            synthetic_agents = ["AGENT-FINANCE-01", "AGENT-ADMIN-03", "AGENT-HR-07", "AGENT-DEV-12", "AGENT-BENIGN-01"]
            cur.execute("DELETE FROM model_v3_review_queue WHERE agent_id = ANY(%s)", (synthetic_agents,))
            cur.execute("DELETE FROM endpoint_daily_model_scores WHERE agent_id = ANY(%s)", (synthetic_agents,))
            cur.execute("DELETE FROM model_v3_review_feedback_audit WHERE agent_id = ANY(%s)", (synthetic_agents,))
            cur.execute("DELETE FROM agents WHERE agent_id = ANY(%s)", (synthetic_agents,))
        conn.commit()
    pg.close()
    print("[+] Cleaned simulated demo records from PostgreSQL.")

    try:
        from server.storage.clickhouse_storage import ClickHouseStorage
        ch = ClickHouseStorage(
            host=config.clickhouse_host, port=config.clickhouse_port,
            username=config.clickhouse_user, password=config.clickhouse_password,
            database=config.clickhouse_db,
        )
        if ch.is_connected():
            client = getattr(ch, "_client", ch)
            client.command("ALTER TABLE risk_events DELETE WHERE payload_id LIKE 'payload-%-live'")
            print("[+] Cleaned simulated demo records from ClickHouse.")
            ch.close()
    except Exception as exc:
        print(f"[-] Note: ClickHouse cleanup skipped ({exc})")

    try:
        import redis
        if config.redis_url:
            r = redis.Redis.from_url(config.redis_url, decode_responses=True)
            keys = r.keys("snapshot:v2:*")
            if keys:
                r.delete(*keys)
                print(f"[+] Cleared {len(keys)} cached dashboard summary keys from Redis.")
    except Exception:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Model V3 & SOC Dashboard Demo Simulation Tool")
    parser.add_argument("--mode", choices=["direct", "pipeline", "clean"], default="direct",
                        help="direct: fastest PG injection; pipeline: end-to-end ML model run; clean: reset demo data")
    parser.add_argument("--as-of", type=date.fromisoformat, default=None,
                        help="Completed UTC date (default: yesterday's UTC date)")
    args = parser.parse_args()

    as_of = args.as_of or (datetime.now(timezone.utc).date() - timedelta(days=1))

    if args.mode == "clean":
        clean_simulation()
        return

    print("=" * 70)
    print(" INSIEDR MODEL V3 & SOC DASHBOARD - FLEET SIMULATION")
    print("=" * 70)

    if args.mode == "direct":
        run_direct_simulation(as_of)
    elif args.mode == "pipeline":
        run_pipeline_simulation(as_of)

    print("\n" + "=" * 70)
    print(" DEMO IS READY ON THE DASHBOARD!")
    print("=" * 70)
    print("\n[A] MODEL V3 REVIEW QUEUE:")
    print("  1. Select 'Model V3 Review Queue' in the top navigation.")
    print("  2. Click 'Refresh' to view ranked anomaly candidates for your fleet Hostnames.")
    print("  3. Look up any candidate's Agent ID in 'Endpoint warmup and review':")
    print("     -> Displays 'Day 22 of 22 · Review eligible'")
    print("     -> Review the 22-day warmup trajectory chart.")
    print("     -> Select 'Confirmed Incident' and submit forensic feedback!")

    print("\n[B] MAIN SOC DASHBOARD (Threat Matrix):")
    print("  1. Switch to 'Insider EDR - Dashboard'.")
    print("  2. Check the widgets:")
    print("     * Fleet Threat Posture: Shows 'Action Required' (Critical breaches).")
    print("     * Risk Severity Breakdown: Stratified by monitored Hostnames.")
    print("     * Detection Engine: Active with correlated risk detections.")
    print("     * Threat Detection Stream: Live incident cards titled by Hostname.")
    print("     * Attack Surface & Domain Vectors: Logon, File, USB/Device, and Web bars.")
    print("     * Fleet Severity Distribution: Donut chart displaying Critical & High breakdown.")
    print("     * Endpoint Fleet Risk Matrix: Monitored endpoints sorted by Hostname & Risk Score.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
