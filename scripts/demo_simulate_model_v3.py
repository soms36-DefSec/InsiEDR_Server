"""
Demo Simulation Tool for InsiEDR Model V3 Review Queue
------------------------------------------------------
Simulates 22 consecutive completed UTC days of endpoint activity, bypassing the 22-day
real-time wait so you can immediately demonstrate the Model V3 Review Queue in the SOC dashboard.

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

# Ensure repository root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.config import config
from server.risk.daily_adapter import CONTRACT_VERSION, RAW_FEATURES
from server.storage.postgres_storage import PostgresStorage
from server.storage.repositories.model_repo import ModelReviewRepository


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

DEMO_AGENTS = [
    {
        "agent_id": "AGENT-FINANCE-01",
        "hostname": "DESKTOP-FIN-01",
        "scenario": "DATA_HOARDING",
        "pair_threat": 0.9706,
        "threat_prob": 0.9837,
        "if_risk": 0.9418,
        "fused_risk": 0.9774,
        "forecasted_risk": 0.1393,
        "drift_error": 0.8381,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.012,
            "DATA_HOARDING": 0.915,
            "CLOUD_EXFILTRATION_PRECURSOR": 0.041,
            "CREDENTIAL_DUMP": 0.010,
            "IT_SABOTAGE": 0.008,
            "USB_EXFILTRATION_PRECURSOR": 0.007,
            "HONEYTOKEN_TRIP": 0.004,
            "KILL_CHAIN_APT": 0.003,
        },
    },
    {
        "agent_id": "AGENT-ADMIN-03",
        "hostname": "WS-SYSADMIN-03",
        "scenario": "CREDENTIAL_DUMP",
        "pair_threat": 0.8842,
        "threat_prob": 0.9120,
        "if_risk": 0.8650,
        "fused_risk": 0.9050,
        "forecasted_risk": 0.1520,
        "drift_error": 0.7530,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.025,
            "CREDENTIAL_DUMP": 0.872,
            "KILL_CHAIN_APT": 0.051,
            "DATA_HOARDING": 0.018,
            "IT_SABOTAGE": 0.014,
            "CLOUD_EXFILTRATION_PRECURSOR": 0.009,
            "USB_EXFILTRATION_PRECURSOR": 0.006,
            "HONEYTOKEN_TRIP": 0.005,
        },
    },
    {
        "agent_id": "AGENT-HR-07",
        "hostname": "LAPTOP-HR-07",
        "scenario": "USB_EXFILTRATION_PRECURSOR",
        "pair_threat": 0.7655,
        "threat_prob": 0.8140,
        "if_risk": 0.7920,
        "fused_risk": 0.8105,
        "forecasted_risk": 0.1180,
        "drift_error": 0.6925,
        "evidence_dates": ["{t_minus_1}", "{t_as_of}"],
        "scenario_probs": {
            "BENIGN": 0.048,
            "USB_EXFILTRATION_PRECURSOR": 0.805,
            "CLOUD_EXFILTRATION_PRECURSOR": 0.072,
            "DATA_HOARDING": 0.035,
            "CREDENTIAL_DUMP": 0.015,
            "IT_SABOTAGE": 0.012,
            "HONEYTOKEN_TRIP": 0.008,
            "KILL_CHAIN_APT": 0.005,
        },
    },
    {
        "agent_id": "AGENT-BENIGN-01",
        "hostname": "DESKTOP-STAFF-01",
        "scenario": "BENIGN",
        "pair_threat": 0.0421,
        "threat_prob": 0.0380,
        "if_risk": 0.0610,
        "fused_risk": 0.0415,
        "forecasted_risk": 0.0390,
        "drift_error": 0.0025,
        "evidence_dates": [],
        "scenario_probs": {
            "BENIGN": 0.965,
            "DATA_HOARDING": 0.008,
            "USB_EXFILTRATION_PRECURSOR": 0.007,
            "CLOUD_EXFILTRATION_PRECURSOR": 0.006,
            "CREDENTIAL_DUMP": 0.005,
            "IT_SABOTAGE": 0.004,
            "HONEYTOKEN_TRIP": 0.003,
            "KILL_CHAIN_APT": 0.002,
        },
    },
]


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

    return vec


def run_direct_simulation(as_of: date) -> None:
    """Directly populate PostgreSQL scores and review queue table (Fast, 100% reliable)."""
    pg = PostgresStorage(get_pg_dsn(), minconn=1, maxconn=2)
    repo = ModelReviewRepository(pg)
    start_date = as_of - timedelta(days=21)

    print(f"\n[*] Mode: DIRECT DATABASE SIMULATION")
    print(f"[*] Window: 22 completed UTC days from {start_date.isoformat()} to {as_of.isoformat()}")

    t_as_of_str = as_of.isoformat()
    t_minus_1_str = (as_of - timedelta(days=1)).isoformat()

    queue_items = []
    rank = 1

    for agent_cfg in DEMO_AGENTS:
        agent_id = agent_cfg["agent_id"]
        hostname = agent_cfg["hostname"]
        scenario = agent_cfg["scenario"]

        print(f"  -> Simulating 22 consecutive days for {hostname} ({agent_id}) [{scenario}]...")

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
    print(f"[+] Successfully saved 22 daily scores for all {len(DEMO_AGENTS)} endpoints into endpoint_daily_model_scores.")
    pg.close()


def run_pipeline_simulation(as_of: date) -> None:
    """Populate ClickHouse endpoint_daily_feature_rollups and run real run_daily_model_pipeline.py."""
    from server.storage.clickhouse_storage import ClickHouseStorage
    from server.risk.daily_rollup import COLUMNS, run_daily_model_pipeline
    from server.risk.ml_cache import _redis_client

    ch = ClickHouseStorage(
        host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure,
        ca_cert=config.clickhouse_ca_cert, query_timeout=config.clickhouse_query_timeout,
    )
    if not ch.is_connected():
        raise RuntimeError("ClickHouse is not available at configured host/port.")

    start_date = as_of - timedelta(days=21)
    print(f"\n[*] Mode: PIPELINE WITH FROZEN MODEL V3")
    print(f"[*] Populating ClickHouse endpoint_daily_feature_rollups ({start_date} to {as_of})...")

    client = getattr(ch, "_client", ch)
    insert_rows = []

    for agent_cfg in DEMO_AGENTS:
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
            # Tuple ordered according to ClickHouse table columns
            insert_rows.append(row_dict)

    # Insert into ClickHouse
    col_names = list(insert_rows[0].keys())
    data = [[r[c] for c in col_names] for r in insert_rows]
    client.insert("endpoint_daily_feature_rollups", data, column_names=col_names)
    print(f"[+] Inserted {len(insert_rows)} daily40 rows into ClickHouse.")

    print(f"[*] Running Model V3 daily batch worker...")
    pg = PostgresStorage(get_pg_dsn(), minconn=1, maxconn=2)
    repo = ModelReviewRepository(pg)
    redis_client = _redis_client(config.redis_url) if config.redis_url else None

    result = run_daily_model_pipeline(ch, repo, redis_client, as_of=as_of, max_reviews=20)
    print(f"[+] Model V3 Batch Result:\n{json.dumps(result, indent=2)}")

    ch.close()
    pg.close()


def clean_simulation() -> None:
    """Clean demo endpoints from PostgreSQL and ClickHouse."""
    pg = PostgresStorage(get_pg_dsn(), minconn=1, maxconn=2)
    with pg.connection() as conn:
        with conn.cursor() as cur:
            demo_ids = [a["agent_id"] for a in DEMO_AGENTS]
            cur.execute("DELETE FROM model_v3_review_queue WHERE agent_id = ANY(%s)", (demo_ids,))
            cur.execute("DELETE FROM endpoint_daily_model_scores WHERE agent_id = ANY(%s)", (demo_ids,))
            cur.execute("DELETE FROM model_v3_review_feedback_audit WHERE agent_id = ANY(%s)", (demo_ids,))
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
            ids_str = "', '".join(a["agent_id"] for a in DEMO_AGENTS)
            client.command(f"ALTER TABLE endpoint_daily_feature_rollups DELETE WHERE agent_id IN ('{ids_str}')")
            print("[+] Cleaned simulated demo records from ClickHouse.")
            ch.close()
    except Exception as exc:
        print(f"[-] Note: ClickHouse cleanup skipped ({exc})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Model V3 Demo Simulation Tool")
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
    print(" INSIEDR MODEL V3 REVIEW QUEUE - DEMO SIMULATION")
    print("=" * 70)

    if args.mode == "direct":
        run_direct_simulation(as_of)
    elif args.mode == "pipeline":
        run_pipeline_simulation(as_of)

    print("\n" + "=" * 70)
    print(" DEMO IS READY ON THE DASHBOARD!")
    print("=" * 70)
    print(f"1. Open the Model V3 Review Queue dashboard.")
    print(f"2. Click the 'Refresh' button.")
    print(f"3. You will see ranked anomaly candidates with threat scores:")
    for a in DEMO_AGENTS:
        if a["pair_threat"] >= 0.4103:
            print(f"   * {a['hostname']} ({a['agent_id']}): {a['scenario']} (Pair Threat: {a['pair_threat']})")
    print(f"\n4. In 'Endpoint warmup and review', look up: {DEMO_AGENTS[0]['agent_id']}")
    print(f"   -> Verifies: 'Day 22 of 22 · Review eligible'")
    print(f"   -> Review the 22-day warmup trajectory.")
    print(f"   -> Select 'Confirmed Incident' and enter forensic feedback!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
