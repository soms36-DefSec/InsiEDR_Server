"""Prepare Model V3 scenario histories and replay dataset collector events.

This command is restricted to an explicitly enabled, isolated staging instance.
It never writes synthetic rows to the observed daily40 or Model V3 tables.
"""
from __future__ import annotations

import argparse
import base64
import csv
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server.config import config

def _feature_contract():
    """Load Model V3 schema only for history preparation, not live playback."""
    from server.risk.daily_adapter import RAW_FEATURES, RATIOS, SUBSETS
    return RAW_FEATURES, RATIOS, SUBSETS

SCENARIOS = (
    ("SIM_CREDENTIAL_DUMP", "AGENT-SOCL2-64"),
    ("SIM_USB_PRECURSOR", "AGENT-DSL-174"),
    ("SIM_IT_SABOTAGE", "AGENT-DATASL-173"),
    ("SIM_CLOUD_PRECURSOR", "AGENT-MCALAB1-07"),
    ("SIM_DATA_HOARDING", "AGENT-SOCL8-53"),
    ("SIM_HONEYTOKEN_TRIP", "AGENT-SOCL8-03"),
    ("SIM_KILL_CHAIN", "AGENT-SOCL4-61"),
)
AGENTS = {agent for _, agent in SCENARIOS}
CONTROL_AGENTS = ("AGENT-SOCL4-62", "AGENT-SOCL4-63")
DISPLAY_HOSTNAMES = {agent: f"EMPLOYEE-{index:02d}"
                     for index, (_, agent) in enumerate(SCENARIOS, 1)}
DISPLAY_HOSTNAMES.update({agent: f"CONTROL-{index:02d}"
                          for index, agent in enumerate(CONTROL_AGENTS, 1)})


def display_hostname(agent: str) -> str:
    """Stable endpoint label for the isolated replay; dataset agent ID stays intact."""
    return DISPLAY_HOSTNAMES.get(agent, agent.removeprefix("AGENT-"))
COLLECTOR_FIELDS = {
    "logon": {
        "successful_logons": "successful_logons", "failed_logons": "failed_logons",
        "daily_after_hours_logon_ratio": "after_hours_logon_ratio",
        "daily_unique_pc_count": "unique_pc_count",
        "daily_pc_access_entropy": "pc_access_entropy",
        "interactive_duration_seconds": "interactive_duration_seconds",
        "session_duration_avg": "mean_session_duration_seconds",
    },
    "devices": {
        "usb_connect_count": "usb_connect_count", "usb_disconnect_count": "usb_disconnect_count",
        "after_hours_usb_usage": "after_hours_usb_ratio",
        "usb_devices_count": "distinct_usb_devices",
    },
    "file-integrity-monitor": {
        "file_access_count": "file_access_count",
        "daily_unique_filename_count": "unique_filename_count",
        "daily_new_filename_count": "new_filename_count",
        "daily_file_access_entropy": "file_access_entropy",
    },
    "usn-monitor": {"file_delete_count_delta": "file_delete_count"},
    "http": {
        "daily_http_request_count": "http_request_count",
        "daily_unique_domain_count": "unique_domain_count",
        "daily_new_domain_count": "new_domain_count",
        "daily_external_domain_ratio": "external_domain_ratio",
        "daily_domain_access_entropy": "domain_access_entropy",
        "file_sharing_site_visits": "file_sharing_visit_count",
    },
    "process-watcher": {
        "process_count": "mean_process_count",
        "admin_process_count": "admin_process_count",
        "executables_from_temp_folder": "temp_exec_count",
    },
    "network": {
        "bytes_sent": "bytes_sent", "bytes_received": "bytes_received",
        "active_connections_count": "external_connection_count",
        "unique_remote_ips": "unique_remote_ip_count",
    },
    "clipboard-monitor": {"clipboard_copy_count": "clipboard_copy_count"},
    "lsass-monitor": {
        "handle_requests": "lsass_handle_request_count",
        "memory_dump_attempts": "memory_dump_attempt_count",
    },
    "decoy-monitor": {"event_count": "decoy_access_count"},
    "wmi-activity": {"total_queries_captured": "wmi_query_count"},
    "named-pipe-monitor": {"pipe_count": "named_pipe_event_count"},
    "dns-monitor": {"total_queries_captured": "dns_query_count"},
    "email-monitor": {"outbound_attachment_count": "outbound_attachment_count"},
}
BASELINE = {
    "successful_logons": 4, "unique_pc_count": 1,
    "interactive_duration_seconds": 28800, "mean_session_duration_seconds": 14400,
    "file_access_count": 150, "unique_filename_count": 45, "new_filename_count": 10,
    "file_delete_count": 5, "file_access_entropy": 1.2,
    "http_request_count": 350, "unique_domain_count": 25, "new_domain_count": 3,
    "external_domain_ratio": .2, "domain_access_entropy": 1.3,
    "mean_process_count": 40, "peak_process_count": 65,
    "bytes_sent": 2500000, "bytes_received": 12000000,
    "external_connection_count": 25, "unique_remote_ip_count": 12,
    "clipboard_copy_count": 8, "dns_query_count": 120,
}
SCENARIO_FEATURES = {
    "SIM_CREDENTIAL_DUMP": {"lsass_handle_request_count": 28, "memory_dump_attempt_count": 4,
                            "admin_process_count": 18, "temp_exec_count": 8},
    "SIM_USB_PRECURSOR": {"usb_connect_count": 12, "usb_disconnect_count": 12,
                          "after_hours_usb_ratio": .8, "distinct_usb_devices": 3,
                          "file_access_count": 3500, "unique_filename_count": 1200},
    "SIM_IT_SABOTAGE": {"file_access_count": 3500, "file_delete_count": 1200,
                        "protected_file_touch_count": 30, "temp_exec_count": 8},
    "SIM_CLOUD_PRECURSOR": {"http_request_count": 1200, "file_sharing_visit_count": 40,
                            "external_domain_ratio": .9, "bytes_sent": 650000000},
    "SIM_DATA_HOARDING": {"file_access_count": 9800, "unique_filename_count": 4200,
                           "new_filename_count": 3900, "clipboard_copy_count": 95,
                           "protected_file_touch_count": 35},
    "SIM_HONEYTOKEN_TRIP": {"decoy_access_count": 3, "protected_file_touch_count": 5,
                             "failed_logons": 8},
    "SIM_KILL_CHAIN": {"lsass_handle_request_count": 28, "memory_dump_attempt_count": 4,
                       "wmi_query_count": 35, "named_pipe_event_count": 18,
                       "file_access_count": 9800, "file_sharing_visit_count": 40,
                       "http_request_count": 1200},
}
DDL = """
CREATE SCHEMA IF NOT EXISTS scenario_replay;
CREATE TABLE IF NOT EXISTS scenario_replay.runs (
  run_id TEXT PRIMARY KEY, as_of DATE NOT NULL, source_kind TEXT NOT NULL
    CHECK (source_kind='synthetic'), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  summary_json JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS scenario_replay.daily_scores (
  run_id TEXT NOT NULL REFERENCES scenario_replay.runs(run_id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL, review_date DATE NOT NULL, score_json JSONB NOT NULL,
  PRIMARY KEY(run_id, agent_id, review_date));
CREATE TABLE IF NOT EXISTS scenario_replay.review_queue (
  run_id TEXT NOT NULL REFERENCES scenario_replay.runs(run_id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL, rank INTEGER NOT NULL, item_json JSONB NOT NULL,
  PRIMARY KEY(run_id, agent_id));
CREATE TABLE IF NOT EXISTS scenario_replay.host_rankings (
  run_id TEXT NOT NULL REFERENCES scenario_replay.runs(run_id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL, item_json JSONB NOT NULL,
  PRIMARY KEY(run_id, agent_id));
"""


def _guard() -> None:
    if config.environment != "staging" or os.environ.get("INSIEDR_SCENARIO_REPLAY_ENABLED") != "true":
        raise RuntimeError("Scenario replay requires staging and INSIEDR_SCENARIO_REPLAY_ENABLED=true")
    if config.enable_model_pipeline:
        raise RuntimeError("Model V3 must remain in shadow mode")
    if not config.agent_auth_enforced:
        raise RuntimeError("Authenticated agent ingestion must be enforced")
    dsn = config.database_dsn or ""
    if not urlparse(dsn).path.lstrip("/").endswith("_scenario"):
        raise RuntimeError("Staging PostgreSQL database name must end in _scenario")
    if urlparse(dsn).hostname not in ("127.0.0.1", "localhost"):
        raise RuntimeError("Replay CLI must connect only to the local isolated mirror")
    if config.clickhouse_host not in ("127.0.0.1", "localhost"):
        raise RuntimeError("Replay CLI ClickHouse must be local")
    if not config.clickhouse_db.endswith("_scenario"):
        raise RuntimeError("ClickHouse database name must end in _scenario")


def init_env(args):
    path = Path(args.env_file).resolve()
    if path.exists():
        raise FileExistsError(path)
    agents = {agent: secrets.token_hex(24) for _, agent in SCENARIOS}
    pg_password, ch_password, redis_password = (secrets.token_hex(24) for _ in range(3))
    aes_key = secrets.token_hex(32)
    lines = {
        "INSIEDR_ENVIRONMENT": "staging",
        "INSIEDR_SCENARIO_REPLAY_ENABLED": "true",
        "INSIEDR_ENABLE_MODEL_PIPELINE": "false",
        "INSIEDR_AUTH_ENFORCED": "false",
        "INSIEDR_AGENT_AUTH_ENFORCED": "true",
        "INSIEDR_OPERATOR_API_KEY": secrets.token_hex(24),
        "INSIEDR_AGENT_TOKENS": json.dumps(agents, separators=(",", ":")),
        "INSIEDR_SCENARIO_AGENT_TOKENS": json.dumps(agents, separators=(",", ":")),
        "INSIEDR_AES_KEY": aes_key,
        "INSIEDR_SCENARIO_AES_KEY": aes_key,
        "POSTGRES_USER": "insiedr_scenario",
        "POSTGRES_DB": "insiedr_scenario",
        "POSTGRES_PASSWORD": pg_password,
        "INSIEDR_DATABASE_DSN": f"postgresql://insiedr_scenario:{pg_password}@127.0.0.1:15432/insiedr_scenario",
        "CLICKHOUSE_USER": "scenario",
        "CLICKHOUSE_DB": "insiedr_scenario",
        "CLICKHOUSE_PASSWORD": ch_password,
        "INSIEDR_CLICKHOUSE_HOST": "127.0.0.1",
        "INSIEDR_CLICKHOUSE_PORT": "18123",
        "INSIEDR_CLICKHOUSE_USER": "scenario",
        "INSIEDR_CLICKHOUSE_DB": "insiedr_scenario",
        "INSIEDR_CLICKHOUSE_PASSWORD": ch_password,
        "REDIS_PASSWORD": redis_password,
    }
    path.write_text("\n".join(f"{key}={value}" for key, value in lines.items()) + "\n", encoding="utf-8")
    print(f"Created {path}; keep it private. Operator key is in this file.")


def _load_env(path):
    env_file = Path(path)
    if not env_file.is_file():
        raise FileNotFoundError(f"Run init-env first: {env_file}")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line and not line.lstrip().startswith("#"):
            key, sep, value = line.partition("=")
            if sep:
                os.environ[key] = value


def _dataset_roots(args):
    root = Path(args.dataset_root).resolve()
    paths = {name: root / name for name in ("Dataset_RealTime", "Dataset_Simulated", "Dataset_Simulated_Harmonized")}
    if not all(path.is_dir() for path in paths.values()):
        raise FileNotFoundError("Expected all three dataset folders under --dataset-root")
    return paths


def _files(path: Path):
    return {file.name.split("_dataset_")[0]: file for file in path.glob("*_dataset_*.csv")}


def _schema_audit(roots):
    original = _files(roots["Dataset_Simulated"])
    harmonized = _files(roots["Dataset_Simulated_Harmonized"])
    report = {}
    for collector in sorted(COLLECTOR_FIELDS):
        if collector not in original or collector not in harmonized:
            raise ValueError(f"Collector missing from source or harmonized dataset: {collector}")
        headers = []
        for file in (original[collector], harmonized[collector]):
            with file.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
                headers.append(set(next(csv.reader(handle))))
        raw, checked = headers
        report[collector] = {"raw_only_columns": len(raw - checked),
            "harmonized_only_columns": len(checked - raw),
            "missing_model_source_columns": sorted(set(COLLECTOR_FIELDS[collector]) - raw)}
    return report


def _number(value):
    if value in (None, "", "NaN", "nan"):
        return None
    if str(value).lower() in ("true", "false"):
        return float(str(value).lower() == "true")
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _utc(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _collector_samples(path, agents, *, windows=None, max_per_key=128):
    """Bound memory while reading collector CSVs; retain source rows and numeric samples."""
    raw_features, _, _ = _feature_contract()
    metrics = {agent: {name: [] for name in raw_features} for agent in agents}
    snapshots = {agent: {} for agent in agents}
    for collector, file in _files(path).items():
        aliases = COLLECTOR_FIELDS.get(collector, {})
        with file.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            for row in csv.DictReader(handle):
                agent = row.get("agent_id")
                if agent not in agents or row.get("status") != "success":
                    continue
                if windows is not None:
                    start, end = windows[agent]
                    ts = _utc(row["timestamp"])
                    if not start <= ts < end:
                        continue
                source_hours = snapshots[agent].setdefault(collector, [])
                if len(source_hours) < 22:
                    hour_key = row["timestamp"][:13]
                    if not source_hours or source_hours[-1]["timestamp"][:13] != hour_key:
                        source_hours.append(row)
                for source, target in aliases.items():
                    value = _number(row.get(source))
                    if value is None:
                        continue
                    sample = metrics[agent][target]
                    if windows is not None:
                        if not sample or value > sample[0]:
                            sample[:] = [max(0.0, value)]
                    elif len(sample) < max_per_key:
                        sample.append(max(0.0, value))
    return metrics, snapshots


def _vector(agent, scenario, day, index, baseline, peaks):
    raw_features, ratios, subsets = _feature_contract()
    values = {name: float(BASELINE.get(name, 0)) for name in raw_features}
    for name, samples in baseline[agent].items():
        if samples:
            values[name] = max(0.0, statistics.median(samples))
    if index >= 19:
        for name, samples in peaks[agent].items():
            if samples:
                values[name] = max(values[name], max(samples))
        for name, floor in SCENARIO_FEATURES.get(scenario, {}).items():
            values[name] = max(values[name], float(floor))
    values["weekend_activity"] = float(day.weekday() >= 5)
    values["peak_process_count"] = max(values["peak_process_count"], values["mean_process_count"])
    values["interactive_duration_seconds"] = min(values["interactive_duration_seconds"], 86400)
    for name in ratios:
        values[name] = min(values[name], 1.0)
    for child, total in subsets:
        values[total] = max(values[total], values[child])
    return [values[name] for name in raw_features]


def _history_window(args):
    """Resolve a window containing only completed UTC calendar days."""
    days = args.days
    if not 22 <= days <= 90:
        raise ValueError("--days must be between 22 and 90")
    completed_through = datetime.now(timezone.utc).date() - timedelta(days=1)
    end = (args.start_date + timedelta(days=days - 1) if args.start_date else
           args.as_of or completed_through)
    start = end - timedelta(days=days - 1)
    if end > completed_through:
        raise ValueError("Replay history must end on a completed UTC day")
    if args.start_date and args.as_of and args.as_of != end:
        raise ValueError("--start-date, --days, and --as-of disagree")
    return start, end, days


def _scenario_offsets(days):
    """Recurring dataset scenario dates, with a consecutive final sequence."""
    return set(range(7, days - 3, 10)) | set(range(days - 3, days))


def _pg():
    import psycopg2
    return psycopg2.connect(config.database_dsn)


def _save_scores(run_id, as_of, output):
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    if summary.get("source_admission") != "declared_synthetic":
        raise ValueError("Frozen model did not acknowledge synthetic source")
    summary["scenario_agents"] = sorted(AGENTS)
    summary["control_agents"] = list(CONTROL_AGENTS)
    with _pg() as conn, conn.cursor() as cur:
        cur.execute(DDL)
        cur.execute("INSERT INTO scenario_replay.runs(run_id,as_of,source_kind,summary_json) "
                    "VALUES (%s,%s,'synthetic',%s::jsonb)", (run_id, as_of, json.dumps(summary)))
        with (output / "daily_predictions.csv").open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                cur.execute("INSERT INTO scenario_replay.daily_scores(run_id,agent_id,review_date,score_json) "
                            "VALUES (%s,%s,%s,%s::jsonb)",
                            (run_id, row["hostname"], row["date"], json.dumps(row)))
        with (output / "review_queue.csv").open(newline="", encoding="utf-8") as handle:
            for rank, row in enumerate(csv.DictReader(handle), 1):
                cur.execute("INSERT INTO scenario_replay.review_queue(run_id,agent_id,rank,item_json) "
                            "VALUES (%s,%s,%s,%s::jsonb)",
                            (run_id, row["hostname"], rank, json.dumps(row)))
        with (output / "host_rankings.csv").open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                cur.execute("INSERT INTO scenario_replay.host_rankings(run_id,agent_id,item_json) "
                            "VALUES (%s,%s,%s::jsonb)",
                            (run_id, row["hostname"], json.dumps(row)))
    return summary


def _backfill(run_id, start, days, snapshots, dataset_name,
              scenario_items, scenario_dataset):
    from server.storage.clickhouse_storage import ClickHouseStorage
    from server.storage.clickhouse_telemetry_queries import extract_summary_preview
    from server.risk.pipeline import process_telemetry_risk
    ch = ClickHouseStorage(host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure, dlq_enabled=False)
    try:
        if not ch.is_connected():
            raise RuntimeError("isolated ClickHouse unavailable")
        ch.ensure_schema()
        rows = []
        explorer_rows = []
        for agent, collectors in snapshots.items():
            hostname = display_hostname(agent)
            for offset in range(days):
                day = start + timedelta(days=offset)
                for collector, sources in collectors.items():
                    for slot in range(3):
                        source = sources[(offset * 3 + slot) % len(sources)]
                        payload = {key: value for key, value in source.items()
                                   if key not in ("timestamp", "username", "hostname", "agent_id", "status") and value not in ("", None)}
                        original = source.get("timestamp", "")
                        shifted = datetime.combine(day, _utc(original).time(), timezone.utc)
                        payload_id = f"scenario-{run_id}-{agent}-{collector}-{offset}-{slot}"
                        rows.append((payload_id, agent, collector, shifted,
                                     hostname, "success", json.dumps(payload), "scenario_replay",
                                     json.dumps({"source_dataset": dataset_name, "original_timestamp": original,
                                                 "original_hostname": source.get("hostname"),
                                                 "run_id": run_id, "source_kind": "synthetic"})))
                        explorer_rows.append((payload_id, agent, collector, shifted, hostname,
                            source.get("username", ""), "success",
                            extract_summary_preview(collector, payload), json.dumps(payload)))
        risk_rows = []
        for scenario, agent in SCENARIOS:
            item = scenario_items[scenario]
            frames = _scenario_frames(scenario_dataset, item)
            hostname = display_hostname(agent)
            username = item.get("target_username", "")
            for offset in sorted(_scenario_offsets(days)):
                day = start + timedelta(days=offset)
                best = None
                for frame_index, (_, sources) in enumerate(frames):
                    source_row = next(iter(sources.values()))
                    original = source_row["timestamp"]
                    shifted = datetime.combine(day, _utc(original).time(), timezone.utc)
                    payload_id = f"scenario-{run_id}-{agent}-evidence-{offset}-{frame_index}"
                    collectors = []
                    for collector, source in sources.items():
                        body = {key: value for key, value in source.items()
                                if key not in ("timestamp", "username", "hostname", "agent_id", "status")
                                and value not in ("", None)}
                        collectors.append({"collector": collector, "status": "success", "payload": body})
                        rows.append((payload_id, agent, collector, shifted, hostname, "success",
                            json.dumps(body), "scenario_replay", json.dumps({"source_dataset": "Dataset_Simulated",
                                "original_timestamp": source["timestamp"],
                                "original_hostname": source.get("hostname"), "run_id": run_id,
                                "source_kind": "synthetic", "scenario": scenario})))
                        explorer_rows.append((payload_id, agent, collector, shifted, hostname, username,
                            "success", extract_summary_preview(collector, body), json.dumps(body)))
                    result = process_telemetry_risk(None, {"payload_id": payload_id, "agent_id": agent,
                        "hostname": hostname, "username": username,
                        "collected_at": shifted.isoformat(), "collectors": collectors}, emit=False)
                    if result.get("summary") == "Error evaluating risk.":
                        raise RuntimeError(f"Historical risk evaluation failed for {agent} {day}")
                    if best is None or result["risk_score"] > best["risk_score"]:
                        best = result
                if best is not None and best["risk_score"] > 0:
                    risk_rows.append((best["payload_id"], agent, username, best["risk_score"],
                        best["risk_level"], json.dumps(best["correlated_signals_json"]),
                        best["summary"], _utc(best["collected_at"])))
        ch._client.insert("collector_results", rows, column_names=(
            "payload_id", "agent_id", "collector", "collector_collected_at", "hostname",
            "status", "payload_json", "source_quality", "agent_quality_json"))
        ch._client.insert("telemetry_events", explorer_rows, column_names=(
            "payload_id", "agent_id", "collector_name", "timestamp", "hostname",
            "username", "status", "summary_preview", "raw_payload_json"))
        if risk_rows:
            ch._client.insert("risk_events", risk_rows, column_names=(
                "payload_id", "agent_id", "username", "risk_score", "risk_level",
                "correlated_signals_json", "summary", "created_at"))
    finally:
        ch.close()
    with _pg() as conn, conn.cursor() as cur:
        for scenario, agent in SCENARIOS:
            cur.execute("INSERT INTO agents (agent_id, hostname, username_last_seen, first_seen_at, "
                        "last_seen_at, status) VALUES (%s,%s,%s,%s,%s,'offline') "
                        "ON CONFLICT (agent_id) DO NOTHING", (agent, display_hostname(agent),
                        scenario_items[scenario].get("target_username", ""), start,
                        start + timedelta(days=days - 1)))
        for agent in CONTROL_AGENTS:
            cur.execute("INSERT INTO agents (agent_id, hostname, first_seen_at, last_seen_at, status) "
                        "VALUES (%s,%s,%s,%s,'offline') ON CONFLICT (agent_id) DO NOTHING",
                        (agent, display_hostname(agent), start,
                         start + timedelta(days=days - 1)))
    return {"collector_rows": len(rows), "explorer_rows": len(explorer_rows),
            "computed_historical_risk_events": len(risk_rows)}


def prepare(args):
    _guard()
    raw_features, _, _ = _feature_contract()
    roots = _dataset_roots(args)
    schema_audit = _schema_audit(roots)
    start, as_of, days = _history_window(args)
    scenario_offsets = _scenario_offsets(days)
    run_id = args.run_id or uuid.uuid4().hex[:12]
    output = Path(args.output_root).resolve() / run_id
    if output.exists():
        raise FileExistsError(output)
    manifest = json.loads((roots["Dataset_Simulated_Harmonized"] / "simulation_manifest.json").read_text(encoding="utf-8"))
    by_scenario = {item["scenario_id"]: item for item in manifest["scenarios"]}
    windows = {}
    for scenario, agent in SCENARIOS:
        item = by_scenario[scenario]
        if item["target_agent_id"] != agent:
            raise ValueError(f"manifest identity mismatch: {scenario}")
        windows[agent] = (_utc(item["start_time"]), _utc(item["end_time"]))
    baseline, snapshots = _collector_samples(roots["Dataset_RealTime"], AGENTS | set(CONTROL_AGENTS))
    peaks, _ = _collector_samples(roots["Dataset_Simulated"], AGENTS, windows=windows)
    output.mkdir(parents=True)
    with (output / "X.csv").open("w", newline="", encoding="utf-8") as feature_file, \
         (output / "metadata.csv").open("w", newline="", encoding="utf-8") as metadata_file:
        feature_writer, metadata_writer = csv.writer(feature_file), csv.writer(metadata_file)
        feature_writer.writerow(raw_features)
        metadata_writer.writerow(("hostname", "date", "observation_complete", "source_kind"))
        for scenario, agent in SCENARIOS:
            for offset in range(days):
                day = start + timedelta(days=offset)
                feature_writer.writerow(_vector(agent, scenario, day,
                    19 if offset in scenario_offsets else 0, baseline, peaks))
                metadata_writer.writerow((agent, day.isoformat(), 1, "synthetic"))
        for agent in CONTROL_AGENTS:
            for offset in range(days):
                day = start + timedelta(days=offset)
                feature_writer.writerow(_vector(agent, "", day, 0, baseline,
                    {agent: {name: [] for name in raw_features}}))
                complete = int(not (agent == CONTROL_AGENTS[0] and offset == days - 1))
                metadata_writer.writerow((agent, day.isoformat(), complete, "synthetic"))
    model_output = output / "model"
    if args.precomputed_model:
        source_model = Path(args.precomputed_model).resolve()
        from scripts.check_model_v3_prerequisites import verify_frozen_files
        verify_frozen_files()
        for name in ("X.csv", "metadata.csv"):
            generated = hashlib.sha256((output / name).read_bytes()).hexdigest()
            source = hashlib.sha256((source_model.parent / name).read_bytes()).hexdigest()
            if generated != source:
                raise RuntimeError(f"Precomputed Model V3 input mismatch: {name}")
        source_summary = json.loads((source_model / "summary.json").read_text(encoding="utf-8"))
        if (source_summary.get("as_of") != as_of.isoformat() or
                source_summary.get("source_admission") != "declared_synthetic"):
            raise RuntimeError("Precomputed Model V3 output has wrong date or source admission")
        shutil.copytree(source_model, model_output)
    else:
        python_bin = ROOT / "model" / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python_bin.is_file():
            raise FileNotFoundError(python_bin)
        subprocess.run((str(python_bin), str(ROOT / "model" / "predict.py"),
                        "--features", str(output / "X.csv"), "--metadata", str(output / "metadata.csv"),
                        "--output", str(model_output), "--as-of", as_of.isoformat()),
                       cwd=ROOT, timeout=300, check=True)
    with (model_output / "review_queue.csv").open(newline="", encoding="utf-8") as handle:
        selected = {row["hostname"] for row in csv.DictReader(handle)}
    if CONTROL_AGENTS[0] in selected:
        raise RuntimeError("Missing-day control was selected for review; refusing to publish run")
    model_summary = json.loads((model_output / "summary.json").read_text(encoding="utf-8"))
    if (model_summary.get("eligible_hosts") != len(AGENTS) + 1 or
            model_summary.get("total_hosts") != len(AGENTS) + len(CONTROL_AGENTS)):
        raise RuntimeError("Frozen model eligibility did not match scenario and control expectations")
    dates_by_agent = {}
    with (model_output / "daily_predictions.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            dates_by_agent.setdefault(row["hostname"], set()).add(row["date"])
    if any(len(dates_by_agent.get(agent, ())) != days for agent in AGENTS | set(CONTROL_AGENTS)):
        raise RuntimeError(f"Frozen model output does not contain {days} unique dates per host")
    preview_only = getattr(args, "preview_only", False)
    if preview_only:
        summary = json.loads((model_output / "summary.json").read_text(encoding="utf-8"))
        summary["scenario_agents"] = sorted(AGENTS)
        summary["control_agents"] = list(CONTROL_AGENTS)
    else:
        backfill_counts = _backfill(run_id, start, days, snapshots, "Dataset_RealTime",
                                   by_scenario, roots["Dataset_Simulated"])
        summary = _save_scores(run_id, as_of, model_output)
    (output / "run.json").write_text(json.dumps({"run_id": run_id, "as_of": as_of.isoformat(),
        "start_date": start.isoformat(), "end_date": as_of.isoformat(), "days": days,
        "source_kind": "synthetic", "preview_only": preview_only,
        "scenario_agents": sorted(AGENTS), "control_agents": list(CONTROL_AGENTS),
        "scenario_dates": [(start + timedelta(days=i)).isoformat() for i in sorted(scenario_offsets)],
        "synthetic_feature_floors": SCENARIO_FEATURES,
        "backfill_counts": backfill_counts if not preview_only else None,
        "harmonized_schema_audit": schema_audit,
        "summary": summary}, indent=2), encoding="utf-8")
    print(json.dumps({"run_id": run_id, "as_of": as_of.isoformat(), "reviewed": summary["reviewed"],
                      "output": str(output)}, indent=2))


def preview(args):
    args.preview_only = True
    prepare(args)


def _scenario_frames(dataset, item):
    agent, start, end = item["target_agent_id"], _utc(item["start_time"]), _utc(item["end_time"])
    grouped = {}
    for collector in item["injected_collectors"]:
        file = _files(dataset).get(collector)
        if file is None:
            continue
        with file.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            for row in csv.DictReader(handle):
                if row.get("agent_id") != agent or row.get("status") != "success":
                    continue
                ts = _utc(row["timestamp"])
                if start <= ts < end:
                    bucket = int((ts-start).total_seconds() // 30)
                    grouped.setdefault(bucket, {})[collector] = row
    if not grouped:
        raise ValueError(f"No source scenario rows for {agent}")
    buckets = sorted(grouped)
    count = 24 if item["scenario_id"] == "SIM_KILL_CHAIN" else 12
    indexes = sorted({round(i * (len(buckets)-1) / (count-1)) for i in range(count)})
    selected = [(buckets[i], grouped[buckets[i]]) for i in indexes]
    for phase in item.get("phases", []):
        phase_start, phase_end = _utc(phase["start_time"]), _utc(phase["end_time"])
        if not any(phase_start <= start + timedelta(seconds=bucket * 30) < phase_end and
                   set(rows).intersection(phase["active_collectors"]) for bucket, rows in selected):
            raise RuntimeError(f"Missing playback evidence for {phase['phase_name']}")
    return selected


def _envelope(agent, hostname, username, source_rows, run_id, aes_key, token):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from server.crypto.aesgcm_plugin import AES_GCM_AAD
    from shared.protocol import encrypted_payload_headers
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload_id = f"scenario-{run_id}-{uuid.uuid4()}"
    collectors = []
    for collector, row in source_rows.items():
        original = row.get("timestamp", "")
        body = {key: value for key, value in row.items()
                if key not in ("timestamp", "username", "hostname", "agent_id", "status") and value not in ("", None)}
        collectors.append({"collector": collector, "collected_at": now, "hostname": hostname,
            "status": "success", "payload": body,
            "quality": {"source_kind": "synthetic", "source_dataset": "Dataset_Simulated",
                        "original_timestamp": original,
                        "original_hostname": row.get("hostname"), "run_id": run_id}})
    payload = {"schema": "insiedr.agent.telemetry.v1", "protocol_version": "2.0",
        "payload_id": payload_id, "agent_id": agent, "hostname": hostname,
        "collected_at": now, "username": username, "collectors": collectors,
        "summary": {"collector_count": len(collectors), "success_count": len(collectors), "failed_count": 0}}
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, json.dumps(payload).encode(), AES_GCM_AAD)
    envelope = {"protocol_version": "2.0", "scheme": "aes-256-gcm", "payload_id": payload_id,
        "key_id": "scenario-replay", "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(), "created_at": now}
    headers = encrypted_payload_headers(envelope, agent, payload_id)
    headers["X-Agent-Token"] = token
    return envelope, headers


def verify(args):
    """Run sampled source frames through the unchanged live risk pipeline offline."""
    _guard()
    from server.risk.pipeline import process_telemetry_risk

    roots = _dataset_roots(args)
    manifest = json.loads((roots["Dataset_Simulated_Harmonized"] / "simulation_manifest.json").read_text(encoding="utf-8"))
    items = {item["scenario_id"]: item for item in manifest["scenarios"]}
    report = []
    for scenario, agent in SCENARIOS:
        frames = _scenario_frames(roots["Dataset_Simulated"], items[scenario])
        best = {"risk_score": -1}
        for _, rows in frames:
            payload = {"payload_id": f"verification-{uuid.uuid4()}", "agent_id": agent,
                "hostname": display_hostname(agent), "username": items[scenario].get("target_username", ""),
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "collectors": [{"collector": collector, "status": "success", "payload": {
                    key: value for key, value in row.items()
                    if key not in ("timestamp", "username", "hostname", "agent_id", "status") and value not in ("", None)}}
                    for collector, row in rows.items()]}
            risk = process_telemetry_risk(None, payload)
            if risk["risk_score"] > best["risk_score"]:
                best = risk
        report.append({"scenario": scenario, "agent_id": agent, "frames": len(frames),
                       "risk_score": best["risk_score"], "risk_level": best.get("risk_level"),
                       "summary": best.get("summary")})
    print(json.dumps(report, indent=2))
    if any(item["risk_score"] <= 0 or "Heuristics:" not in item["summary"] for item in report):
        raise RuntimeError("At least one scenario did not produce a heuristic live risk event")


def play(args):
    _guard()
    import httpx
    from shared.crypto_utils import normalize_aes_key
    roots = _dataset_roots(args)
    output = Path(args.output_root).resolve() / args.run_id
    manifest_path = output / "run.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Run prepare first")
    manifest = json.loads((roots["Dataset_Simulated_Harmonized"] / "simulation_manifest.json").read_text(encoding="utf-8"))
    items = {item["scenario_id"]: item for item in manifest["scenarios"]}
    tokens = json.loads(os.environ["INSIEDR_SCENARIO_AGENT_TOKENS"])
    key = normalize_aes_key(os.environ["INSIEDR_SCENARIO_AES_KEY"])
    base_url = args.server_url.rstrip("/")
    if not base_url.startswith("http://127.0.0.1:") and not base_url.startswith("http://localhost:"):
        raise ValueError("Replay endpoint must be a local isolated mirror URL")
    stop_file = output / "stop"
    stop_file.unlink(missing_ok=True)
    with httpx.Client(timeout=30) as client:
        operator_key = os.environ["INSIEDR_OPERATOR_API_KEY"]
        preflight = client.get(base_url + "/api/v1/detection/ml/scenario/hosts",
                               headers={"X-Operator-Key": operator_key})
        preflight.raise_for_status()
        if preflight.json().get("run_id") != args.run_id:
            raise RuntimeError("Website is not serving the prepared scenario run")
        for scenario, agent in SCENARIOS:
            if args.scenario and args.scenario != scenario:
                continue
            item = items[scenario]
            frames = _scenario_frames(roots["Dataset_Simulated"], item)
            started_at = datetime.now(timezone.utc)
            for bucket, rows in frames:
                if stop_file.exists():
                    print("Playback stopped")
                    return
                envelope, headers = _envelope(agent, display_hostname(agent), item.get("target_username", ""), rows,
                    args.run_id, key, tokens[agent])
                response = client.post(base_url + "/api/logs", json=envelope, headers=headers)
                response.raise_for_status()
                if response.status_code != 202:
                    raise RuntimeError(f"Ingest did not accept {agent} frame {bucket}")
                (output / "progress.json").write_text(json.dumps({"scenario": scenario,
                    "agent_id": agent, "frame": bucket, "sent_at": datetime.now(timezone.utc).isoformat()}),
                    encoding="utf-8")
                print(f"{agent} {scenario} frame={bucket} accepted", flush=True)
                time.sleep(args.interval)
            deadline = time.monotonic() + 45
            while True:
                host_response = client.get(base_url + "/api/v1/detection/ml/scenario/hosts",
                    headers={"X-Operator-Key": operator_key})
                host_response.raise_for_status()
                host = next((entry for entry in host_response.json()["hosts"] if entry["agent_id"] == agent), None)
                event_at = _utc(host["live_at"]) if host and host.get("live_at") else None
                explorer_response = client.get(base_url + "/api/v1/telemetry/explorer",
                    params={"agent_id": agent, "start_time": started_at.isoformat(), "limit": 1},
                    headers={"X-Operator-Key": operator_key})
                explorer_response.raise_for_status()
                if (host and (host.get("live_peak_risk_score") or 0) > 0 and event_at and
                        event_at >= started_at and explorer_response.json().get("events")):
                    print(f"{agent} confirmed: searchable collector event and live risk={host['live_risk_score']}", flush=True)
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Live ingestion verification failed for {agent}")
                time.sleep(2)


def status(args):
    _guard()
    path = Path(args.output_root).resolve() / args.run_id / "run.json"
    if not path.exists():
        raise FileNotFoundError(path)
    result = json.loads(path.read_text(encoding="utf-8"))
    progress = path.with_name("progress.json")
    if progress.exists():
        result["playback"] = json.loads(progress.read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2))


def stop(args):
    _guard()
    path = Path(args.output_root).resolve() / args.run_id
    if not (path / "run.json").exists():
        raise FileNotFoundError(path)
    (path / "stop").touch()
    print("Stop requested")


def reset(args):
    _guard()
    run_id = args.run_id
    if not run_id:
        raise ValueError("reset requires --run-id")
    output = Path(args.output_root).resolve() / run_id
    if not (output / "run.json").is_file():
        raise FileNotFoundError(output / "run.json")
    subprocess.run(("docker", "compose", "--env-file", str(Path(args.env_file).resolve()),
                    "-f", str(ROOT / "docker-compose.scenario.yml"), "down", "--volumes"),
                   cwd=ROOT, check=True)
    (output / "reset.json").write_text(json.dumps({"reset_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id, "isolated_volumes_removed": True}), encoding="utf-8")
    print("Isolated PostgreSQL, ClickHouse, and Redis volumes removed. Local run artifacts retained for audit.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init-env", "preview", "verify", "prepare", "play", "status", "stop", "reset"))
    parser.add_argument("--env-file", default=str(ROOT / ".env.scenario"))
    parser.add_argument("--dataset-root", default=r"D:\Projects\AISH")
    parser.add_argument("--output-root", default=str(ROOT / "data" / "scenario_replay"))
    parser.add_argument("--run-id")
    parser.add_argument("--precomputed-model", help="Frozen-model output for identical X.csv and metadata.csv")
    parser.add_argument("--as-of", type=date.fromisoformat)
    parser.add_argument("--start-date", type=date.fromisoformat)
    parser.add_argument("--days", type=int, default=22)
    parser.add_argument("--scenario", choices=[name for name, _ in SCENARIOS])
    parser.add_argument("--server-url", default="http://127.0.0.1:5088")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if args.interval < 0:
        parser.error("--interval must be nonnegative")
    if args.command in ("play", "status", "stop", "reset") and not args.run_id:
        parser.error(f"{args.command} requires --run-id")
    if args.run_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.run_id):
        parser.error("--run-id must be 1-64 letters, digits, underscores, or hyphens")
    if args.command == "init-env":
        init_env(args)
    else:
        _load_env(args.env_file)
        globals()[args.command](args)


if __name__ == "__main__":
    main()
