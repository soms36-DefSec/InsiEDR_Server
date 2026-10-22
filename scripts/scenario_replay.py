"""Prepare and replay provenance-tagged dataset events in the main deployment.

This command requires an explicit main-presentation opt-in, uses authenticated
ingestion, and keeps Model V3 in shadow mode. Synthetic history remains marked
as synthetic and never changes live alert severity.
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
MAIN_AGENT_IDS = {agent: f"AGENT-EMPLOYEE-{index:02d}"
                  for index, (_, agent) in enumerate(SCENARIOS, 1)}
MAIN_CONTROL_IDS = {agent: f"AGENT-CONTROL-{index:02d}"
                    for index, agent in enumerate(CONTROL_AGENTS, 1)}
DISPLAY_HOSTNAMES = {agent: f"EMPLOYEE-{index:02d}"
                     for index, (_, agent) in enumerate(SCENARIOS, 1)}
DISPLAY_HOSTNAMES.update({agent: f"CONTROL-{index:02d}"
                          for index, agent in enumerate(CONTROL_AGENTS, 1)})


def display_hostname(agent: str) -> str:
    """Stable employee label for the main deployment; source IDs stay in provenance."""
    return DISPLAY_HOSTNAMES.get(agent, agent.removeprefix("AGENT-"))


def target_agent(source_agent: str, args) -> str:
    return MAIN_AGENT_IDS.get(source_agent, MAIN_CONTROL_IDS.get(source_agent, source_agent))
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


def _guard(args) -> None:
    if os.environ.get("INSIEDR_MAIN_PRESENTATION_ENABLED") != "true":
        raise RuntimeError("Main replay requires INSIEDR_MAIN_PRESENTATION_ENABLED=true")
    if config.enable_model_pipeline:
        raise RuntimeError("Model V3 must remain in shadow mode")
    if not config.agent_auth_enforced:
        raise RuntimeError("Authenticated agent ingestion must be enforced")
    dsn = urlparse(config.database_dsn or "")
    if (dsn.hostname != "db" or not dsn.path.lstrip("/")
            or dsn.path.lstrip("/").endswith("_scenario")
            or config.clickhouse_host != "clickhouse"
            or config.clickhouse_db.endswith("_scenario")):
        raise RuntimeError("Replay must run inside the main backend Compose network")


def install_main_tokens(args):
    """Add only the seven replay identities without replacing existing agent auth."""
    if args.target != "main":
        raise RuntimeError("Use --target main for this command")
    main_env = Path(args.env_file).resolve()
    if not main_env.is_file():
        raise FileNotFoundError("Main env file is required")
    lines = main_env.read_text(encoding="utf-8").splitlines()
    values = dict(line.split("=", 1) for line in lines if "=" in line and not line.lstrip().startswith("#"))
    prior_replay = json.loads(values.get("INSIEDR_SCENARIO_AGENT_TOKENS", "{}"))
    targets = [MAIN_AGENT_IDS[agent] for _, agent in SCENARIOS]
    existing = dict(config.agent_tokens)
    if existing or not config.agent_bearer_token:
        replay_tokens = {agent: prior_replay.get(agent) or secrets.token_hex(24) for agent in targets}
    else:
        replay_tokens = {agent: config.agent_bearer_token for agent in targets}
    updates = {
        "INSIEDR_MAIN_PRESENTATION_ENABLED": "true",
        "INSIEDR_SCENARIO_AGENT_TOKENS": json.dumps(replay_tokens, separators=(",", ":")),
    }
    if existing or not config.agent_bearer_token:
        for agent, token in replay_tokens.items():
            if token in existing and existing[token] != agent:
                raise RuntimeError("A replay token is already bound to another agent")
            existing[token] = agent
        updates["INSIEDR_AGENT_TOKENS"] = json.dumps(existing, separators=(",", ":"))
    present = set()
    amended = []
    for line in lines:
        key = line.partition("=")[0]
        if key in updates:
            amended.append(f"{key}={updates[key]}")
            present.add(key)
        else:
            amended.append(line)
    amended.extend(f"{key}={value}" for key, value in updates.items() if key not in present)
    backup = main_env.with_name(main_env.name + ".before-main-replay-"
                                + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"))
    shutil.copy2(main_env, backup)
    os.chmod(backup, 0o600)
    temporary = main_env.with_name(main_env.name + ".main-replay-tmp")
    temporary.write_text("\n".join(amended) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, main_env)
    print(f"Main agent credentials updated for seven replay hosts; backup: {backup.name}")


def _load_env(path, *, preserve_existing=False):
    env_file = Path(path)
    if not env_file.is_file():
        raise FileNotFoundError(f"Main deployment environment file not found: {env_file}")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line and not line.lstrip().startswith("#"):
            key, sep, value = line.partition("=")
            if sep:
                if not preserve_existing or key not in os.environ:
                    os.environ[key] = value


def _dataset_roots(args):
    root = Path(args.dataset_root).resolve()
    paths = {name: root / name for name in ("Dataset_RealTime", "Dataset_Simulated", "Dataset_Simulated_Harmonized")}
    if not all(path.is_dir() for path in paths.values()):
        portable = ROOT / "data" / "scenario_replay" / "portable_sources"
        paths = {name: portable / name for name in ("Dataset_RealTime", "Dataset_Simulated", "Dataset_Simulated_Harmonized")}
        if not all(path.is_dir() for path in paths.values()):
            raise FileNotFoundError("Expected all three dataset folders under --dataset-root or data/scenario_replay/portable_sources")
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


def _save_scores(run_id, as_of, output, args):
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    if summary.get("source_admission") != "declared_synthetic":
        raise ValueError("Frozen model did not acknowledge synthetic source")
    summary["scenario_agents"] = sorted(target_agent(agent, args) for agent in AGENTS)
    summary["control_agents"] = [target_agent(agent, args) for agent in CONTROL_AGENTS]
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
              scenario_items, scenario_dataset, args):
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
        for source_agent, collectors in snapshots.items():
            agent = target_agent(source_agent, args)
            hostname = display_hostname(source_agent)
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
                                                 "source_agent_id": source_agent,
                                                 "run_id": run_id, "source_kind": "synthetic"})))
                        explorer_rows.append((payload_id, agent, collector, shifted, hostname,
                            source.get("username", ""), "success",
                            extract_summary_preview(collector, payload), json.dumps(payload)))
        risk_rows = []
        for scenario, source_agent in SCENARIOS:
            agent = target_agent(source_agent, args)
            item = scenario_items[scenario]
            frames = _scenario_frames(scenario_dataset, item)
            hostname = display_hostname(source_agent)
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
                                "original_hostname": source.get("hostname"),
                                "source_agent_id": source_agent, "run_id": run_id,
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
        for scenario, source_agent in SCENARIOS:
            agent = target_agent(source_agent, args)
            cur.execute("INSERT INTO agents (agent_id, hostname, username_last_seen, first_seen_at, "
                        "last_seen_at, status) VALUES (%s,%s,%s,%s,%s,'offline') "
                        "ON CONFLICT (agent_id) DO NOTHING", (agent, display_hostname(source_agent),
                        scenario_items[scenario].get("target_username", ""), start,
                        start + timedelta(days=days - 1)))
    return {"collector_rows": len(rows), "explorer_rows": len(explorer_rows),
            "computed_historical_risk_events": len(risk_rows)}


def prepare(args):
    if not (args.target == "main" and getattr(args, "preview_only", False)):
        _guard(args)
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
                metadata_writer.writerow((target_agent(agent, args), day.isoformat(), 1, "synthetic"))
        for agent in CONTROL_AGENTS:
            for offset in range(days):
                day = start + timedelta(days=offset)
                feature_writer.writerow(_vector(agent, "", day, 0, baseline,
                    {agent: {name: [] for name in raw_features}}))
                complete = int(not (agent == CONTROL_AGENTS[0] and offset == days - 1))
                metadata_writer.writerow((target_agent(agent, args), day.isoformat(), complete, "synthetic"))
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
    if target_agent(CONTROL_AGENTS[0], args) in selected:
        raise RuntimeError("Missing-day control was selected for review; refusing to publish run")
    model_summary = json.loads((model_output / "summary.json").read_text(encoding="utf-8"))
    if (model_summary.get("eligible_hosts") != len(AGENTS) + 1 or
            model_summary.get("total_hosts") != len(AGENTS) + len(CONTROL_AGENTS)):
        raise RuntimeError("Frozen model eligibility did not match scenario and control expectations")
    dates_by_agent = {}
    with (model_output / "daily_predictions.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            dates_by_agent.setdefault(row["hostname"], set()).add(row["date"])
    if any(len(dates_by_agent.get(target_agent(agent, args), ())) != days
           for agent in AGENTS | set(CONTROL_AGENTS)):
        raise RuntimeError(f"Frozen model output does not contain {days} unique dates per host")
    preview_only = getattr(args, "preview_only", False)
    if preview_only:
        summary = json.loads((model_output / "summary.json").read_text(encoding="utf-8"))
        summary["scenario_agents"] = sorted(target_agent(agent, args) for agent in AGENTS)
        summary["control_agents"] = [target_agent(agent, args) for agent in CONTROL_AGENTS]
    else:
        backfill_counts = _backfill(run_id, start, days, snapshots, "Dataset_RealTime",
                                   by_scenario, roots["Dataset_Simulated"], args)
        summary = _save_scores(run_id, as_of, model_output, args)
    (output / "run.json").write_text(json.dumps({"run_id": run_id, "as_of": as_of.isoformat(),
        "start_date": start.isoformat(), "end_date": as_of.isoformat(), "days": days,
        "source_kind": "synthetic", "preview_only": preview_only,
        "scenario_agents": sorted(target_agent(agent, args) for agent in AGENTS),
        "control_agents": [target_agent(agent, args) for agent in CONTROL_AGENTS],
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


def expand_fleet(args):
    """Add benign dataset-backed employee hosts to a prepared isolated run.

    The extra hosts have historical collector logs and fleet identities. They
    receive no fabricated Model V3 score or risk event.
    """
    _guard(args)
    if args.target == "main":
        raise RuntimeError("Fleet expansion is disabled on the main database; existing hosts are preserved")
    run_id = args.run_id
    manifest_path = Path(args.output_root).resolve() / run_id / "run.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Run prepare before expand-fleet")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("preview_only") or manifest.get("source_kind") != "synthetic":
        raise RuntimeError("Fleet expansion requires a prepared isolated synthetic run")
    fleet_size = args.fleet_size
    if not 7 <= fleet_size <= 500:
        raise ValueError("--fleet-size must be between 7 and 500")
    if fleet_size == 7:
        print("Seven scenario hosts already prepared; no extra fleet hosts requested")
        return
    from server.storage.clickhouse_storage import ClickHouseStorage

    ch = ClickHouseStorage(host=config.clickhouse_host, port=config.clickhouse_port,
        username=config.clickhouse_user, password=config.clickhouse_password,
        database=config.clickhouse_db, secure=config.clickhouse_secure, dlq_enabled=False)
    source_agent = CONTROL_AGENTS[1]
    first = 8
    extra = fleet_size - 7
    marker = f"scenario-{run_id}-{source_agent}-%"
    try:
        if not ch.is_connected():
            raise RuntimeError("isolated ClickHouse unavailable")
        source_count = ch._client.query(
            "SELECT count() FROM collector_results WHERE agent_id = %(agent)s "
            "AND payload_id LIKE %(marker)s", parameters={"agent": source_agent,
                                                  "marker": marker}).result_rows[0][0]
        if source_count == 0:
            raise RuntimeError("Prepared benign source logs are missing")
        fleet_prefix = f"scenario-{run_id}-fleet-"
        existing = ch._client.query(
            "SELECT count() FROM collector_results WHERE startsWith(payload_id, %(prefix)s)",
            parameters={"prefix": fleet_prefix}).result_rows[0][0]
        source_events = ch._client.query(
            "SELECT count() FROM telemetry_events WHERE agent_id = %(agent)s "
            "AND payload_id LIKE %(marker)s", parameters={"agent": source_agent,
                                                  "marker": marker}).result_rows[0][0]
        if source_events == 0:
            raise RuntimeError("Prepared benign explorer rows are missing")
        existing_events = ch._client.query(
            "SELECT count() FROM telemetry_events WHERE startsWith(payload_id, %(prefix)s)",
            parameters={"prefix": fleet_prefix}).result_rows[0][0]
        if existing not in (0, source_count * extra) or existing_events not in (0, source_events * extra):
            raise RuntimeError("Partial fleet rows exist; inspect the isolated run before retrying")
        alias = f"concat('EMPLOYEE-', leftPad(toString(number + {first}), 2, '0'))"
        agent = f"concat('AGENT-', {alias})"
        payload = f"concat('{fleet_prefix}', toString(number + {first}), '-', payload_id)"
        provenance = ("concat(substring(agent_quality_json, 1, length(agent_quality_json)-1), "
                      "',\"source_agent_id\":\"AGENT-SOCL4-63\"}')")
        source_filter = (f"agent_id = '{source_agent}' AND "
                         f"startsWith(payload_id, 'scenario-{run_id}-{source_agent}-')")
        if not existing:
            ch._client.command(
                "INSERT INTO collector_results (payload_id, agent_id, collector, "
                "collector_collected_at, hostname, status, payload_json, source_quality, agent_quality_json) "
                f"SELECT {payload}, {agent}, collector, collector_collected_at, {alias}, status, "
                f"payload_json, 'scenario_replay', {provenance} "
                f"FROM collector_results CROSS JOIN numbers({extra}) WHERE {source_filter}")
        if not existing_events:
            ch._client.command(
                "INSERT INTO telemetry_events (payload_id, agent_id, collector_name, timestamp, "
                "hostname, username, status, summary_preview, raw_payload_json) "
                f"SELECT {payload}, {agent}, collector_name, timestamp, {alias}, "
                f"concat('employee', toString(number + {first})), status, summary_preview, raw_payload_json "
                f"FROM telemetry_events CROSS JOIN numbers({extra}) WHERE {source_filter}")
    finally:
        ch.close()
    start = date.fromisoformat(manifest["start_date"])
    end = date.fromisoformat(manifest["end_date"])
    with _pg() as conn, conn.cursor() as cur:
        for index in range(first, fleet_size + 1):
            label = f"EMPLOYEE-{index:02d}"
            cur.execute("INSERT INTO agents (agent_id, hostname, username_last_seen, "
                        "first_seen_at, last_seen_at, status) VALUES (%s,%s,%s,%s,%s,'offline') "
                        "ON CONFLICT (agent_id) DO NOTHING",
                        (f"AGENT-{label}", label, f"employee{index}", start, end))
    manifest["fleet_size"] = fleet_size
    manifest["fleet_background_source"] = source_agent
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    env_path = Path(args.env_file).resolve()
    lines = env_path.read_text(encoding="utf-8").splitlines()
    values = dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))
    if not {"INSIEDR_AGENT_TOKENS", "INSIEDR_SCENARIO_AGENT_TOKENS"} <= values.keys():
        raise RuntimeError("Scenario agent-token entries are missing from the private env file")
    tokens = json.loads(values["INSIEDR_AGENT_TOKENS"])
    for index in range(first, fleet_size + 1):
        tokens.setdefault(f"AGENT-EMPLOYEE-{index:02d}", secrets.token_hex(24))
    encoded = json.dumps(tokens, separators=(",", ":"))
    updates = {"INSIEDR_AGENT_TOKENS": encoded, "INSIEDR_SCENARIO_AGENT_TOKENS": encoded}
    updated_lines = [f"{key}={updates[key]}" if key in updates else line
                     for line in lines for key in [line.partition("=")[0]]]
    tmp = env_path.with_suffix(env_path.suffix + ".tmp")
    tmp.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, env_path)
    print(json.dumps({"run_id": run_id, "fleet_size": fleet_size,
                      "model_scored_hosts": len(AGENTS) + len(CONTROL_AGENTS),
                      "background_model_state": "none",
                      "next_step": "Recreate the scenario backend to load the new agent tokens"}, indent=2))


def play_fleet(args):
    """Send one current, authenticated benign observation for each extra host."""
    _guard(args)
    if args.target == "main":
        raise RuntimeError("Fleet expansion playback is disabled on the main database")
    import httpx
    from shared.crypto_utils import normalize_aes_key

    output = Path(args.output_root).resolve() / args.run_id
    manifest = json.loads((output / "run.json").read_text(encoding="utf-8"))
    fleet_size = manifest.get("fleet_size", 7)
    if fleet_size <= 7:
        raise RuntimeError("Run expand-fleet first")
    roots = _dataset_roots(args)
    files = _files(roots["Dataset_RealTime"])
    source_rows = {}
    for collector in ("logon", "process-watcher", "network", "file-integrity-monitor", "http"):
        file = files.get(collector)
        if file is None:
            raise FileNotFoundError(f"Missing background collector source: {collector}")
        with file.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            source_rows[collector] = next((row for row in csv.DictReader(handle)
                if row.get("agent_id") == CONTROL_AGENTS[1] and row.get("status") == "success"), None)
        if source_rows[collector] is None:
            raise RuntimeError(f"No benign source row for {collector}")
    tokens = json.loads(os.environ["INSIEDR_SCENARIO_AGENT_TOKENS"])
    key = normalize_aes_key(os.environ["INSIEDR_SCENARIO_AES_KEY"])
    base_url = args.server_url.rstrip("/")
    if not base_url.startswith("http://127.0.0.1:") and not base_url.startswith("http://localhost:"):
        raise ValueError("Replay endpoint must be a local isolated mirror URL")
    with httpx.Client(timeout=30) as client:
        for index in range(8, fleet_size + 1):
            hostname = f"EMPLOYEE-{index:02d}"
            agent = f"AGENT-{hostname}"
            if agent not in tokens:
                raise RuntimeError("Scenario backend tokens need reloading after expand-fleet")
            envelope, headers = _envelope(agent, hostname, f"employee{index}", source_rows,
                                          args.run_id, key, tokens[agent])
            response = client.post(base_url + "/api/logs", json=envelope, headers=headers)
            response.raise_for_status()
            if response.status_code != 202:
                raise RuntimeError(f"Background ingest did not accept {agent}")
            if index % 25 == 0 or index == fleet_size:
                print(f"Background collector envelopes accepted: {index - 7}/{fleet_size - 7}", flush=True)
            time.sleep(args.interval)


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
                        "source_agent_id": row.get("agent_id"),
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
    _guard(args)
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


class _SimpleResponse:
    def __init__(self, status_code: int, content: bytes):
        self.status_code = status_code
        self.content = content

    def json(self):
        return json.loads(self.content.decode("utf-8"))

    def raise_for_status(self):
        if not (200 <= self.status_code < 300):
            detail = self.content[:200].decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP request failed with status {self.status_code}: {detail}")


class _ReplayHttpClient:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        try:
            import httpx
            self._client = httpx.Client(timeout=timeout)
        except ImportError:
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client is not None:
            self._client.close()

    def get(self, url: str, headers: dict | None = None, params: dict | None = None):
        if self._client is not None:
            return self._client.get(url, headers=headers, params=params)
        from urllib.parse import urlencode
        import urllib.request
        import urllib.error
        if params:
            url = f"{url}?{urlencode(params)}"
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return _SimpleResponse(resp.status, resp.read())
        except urllib.error.HTTPError as err:
            return _SimpleResponse(err.code, err.read())

    def post(self, url: str, json: dict | None = None, headers: dict | None = None):
        if self._client is not None:
            return self._client.post(url, json=json, headers=headers)
        import urllib.request
        import urllib.error
        body = json.dumps(json).encode("utf-8") if json is not None else None
        h = dict(headers or {})
        h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return _SimpleResponse(resp.status, resp.read())
        except urllib.error.HTTPError as err:
            return _SimpleResponse(err.code, err.read())


def play(args):
    _guard(args)
    roots = _dataset_roots(args)
    output = Path(args.output_root).resolve() / args.run_id
    manifest_path = output / "run.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("Run prepare first")
    manifest = json.loads((roots["Dataset_Simulated_Harmonized"] / "simulation_manifest.json").read_text(encoding="utf-8"))
    items = {item["scenario_id"]: item for item in manifest["scenarios"]}
    tokens = json.loads(os.environ["INSIEDR_SCENARIO_AGENT_TOKENS"])
    key = config.load_aes_key()
    base_url = args.server_url.rstrip("/")
    allowed_urls = ("http://backend:5000", "http://127.0.0.1:5000")
    if base_url not in allowed_urls:
        raise ValueError("Replay endpoint must be the main backend Compose service")
    stop_file = output / "stop"
    stop_file.unlink(missing_ok=True)
    with _ReplayHttpClient(timeout=30) as client:
        operator_key = os.environ["INSIEDR_OPERATOR_API_KEY"]
        preflight = client.get(base_url + "/api/v1/detection/ml/scenario/hosts",
                               headers={"X-Operator-Key": operator_key})
        preflight.raise_for_status()
        if preflight.json().get("run_id") != args.run_id:
            raise RuntimeError("Website is not serving the prepared scenario run")
        for scenario, source_agent in SCENARIOS:
            if args.scenario and args.scenario != scenario:
                continue
            agent = target_agent(source_agent, args)
            item = items[scenario]
            frames = _scenario_frames(roots["Dataset_Simulated"], item)
            started_at = datetime.now(timezone.utc)
            for bucket, rows in frames:
                if stop_file.exists():
                    print("Playback stopped")
                    return
                envelope, headers = _envelope(agent, display_hostname(source_agent), item.get("target_username", ""), rows,
                    args.run_id, key, tokens[agent])
                # The runner is on the private Compose network; the public
                # HTTPS hop terminates at the main Nginx proxy.
                headers["X-Forwarded-Proto"] = "https"
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
    _guard(args)
    path = Path(args.output_root).resolve() / args.run_id / "run.json"
    if not path.exists():
        raise FileNotFoundError(path)
    result = json.loads(path.read_text(encoding="utf-8"))
    progress = path.with_name("progress.json")
    if progress.exists():
        result["playback"] = json.loads(progress.read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2))


def stop(args):
    _guard(args)
    path = Path(args.output_root).resolve() / args.run_id
    if not (path / "run.json").exists():
        raise FileNotFoundError(path)
    (path / "stop").touch()
    print("Stop requested")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install-main-tokens", "preview", "verify", "prepare", "play", "status", "stop"))
    parser.add_argument("--target", choices=("main",), default="main",
                        help="Main deployment is the only supported replay target")
    parser.add_argument("--env-file")
    parser.add_argument("--dataset-root", default=r"D:\Projects\AISH")
    parser.add_argument("--output-root", default=str(ROOT / "data" / "scenario_replay"))
    parser.add_argument("--run-id")
    parser.add_argument("--precomputed-model", help="Frozen-model output for identical X.csv and metadata.csv")
    parser.add_argument("--as-of", type=date.fromisoformat)
    parser.add_argument("--start-date", type=date.fromisoformat)
    parser.add_argument("--days", type=int, default=22)
    parser.add_argument("--fleet-size", type=int, default=200)
    parser.add_argument("--scenario", choices=[name for name, _ in SCENARIOS])
    parser.add_argument("--server-url", default="http://backend:5000")
    parser.add_argument("--interval", type=float, default=5.0)
    args = parser.parse_args()
    if args.env_file is None:
        args.env_file = str(ROOT / ".env")
    if args.interval < 0:
        parser.error("--interval must be nonnegative")
    if args.command in ("play", "status", "stop") and not args.run_id:
        parser.error(f"{args.command} requires --run-id")
    if args.run_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.run_id):
        parser.error("--run-id must be 1-64 letters, digits, underscores, or hyphens")
    if not (args.command == "preview"):
        _load_env(args.env_file, preserve_existing=True)
    globals()[args.command.replace("-", "_")](args)


if __name__ == "__main__":
    main()
