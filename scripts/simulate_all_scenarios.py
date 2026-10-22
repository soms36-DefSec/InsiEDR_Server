"""Replay the supported synthetic scenarios into an InsiEDR dashboard.

The replay writes controlled, provenance-tagged telemetry through the normal
authenticated ingestion API. Model V3 scores are produced by the frozen model;
this wrapper does not insert preset risk scores or change alert severity.

Usage:
    python scripts/simulate_all_scenarios.py --mode run

The dataset currently contains seven attack scenarios. Main-target playback
adds synthetic records to the main database. Main data cleanup is intentionally
not offered by this demo script.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "scripts" / "scenario_replay.py"
MAIN_ENV_FILE = ROOT / ".env"
MAIN_COMPOSE_FILE = ROOT / "docker-compose.yml"
OUTPUT_ROOT = ROOT / "data" / "scenario_replay"
LATEST_RUN_FILE = OUTPUT_ROOT / "simulate_all_scenarios_latest.json"
MAIN_PREVIEW_MODEL = ROOT / "data" / "scenario_replay" / "main-preview-20261022" / "model"
MAIN_AS_OF = "2026-10-21"


def _run(command: list[str], *, cwd: Path = ROOT) -> None:
    print("\n> " + subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def _main_replay(*args: str) -> None:
    command = ["docker", "compose", "--env-file", str(MAIN_ENV_FILE),
               "-f", str(MAIN_COMPOSE_FILE), "run", "--rm", "--no-deps"]
    if os.name != "nt" and hasattr(os, "getuid"):
        command.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
    command.extend(("-v", f"{ROOT}:/app", "backend", "python",
                    "scripts/scenario_replay.py", *args))
    _run(command)


def _validate_run_id(run_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", run_id):
        raise ValueError("Run ID must be 1-64 letters, digits, underscores, or hyphens")


def run_simulation(args: argparse.Namespace) -> None:
    run_id = args.run_id or datetime.now(timezone.utc).strftime("demo-%Y%m%d-%H%M%S")
    _validate_run_id(run_id)

    run_main_simulation(args, run_id)


def run_main_simulation(args: argparse.Namespace, run_id: str) -> None:
    if not MAIN_ENV_FILE.is_file():
        raise FileNotFoundError(f"Main Docker environment file not found: {MAIN_ENV_FILE}")
    dataset_root = OUTPUT_ROOT / "portable_sources"
    required_sources = ("Dataset_RealTime", "Dataset_Simulated", "Dataset_Simulated_Harmonized")
    missing_sources = [name for name in required_sources if not (dataset_root / name).is_dir()]
    if missing_sources:
        raise FileNotFoundError(
            "Main replay source data is missing under "
            f"{dataset_root}: {', '.join(missing_sources)}"
        )
    if not (MAIN_PREVIEW_MODEL / "summary.json").is_file():
        raise FileNotFoundError(
            "Main frozen-model preview is missing: "
            f"{MAIN_PREVIEW_MODEL}. Copy and unpack data/main-preview-model-20261022.zip first."
        )

    # The replay CLI edits only its opt-in and replay-token entries, preserving
    # existing agent credentials and writing a private .env backup.
    _main_replay("install-main-tokens", "--target", "main", "--env-file", "/app/.env")
    _run(["docker", "compose", "--env-file", str(MAIN_ENV_FILE), "-f",
          str(MAIN_COMPOSE_FILE), "up", "-d", "--build", "backend"])

    common = ["--target", "main", "--env-file", "/app/.env",
              "--dataset-root", "/app/data/scenario_replay/portable_sources",
              "--output-root", "/app/data/scenario_replay"]
    if args.days != 60:
        raise ValueError("Main dashboard replay requires --days 60 to match its frozen model preview")
    _main_replay("prepare", *common, "--run-id", run_id, "--days", str(args.days),
                 "--as-of", MAIN_AS_OF,
                 "--precomputed-model",
                 "/app/data/scenario_replay/main-preview-20261022/model")

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = LATEST_RUN_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"run_id": run_id, "target": "main"}, indent=2) + "\n",
                         encoding="utf-8")
    os.replace(temporary, LATEST_RUN_FILE)

    _main_replay("play", *common, "--run-id", run_id, "--interval", str(args.interval),
                 "--server-url", "http://backend:5000")
    print("\nReplay complete. View the main dashboard at http://172.16.22.198/dashboard/",
          flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("run",), required=True,
                        help="Only the main Docker deployment is supported")
    parser.add_argument("--run-id", help="Optional replay ID (run mode; generated if omitted)")
    parser.add_argument("--days", type=int, default=60,
                        help="Completed history days (main frozen preview requires 60)")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Seconds between live telemetry frames (default: 5)")
    args = parser.parse_args()

    if args.days < 22 or args.days > 90:
        parser.error("--days must be between 22 and 90")
    if args.interval < 0:
        parser.error("--interval must be nonnegative")
    run_simulation(args)


if __name__ == "__main__":
    main()
