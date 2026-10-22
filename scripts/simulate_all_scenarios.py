"""Replay the supported synthetic scenarios into an InsiEDR dashboard.

The replay writes controlled, provenance-tagged telemetry through the normal
authenticated ingestion API. Model V3 scores are produced by the frozen model;
this wrapper does not insert preset risk scores or change alert severity.

Usage:
    python scripts/simulate_all_scenarios.py --mode run --target main
    python scripts/simulate_all_scenarios.py --mode run --target scenario
    python scripts/simulate_all_scenarios.py --mode clean --target scenario

The dataset currently contains seven attack scenarios. Main-target playback
adds synthetic records to the main database and has no destructive clean mode.
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
ENV_FILE = ROOT / ".env.scenario"
MAIN_ENV_FILE = ROOT / ".env"
COMPOSE_FILE = ROOT / "docker-compose.scenario.yml"
MAIN_COMPOSE_FILE = ROOT / "docker-compose.yml"
OUTPUT_ROOT = ROOT / "data" / "scenario_replay"
LATEST_RUN_FILE = OUTPUT_ROOT / "simulate_all_scenarios_latest.json"
MAIN_PREVIEW_MODEL = ROOT / "data" / "scenario_replay" / "main-preview-20261022" / "model"
MAIN_AS_OF = "2026-10-21"


def _run(command: list[str], *, cwd: Path = ROOT) -> None:
    print("\n> " + subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def _replay(*args: str) -> None:
    _run([sys.executable, str(REPLAY), *args])


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

    if args.target == "main":
        run_main_simulation(args, run_id)
        return

    if not ENV_FILE.is_file():
        _replay("init-env", "--target", "scenario", "--env-file", str(ENV_FILE))

    _run(["docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE),
          "up", "-d", "--build"])

    common = ["--target", "scenario", "--env-file", str(ENV_FILE),
              "--dataset-root", args.dataset_root,
              "--output-root", str(OUTPUT_ROOT)]
    _replay("verify", *common)
    _replay("prepare", *common, "--run-id", run_id, "--days", str(args.days))

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = LATEST_RUN_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"run_id": run_id}, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, LATEST_RUN_FILE)

    _replay("play", *common, "--run-id", run_id, "--interval", str(args.interval),
            "--server-url", "http://127.0.0.1:5088")
    print("\nReplay complete. Open the isolated dashboard at http://127.0.0.1:5088", flush=True)


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


def clean_simulation() -> None:
    if not ENV_FILE.is_file():
        raise FileNotFoundError(f"Scenario environment not found: {ENV_FILE}")
    if not LATEST_RUN_FILE.is_file():
        raise FileNotFoundError(
            "No run created by this wrapper was found. Refusing to reset the scenario stack."
        )

    record = json.loads(LATEST_RUN_FILE.read_text(encoding="utf-8"))
    run_id = record.get("run_id")
    if not isinstance(run_id, str):
        raise ValueError(f"Invalid latest-run record: {LATEST_RUN_FILE}")
    _validate_run_id(run_id)
    manifest = OUTPUT_ROOT / run_id / "run.json"
    if not manifest.is_file():
        raise FileNotFoundError(f"Replay manifest missing; refusing cleanup: {manifest}")

    _replay("reset", "--target", "scenario", "--env-file", str(ENV_FILE),
            "--output-root", str(OUTPUT_ROOT), "--run-id", run_id)
    print("Scenario database volumes were reset. Local replay artifacts were retained.", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("run", "clean"), required=True)
    parser.add_argument("--target", choices=("main", "scenario"), default="main",
                        help="Dashboard target (default: main; clean is supported only for scenario)")
    parser.add_argument("--run-id", help="Optional replay ID (run mode; generated if omitted)")
    parser.add_argument("--days", type=int,
                        help="Completed history days (main target requires 60; scenario defaults to 22)")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Seconds between live telemetry frames (default: 5)")
    parser.add_argument("--dataset-root", default=r"D:\Projects\AISH",
                        help="Folder containing the three scenario dataset folders")
    args = parser.parse_args()

    if args.days is None:
        args.days = 60 if args.target == "main" else 22
    if args.days < 22 or args.days > 90:
        parser.error("--days must be between 22 and 90")
    if args.interval < 0:
        parser.error("--interval must be nonnegative")
    if args.mode == "clean":
        if args.target != "scenario":
            parser.error("Main dashboard cleanup is disabled to protect production data; use --target scenario")
        clean_simulation()
    else:
        run_simulation(args)


if __name__ == "__main__":
    main()
