"""Create a compact, dataset-faithful source bundle for isolated replay hosts.

Only rows consumed by scenario_replay.py are retained. Original field values,
agent IDs, timestamps, and scenario ordering are preserved.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

from scenario_replay import AGENTS, CONTROL_AGENTS, SCENARIOS


def utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def copy_rows(source: Path, target: Path, *, windows: dict[str, tuple[datetime, datetime]] | None) -> int:
    count = 0
    metrics_count: dict[str, int] = {}
    snapshot_hours: dict[str, list[str]] = {}
    with source.open(newline="", encoding="utf-8-sig", errors="replace") as src, \
         target.open("w", newline="", encoding="utf-8") as dst:
        reader = csv.DictReader(src)
        writer = csv.DictWriter(dst, fieldnames=reader.fieldnames)
        writer.writeheader()
        for row in reader:
            agent = row.get("agent_id")
            if agent not in AGENTS | set(CONTROL_AGENTS) or row.get("status") != "success":
                continue
            if windows is not None:
                window = windows.get(agent)
                if window is None or not window[0] <= utc(row["timestamp"]) < window[1]:
                    continue
            else:
                seen = metrics_count.get(agent, 0)
                hours = snapshot_hours.setdefault(agent, [])
                hour = row["timestamp"][:13]
                snapshot = len(hours) < 22 and (not hours or hours[-1] != hour)
                if snapshot:
                    hours.append(hour)
                metrics_count[agent] = seen + 1
                if seen >= 128 and not snapshot:
                    continue
            writer.writerow(row)
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_root.resolve()
    if output.exists():
        raise FileExistsError(output)
    source = args.dataset_root.resolve()
    manifest = json.loads((source / "Dataset_Simulated_Harmonized" / "simulation_manifest.json").read_text(encoding="utf-8"))
    by_scenario = {item["scenario_id"]: item for item in manifest["scenarios"]}
    windows = {}
    for scenario, agent in SCENARIOS:
        item = by_scenario[scenario]
        if item["target_agent_id"] != agent:
            raise ValueError(f"Manifest identity mismatch: {scenario}")
        windows[agent] = (utc(item["start_time"]), utc(item["end_time"]))

    counts = {}
    for name in ("Dataset_RealTime", "Dataset_Simulated", "Dataset_Simulated_Harmonized"):
        source_dir = source / name
        target_dir = output / name
        target_dir.mkdir(parents=True)
        for file in source_dir.glob("*_dataset_*.csv"):
            if name == "Dataset_Simulated_Harmonized":
                with file.open(newline="", encoding="utf-8-sig", errors="replace") as src, \
                     (target_dir / file.name).open("w", newline="", encoding="utf-8") as dst:
                    writer = csv.writer(dst)
                    writer.writerow(next(csv.reader(src)))
                rows = 0
            else:
                rows = copy_rows(file, target_dir / file.name,
                                 windows=windows if name == "Dataset_Simulated" else None)
            counts[f"{name}/{file.name}"] = rows
        if name == "Dataset_Simulated_Harmonized":
            shutil.copy2(source_dir / "simulation_manifest.json", target_dir / "simulation_manifest.json")
    archive = shutil.make_archive(str(output), "zip", root_dir=output)
    print(json.dumps({"archive": archive, "rows": counts}, indent=2))


if __name__ == "__main__":
    main()
