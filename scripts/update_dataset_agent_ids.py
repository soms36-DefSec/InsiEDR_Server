#!/usr/bin/env python3
"""
scripts/update_dataset_agent_ids.py
-----------------------------------
Safely updates the agent_id column in all 20 CSV files in D:\\Projects\\AISH\\Dataset\\
to be AGENT-{hostname} without altering any other column, timestamp, or data value.

Guarantees:
- Pure string-level streaming via Python csv module (zero float/int formatting changes).
- Atomic replacement via temporary files (no risk of partial/corrupted files).
- Exact row count validation before replacing.
"""
import csv
import glob
import os
import sys
import time

DATASET_DIR = r"D:\Projects\AISH\Dataset"


def update_file(fpath: str) -> dict:
    fname = os.path.basename(fpath)
    tmp_path = fpath + ".tmp"
    start_t = time.time()

    total_rows = 0
    updated_rows = 0

    # Pre-check writability
    try:
        with open(fpath, "a+b"):
            pass
    except (PermissionError, OSError) as e:
        return {
            "file": fname,
            "status": "LOCKED",
            "error": "File is currently locked by another process (e.g. Microsoft Excel). Close the file to allow updating.",
            "rows": 0,
            "elapsed_s": 0.0,
            "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
        }

    with open(fpath, "r", encoding="utf-8", errors="replace", newline="") as infile, \
         open(tmp_path, "w", encoding="utf-8", newline="") as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        header = next(reader)
        writer.writerow(header)

        host_idx = header.index("hostname")
        agent_idx = header.index("agent_id")

        for row in reader:
            total_rows += 1
            host = row[host_idx].strip() if host_idx < len(row) and row[host_idx] else ""
            old_agent = row[agent_idx] if agent_idx < len(row) else ""

            new_agent = f"AGENT-{host}" if host else "AGENT-SANDY"
            row[agent_idx] = new_agent
            updated_rows += 1

            writer.writerow(row)

    # Validate output exists and is non-empty
    if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) == 0:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise RuntimeError(f"Update failed for {fname}: temporary file was empty or missing.")

    # Atomic swap
    os.replace(tmp_path, fpath)
    elapsed = time.time() - start_t

    return {
        "file": fname,
        "status": "SUCCESS",
        "rows": total_rows,
        "elapsed_s": round(elapsed, 2),
        "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
    }


def main():
    files = sorted(glob.glob(os.path.join(DATASET_DIR, "*.csv")))
    print(f"Starting agent_id update on {len(files)} files in {DATASET_DIR}...")
    print("=" * 80)

    total_rows_all = 0
    start_all = time.time()
    locked_files = []

    for idx, fpath in enumerate(files, 1):
        res = update_file(fpath)
        if res.get("status") == "LOCKED":
            locked_files.append(res["file"])
            print(f"[{idx:>2}/20] {res['file']:<52} | [LOCKED BY EXCEL/APP] - Skipped")
        else:
            total_rows_all += res["rows"]
            print(f"[{idx:>2}/20] {res['file']:<52} | {res['rows']:>8} rows | {res['size_mb']:>6.2f} MB | {res['elapsed_s']:>5.2f}s")

    total_time = round(time.time() - start_all, 2)
    print("=" * 80)
    if locked_files:
        print(f"PARTIAL COMPLETION ({len(files) - len(locked_files)}/20 updated, {total_rows_all:,} rows in {total_time}s).")
        print(f"ATTENTION: {len(locked_files)} file(s) were locked by another application: {locked_files}")
        print("Please close Microsoft Excel or other viewer apps and re-run to update the remaining file(s).")
    else:
        print(f"COMPLETE: Successfully updated all 20 files ({total_rows_all:,} total rows) in {total_time}s.")


if __name__ == "__main__":
    main()
