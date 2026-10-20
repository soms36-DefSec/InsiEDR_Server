#!/usr/bin/env python3
"""
prepare_keystroke_ml_dataset.py
==============================
Processes InsiEDR keystroke collector telemetry into ML-ready datasets for
the Keystroke Biometrics / Continuous Authentication ML Team.

Features & Fixes:
1. Robust Ingestion:
   - Supports BOTH live telemetry JSON arrays (keystroke_timings: [[d1, f1], ...])
     and flattened CSV columns (keystroke_timings_0 .. 19).
2. Proper Identity Attribution:
   - Identifies real user accounts (username@hostname) when present.
   - Falls back to agent_id (workstation surrogate) with explicit logging when blank.
3. Deduplication & Suffix-Matching:
   - Deduplicates idle snapshots while stitching non-redundant key events chronologically.
4. Turnkey Biometric Evaluation Protocol:
   - Exports cross-identity training/validation splits.
   - Exports explicit Continuous Authentication Benchmark (Enrollment vs Genuine Probe vs Impostor Probe)
     allowing immediate evaluation of False Acceptance Rate (FAR), False Rejection Rate (FRR), and Equal Error Rate (EER).
"""

import os
import sys
import json
import argparse
import random
import numpy as np
import pandas as pd
from typing import List, Tuple, Dict, Union


def parse_timing_pair(val) -> Tuple[float, float]:
    """Parse 'dwell;flight' string into (float, float)."""
    if pd.isna(val) or not val:
        return None
    try:
        parts = str(val).strip().split(';')
        if len(parts) == 2:
            d = float(parts[0])
            f = float(parts[1])
            if 1.0 <= d <= 1000.0 and 0.0 <= f <= 5000.0:
                return (d, f)
    except Exception:
        pass
    return None


def extract_row_pairs(row, timing_cols: List[str]) -> List[Tuple[float, float]]:
    """
    Extracts timing pairs from a row, handling BOTH:
    1. Nested JSON array in 'keystroke_timings' (live telemetry / ClickHouse export)
    2. Flattened columns 'keystroke_timings_0' .. 'keystroke_timings_19' (simulated CSV)
    """
    # Format 1: JSON array column
    if 'keystroke_timings' in row and row['keystroke_timings'] is not None:
        val = row['keystroke_timings']
        if isinstance(val, float) and pd.isna(val):
            val = None
        if val is not None and isinstance(val, str) and val.strip().startswith('['):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    pairs = []
                    for item in parsed:
                        if isinstance(item, (list, tuple)) and len(item) == 2:
                            d, f = float(item[0]), float(item[1])
                            if 1.0 <= d <= 1000.0 and 0.0 <= f <= 5000.0:
                                pairs.append((d, f))
                    if pairs:
                        return pairs
            except Exception:
                pass
        elif val is not None and isinstance(val, (list, tuple)):
            pairs = []
            for item in val:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    d, f = float(item[0]), float(item[1])
                    if 1.0 <= d <= 1000.0 and 0.0 <= f <= 5000.0:
                        pairs.append((d, f))
            if pairs:
                return pairs

    # Format 2: Flattened columns
    pairs = []
    for col in timing_cols:
        val = row.get(col)
        pair = parse_timing_pair(val)
        if pair is not None:
            pairs.append(pair)
    return pairs


def deduplicate_and_extract_sequences(df: pd.DataFrame, identity_col: str, min_session_keys: int = 20) -> Dict[str, List[List[float]]]:
    """
    Groups chronologically by identity and stitches unique timing pairs.
    """
    timing_cols = [f"keystroke_timings_{i}" for i in range(20) if f"keystroke_timings_{i}" in df.columns]

    user_streams = {}
    total_raw_rows = len(df)
    total_deduped_rows = 0

    grouped = df.groupby(identity_col)
    print(f"[*] Processing {len(grouped)} distinct '{identity_col}' identities...")

    for identity_id, group in grouped:
        group_sorted = group.sort_values('timestamp')
        last_snapshot_sig = None
        stream = []

        for _, row in group_sorted.iterrows():
            pairs = extract_row_pairs(row, timing_cols)
            if not pairs:
                continue

            snapshot_sig = ";".join([f"{p[0]:.2f}:{p[1]:.2f}" for p in pairs])
            if snapshot_sig == last_snapshot_sig:
                continue

            last_snapshot_sig = snapshot_sig
            total_deduped_rows += 1

            if not stream:
                stream.extend([[p[0], p[1]] for p in pairs])
            else:
                tail = stream[-len(pairs):]
                tail_tuples = [tuple(x) for x in tail]
                overlap = 0
                for k in range(min(len(tail_tuples), len(pairs)), 0, -1):
                    if tail_tuples[-k:] == pairs[:k]:
                        overlap = k
                        break
                new_events = pairs[overlap:]
                stream.extend([[p[0], p[1]] for p in new_events])

        if len(stream) >= min_session_keys:
            user_streams[str(identity_id)] = stream

    print(f"[*] Deduplication complete: {total_raw_rows:,} raw rows -> {total_deduped_rows:,} unique snapshot updates.")
    print(f"[*] Retained {len(user_streams)} identities with >= {min_session_keys} sequential keystroke events.")
    return user_streams


def build_windowed_dataset(user_streams: Dict[str, List[List[float]]], seq_len: int = 20, step: int = 10):
    """
    Builds sliding window sequences of shape (N, seq_len, 2) partitioned into train/val/test splits.
    """
    identities = sorted(list(user_streams.keys()))
    n_users = len(identities)
    if n_users == 0:
        raise ValueError("No identities with sufficient keystroke data.")

    n_train = max(1, int(n_users * 0.70))
    n_val = max(1, int(n_users * 0.15))
    train_users = set(identities[:n_train])
    val_users = set(identities[n_train:n_train + n_val])
    test_users = set(identities[n_train + n_val:])
    if not test_users:
        test_users = val_users

    splits = {
        'train': {'X': [], 'y': [], 'id': []},
        'val': {'X': [], 'y': [], 'id': []},
        'test': {'X': [], 'y': [], 'id': []},
    }

    user_to_idx = {uid: idx for idx, uid in enumerate(identities)}

    for uid, stream in user_streams.items():
        label = user_to_idx[uid]
        if uid in train_users:
            target_split = 'train'
        elif uid in val_users:
            target_split = 'val'
        else:
            target_split = 'test'

        stream_arr = np.array(stream, dtype=np.float32)
        n_windows = max(1, (len(stream_arr) - seq_len) // step + 1)

        for w in range(n_windows):
            start = w * step
            end = start + seq_len
            if end <= len(stream_arr):
                window = stream_arr[start:end]
                splits[target_split]['X'].append(window)
                splits[target_split]['y'].append(label)
                splits[target_split]['id'].append(uid)

    result = {}
    for sp in ['train', 'val', 'test']:
        if splits[sp]['X']:
            result[f"X_{sp}"] = np.array(splits[sp]['X'], dtype=np.float32)
            result[f"y_{sp}"] = np.array(splits[sp]['y'], dtype=np.int32)
            result[f"identities_{sp}"] = np.array(splits[sp]['id'], dtype=object)
        else:
            result[f"X_{sp}"] = np.empty((0, seq_len, 2), dtype=np.float32)
            result[f"y_{sp}"] = np.empty((0,), dtype=np.int32)
            result[f"identities_{sp}"] = np.empty((0,), dtype=object)

    return result, user_to_idx


def build_continuous_verification_benchmark(user_streams: Dict[str, List[List[float]]], seq_len: int = 20, step: int = 10):
    """
    Constructs the Continuous Authentication Evaluation Benchmark:
    Rigorous Leakage-Free Design:
    1. Splits the chronological event stream FIRST into enroll (60%) and probe (40%) event streams.
    2. Windows each stream independently. This guarantees ZERO overlapping keystrokes across the boundary!
    """
    random.seed(42)
    enroll_windows = []
    enroll_labels = []
    enroll_ids = []

    genuine_probe_windows = []
    genuine_probe_labels = []
    genuine_probe_ids = []

    per_user_probes = {}
    identities = sorted(list(user_streams.keys()))
    user_to_idx = {uid: idx for idx, uid in enumerate(identities)}

    for uid, stream in user_streams.items():
        label = user_to_idx[uid]
        stream_arr = np.array(stream, dtype=np.float32)
        total_events = len(stream_arr)

        # Minimum events to produce independent non-overlapping windows on both sides
        min_events_required = seq_len * 2 + step * 4
        if total_events < min_events_required:
            continue

        # Split event stream FIRST (60% enroll, 40% probe)
        split_event_idx = int(total_events * 0.60)
        enroll_events = stream_arr[:split_event_idx]
        probe_events = stream_arr[split_event_idx:]

        # Window enrollment stream independently
        n_enroll_windows = (len(enroll_events) - seq_len) // step + 1
        user_enroll = [
            enroll_events[w * step : w * step + seq_len]
            for w in range(n_enroll_windows)
            if w * step + seq_len <= len(enroll_events)
        ]

        # Window genuine probe stream independently
        n_probe_windows = (len(probe_events) - seq_len) // step + 1
        user_genuine = [
            probe_events[w * step : w * step + seq_len]
            for w in range(n_probe_windows)
            if w * step + seq_len <= len(probe_events)
        ]

        if len(user_enroll) < 3 or len(user_genuine) < 3:
            continue

        enroll_windows.extend(user_enroll)
        enroll_labels.extend([label] * len(user_enroll))
        enroll_ids.extend([uid] * len(user_enroll))

        genuine_probe_windows.extend(user_genuine)
        genuine_probe_labels.extend([label] * len(user_genuine))
        genuine_probe_ids.extend([uid] * len(user_genuine))

        per_user_probes[label] = user_genuine

    # Build balanced impostor probe pairs
    impostor_probe_windows = []
    impostor_target_labels = []

    active_labels = list(per_user_probes.keys())
    for target_label, genuine_samples in per_user_probes.items():
        other_labels = [l for l in active_labels if l != target_label]
        if not other_labels:
            continue
        # Sample impostor probes from other users matching genuine probe count
        for _ in range(len(genuine_samples)):
            imp_user = random.choice(other_labels)
            imp_sample = random.choice(per_user_probes[imp_user])
            impostor_probe_windows.append(imp_sample)
            impostor_target_labels.append(target_label)

    return {
        "X_enroll": np.array(enroll_windows, dtype=np.float32),
        "y_enroll": np.array(enroll_labels, dtype=np.int32),
        "identities_enroll": np.array(enroll_ids, dtype=object),
        "X_probe_genuine": np.array(genuine_probe_windows, dtype=np.float32),
        "y_probe_genuine": np.array(genuine_probe_labels, dtype=np.int32),
        "identities_probe_genuine": np.array(genuine_probe_ids, dtype=object),
        "X_probe_impostor": np.array(impostor_probe_windows, dtype=np.float32),
        "target_y_impostor": np.array(impostor_target_labels, dtype=np.int32),
        "identities_benchmark": np.array(sorted(list(set(enroll_ids))), dtype=object),
    }


def prepare_keystroke_datasets_and_benchmark(
    user_streams: Dict[str, List[List[float]]],
    protocol: str = "auto",
    seq_len: int = 20,
    step: int = 10,
) -> Tuple[
    Dict[str, np.ndarray],
    Dict[str, np.ndarray],
    Dict[str, Union[str, Dict[str, int]]],
]:
    """
    Constructs both the sliding-window training/validation sequences AND the continuous
    authentication verification benchmark with strict, provable zero data leakage.

    Supported Evaluation Protocols:
    1. 'open-set' (Default when >= 4 identities):
       - Identities are split into disjoint sets: Training Pool (70%) vs Benchmark Evaluation Pool (30%).
       - Training/Validation sequences are built exclusively from the Training Pool.
       - The Verification Benchmark (Enrollment, Genuine Probe, Impostor Probe) is built
         exclusively from the held-out Benchmark Evaluation Pool.
       - Invariant: set(X_train identities) & set(benchmark identities) == empty set.

    2. 'temporal' (Within-subject continuous authentication, or when < 4 identities):
       - For every identity, the raw chronological event sequence is partitioned FIRST into:
         - Training Range (first 50% of events) -> used for X_train / X_val.
         - Enrollment Range (next 30% of events) -> used for X_enroll.
         - Probe Range (final 20% of events) -> used for X_probe_genuine / X_probe_impostor.
       - Invariant: For each user, max(train_time) < min(enroll_time) < min(probe_time).
    """
    identities = sorted(list(user_streams.keys()))
    n_users = len(identities)
    if n_users == 0:
        raise ValueError("No identities with sufficient keystroke data.")

    if protocol == "auto":
        protocol = "open-set" if n_users >= 4 else "temporal"

    if protocol == "open-set":
        if n_users < 4:
            print(f"[!] [NOTICE] Only {n_users} identities available (need >= 4 for open-set: min 2 train, min 2 bench). Falling back to 'temporal' protocol.")
            return prepare_keystroke_datasets_and_benchmark(
                user_streams,
                protocol="temporal",
                seq_len=seq_len,
                step=step,
            )
        else:
            # Deterministic, un-biased shuffling by fixed seed (not sensitive to naming/alphabetical order)
            shuffled_ids = sorted(list(user_streams.keys()))
            random.Random(42).shuffle(shuffled_ids)

            # Hold out at least 2 identities for benchmark (guarantees impostor sampling pool),
            # while leaving at least 2 identities for training/validation pool.
            n_bench = max(2, int(n_users * 0.30))
            if n_users - n_bench < 2:
                n_bench = n_users - 2

            train_pool_ids = shuffled_ids[:-n_bench]
            bench_ids = shuffled_ids[-n_bench:]

            print(f"[*] Evaluation Protocol: OPEN-SET (Identity-Disjoint, seed=42)")
            print(f"    - Training/Val identity pool ({len(train_pool_ids)}): {train_pool_ids[:5]}... ({len(train_pool_ids)} total)")
            print(f"    - Held-out Benchmark evaluation pool ({len(bench_ids)}): {bench_ids[:5]}... ({len(bench_ids)} total)")

            train_streams = {uid: user_streams[uid] for uid in train_pool_ids}
            bench_streams = {uid: user_streams[uid] for uid in bench_ids}

            train_val_data, train_user_to_idx = build_windowed_dataset(
                train_streams, seq_len=seq_len, step=step
            )
            bench_data = build_continuous_verification_benchmark(bench_streams, seq_len=seq_len, step=step)
            # Each artifact has its own label space: the classifier is trained on
            # training identities, while verification labels identify held-out users.
            benchmark_user_to_idx = {
                str(uid): int(label)
                for uid, label in zip(
                    bench_data["identities_enroll"], bench_data["y_enroll"]
                )
            }
            identity_mappings = {
                "protocol": protocol,
                "train": train_user_to_idx,
                "benchmark": benchmark_user_to_idx,
            }
            return train_val_data, bench_data, identity_mappings

    elif protocol == "temporal":
        print(f"[*] Evaluation Protocol: TEMPORAL (Within-Subject Chronological Event Partitioning)")
        train_streams = {}
        bench_streams = {}

        for uid, stream in user_streams.items():
            total_events = len(stream)
            split_train = int(total_events * 0.50)
            train_events = stream[:split_train]
            bench_events = stream[split_train:]

            if len(train_events) >= seq_len:
                train_streams[uid] = train_events
            if len(bench_events) >= seq_len:
                bench_streams[uid] = bench_events

        train_val_data, train_user_to_idx = build_windowed_dataset(
            train_streams, seq_len=seq_len, step=step
        )
        bench_data = build_continuous_verification_benchmark(bench_streams, seq_len=seq_len, step=step)
        benchmark_user_to_idx = {
            str(uid): int(label)
            for uid, label in zip(
                bench_data["identities_enroll"], bench_data["y_enroll"]
            )
        }
        identity_mappings = {
            "protocol": protocol,
            "train": train_user_to_idx,
            "benchmark": benchmark_user_to_idx,
        }
        return train_val_data, bench_data, identity_mappings

    else:
        raise ValueError(f"Unknown protocol '{protocol}'. Must be 'open-set', 'temporal', or 'auto'.")


def extract_tabular_behavioral_metrics(df: pd.DataFrame, output_csv: str):
    """
    Extracts clean tabular summary metrics for anomaly detection.
    """
    metric_cols = [
        'timestamp', 'agent_id', 'hostname', 'username',
        'mean_dwell_time_ms', 'std_dwell_time_ms',
        'mean_flight_time_ms', 'std_flight_time_ms',
        'typing_speed_cpm', 'backspace_ratio',
        'total_keys_sampled', 'dwell_sample_count', 'flight_sample_count'
    ]
    avail_cols = [c for c in metric_cols if c in df.columns]
    metrics_df = df[avail_cols].copy()

    core_features = ['mean_dwell_time_ms', 'mean_flight_time_ms', 'typing_speed_cpm']
    existing_core = [c for c in core_features if c in metrics_df.columns]
    metrics_df = metrics_df.dropna(subset=existing_core, how='all')

    dedup_cols = ['agent_id'] + existing_core
    if 'agent_id' in metrics_df.columns:
        metrics_df = metrics_df.drop_duplicates(subset=dedup_cols)

    metrics_df.to_csv(output_csv, index=False)
    print(f"[*] Saved clean tabular behavioral dataset: {output_csv} ({len(metrics_df):,} rows)")


def is_valid_token(val) -> bool:
    """Returns True if val is a non-empty string and not a NaN/null representation."""
    if val is None or pd.isna(val):
        return False
    s = str(val).strip()
    return bool(s) and s.lower() not in ('nan', 'none', 'null', 'undefined', '')


def resolve_row_identity(row) -> str:
    """
    Resolves identity for a row with strict anti-aliasing:
    1. Human username (excluding non-interactive SYSTEM service accounts) -> user@host
    2. Workstation agent_id surrogate -> agent_id
    3. Workstation hostname fallback -> hostname
    4. Stable unknown-device token -> UNKNOWN_DEVICE
    Guarantees no 'nan', 'none', or 'nan@...' tokens are ever emitted.
    """
    # Priority 1: Human username (excluding non-interactive SYSTEM service accounts)
    raw_u = row.get('username')
    if is_valid_token(raw_u):
        u_clean = str(raw_u).strip()
        if u_clean.lower() not in ('system', 'local system'):
            raw_h = row.get('hostname')
            if is_valid_token(raw_h):
                return f"{u_clean}@{str(raw_h).strip()}"
            return u_clean

    # Priority 2: Workstation agent_id surrogate
    raw_agent = row.get('agent_id')
    if is_valid_token(raw_agent):
        return str(raw_agent).strip()

    # Priority 3: Workstation hostname fallback
    raw_host = row.get('hostname')
    if is_valid_token(raw_host):
        return str(raw_host).strip()

    # Priority 4: Stable unknown-device token (never returns 'nan' or empty string)
    return "UNKNOWN_DEVICE"


def main():
    parser = argparse.ArgumentParser(description="Prepare ML dataset from InsiEDR keystroke collector telemetry.")
    parser.add_argument(
        "--input",
        type=str,
        default=r"D:\Projects\AISH\Dataset_Simulated_Harmonized\keystroke-collector_dataset_20261015_052208.csv",
        help="Path to raw simulated or live keystroke telemetry CSV"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=r"D:\Projects\AISH\Dataset_ML_Ready\keystrokes",
        help="Output directory for prepared ML datasets"
    )
    parser.add_argument("--seq-len", type=int, default=20, help="Window sequence length (default: 20)")
    parser.add_argument("--step", type=int, default=10, help="Sliding window stride (default: 10)")
    parser.add_argument(
        "--protocol",
        type=str,
        choices=["auto", "open-set", "temporal"],
        default="auto",
        help="Evaluation protocol: 'open-set' (held-out identities), 'temporal' (within-subject split), or 'auto'"
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Error: Input file not found: {args.input}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    print(f"[*] Reading telemetry from: {args.input}")
    df = pd.read_csv(args.input, low_memory=False)

    # 1. Identity Attribution Analysis with Robust Sanitization
    df['identity'] = df.apply(resolve_row_identity, axis=1)

    # Check distribution of resolved identities
    has_real_users = any('@' in str(ident) for ident in df['identity'].unique())
    if has_real_users:
        user_count = sum(1 for ident in df['identity'].unique() if '@' in str(ident))
        print(f"[*] Identity Attribution: Human user accounts detected! Found {user_count} 'username@hostname' identities.")
    else:
        print("[!] [NOTICE] 'username' field is blank or SYSTEM across dataset. Falling back to workstation 'agent_id' as operational identity surrogate.")

    # 2. Export clean tabular summary metrics
    tabular_out = os.path.join(args.output_dir, "keystroke_behavioral_metrics.csv")
    extract_tabular_behavioral_metrics(df, tabular_out)

    # 3. Extract and stitch event sequences
    user_streams = deduplicate_and_extract_sequences(df, identity_col='identity', min_session_keys=args.seq_len)

    # 4. Construct Leakage-Free Training Sequences and Continuous Authentication Benchmark
    print(f"[*] Constructing leakage-free datasets (protocol={args.protocol}, seq_len={args.seq_len}, step={args.step})...")
    npz_data, bench_data, identity_mappings = prepare_keystroke_datasets_and_benchmark(
        user_streams,
        protocol=args.protocol,
        seq_len=args.seq_len,
        step=args.step,
    )

    npz_out = os.path.join(args.output_dir, f"keystroke_sequences_seq{args.seq_len}.npz")
    np.savez_compressed(npz_out, **npz_data)
    print(f"[*] Saved windowed sequence arrays: {npz_out}")
    print(f"    - X_train shape: {npz_data['X_train'].shape}, y_train: {npz_data['y_train'].shape}")
    print(f"    - X_val shape:   {npz_data['X_val'].shape}, y_val:   {npz_data['y_val'].shape}")
    print(f"    - X_test shape:  {npz_data['X_test'].shape}, y_test:  {npz_data['y_test'].shape}")

    bench_out = os.path.join(args.output_dir, "keystroke_verification_protocol.npz")
    np.savez_compressed(bench_out, **bench_data)
    print(f"[*] Saved verification benchmark: {bench_out}")
    print(f"    - X_enroll shape:         {bench_data['X_enroll'].shape} (Template baseline)")
    print(f"    - X_probe_genuine shape:  {bench_data['X_probe_genuine'].shape} (For FRR evaluation)")
    print(f"    - X_probe_impostor shape: {bench_data['X_probe_impostor'].shape} (For FAR evaluation)")

    # 5. Save identity mapping metadata
    mapping_out = os.path.join(args.output_dir, "agent_identity_mapping.json")
    with open(mapping_out, 'w') as f:
        json.dump(identity_mappings, f, indent=2)
    print(
        f"[*] Saved {identity_mappings['protocol']} label mappings: {mapping_out} "
        f"({len(identity_mappings['train'])} training, "
        f"{len(identity_mappings['benchmark'])} benchmark identities)"
    )

    print("\n[+] SUCCESS: Dataset preprocessing complete! All benchmark and training files ready.")


if __name__ == "__main__":
    main()
