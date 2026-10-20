"""
tests/test_keystroke_ml_dataset.py
==================================
Unit tests verifying the Keystroke Biometrics / Continuous Authentication ML pipeline:
1. Ingestion parsing (JSON array vs. flattened CSV).
2. Snapshot deduplication and suffix-stitching.
3. Strict zero-leakage continuous authentication benchmark partitioning:
   Asserts chronological event-stream splitting FIRST, followed by independent windowing,
   guaranteeing 0% stride overlap between enrollment and probe sets.
"""

import os
import sys
import pytest
import numpy as np
import pandas as pd

# Add scripts directory to path
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from prepare_keystroke_ml_dataset import (
    parse_timing_pair,
    extract_row_pairs,
    deduplicate_and_extract_sequences,
    build_windowed_dataset,
    build_continuous_verification_benchmark,
    prepare_keystroke_datasets_and_benchmark,
)


def test_parse_timing_pair():
    assert parse_timing_pair("65.2;112.5") == (65.2, 112.5)
    assert parse_timing_pair("  70.0;115.0  ") == (70.0, 115.0)
    # Out of human bounds
    assert parse_timing_pair("0.5;100.0") is None   # Dwell < 1ms
    assert parse_timing_pair("1200.0;100.0") is None # Dwell > 1000ms
    assert parse_timing_pair("50.0;6000.0") is None  # Flight > 5000ms
    assert parse_timing_pair("invalid_string") is None
    assert parse_timing_pair(None) is None


def test_extract_row_pairs_json_and_flattened():
    # Format 1: JSON string array
    row_json_str = {"keystroke_timings": "[[68.2, 115.4], [72.1, 118.0]]"}
    pairs_json = extract_row_pairs(row_json_str, [])
    assert len(pairs_json) == 2
    assert pairs_json[0] == (68.2, 115.4)

    # Format 2: Python list
    row_list = {"keystroke_timings": [[65.0, 112.5]]}
    pairs_list = extract_row_pairs(row_list, [])
    assert len(pairs_list) == 1
    assert pairs_list[0] == (65.0, 112.5)

    # Format 3: Flattened CSV columns
    row_csv = {
        "keystroke_timings_0": "60.0;110.0",
        "keystroke_timings_1": "62.0;112.0",
    }
    cols = ["keystroke_timings_0", "keystroke_timings_1"]
    pairs_csv = extract_row_pairs(row_csv, cols)
    assert len(pairs_csv) == 2
    assert pairs_csv[0] == (60.0, 110.0)
    assert pairs_csv[1] == (62.0, 112.0)


def test_deduplication_and_stitching():
    # Create simulated chronological rows with overlapping sliding snapshots
    data = [
        # Snapshot 1: keys 1, 2, 3
        {"timestamp": "2026-10-19T10:00:00Z", "user": "alice", "keystroke_timings": "[[10, 10], [20, 20], [30, 30]]"},
        # Duplicate Snapshot 1 (idle agent poll) - should be skipped
        {"timestamp": "2026-10-19T10:00:01Z", "user": "alice", "keystroke_timings": "[[10, 10], [20, 20], [30, 30]]"},
        # Snapshot 2: keys 2, 3, 4, 5 (overlap on [20, 20], [30, 30])
        {"timestamp": "2026-10-19T10:00:02Z", "user": "alice", "keystroke_timings": "[[20, 20], [30, 30], [40, 40], [50, 50]]"},
    ]
    df = pd.DataFrame(data)
    streams = deduplicate_and_extract_sequences(df, identity_col="user", min_session_keys=4)

    assert "alice" in streams
    # Expected stitched stream: [10, 10], [20, 20], [30, 30], [40, 40], [50, 50]
    expected = [[10.0, 10.0], [20.0, 20.0], [30.0, 30.0], [40.0, 40.0], [50.0, 50.0]]
    assert streams["alice"] == expected


def test_continuous_verification_benchmark_zero_boundary_leakage():
    """
    Critical Test:
    Verifies that build_continuous_verification_benchmark splits the chronological
    stream FIRST before windowing, ensuring ZERO keystroke overlap between
    enrollment windows and genuine probe windows.
    """
    # Generate 120 strictly monotonic keystrokes for user 'alice'
    # Each key has dwell = index + 1, flight = (index + 1) * 2
    n_keys = 120
    stream = [[float(i + 1), float((i + 1) * 2)] for i in range(n_keys)]

    # Generate enough keys for another user 'bob' so impostor sampling succeeds
    stream_bob = [[float(i + 500), float((i + 500) * 2)] for i in range(n_keys)]

    user_streams = {
        "alice": stream,
        "bob": stream_bob,
    }

    seq_len = 20
    step = 10
    bench = build_continuous_verification_benchmark(user_streams, seq_len=seq_len, step=step)

    assert bench["X_enroll"].shape[1:] == (seq_len, 2)
    assert bench["X_probe_genuine"].shape[1:] == (seq_len, 2)
    assert bench["X_probe_impostor"].shape[1:] == (seq_len, 2)

    # For user 'alice' (label 0):
    # Total events = 120. Split 60% = 72 events.
    # Enroll events: indices 1 to 72.
    # Probe events: indices 73 to 120.
    alice_enroll_windows = bench["X_enroll"][bench["y_enroll"] == 0]
    alice_probe_windows = bench["X_probe_genuine"][bench["y_probe_genuine"] == 0]

    assert len(alice_enroll_windows) > 0
    assert len(alice_probe_windows) > 0

    # The maximum dwell in enrollment windows must be <= 72.0
    max_enroll_dwell = float(np.max(alice_enroll_windows[:, :, 0]))
    # The minimum dwell in genuine probe windows must be >= 73.0
    min_probe_dwell = float(np.min(alice_probe_windows[:, :, 0]))

    # Strict zero-leakage invariant:
    assert max_enroll_dwell < min_probe_dwell, (
        f"Data leakage detected across benchmark split! "
        f"Max enroll event ({max_enroll_dwell}) must be strictly less than min probe event ({min_probe_dwell})"
    )
    assert max_enroll_dwell <= 72.0
    assert min_probe_dwell >= 73.0


def test_prepare_keystroke_datasets_open_set_zero_identity_leakage():
    """
    Verifies that the OPEN-SET evaluation protocol partitions identities
    so that the model's training data (X_train, X_val) has 0% identity overlap
    with the continuous authentication verification benchmark (X_enroll, X_probe).
    """
    users = ["alice", "bob", "charlie", "david", "eve"]
    n_keys = 120
    user_streams = {}
    for idx, u in enumerate(users):
        user_streams[u] = [[float(i + 1), float((i + 1) * 2)] for i in range(n_keys)]

    npz_data, bench_data, _ = prepare_keystroke_datasets_and_benchmark(
        user_streams,
        protocol="open-set",
        seq_len=20,
        step=10,
    )

    train_identities = set(npz_data["identities_train"])
    val_identities = set(npz_data["identities_val"])
    benchmark_identities = set(bench_data["identities_benchmark"])

    assert len(train_identities) > 0
    assert len(benchmark_identities) > 0

    # Invariant: Training identities and benchmark identities are strictly disjoint
    overlap = train_identities.intersection(benchmark_identities)
    assert len(overlap) == 0, f"Identity leakage detected! Overlapping identities: {overlap}"

    val_overlap = val_identities.intersection(benchmark_identities)
    assert len(val_overlap) == 0, f"Validation identity leakage! Overlapping: {val_overlap}"


def test_prepare_keystroke_datasets_temporal_zero_event_leakage():
    """
    Verifies that the TEMPORAL evaluation protocol partitions the raw chronological
    event sequence into three distinct non-overlapping slices:
    [0 .. 50% for Train] < [50% .. 80% for Enroll] < [80% .. 100% for Probe].
    Guarantees 0% event overlap across all splits for every subject.
    """
    users = ["alice", "bob"]
    n_keys = 240
    user_streams = {}
    for idx, u in enumerate(users):
        # Monotonically increasing event indices
        base = idx * 1000
        user_streams[u] = [[float(base + i + 1), float(100.0)] for i in range(n_keys)]

    npz_data, bench_data, _ = prepare_keystroke_datasets_and_benchmark(
        user_streams,
        protocol="temporal",
        seq_len=20,
        step=10,
    )

    # Total = 240.
    # Train = first 50% = 120 events (values 1 to 120).
    # Benchmark = remaining 50% = 120 events (values 121 to 240).
    # Benchmark split: Enroll = 60% of 120 = 72 events (values 121 to 192).
    # Benchmark split: Probe = 40% of 120 = 48 events (values 193 to 240).
    alice_train = npz_data["X_train"][npz_data["identities_train"] == "alice"]
    alice_enroll = bench_data["X_enroll"][bench_data["identities_enroll"] == "alice"]
    alice_probe = bench_data["X_probe_genuine"][bench_data["identities_probe_genuine"] == "alice"]

    assert len(alice_train) > 0
    assert len(alice_enroll) > 0
    assert len(alice_probe) > 0

    max_train_val = float(np.max(alice_train[:, :, 0]))
    min_enroll_val = float(np.min(alice_enroll[:, :, 0]))
    max_enroll_val = float(np.max(alice_enroll[:, :, 0]))
    min_probe_val = float(np.min(alice_probe[:, :, 0]))

    # Strict temporal boundary sequence:
    assert max_train_val < min_enroll_val, (
        f"Temporal leakage between train and benchmark enroll! "
        f"max_train ({max_train_val}) >= min_enroll ({min_enroll_val})"
    )
    assert max_enroll_val < min_probe_val, (
        f"Temporal leakage between benchmark enroll and probe! "
        f"max_enroll ({max_enroll_val}) >= min_probe ({min_probe_val})"
    )

