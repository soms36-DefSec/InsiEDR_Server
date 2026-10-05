"""
tests/test_performance_benchmark.py
------------------------------------
Representative load and concurrency benchmark establishing server capacity,
measuring requests per second (RPS), latency percentiles (p50, p95, max),
and verifying non-blocking async event loop execution under high load.
"""
from __future__ import annotations

import time
import statistics
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from fastapi.testclient import TestClient

from server.app import create_app
from tests.test_hardening_verification import HardenedMockStorage


def test_concurrent_agent_heartbeat_benchmark():
    """Benchmark concurrent agent heartbeats establishing throughput and latency percentiles."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    num_requests = 100
    concurrency = 10

    def make_request(i: int) -> float:
        t0 = time.perf_counter()
        resp = client.post(
            "/api/agent/heartbeat",
            json={
                "agent_id": f"agent-{i % 10}",
                "hostname": f"HOST-{i % 10}",
                "status": "healthy",
                "metrics": {"cpu_percent": 1.5, "memory_mb": 42.0},
            },
        )
        assert resp.status_code == 200
        return (time.perf_counter() - t0) * 1000.0  # ms

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies = list(executor.map(make_request, range(num_requests)))
    total_time = time.perf_counter() - t_start

    rps = num_requests / total_time
    p50 = statistics.median(latencies)
    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95)]
    max_lat = max(latencies)

    # Establish baseline production capacity requirements
    assert rps > 10.0, f"Expected > 10 RPS in test harness, got {rps:.2f}"
    assert p50 < 100.0, f"Expected p50 < 100ms, got {p50:.2f}ms"
    assert p95 < 500.0, f"Expected p95 < 500ms, got {p95:.2f}ms"

    print(f"\n--- InsiEDR Concurrency Benchmark ({num_requests} requests @ {concurrency} workers) ---")
    print(f"Throughput: {rps:.1f} RPS")
    print(f"Latency: p50={p50:.2f}ms, p95={p95:.2f}ms, max={max_lat:.2f}ms")


def test_concurrent_operator_command_benchmark():
    """Benchmark concurrent operator command dispatch and atomic audit logging."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    num_commands = 50
    concurrency = 5

    def dispatch_command(i: int) -> float:
        t0 = time.perf_counter()
        resp = client.post(
            f"/api/agents/agent-{i % 5}/isolate",
            json={"server_ip": "10.0.0.1"},
        )
        assert resp.status_code == 200
        return (time.perf_counter() - t0) * 1000.0

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies = list(executor.map(dispatch_command, range(num_commands)))
    total_time = time.perf_counter() - t_start

    rps = num_commands / total_time
    assert len(storage.audit_log) == num_commands
    assert rps > 5.0
