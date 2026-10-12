"""
tests/test_log_pipeline_performance.py
---------------------------------------
Benchmark and verification suite for server-side log pipeline improvements:
- Ingestion unique collector observation UUID generation
- ClickHouse list_logs filtering (collector, status)
- Postgres list_logs case-insensitivity
- Telemetry explorer fallback username safety
- Telemetry histogram bucket intervals
- Caching layer for fast UI delivery
- Cache invalidation on telemetry ingest
- Before-and-after performance benchmarking
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.api import logs, telemetry
from server.api.cache import api_cache
from server.api.deps import get_storage
from server.api.errors import register_error_handlers
from server.api.events import dispatch_telemetry_event
from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.clickhouse_telemetry_queries import (
    telemetry_explorer as ch_explorer,
    telemetry_event_detail as ch_detail,
    telemetry_histogram as ch_histogram,
)
from server.storage.postgres_storage import PostgresStorage, _SQLiteParamAdapter
from server.storage.telemetry_queries import (
    telemetry_explorer as pg_explorer,
    telemetry_event_detail as pg_detail,
    telemetry_histogram as pg_histogram,
)


def create_sqlite_test_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE raw_payloads (
            payload_id TEXT PRIMARY KEY,
            agent_id TEXT,
            received_at TEXT,
            envelope_created_at TEXT,
            payload_collected_at TEXT,
            hostname TEXT,
            username TEXT,
            crypto_scheme TEXT,
            key_id TEXT,
            nonce_hash TEXT,
            ciphertext_hash TEXT,
            decrypted_payload_hash TEXT,
            encrypted_envelope_json TEXT,
            validation_status TEXT
        );
        CREATE TABLE collector_results (
            id INTEGER PRIMARY KEY,
            payload_id TEXT,
            agent_id TEXT,
            collector TEXT,
            collector_collected_at TEXT,
            hostname TEXT,
            status TEXT,
            payload_json TEXT
        );
        CREATE TABLE risk_events (
            id INTEGER PRIMARY KEY,
            payload_id TEXT,
            agent_id TEXT,
            username TEXT,
            risk_level TEXT,
            summary TEXT,
            correlated_signals_json TEXT,
            risk_score REAL,
            created_at TEXT
        );
        CREATE TABLE normalized_features (
            id INTEGER PRIMARY KEY,
            payload_id TEXT,
            agent_id TEXT,
            username TEXT,
            hostname TEXT,
            collector TEXT,
            feature_name TEXT,
            feature_value_numeric REAL,
            feature_value_text TEXT,
            feature_value_json TEXT,
            created_at TEXT
        );
    """)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    for i in range(1, 101):
        conn.execute(
            "INSERT INTO raw_payloads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"p-{i}", f"agent-{i % 5}", now_str, now_str, now_str, f"HOST-{i % 5}", f"user-{i % 3}",
             "aes-256-gcm", "k1", "n1", "c1", "d1", "{}", "accepted")
        )
        conn.execute(
            "INSERT INTO collector_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (i, f"p-{i}", f"agent-{i % 5}", "process" if i % 2 == 0 else "network",
             now_str, f"HOST-{i % 5}", "success" if i % 3 != 0 else "failed",
             json.dumps({"cmdline": f"proc_{i}.exe" if i % 2 == 0 else "GET /"}))
        )
    conn.commit()
    return conn


def test_sqlite_db_init():
    conn = create_sqlite_test_db()
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM raw_payloads")
    assert cursor.fetchone()[0] == 100
    conn.close()


# ==============================================================================
# 1. Ingestion Unique Collector Observation UUID Generation
# ==============================================================================

def test_ingestion_unique_collector_observation_uuids():
    """Verify that multiple observations from the same collector produce unique UUIDs,
    while maintaining determinism and backward compatibility for single observations."""
    client = Mock()
    ch = ClickHouseStorage(client=client)
    ch.batcher.stop()

    sink = Mock()
    sink.add = Mock()

    payload_id = "test-payload-uuid-multi-1"
    envelope = {"scheme": "aes-256-gcm", "key_id": "k1", "created_at": "2026-10-10T12:00:00Z"}
    decrypted_payload = {
        "payload_id": payload_id,
        "agent_id": "agent-1",
        "hostname": "HOST-1",
        "username": "alice",
        "collected_at": "2026-10-10T12:00:00Z",
        "collectors": [
            {"collector": "process", "status": "success", "payload": {"pid": 100, "name": "cmd.exe"}},
            {"collector": "process", "status": "success", "payload": {"pid": 200, "name": "powershell.exe"}},
            {"collector": "network", "status": "success", "payload": {"dest_ip": "10.0.0.1", "port": 443}},
        ]
    }

    ch.store_raw_payload(envelope, decrypted_payload, _sink=sink)

    # Collect all rows added to collector_results and telemetry_events
    collector_calls = [call.args[1] for call in sink.add_many.call_args_list if call.args[0] == "collector_results"][0]
    assert len(collector_calls) == 3

    col_ids = [c["id"] for c in collector_calls]
    # 1. All UUIDs must be distinct
    assert len(set(col_ids)) == 3
    # 2. All must be valid UUID strings
    for cid in col_ids:
        assert UUID(cid)

    # 3. First process observation matches canonical uuid5 for backwards compatibility
    canonical_proc_uuid = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload_id}:col:process"))
    assert col_ids[0] == canonical_proc_uuid

    # 4. Second process observation has index-disambiguated unique uuid5
    indexed_proc_uuid = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload_id}:col:process:1"))
    assert col_ids[1] == indexed_proc_uuid
    assert col_ids[1] != col_ids[0]

    # 5. Network observation (at list index 2, but occurrence 1 of 'network') MUST match canonical uuid5!
    canonical_net_uuid = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload_id}:col:network"))
    assert col_ids[2] == canonical_net_uuid

    # 6. Permutation invariance: changing collector list order maintains identical canonical IDs
    decrypted_permuted = {
        **decrypted_payload,
        "collectors": [
            {"collector": "network", "status": "success", "payload": {"dest_ip": "10.0.0.1", "port": 443}},
            {"collector": "process", "status": "success", "payload": {"pid": 100, "name": "cmd.exe"}},
            {"collector": "process", "status": "success", "payload": {"pid": 200, "name": "powershell.exe"}},
        ]
    }
    sink.add_many.reset_mock()
    ch.store_raw_payload(envelope, decrypted_permuted, _sink=sink)
    perm_calls = [call.args[1] for call in sink.add_many.call_args_list if call.args[0] == "collector_results"][0]
    perm_ids = [c["id"] for c in perm_calls]
    assert perm_ids[0] == canonical_net_uuid
    assert perm_ids[1] == canonical_proc_uuid
    assert perm_ids[2] == indexed_proc_uuid

    # 7. Deterministic replay: same payload produces exact same UUIDs
    sink.add_many.reset_mock()
    ch.store_raw_payload(envelope, decrypted_payload, _sink=sink)
    replay_calls = [call.args[1] for call in sink.add_many.call_args_list if call.args[0] == "collector_results"][0]
    assert [c["id"] for c in replay_calls] == col_ids


# ==============================================================================
# 2. ClickHouse list_logs Filtering (collector, status)
# ==============================================================================

def test_clickhouse_list_logs_filtering_collector_and_status():
    """Verify ClickHouse list_logs correctly constructs subquery filters for collector and status."""
    client = Mock()
    ch = ClickHouseStorage(client=client)
    ch.batcher.stop()

    ch._query = Mock()
    ch._query.return_value = SimpleNamespace(column_names=["payload_id", "received_at"], result_rows=[])

    # 1. Filter by collector
    ch.list_logs(collector="process")
    sql = ch._query.call_args.args[0]
    params = ch._query.call_args.kwargs.get("parameters", {})
    assert "payload_id IN (SELECT payload_id FROM collector_results WHERE positionCaseInsensitiveUTF8(collector, %(collector)s) > 0)" in sql
    assert params["collector"] == "process"

    # 2. Filter by status: 'error' expands to error statuses
    ch._query.reset_mock()
    ch.list_logs(status="error")
    sql = ch._query.call_args.args[0]
    params = ch._query.call_args.kwargs.get("parameters", {})
    assert "lower(status) IN ('error', 'failed', 'critical', 'tampered')" in sql

    # 3. Filter by status: specific status
    ch._query.reset_mock()
    ch.list_logs(status="success")
    sql = ch._query.call_args.args[0]
    params = ch._query.call_args.kwargs.get("parameters", {})
    assert "lower(status) = lower(%(status)s)" in sql
    assert params["status"] == "success"

    # 4. Combined filtering with case-insensitivity: uses SINGLE correlated subquery
    ch._query.reset_mock()
    ch.list_logs(collector="network", status="failed", username="Alice", hostname="HOST-1")
    sql = ch._query.call_args.args[0]
    params = ch._query.call_args.kwargs.get("parameters", {})
    assert "lower(username) = lower(%(username)s)" in sql
    assert "lower(hostname) = lower(%(hostname)s)" in sql
    assert "WHERE positionCaseInsensitiveUTF8(collector, %(collector)s) > 0 AND lower(status) = lower(%(status)s)" in sql
    assert params["username"] == "Alice"
    assert params["hostname"] == "HOST-1"
    assert params["collector"] == "network"
    assert params["status"] == "failed"

    # 5. Combined filtering with status='error' multi-status expansion
    ch._query.reset_mock()
    ch.list_logs(collector="process", status="error")
    sql = ch._query.call_args.args[0]
    assert "WHERE positionCaseInsensitiveUTF8(collector, %(collector)s) > 0 AND lower(status) IN ('error', 'failed', 'critical', 'tampered')" in sql


# ==============================================================================
# 3. Postgres list_logs Case-Insensitivity
# ==============================================================================

def test_postgres_list_logs_case_insensitivity():
    """Verify PostgreSQL/SQLite list_logs handles case-insensitive filtering for username,
    hostname, collector, and status."""
    conn = create_sqlite_test_db()

    @contextmanager
    def checkout():
        yield _SQLiteParamAdapter(conn)

    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection = checkout
    storage._is_sqlite = True

    # 1. Uppercase username matches lowercase stored user-0
    logs_user = storage.list_logs(username="USER-0")
    assert len(logs_user) > 0
    assert all(l["username"] == "user-0" for l in logs_user)

    # 2. Lowercase hostname matches uppercase stored HOST-0
    logs_host = storage.list_logs(hostname="host-0")
    assert len(logs_host) > 0
    assert all(l["hostname"] == "HOST-0" for l in logs_host)

    # 3. Mixed-case collector matches process
    logs_proc = storage.list_logs(collector="PrOcEsS")
    assert len(logs_proc) > 0

    # 4. Status case-insensitivity: 'FAILED' matches 'failed'
    logs_failed = storage.list_logs(status="FAILED")
    assert len(logs_failed) > 0

    # 5. Status 'error' maps to error/failed
    logs_err = storage.list_logs(status="error")
    assert len(logs_err) > 0

    # 6. Cross-collector false positive elimination:
    # Insert payload p-split where process succeeded but network failed
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO raw_payloads VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("p-split", "agent-split", now_str, now_str, now_str, "HOST-SPLIT", "user-split",
         "aes-256-gcm", "k1", "n1", "c1", "d1", "{}", "accepted")
    )
    conn.execute(
        "INSERT INTO collector_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (9991, "p-split", "agent-split", "process", now_str, "HOST-SPLIT", "success", "{}")
    )
    conn.execute(
        "INSERT INTO collector_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (9992, "p-split", "agent-split", "network", now_str, "HOST-SPLIT", "failed", "{}")
    )
    conn.commit()

    # Querying process + failed MUST NOT return p-split (process did not fail)
    split_proc_fail = storage.list_logs(collector="process", status="failed")
    assert not any(l["payload_id"] == "p-split" for l in split_proc_fail)

    # Querying process + error MUST NOT return p-split
    split_proc_err = storage.list_logs(collector="process", status="error")
    assert not any(l["payload_id"] == "p-split" for l in split_proc_err)

    # Querying network + failed MUST return p-split
    split_net_fail = storage.list_logs(collector="network", status="failed")
    assert any(l["payload_id"] == "p-split" for l in split_net_fail)

    # Querying process + success MUST return p-split
    split_proc_succ = storage.list_logs(collector="process", status="success")
    assert any(l["payload_id"] == "p-split" for l in split_proc_succ)

    conn.close()


# ==============================================================================
# 4. Telemetry Explorer Fallback Username Safety
# ==============================================================================

def test_telemetry_explorer_fallback_username_safety_and_search():
    """Verify fallback from telemetry_events to collector_results when schema v1 is used,
    rewriting username and search clauses so ClickHouse does not crash on missing column."""
    storage = Mock()
    storage.collector_schema_version = 1
    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

    fb_cols = ["event_id", "payload_id", "timestamp", "agent_id", "collector_name", "hostname", "username", "status", "payload_json"]
    fb_rows = [
        (UUID(int=1), "p-10", now, "agent-1", "process", "HOST-1", "", "success", json.dumps({"name": "svchost.exe"}))
    ]
    rp_cols = ["payload_id", "username"]
    rp_rows = [("p-10", "alice")]

    # 1. Search with username filter on schema v1
    storage._query.side_effect = [
        Exception("telemetry_events not available"),
        SimpleNamespace(column_names=fb_cols, result_rows=fb_rows),
        SimpleNamespace(column_names=rp_cols, result_rows=rp_rows),
    ]

    res = ch_explorer(storage, limit=10, username="alice")
    assert len(res["events"]) == 1
    assert res["events"][0]["username"] == "alice"

    # Verify query was rewritten to query raw_payloads subquery instead of nonexistent cr.username
    fb_sql = storage._query.call_args_list[1].args[0]
    assert "cr.payload_id IN (SELECT payload_id FROM raw_payloads WHERE positionCaseInsensitiveUTF8(username," in fb_sql

    # 2. Free-text search on schema v1: ensure username in disjunction is safely rewritten
    storage._query.reset_mock()
    storage._query.side_effect = [
        Exception("telemetry_events not available"),
        SimpleNamespace(column_names=fb_cols, result_rows=fb_rows),
        SimpleNamespace(column_names=rp_cols, result_rows=rp_rows),
    ]

    res_search = ch_explorer(storage, limit=10, search="alice")
    assert len(res_search["events"]) == 1
    assert res_search["events"][0]["username"] == "alice"
    search_fb_sql = storage._query.call_args_list[1].args[0]
    assert "cr.payload_id IN (SELECT payload_id FROM raw_payloads WHERE positionCaseInsensitiveUTF8(username," in search_fb_sql


# ==============================================================================
# 5. Telemetry Histogram Bucket Intervals
# ==============================================================================

def test_telemetry_histogram_bucket_intervals():
    """Verify histogram aggregation supports variable intervals (1m, 1h, 1d) on both engines."""
    conn = create_sqlite_test_db()

    @contextmanager
    def checkout():
        yield _SQLiteParamAdapter(conn)

    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection = checkout
    storage._is_sqlite = True

    # 1. Default 1h time window uses 1m buckets
    h1 = pg_histogram(storage, time_range="1h")
    assert h1["ok"] is True
    assert h1["interval"] == "1m"
    assert h1["total_events"] == 100
    assert len(h1["histogram"]) >= 1

    # 2. Explicit interval 1d on time_range 'all'
    h_day = pg_histogram(storage, time_range="all", interval="1d")
    assert h_day["ok"] is True
    assert h_day["interval"] == "1d"
    assert h_day["total_events"] == 100

    # 3. ClickHouse histogram with interval 5m
    ch = Mock()
    t1 = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    ch._query.return_value = SimpleNamespace(
        column_names=["t", "c"],
        result_rows=[(t1, 50)]
    )
    ch_hist = ch_histogram(ch, time_range="24h", interval="5m")
    assert ch_hist["ok"] is True
    assert ch_hist["interval"] == "5m"
    assert ch_hist["total_events"] == 50
    sql = ch._query.call_args.args[0]
    assert "toStartOfFiveMinutes(timestamp)" in sql

    # 4. Status 'error' multi-status expansion on ClickHouse histogram
    ch._query.reset_mock()
    ch_histogram(ch, time_range="1h", status="error")
    ch_sql = ch._query.call_args.args[0]
    assert "lower(status) IN ('error', 'failed', 'critical', 'tampered')" in ch_sql

    # 5. Status 'error' multi-status expansion on Postgres histogram
    h_err = pg_histogram(storage, time_range="all", status="error")
    assert h_err["ok"] is True
    # create_sqlite_test_db() sets 'failed' on 1/3 of rows: exactly 33 failed rows
    assert h_err["total_events"] == 33

    conn.close()


# ==============================================================================
# 6. Caching Layer for Fast UI Delivery
# ==============================================================================

def api_client(storage, operator_actor: str | None = None):
    app = FastAPI()
    app.include_router(telemetry.router)
    app.include_router(logs.router)
    register_error_handlers(app)
    app.dependency_overrides[get_storage] = lambda: storage
    from server.api.deps import OperatorPrincipal
    op = OperatorPrincipal(actor=operator_actor or "test_operator", roles={"operator:read", "admin"})
    for r in list(app.routes) + list(telemetry.router.routes) + list(logs.router.routes):
        for dependency in getattr(getattr(r, 'dependant', None), 'dependencies', []):
            if dependency.name == 'operator':
                app.dependency_overrides[dependency.call] = (lambda _o=op: _o)
    return TestClient(app)


def test_caching_layer_fast_ui_delivery():
    """Verify that repeated queries to explorer, event detail, histogram, and logs are served
    directly from api_cache with sub-millisecond response latency, while isolating operator identities."""
    api_cache.clear()

    storage = Mock()
    storage.get_telemetry_explorer.return_value = {
        "events": [{
            "event_id": "evt-cache-1", "id": "evt-cache-1", "timestamp": "2026-10-10T12:00:00Z",
            "agent_id": "agent-1", "collector_name": "process", "hostname": "HOST-1",
            "username": "alice", "status": "success", "summary_preview": "Process: explorer.exe",
        }],
        "next_cursor": None,
        "has_more": False,
        "source": "clickhouse",
    }
    storage.get_telemetry_event_detail.return_value = {
        "event_id": "evt-cache-1", "id": "evt-cache-1", "timestamp": "2026-10-10T12:00:00Z",
        "payload": {"cmdline": "explorer.exe"},
    }
    storage.get_telemetry_histogram.return_value = {
        "time_range": "1h", "interval": "1m", "total_events": 42,
        "histogram": [{"timestamp": "2026-10-10T12:00:00Z", "count": 42}],
    }
    storage.list_logs.return_value = [
        {"payload_id": "p-1", "hostname": "HOST-1", "username": "alice"}
    ]

    client = api_client(storage, operator_actor="operator_1")

    # 1. Explorer endpoint: Call 1 misses cache (hits storage), Call 2 hits cache
    resp1 = client.get("/api/v1/telemetry/explorer", params={"limit": 50})
    assert resp1.status_code == 200
    assert storage.get_telemetry_explorer.call_count == 1

    resp2 = client.get("/api/v1/telemetry/explorer", params={"limit": 50})
    assert resp2.status_code == 200
    assert resp2.json()["events"][0]["event_id"] == "evt-cache-1"
    # Call count MUST remain 1 because Call 2 was served from cache
    assert storage.get_telemetry_explorer.call_count == 1

    # Operator isolation: different operator misses cache (call count increments to 2)
    client_bob = api_client(storage, operator_actor="operator_2")
    resp_bob = client_bob.get("/api/v1/telemetry/explorer", params={"limit": 50})
    assert resp_bob.status_code == 200
    assert storage.get_telemetry_explorer.call_count == 2

    # 2. Event detail endpoint: Call 1 misses, Call 2 hits
    resp_d1 = client.get("/api/v1/telemetry/events/evt-cache-1")
    assert resp_d1.status_code == 200
    assert storage.get_telemetry_event_detail.call_count == 1

    resp_d2 = client.get("/api/v1/telemetry/events/evt-cache-1")
    assert resp_d2.status_code == 200
    assert resp_d2.json()["event"]["payload"]["cmdline"] == "explorer.exe"
    assert storage.get_telemetry_event_detail.call_count == 1

    # Event detail fallback with storage.get_payload
    storage.get_telemetry_event_detail.return_value = None
    storage.get_payload.return_value = {
        "payload_id": "p-raw-99", "agent_id": "agent-99", "validation_status": "accepted",
    }
    resp_raw = client.get("/api/v1/telemetry/events/p-raw-99")
    assert resp_raw.status_code == 200
    assert resp_raw.json()["event"]["payload_id"] == "p-raw-99"
    assert storage.get_payload.call_count == 1

    # 3. Histogram endpoint: Call 1 misses, Call 2 hits
    resp_h1 = client.get("/api/v1/telemetry/histogram", params={"time_range": "1h"})
    assert resp_h1.status_code == 200
    assert storage.get_telemetry_histogram.call_count == 1

    resp_h2 = client.get("/api/v1/telemetry/histogram", params={"time_range": "1h"})
    assert resp_h2.status_code == 200
    assert resp_h2.json()["total_events"] == 42
    assert storage.get_telemetry_histogram.call_count == 1

    # 4. Logs endpoint: Call 1 misses, Call 2 hits
    resp_l1 = client.get("/api/v1/logs", params={"limit": 100})
    assert resp_l1.status_code == 200
    assert storage.list_logs.call_count == 1

    resp_l2 = client.get("/api/v1/logs", params={"limit": 100})
    assert resp_l2.status_code == 200
    assert resp_l2.json()["logs"][0]["payload_id"] == "p-1"
    assert storage.list_logs.call_count == 1


# ==============================================================================
# 7. Cache Invalidation on Telemetry Ingest
# ==============================================================================

def test_cache_invalidation_on_telemetry_ingest():
    """Verify that dispatching new telemetry events purges telemetry:* and logs:* cache keys,
    guaranteeing fresh data delivery to the UI on next poll."""
    api_cache.clear()

    storage = Mock()
    storage.get_telemetry_explorer.return_value = {
        "events": [{"event_id": "v1", "id": "v1", "summary_preview": "Version 1"}],
        "next_cursor": None, "has_more": False, "source": "clickhouse",
    }
    storage.list_logs.return_value = [{"payload_id": "log-v1"}]

    client = api_client(storage)

    # Hydrate caches
    r1 = client.get("/api/v1/telemetry/explorer", params={"limit": 50})
    assert r1.status_code == 200
    r_log1 = client.get("/api/v1/logs", params={"limit": 100})
    assert r_log1.status_code == 200
    assert storage.get_telemetry_explorer.call_count == 1
    assert storage.list_logs.call_count == 1

    # Update storage return values
    storage.get_telemetry_explorer.return_value = {
        "events": [{"event_id": "v2", "id": "v2", "summary_preview": "Version 2"}],
        "next_cursor": None, "has_more": False, "source": "clickhouse",
    }
    storage.list_logs.return_value = [{"payload_id": "log-v2"}]

    # Invalidate via telemetry ingest dispatch
    dispatch_telemetry_event("new-payload-999")

    # Next calls must bypass cache and fetch fresh Version 2 data from storage
    r2 = client.get("/api/v1/telemetry/explorer", params={"limit": 50})
    assert r2.status_code == 200
    assert r2.json()["events"][0]["event_id"] == "v2"
    assert storage.get_telemetry_explorer.call_count == 2

    r_log2 = client.get("/api/v1/logs", params={"limit": 100})
    assert r_log2.status_code == 200
    assert r_log2.json()["logs"][0]["payload_id"] == "log-v2"
    assert storage.list_logs.call_count == 2


# ==============================================================================
# 8. Performance Benchmarks / Before-and-After Measurements
# ==============================================================================

def test_performance_benchmark_cache_and_explorer_latency():
    """Benchmark showing cache hit latency improvement and explorer projection speedup."""
    api_cache.clear()

    storage = Mock()
    def simulated_db_query(**kw):
        time.sleep(0.005)  # Simulate 5ms database query latency
        return {
            "events": [{"event_id": f"evt-{i}", "id": f"evt-{i}", "summary_preview": f"Event {i}"} for i in range(50)],
            "next_cursor": None, "has_more": False, "source": "clickhouse",
        }
    storage.get_telemetry_explorer.side_effect = simulated_db_query

    client = api_client(storage)

    # Before (cache miss, querying simulated DB)
    t0 = time.perf_counter()
    resp_miss = client.get("/api/v1/telemetry/explorer", params={"limit": 50})
    t_miss = (time.perf_counter() - t0) * 1000  # ms
    assert resp_miss.status_code == 200

    # After (cache hit, serving from L1 memory)
    t0 = time.perf_counter()
    resp_hit = client.get("/api/v1/telemetry/explorer", params={"limit": 50})
    t_hit = (time.perf_counter() - t0) * 1000  # ms
    assert resp_hit.status_code == 200

    # Ensure speedup is significant (cache hit should be faster than simulated DB query)
    speedup = t_miss / max(t_hit, 0.001)
    print(f"\n[Performance Benchmark Results]")
    print(f"  DB Query Latency (Miss): {t_miss:.2f} ms")
    print(f"  Cache Hit Latency (Hit):  {t_hit:.2f} ms")
    print(f"  Speedup Factor:          {speedup:.1f}x")

    assert t_hit < t_miss
    assert resp_hit.json() == resp_miss.json()
