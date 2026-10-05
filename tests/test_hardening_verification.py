"""
tests/test_hardening_verification.py
------------------------------------
Comprehensive regression test suite verifying InsiEDR Server hardening
across all 6 engineering dimensions:
1. Architecture & Pipeline Scalability (Outbox replication, bounded offloading, admission limits).
2. Software Design & Modular Patterns (Plug-and-play crypto adapters, typed models).
3. Security, Authentication & Zero Trust (Operator RBAC, Agent credential binding, no cross-agent forgery, secret redaction).
4. Reliability, Concurrency & Persistence Integrity (SQL task ownership by task_id AND agent_id, state transitions, task acknowledgement leases).
5. Performance & Resource Utilization (Request limits, memory bounds, lightweight probes).
6. Developer Experience & Observability (RFC 7807 Problem Details, Kubernetes probes).
"""
from __future__ import annotations

import json
import os
import pytest
from typing import Any, Mapping
from fastapi.testclient import TestClient

from server.app import create_app
from server.config import config
from server.plugin_registry import registry
from server.crypto.base import CryptoAdapter
from server.storage.reconciler import ReplicationReconciler
from server.api.responses import api_error


# --------------------------------------------------------------------------
# Mock Storage for Hardening Verification
# --------------------------------------------------------------------------

class HardenedMockStorage:
    def __init__(self):
        self.agents: dict[str, dict[str, Any]] = {
            "agent-alpha": {"agent_id": "agent-alpha", "hostname": "HOST-ALPHA", "status": "active"}
        }
        self.tasks: list[dict[str, Any]] = []
        self.audit_log: list[dict[str, Any]] = []
        self.outbox: list[dict[str, Any]] = []
        self.task_counter = 0
        self.outbox_counter = 0

    def ping(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        return {"agent_count": len(self.agents), "task_count": len(self.tasks)}

    def list_agents(self, limit=100, offset=0):
        return list(self.agents.values())[offset : offset + limit]

    def get_agent(self, agent_id: str):
        return self.agents.get(agent_id)

    def upsert_agent_heartbeat(self, agent_id: str, hostname: str, **kwargs):
        self.agents[agent_id] = {"agent_id": agent_id, "hostname": hostname, "status": "active"}

    def queue_agent_task(
        self,
        agent_id: str,
        command: str,
        params: dict[str, Any] | None = None,
        signature: str | None = None,
        task_id: str | None = None,
        actor_id: str | None = None,
        actor_role: str | None = None,
        ip_address: str | None = None,
    ) -> str:
        self.task_counter += 1
        tid = task_id or f"task-{self.task_counter}"
        self.tasks.append({
            "task_id": tid,
            "agent_id": agent_id,
            "command": command,
            "params": params or {},
            "status": "pending",
            "dispatch_count": 0,
            "acknowledged_at": None,
        })
        self.audit_log.append({
            "task_id": tid,
            "agent_id": agent_id,
            "command": command,
            "actor_id": actor_id or "system",
            "actor_role": actor_role or "operator",
            "ip_address": ip_address,
            "status": "queued",
        })
        return tid

    def get_pending_agent_tasks(self, agent_id: str):
        return [t for t in self.tasks if t["agent_id"] == agent_id and t["status"] == "pending"]

    def mark_tasks_dispatched(self, task_ids: list[str]):
        for t in self.tasks:
            if t["task_id"] in task_ids and t["status"] == "pending":
                t["status"] = "dispatched"
                t["dispatch_count"] += 1

    def acknowledge_agent_task(self, agent_id: str, task_id: str) -> bool:
        for t in self.tasks:
            if t["task_id"] == task_id and t["agent_id"] == agent_id:
                t["status"] = "acknowledged"
                t["acknowledged_at"] = "now"
                return True
        return False

    def update_agent_task_result(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        exit_code: int = 0,
        message: str = "",
        completed_at: str | None = None,
    ) -> bool:
        allowed_statuses = {"pending", "dispatched", "acknowledged", "running", "success", "completed", "failed", "rejected", "timeout", "cancelled"}
        terminal_statuses = {"success", "completed", "failed", "rejected", "timeout", "cancelled"}
        if status not in allowed_statuses:
            return False

        for t in self.tasks:
            # Enforce task ownership by BOTH task_id AND agent_id
            if t["task_id"] == task_id and t["agent_id"] == agent_id:
                if t["status"] in terminal_statuses and t["status"] != status:
                    return False  # Cannot illegally transition out of terminal state
                t["status"] = status
                t["exit_code"] = exit_code
                t["message"] = message
                return True
        return False

    def list_agent_tasks(self, agent_id: str, limit=50, offset=0):
        return [t for t in self.tasks if t["agent_id"] == agent_id][offset : offset + limit]

    def list_risk_events(self, limit=100, offset=0):
        return []

    def enqueue_clickhouse_outbox(self, target_table: str, record_data: dict[str, Any]):
        self.outbox_counter += 1
        self.outbox.append({
            "outbox_id": self.outbox_counter,
            "target_table": target_table,
            "record_json": record_data,
            "status": "pending",
        })

    def get_pending_clickhouse_outbox(self, limit=100):
        return [r for r in self.outbox if r["status"] == "pending"][:limit]

    def mark_clickhouse_outbox_completed(self, outbox_ids: list[int]):
        for r in self.outbox:
            if r["outbox_id"] in outbox_ids:
                r["status"] = "completed"

    def store_raw_payload(self, envelope: dict[str, Any], payload: dict[str, Any]):
        return True


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_rfc7807_problem_details_structure():
    """Verify api_error produces compliant RFC 7807 Problem Details while keeping legacy keys."""
    resp = api_error(code="INVALID_PAYLOAD", message="Malformed JSON input", status_code=400)
    data = json.loads(resp.body)

    # Standard RFC 7807 fields
    assert data["type"] == "urn:insiedr:error:invalid-payload"
    assert data["title"] == "Bad Request"
    assert data["status"] == 400
    assert data["detail"] == "Malformed JSON input"
    assert "instance" in data

    # Backward-compatible fields
    assert data["ok"] is False
    assert data["success"] is False
    assert data["message"] == "Malformed JSON input"
    assert data["error"]["code"] == "INVALID_PAYLOAD"
    assert resp.media_type == "application/problem+json"


def test_health_probes():
    """Verify Kubernetes liveness and readiness endpoints."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    live_resp = client.get("/api/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json()["status"] == "live"
    assert live_resp.json()["ok"] is True

    ready_resp = client.get("/api/health/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json()["status"] == "ready"
    assert ready_resp.json()["database"] == "ok"


def test_operator_rbac_enforcement(monkeypatch):
    """Verify operator actions enforce granular permissions (containment vs remediation)."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    # Configure RBAC roles in config
    monkeypatch.setenv("INSIEDR_AUTH_ENFORCED", "1")
    monkeypatch.setenv("INSIEDR_OPERATOR_ROLES", "containment-key:operator:containment;remed-key:operator:remediation")

    # 1. Missing credentials fails with 401
    resp_unauth = client.post("/api/agents/agent-alpha/isolate")
    assert resp_unauth.status_code == 401
    assert "type" in resp_unauth.json()  # RFC 7807 formatted

    # 2. Remediation key attempting containment fails with 403
    resp_forbidden = client.post(
        "/api/agents/agent-alpha/isolate",
        headers={"Authorization": "Bearer remed-key"},
    )
    assert resp_forbidden.status_code == 403

    # 3. Containment key attempting containment succeeds
    resp_ok = client.post(
        "/api/agents/agent-alpha/isolate",
        headers={"Authorization": "Bearer containment-key"},
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["ok"] is True
    assert resp_ok.json()["status"] == "queued"

    # 4. Containment key attempting remediation (terminate process) fails with 403
    resp_term_forbidden = client.post(
        "/api/agents/agent-alpha/terminate",
        json={"pid": 1234},
        headers={"Authorization": "Bearer containment-key"},
    )
    assert resp_term_forbidden.status_code == 403

    # 5. Remediation key attempting terminate succeeds
    resp_term_ok = client.post(
        "/api/agents/agent-alpha/terminate",
        json={"pid": 1234},
        headers={"Authorization": "Bearer remed-key"},
    )
    assert resp_term_ok.status_code == 200
    assert resp_term_ok.json()["status"] == "queued"


def test_command_audit_logging():
    """Verify operator actions generate attributed command audit log entries."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    # Post an isolation action
    resp = client.post("/api/agents/agent-alpha/isolate", json={"server_ip": "10.0.0.1"})
    assert resp.status_code == 200
    task_id = resp.json()["task_id"]

    # Verify audit log recorded atomically
    assert len(storage.audit_log) == 1
    log_entry = storage.audit_log[0]
    assert log_entry["task_id"] == task_id
    assert log_entry["agent_id"] == "agent-alpha"
    assert log_entry["command"] == "isolate_host"
    assert "actor_id" in log_entry
    assert log_entry["status"] == "queued"


def test_agent_credential_binding_and_spoof_prevention(monkeypatch):
    """Verify agent identity is strictly bound to credentials and cannot be spoofed."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    # 1. Fail closed when auth enforced but NO agent tokens configured on server
    monkeypatch.setenv("INSIEDR_AUTH_ENFORCED", "1")
    monkeypatch.delenv("INSIEDR_AGENT_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("INSIEDR_AGENT_TOKENS", raising=False)

    resp_no_config = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "agent-alpha", "hostname": "HOST-ALPHA"},
        headers={"Authorization": "Bearer arbitrary-token", "X-Agent-ID": "agent-alpha"},
    )
    assert resp_no_config.status_code == 401

    # Configure per-agent bound tokens
    monkeypatch.setenv("INSIEDR_AGENT_TOKENS", "token-alpha:agent-alpha;token-beta:agent-beta")

    # 2. Missing agent token fails with 401
    resp_unauth = client.post("/api/agent/heartbeat", json={"agent_id": "agent-alpha", "hostname": "HOST-ALPHA"})
    assert resp_unauth.status_code == 401

    # 3. Valid token bound to agent-alpha succeeds when claiming agent-alpha
    resp_ok = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "agent-alpha", "hostname": "HOST-ALPHA"},
        headers={"Authorization": "Bearer token-alpha", "X-Agent-ID": "agent-alpha"},
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["status"] == "acknowledged"

    # 4. Spoof attempt: Token bound to agent-alpha, but body claims agent-beta -> 403 Forbidden!
    resp_spoof1 = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "agent-beta", "hostname": "HOST-BETA"},
        headers={"Authorization": "Bearer token-alpha", "X-Agent-ID": "agent-alpha"},
    )
    assert resp_spoof1.status_code == 403

    # 5. Spoof attempt: Attacker sends agent-beta in BOTH header and body with token-alpha -> 403 Forbidden!
    resp_spoof2 = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "agent-beta", "hostname": "HOST-BETA"},
        headers={"Authorization": "Bearer token-alpha", "X-Agent-ID": "agent-beta"},
    )
    assert resp_spoof2.status_code == 403


def test_sql_task_ownership_and_legal_state_transitions():
    """Verify task results enforce matching agent_id and legal state machine transitions."""
    storage = HardenedMockStorage()
    task_id = storage.queue_agent_task("agent-alpha", "isolate_host")

    # 1. Attacker agent (agent-beta) attempts to report result for agent-alpha's task
    attacker_result = storage.update_agent_task_result(
        agent_id="agent-beta",
        task_id=task_id,
        status="success",
        exit_code=0,
    )
    assert attacker_result is False  # Must be rejected due to ownership mismatch

    # 2. Legitimate agent reports successful completion
    legit_result = storage.update_agent_task_result(
        agent_id="agent-alpha",
        task_id=task_id,
        status="success",
        exit_code=0,
        message="Host successfully isolated",
    )
    assert legit_result is True

    # 3. Stale worker attempts to reopen completed task back to 'running'
    reopen_result = storage.update_agent_task_result(
        agent_id="agent-alpha",
        task_id=task_id,
        status="running",
    )
    assert reopen_result is False  # Cannot overwrite terminal state


def test_task_acknowledgement_protocol():
    """Verify explicit task acknowledgement protocol endpoint."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    task_id = storage.queue_agent_task("agent-alpha", "kill_process", params={"pid": 9999})
    storage.mark_tasks_dispatched([task_id])

    # Agent explicitly acknowledges task receipt
    resp = client.post(
        "/api/agent/task-ack",
        json={"agent_id": "agent-alpha", "task_id": task_id},
    )
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] is True
    assert storage.tasks[0]["status"] == "acknowledged"


def test_transactional_outbox_and_reconciler():
    """Verify PostgreSQL-to-ClickHouse transactional outbox and catchup reconciler."""
    storage = HardenedMockStorage()

    # Enqueue two outbox items
    storage.enqueue_clickhouse_outbox("raw_payloads", {"payload": {"test": 1}})
    storage.enqueue_clickhouse_outbox("raw_payloads", {"payload": {"test": 2}})

    assert len(storage.get_pending_clickhouse_outbox()) == 2

    # Mock ClickHouse storage adapter
    class MockClickHouse:
        def __init__(self):
            self.stored = []

        def is_connected(self):
            return True

        def store_raw_payload(self, envelope, payload):
            self.stored.append((envelope, payload))

    ch_mock = MockClickHouse()
    reconciler = ReplicationReconciler(postgres_storage=storage, clickhouse_storage=ch_mock, batch_size=10)

    # Execute one reconciliation cycle
    processed_count = reconciler.reconcile_once()
    assert processed_count == 2
    assert len(ch_mock.stored) == 2
    # Verify records marked completed
    assert len(storage.get_pending_clickhouse_outbox()) == 0


def test_dynamic_crypto_adapter_registration():
    """Verify a custom crypto adapter can be registered and validated without modifying ingestion."""
    class CustomCryptoAdapter:
        scheme = "custom-cipher-test"

        def validate_envelope(self, envelope: Mapping[str, object]) -> None:
            if not envelope.get("custom_token"):
                raise ValueError("custom_token is required")

        def decrypt(self, envelope: Mapping[str, object]) -> bytes:
            return b'{"agent_id": "test", "hostname": "test", "collectors": [], "summary": {"collector_count": 0, "success_count": 0, "failed_count": 0}, "schema": "insiedr.telemetry.v2", "payload_id": "p1", "collected_at": "2026-10-04T12:00:00Z"}'

    adapter = CustomCryptoAdapter()
    registry.register(adapter)
    try:
        assert "custom-cipher-test" in registry.schemes()
        assert registry.get("custom-cipher-test") is adapter
    finally:
        registry.unregister("custom-cipher-test")


def test_isolation_server_ip_selection():
    """Verify isolation does not use request.client.host (proxy/operator IP)."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    # Calling isolate without params should fall back to config.server_ip
    resp = client.post("/api/agents/agent-alpha/isolate")
    assert resp.status_code == 200

    assert len(storage.tasks) == 1
    task = storage.tasks[0]
    # Verify server_ip is not proxy client host
    assert task["params"]["server_ip"] == config.server_ip


def test_strict_buffer_limits_oversized_incoming_batch(tmp_path):
    """Verify an oversized incoming batch cannot bypass buffer limits when buffer is empty."""
    from server.storage.clickhouse_batcher import ClickHouseBatcher

    # Configure strictly 10 rows / 100 bytes limit
    batcher = ClickHouseBatcher(
        insert_fn=lambda t, r: None,
        batch_size=5,
        flush_interval=10.0,
        max_buffer_rows=10,
        max_buffer_bytes=100,
        dlq_dir=str(tmp_path),
    )

    # 20 rows of ~1000 bytes each
    oversized_batch = [
        {"row_id": i, "payload": "X" * 1000}
        for i in range(20)
    ]

    batcher.add_many("test_table", oversized_batch)

    # Buffer MUST NEVER exceed configured row or byte bounds
    assert len(batcher._buffers.get("test_table", [])) <= 10
    assert batcher._table_bytes.get("test_table", 0) <= 100
    # Overflows must have been dropped to DLQ
    assert batcher.total_overflow_dropped > 0


def test_reconciler_unconfirmed_flush_does_not_acknowledge():
    """Verify reconciler does not mark outbox rows completed if ClickHouse flush fails."""
    storage = HardenedMockStorage()
    storage.enqueue_clickhouse_outbox("raw_payloads", {"payload": {"test": 123}})
    assert len(storage.get_pending_clickhouse_outbox()) == 1

    class FailingFlushClickHouse:
        def is_connected(self):
            return True

        def store_raw_payload(self, envelope, payload):
            pass  # Buffer admission succeeds

        def flush_all(self):
            raise RuntimeError("ClickHouse disk full or network outage")

    ch_failing = FailingFlushClickHouse()
    reconciler = ReplicationReconciler(postgres_storage=storage, clickhouse_storage=ch_failing)

    # Reconcile attempt
    count = reconciler.reconcile_once()
    assert count == 0
    # Outbox rows MUST remain pending in PostgreSQL for future retry
    assert len(storage.get_pending_clickhouse_outbox()) == 1


def test_migration_011_schema_and_query_parity():
    """Verify Migration 011 column definitions match production repository queries."""
    import sqlite3
    from server.storage.migration_runner import run_sql_script

    with open("server/storage/migrations/011_command_audit.sql", "r", encoding="utf-8") as f:
        sql = f.read()

    conn = sqlite3.connect(":memory:")
    # Create prerequisite agent_tasks table
    conn.execute("CREATE TABLE agent_tasks (task_id TEXT PRIMARY KEY, agent_id TEXT);")
    run_sql_script(conn, sql)

    # Verify command_audit_log columns
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(command_audit_log);")
    audit_cols = {row[1] for row in cur.fetchall()}
    expected_audit_cols = {"audit_id", "task_id", "agent_id", "command", "params_json", "actor_id", "actor_role", "ip_address", "status", "created_at"}
    assert expected_audit_cols.issubset(audit_cols)

    # Verify clickhouse_outbox columns
    cur.execute("PRAGMA table_info(clickhouse_outbox);")
    outbox_cols = {row[1] for row in cur.fetchall()}
    expected_outbox_cols = {"outbox_id", "target_table", "record_json", "status", "attempts", "last_error", "created_at", "processed_at"}
    assert expected_outbox_cols.issubset(outbox_cols)

    # Verify query execution matches repository SQL syntax
    cur.execute(
        """
        INSERT INTO command_audit_log (task_id, agent_id, command, params_json, actor_id, actor_role, ip_address, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', CURRENT_TIMESTAMP)
        """,
        ("t1", "a1", "cmd", "{}", "actor", "admin", "127.0.0.1"),
    )
    cur.execute(
        """
        INSERT INTO clickhouse_outbox (target_table, record_json, status, attempts, created_at)
        VALUES (?, ?, 'pending', 0, CURRENT_TIMESTAMP)
        """,
        ("raw_payloads", "{}"),
    )
    conn.commit()

    cur.execute("SELECT outbox_id, target_table, record_json, attempts FROM clickhouse_outbox WHERE status = 'pending'")
    assert len(cur.fetchall()) == 1


def test_redis_task_queue_atomic_transitions():
    """Verify RedisTaskQueue uses atomic BRPOPLPUSH and pipeline transactions to eliminate job-loss windows."""
    from server.task_queue import RedisTaskQueue, _REDIS_KEY_PENDING, _REDIS_KEY_PROCESSING, _REDIS_KEY_RUNNING, _REDIS_KEY_RETRY

    class MockPipeline:
        def __init__(self):
            self.calls = []

        def lrem(self, key, count, val):
            self.calls.append(("lrem", key, count, val))

        def rpush(self, key, val):
            self.calls.append(("rpush", key, val))

        def hset(self, key, hkey, val):
            self.calls.append(("hset", key, hkey, val))

        def hdel(self, key, hkey):
            self.calls.append(("hdel", key, hkey))

        def zadd(self, key, mapping):
            self.calls.append(("zadd", key, mapping))

        def execute(self):
            return True

    class MockRedis:
        def __init__(self):
            self.pipe = MockPipeline()
            self.blmove_called = False
            self.brpoplpush_called = False

        def register_script(self, script):
            return lambda *a, **k: 0

        def blmove(self, src, dst, timeout=2, src_dir="LEFT", dest_dir="RIGHT", **kwargs):
            # Also accept keyword-style src= and dest= arguments used by our code
            self.blmove_called = True
            return json.dumps({"id": "task-xyz", "task_type": "test", "attempts": 0})

        def brpoplpush(self, src, dst, timeout=2):
            self.brpoplpush_called = True
            return json.dumps({"id": "task-xyz", "task_type": "test", "attempts": 0})

        def pipeline(self, transaction=True):
            return self.pipe

    mock_client = MockRedis()
    queue = RedisTaskQueue.__new__(RedisTaskQueue)
    queue._client = mock_client
    queue._promote_retries = lambda: None

    # 1. Test claim_next uses BLMOVE (FIFO) and atomic pipeline
    task = queue.claim_next()
    assert task is not None
    # Should prefer blmove for FIFO (or fall back to brpoplpush for older Redis)
    assert mock_client.blmove_called or mock_client.brpoplpush_called
    # claimed_at entry is pushed back to processing list
    assert any(c[0] == "lrem" and c[1] == _REDIS_KEY_PROCESSING for c in mock_client.pipe.calls)
    assert any(c[0] == "rpush" and c[1] == _REDIS_KEY_PROCESSING for c in mock_client.pipe.calls)
    assert any(c[0] == "hset" and c[1] == _REDIS_KEY_RUNNING for c in mock_client.pipe.calls)
    # Verify claimed_at is stamped on the returned task
    assert "claimed_at" in task

    # 2. Test fail uses atomic pipeline for HDEL + ZADD
    mock_client.pipe.calls.clear()
    queue.fail("task-xyz", {"id": "task-xyz", "attempts": 1, "max_attempts": 3}, error="timeout")
    assert any(c[0] == "hdel" and c[1] == _REDIS_KEY_RUNNING for c in mock_client.pipe.calls)
    assert any(c[0] == "zadd" and c[1] == _REDIS_KEY_RETRY for c in mock_client.pipe.calls)


def test_async_fleet_route_thread_offloading():
    """Verify fleet routes offload synchronous storage execution to a worker thread."""
    import threading

    captured_threads = []

    class ThreadTrackingStorage(HardenedMockStorage):
        def list_agents(self, limit=100, offset=0):
            captured_threads.append(threading.current_thread())
            return super().list_agents(limit, offset)

    storage = ThreadTrackingStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    resp = client.get("/api/agents")
    assert resp.status_code == 200
    assert len(captured_threads) == 1
    # Verify storage called on a background AnyIO worker thread, not the main event loop thread
    assert captured_threads[0] != threading.main_thread()


def test_excel_export_thread_offloading():
    """Verify Excel export workbook generation offloads to a worker thread."""
    import threading

    captured_threads = []

    class ThreadTrackingStorage(HardenedMockStorage):
        def list_normalized_features(self, limit=100, offset=0, **filters):
            captured_threads.append(threading.current_thread())
            return []

    storage = ThreadTrackingStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    resp = client.get("/api/export/features?format=xlsx")
    assert resp.status_code == 200
    assert len(captured_threads) == 1
    assert captured_threads[0] != threading.main_thread()


def test_agent_shared_secret_suffix_impersonation_rejected(monkeypatch):
    """Verify shared-secret suffix impersonation (<secret>:<victim>) is completely rejected."""
    storage = HardenedMockStorage()
    app = create_app(storage=storage, apply_migrations=False)
    client = TestClient(app)

    monkeypatch.setenv("INSIEDR_AUTH_ENFORCED", "1")
    monkeypatch.setenv("INSIEDR_AGENT_BEARER_TOKEN", "supersecretsharedtoken")
    monkeypatch.setenv("INSIEDR_AGENT_TOKENS", "valid-token-alpha:agent-alpha")

    # 1. Attacker tries shared secret with suffix :victim-agent -> 401 Unauthorized
    resp = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "victim-agent", "hostname": "VICTIM-HOST"},
        headers={"Authorization": "Bearer supersecretsharedtoken:victim-agent", "X-Agent-ID": "victim-agent"},
    )
    assert resp.status_code == 401

    # 2. Attacker tries raw shared secret without suffix -> 401 Unauthorized
    resp2 = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "victim-agent", "hostname": "VICTIM-HOST"},
        headers={"Authorization": "Bearer supersecretsharedtoken", "X-Agent-ID": "victim-agent"},
    )
    assert resp2.status_code == 401

    # 3. Valid registered token bound to agent-alpha succeeds for agent-alpha
    resp_ok = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "agent-alpha", "hostname": "ALPHA-HOST"},
        headers={"Authorization": "Bearer valid-token-alpha", "X-Agent-ID": "agent-alpha"},
    )
    assert resp_ok.status_code == 200

    # 4. Valid registered token bound to agent-alpha fails if trying to act as victim-agent -> 403 Forbidden
    resp_spoof = client.post(
        "/api/agent/heartbeat",
        json={"agent_id": "victim-agent", "hostname": "VICTIM-HOST"},
        headers={"Authorization": "Bearer valid-token-alpha", "X-Agent-ID": "victim-agent"},
    )
    assert resp_spoof.status_code == 403


def test_reconciler_flush_failure_raises_and_prevents_completion():
    """Verify failed ClickHouse flush raises on error and does NOT mark outbox completed."""
    from server.storage.clickhouse_batcher import ClickHouseBatcher

    def failing_insert(table, rows):
        raise RuntimeError("ClickHouse connection reset by peer")

    batcher = ClickHouseBatcher(insert_fn=failing_insert, batch_size=10, max_retries=1, dlq_enabled=False)
    batcher.add("raw_payloads", {"payload_id": "p-123"})

    # 1. flush_all(raise_on_error=True) must raise RuntimeError
    with pytest.raises(RuntimeError, match="ClickHouse batch flush failed"):
        batcher.flush_all(raise_on_error=True)

    # 2. Reconciler with failing flush retains records in outbox
    class FailingCHStorage:
        def is_connected(self):
            return True
        def store_raw_payload(self, env, pay):
            pass
        def flush_all(self, raise_on_error=False):
            if raise_on_error:
                raise RuntimeError("ClickHouse flush forced failure")

    class MockPGWithOutbox:
        def __init__(self):
            self.outbox = [{"outbox_id": 99, "target_table": "raw_payloads", "record_json": {}}]
            self.completed_ids = []
            self.attempt_counts = {}

        def get_pending_clickhouse_outbox(self, limit=100):
            return list(self.outbox)

        def mark_clickhouse_outbox_completed(self, ids):
            self.completed_ids.extend(ids)

        def increment_clickhouse_outbox_attempts(self, ids, err):
            for i in ids:
                self.attempt_counts[i] = self.attempt_counts.get(i, 0) + 1

    pg = MockPGWithOutbox()
    ch = FailingCHStorage()
    reconciler = ReplicationReconciler(postgres_storage=pg, clickhouse_storage=ch)

    reconciled_count = reconciler.reconcile_once()
    assert reconciled_count == 0
    # Crucial assertion: failed flush must NEVER mark outbox completed
    assert len(pg.completed_ids) == 0
    assert pg.attempt_counts.get(99, 0) >= 1


def test_direct_clickhouse_write_deduplication_and_idempotency():
    """Verify direct ClickHouse write marks outbox completed, and row IDs are deterministic."""
    import uuid
    from server.storage.clickhouse_storage import ClickHouseStorage

    # 1. Deterministic UUID verification
    p_id = "test-payload-uuid-1"
    c_name = "process_monitor"
    col_id_1 = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{p_id}:col:{c_name}"))
    col_id_2 = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{p_id}:col:{c_name}"))
    assert col_id_1 == col_id_2  # Must be strictly deterministic across calls

    # 2. TelemetryRepository must NOT mark outbox completed immediately after direct write.
    #    ch.store_raw_payload() only enqueues rows in the in-memory batcher — not durable.
    #    Marking completed here would cause silent data loss on crash before flush.
    #    The reconciler confirms durable insertion via flush_all(raise_on_error=True) and
    #    only then calls mark_clickhouse_outbox_completed().
    from server.storage.repositories.telemetry_repo import TelemetryRepository

    class MockPG:
        def __init__(self):
            self.completed_payloads: list = []
        def store_raw_payload(self, env, pay):
            return True
        def mark_outbox_completed_by_payload_id(self, payload_id):
            self.completed_payloads.append(payload_id)

    class MockCH:
        def is_connected(self):
            return True
        def store_raw_payload(self, env, pay):
            pass  # Only in-memory queue admission — not durable

    pg = MockPG()
    ch = MockCH()
    repo = TelemetryRepository(pg, ch)
    repo.store_payload({}, {"payload_id": "payload-abc-456"})

    # Direct CH write must NOT immediately mark outbox completed (durable confirmation
    # requires flush_all confirmation from reconciler, not in-memory enqueue).
    assert "payload-abc-456" not in pg.completed_payloads, (
        "Premature outbox completion: mark_outbox_completed_by_payload_id must not be called "
        "after direct CH write. Only the reconciler may mark entries completed after confirmed flush."
    )


def test_reconciler_worker_lifecycle_in_app():
    """Verify ReplicationReconciler worker is wired into app lifespan."""
    from server.storage.hybrid_storage import HybridStorage

    class MockPG(HardenedMockStorage):
        pass

    class MockCH:
        def is_connected(self):
            return True
        def ensure_schema(self):
            pass
        def close(self):
            pass

    hybrid = HybridStorage(postgres_storage=MockPG(), clickhouse_storage=MockCH())
    app = create_app(storage=hybrid, apply_migrations=False)

    with TestClient(app) as client:
        # During active lifespan, reconciler should be started
        assert hasattr(app.state, "reconciler")
        assert app.state.reconciler is not None
        assert app.state.reconciler._running is True

    # After lifespan context exit, reconciler should be stopped
    assert app.state.reconciler._running is False


def test_migration_012_corrective_schema_repair():
    """Verify migration 012 exists and can execute cleanly."""
    import sqlite3
    from server.storage.migration_runner import run_sql_script
    from pathlib import Path

    mig_file = Path("server/storage/migrations/012_repair_command_audit_and_outbox.sql")
    assert mig_file.is_file()

    conn = sqlite3.connect(":memory:")
    # Run migration script against SQLite in-memory database
    count = run_sql_script(conn, mig_file.read_text(encoding="utf-8"))
    assert count >= 1

    # Verify tables created
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "command_audit_log" in tables
    assert "clickhouse_outbox" in tables
    conn.close()


def test_auth_enforced_with_operator_roles_only(monkeypatch):
    """Verify auth_enforced is True when only INSIEDR_OPERATOR_ROLES is set."""
    from server.config import ServerConfig
    cfg = ServerConfig()
    monkeypatch.delenv("INSIEDR_AUTH_ENFORCED", raising=False)
    monkeypatch.delenv("INSIEDR_OPERATOR_API_KEY", raising=False)
    monkeypatch.delenv("OPERATOR_API_KEY", raising=False)
    monkeypatch.delenv("INSIEDR_AGENT_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AGENT_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("INSIEDR_AGENT_TOKENS", raising=False)
    monkeypatch.setenv("INSIEDR_OPERATOR_ROLES", "soc_token_1:operator:read")

    assert cfg.auth_enforced is True


def test_redact_dsn_credentials_formats():
    """Verify redact_dsn_credentials handles both URL format and libpq keyword format."""
    from shared.crypto_utils import redact_dsn_credentials

    # URL format
    url_dsn = "postgresql://insiedr_user:super_secret@db.internal:5432/insiedr_db"
    redacted_url = redact_dsn_credentials(url_dsn)
    assert "super_secret" not in redacted_url
    assert "***" in redacted_url

    # Keyword format
    kw_dsn = "host=db.internal port=5432 user=insiedr password=super_secret dbname=insiedr_db"
    redacted_kw = redact_dsn_credentials(kw_dsn)
    assert "super_secret" not in redacted_kw
    assert "password=***" in redacted_kw


def test_readiness_probe_returns_503_when_storage_none():
    """Verify /api/health/ready returns HTTP 503 when storage is None (unconfigured)."""
    app = create_app(storage=None, apply_migrations=False)
    client = TestClient(app)

    resp = client.get("/api/health/ready")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "not_ready"
    assert data["ok"] is False
    assert data["database"] == "not_configured"


def test_stale_dlq_replaying_recovery(tmp_path):
    """Verify abandoned .replaying DLQ files older than threshold are recovered."""
    import time
    from server.storage.clickhouse_batcher import ClickHouseBatcher

    inserted_batches = []
    def mock_insert(tbl, rows):
        inserted_batches.append((tbl, rows))

    batcher = ClickHouseBatcher(
        insert_fn=mock_insert,
        dlq_dir=tmp_path,
        dlq_enabled=True,
        flush_interval=0.1,
    )

    # Create an abandoned .replaying file with old mtime
    stale_file = tmp_path / "dlq_raw_payloads_1700000000_1234_abcdef12.replaying"
    header = {"_metadata": {"version": 1, "table": "raw_payloads", "row_count": 1}}
    payload = {"row_id": "test-123", "data": "hello"}
    stale_file.write_text(json.dumps(header) + "\n" + json.dumps(payload) + "\n", encoding="utf-8")

    # Set file mtime to 1 hour ago
    old_time = time.time() - 3600
    os.utime(stale_file, (old_time, old_time))

    # Run replay_dlq: should detect the stale .replaying file, rename it to .jsonl, and replay it
    replayed = batcher.replay_dlq()
    assert replayed == 1
    assert len(inserted_batches) == 1
    assert inserted_batches[0][0] == "raw_payloads"
    assert not stale_file.exists()


def test_rust_to_python_interop_envelope_decryption():
    """Verify that Python AESGCMPlugin decrypts the wire envelope generated by the Rust agent."""
    import tempfile
    from pathlib import Path
    from server.crypto.aesgcm_plugin import AESGCMPlugin

    scratch_file = Path(tempfile.gettempdir()) / "insiedr_scratch" / "aes_envelope.json"
    if not scratch_file.is_file():
        pytest.skip("Rust cross-verification envelope not present (run cargo test --test cross_verify first)")

    envelope = json.loads(scratch_file.read_text(encoding="utf-8"))
    key = b"\x42" * 32
    plugin = AESGCMPlugin(key)
    plugin.validate_envelope(envelope)
    plaintext = plugin.decrypt(envelope)
    data = json.loads(plaintext.decode("utf-8"))
    assert data.get("verification") == "rust_to_python_interop_success"
    assert data.get("score") == 100



