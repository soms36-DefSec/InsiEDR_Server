"""
tests/test_tier3_fleet_control.py
---------------------------------
Comprehensive Test Suite for Tier 3: Fleet Management, Distributed Containment
and SOC Command Plane.

Verifies:
1. Agent periodic heartbeat ingestion with host metrics (CPU, RAM, Spool depth).
2. Downlink task dispatching in HeartbeatResponse (zero or more pending tasks).
3. Agent command execution result reporting (POST /api/agent/task-result & /task_result).
4. SOC remote containment REST APIs:
   - POST /api/agents/{agent_id}/isolate (network firewall containment)
   - POST /api/agents/{agent_id}/unisolate (containment release)
   - POST /api/agents/{agent_id}/terminate (malicious process termination by PID)
   - POST /api/agents/{agent_id}/lock (workstation console lock)
   - POST /api/agents/{agent_id}/rollback (VSS snapshot / directory rollback)
5. Task execution history query (GET /api/agents/{agent_id}/tasks).
6. Single agent query & 404 handling.
7. Dual-route REST aliases (/api/... and /api/v1/...).
8. FleetRepository SQLite integration test verifying SQL queries.
"""
from __future__ import annotations

import json
import sqlite3
import pytest
from typing import Any
from fastapi.testclient import TestClient

from server.app import create_app
from server.storage.repositories.fleet_repo import FleetRepository
from server.storage.postgres_storage import _SQLiteParamAdapter


class MockFleetStorage:
    """Mock storage adapter for Tier 3 Fleet Control testing."""

    def __init__(self):
        self.agents: dict[str, dict[str, Any]] = {
            "agent-001": {
                "agent_id": "agent-001",
                "hostname": "CORP-WKS-01",
                "ip_address": "192.168.1.101",
                "status": "active",
                "os_system": "Windows",
                "os_release": "11",
                "os_version": "23H2",
            }
        }
        self.heartbeats: list[dict[str, Any]] = []
        self.tasks: list[dict[str, Any]] = []
        self.task_counter = 0

    def list_agents(self, limit=100, offset=0):
        return list(self.agents.values())[offset : offset + limit]

    def get_agent(self, agent_id: str):
        return self.agents.get(agent_id)

    def upsert_agent_heartbeat(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str | None = None,
        agent_version: str | None = None,
        status: str = "active",
        metrics: dict[str, Any] | None = None,
        config_version: str | None = None,
    ):
        if agent_id not in self.agents:
            self.agents[agent_id] = {
                "agent_id": agent_id,
                "hostname": hostname,
                "ip_address": ip_address,
                "status": status,
            }
        else:
            self.agents[agent_id]["hostname"] = hostname
            self.agents[agent_id]["ip_address"] = ip_address or self.agents[agent_id].get("ip_address")
            self.agents[agent_id]["status"] = status
            self.agents[agent_id]["metrics"] = metrics

        self.heartbeats.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "agent_version": agent_version,
            "status": status,
            "metrics": metrics or {},
            "config_version": config_version,
        })

    def queue_agent_task(
        self,
        agent_id: str,
        command: str,
        params: dict[str, Any] | None = None,
        signature: str | None = None,
        task_id: str | None = None,
    ) -> str:
        self.task_counter += 1
        tid = task_id or f"task-uuid-{self.task_counter}"
        self.tasks.append({
            "task_id": tid,
            "agent_id": agent_id,
            "command": command,
            "params": params or {},
            "signature": signature,
            "status": "pending",
            "exit_code": None,
            "message": None,
            "created_at": "2026-09-27T10:00:00Z",
            "dispatched_at": None,
            "completed_at": None,
        })
        return tid

    def get_pending_agent_tasks(self, agent_id: str):
        return [
            t for t in self.tasks
            if t["agent_id"] == agent_id and t["status"] == "pending"
        ]

    def mark_tasks_dispatched(self, task_ids: list[str]):
        for t in self.tasks:
            if t["task_id"] in task_ids and t["status"] == "pending":
                t["status"] = "dispatched"
                t["dispatched_at"] = "2026-09-27T10:01:00Z"

    def update_agent_task_result(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        exit_code: int,
        message: str,
        completed_at: str | None = None,
    ) -> bool:
        for t in self.tasks:
            if t["task_id"] == task_id:
                t["status"] = status
                t["exit_code"] = exit_code
                t["message"] = message
                t["completed_at"] = completed_at or "2026-09-27T10:02:00Z"
                return True
        return False

    def list_agent_tasks(self, agent_id: str, limit: int = 50, offset: int = 0):
        agent_tasks = [t for t in self.tasks if t["agent_id"] == agent_id]
        return agent_tasks[offset : offset + limit]

    def list_risk_events(self, limit=100, offset=0):
        return []


@pytest.fixture
def mock_storage():
    return MockFleetStorage()


@pytest.fixture
def client(mock_storage):
    app = create_app(storage=mock_storage, apply_migrations=False)
    return TestClient(app)


# --------------------------------------------------------------------------
# Heartbeat & Downlink Tests
# --------------------------------------------------------------------------


def test_heartbeat_ingestion_and_response(client: TestClient, mock_storage: MockFleetStorage):
    """Verify heartbeat ingestion updates agent metrics and returns HeartbeatResponse."""
    req_payload = {
        "agent_id": "agent-001",
        "hostname": "CORP-WKS-01",
        "ip_address": "192.168.1.101",
        "agent_version": "2.0.0",
        "status": "healthy",
        "metrics": {
            "cpu_percent": 0.25,
            "memory_mb": 9.4,
            "spool_queue_depth": 0,
        },
        "config_version": "v1.0",
    }

    resp = client.post("/api/agent/heartbeat", json=req_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "acknowledged"
    assert "pending_tasks" in data
    assert isinstance(data["pending_tasks"], list)
    assert len(data["pending_tasks"]) == 0
    assert data["config_update"] is None

    # Check storage was updated
    assert len(mock_storage.heartbeats) == 1
    hb = mock_storage.heartbeats[0]
    assert hb["agent_id"] == "agent-001"
    assert hb["metrics"]["cpu_percent"] == 0.25


def test_heartbeat_missing_required_fields(client: TestClient):
    """Verify heartbeat returns 400 when required fields are missing."""
    resp = client.post("/api/agent/heartbeat", json={"agent_id": "agent-001"})
    assert resp.status_code == 400
    assert "hostname" in resp.json().get("error", "").lower()

    resp2 = client.post("/api/agent/heartbeat", json={"hostname": "CORP-WKS-01"})
    assert resp2.status_code == 400
    assert "agent_id" in resp2.json().get("error", "").lower()


def test_heartbeat_task_dispatch_lifecycle(client: TestClient, mock_storage: MockFleetStorage):
    """
    Verify full downlink lifecycle:
    1. SOC queues task for agent.
    2. Agent heartbeat fetches pending task and marks dispatched.
    3. Next heartbeat yields 0 pending tasks.
    """
    # 1. Queue task
    task_id = mock_storage.queue_agent_task(
        agent_id="agent-001",
        command="isolate_host",
        params={"server_ip": "10.0.0.1"},
    )
    assert len(mock_storage.get_pending_agent_tasks("agent-001")) == 1

    # 2. Agent heartbeat
    hb_req = {
        "agent_id": "agent-001",
        "hostname": "CORP-WKS-01",
        "ip_address": "192.168.1.101",
        "agent_version": "2.0.0",
        "status": "healthy",
        "metrics": {"cpu_percent": 0.1, "memory_mb": 8.0, "spool_queue_depth": 0},
        "config_version": "v1.0",
    }
    resp = client.post("/api/agent/heartbeat", json=hb_req)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["pending_tasks"]) == 1
    dispatched_task = data["pending_tasks"][0]
    assert dispatched_task["task_id"] == task_id
    assert dispatched_task["command"] == "isolate_host"
    assert dispatched_task["params"] == {"server_ip": "10.0.0.1"}

    # 3. Subsequent heartbeat should have 0 pending tasks
    resp2 = client.post("/api/agent/heartbeat", json=hb_req)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["pending_tasks"]) == 0


# --------------------------------------------------------------------------
# Task Result Uplink Tests
# --------------------------------------------------------------------------


def test_task_result_success(client: TestClient, mock_storage: MockFleetStorage):
    """Verify task result recording for successful containment."""
    tid = mock_storage.queue_agent_task("agent-001", "isolate_host")

    result_payload = {
        "agent_id": "agent-001",
        "task_id": tid,
        "status": "success",
        "exit_code": 0,
        "message": "Host isolated successfully. Windows firewall containment active.",
        "timestamp": "2026-09-27T10:05:00Z",
    }

    resp = client.post("/api/agent/task-result", json=result_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["task_id"] == tid
    assert data["status"] == "recorded"

    # Verify task in storage
    tasks = mock_storage.list_agent_tasks("agent-001")
    target_task = next(t for t in tasks if t["task_id"] == tid)
    assert target_task["status"] == "success"
    assert target_task["exit_code"] == 0
    assert "isolated successfully" in target_task["message"]


def test_task_result_underscore_route(client: TestClient, mock_storage: MockFleetStorage):
    """Verify /api/agent/task_result route alias works identically."""
    tid = mock_storage.queue_agent_task("agent-001", "unisolate_host")

    result_payload = {
        "agent_id": "agent-001",
        "task_id": tid,
        "status": "failed",
        "exit_code": 1,
        "message": "Access denied configuring firewall rules",
        "timestamp": "2026-09-27T10:06:00Z",
    }

    resp = client.post("/api/agent/task_result", json=result_payload)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    tasks = mock_storage.list_agent_tasks("agent-001")
    target_task = next(t for t in tasks if t["task_id"] == tid)
    assert target_task["status"] == "failed"
    assert target_task["exit_code"] == 1


def test_task_result_missing_task_id(client: TestClient):
    """Verify 400 when task_id is omitted."""
    resp = client.post("/api/agent/task-result", json={"agent_id": "agent-001", "status": "success"})
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# SOC Containment Action Endpoints
# --------------------------------------------------------------------------


def test_soc_isolate_endpoint(client: TestClient, mock_storage: MockFleetStorage):
    """POST /api/agents/{agent_id}/isolate queues isolate_host task."""
    resp = client.post("/api/agents/agent-001/isolate", json={"server_ip": "192.168.1.50"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["command"] == "isolate_host"
    assert data["agent_id"] == "agent-001"
    assert data["status"] == "queued"

    pending = mock_storage.get_pending_agent_tasks("agent-001")
    assert len(pending) == 1
    assert pending[0]["command"] == "isolate_host"
    assert pending[0]["params"]["server_ip"] == "192.168.1.50"


def test_soc_unisolate_endpoint(client: TestClient, mock_storage: MockFleetStorage):
    """POST /api/agents/{agent_id}/unisolate queues unisolate_host task."""
    resp = client.post("/api/agents/agent-001/unisolate")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["command"] == "unisolate_host"
    assert data["status"] == "queued"

    pending = mock_storage.get_pending_agent_tasks("agent-001")
    assert any(t["command"] == "unisolate_host" for t in pending)


def test_soc_terminate_endpoint(client: TestClient, mock_storage: MockFleetStorage):
    """POST /api/agents/{agent_id}/terminate queues kill_process task."""
    resp = client.post("/api/agents/agent-001/terminate", json={"pid": 4892})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["command"] == "kill_process"
    assert data["pid"] == 4892

    pending = mock_storage.get_pending_agent_tasks("agent-001")
    target = next(t for t in pending if t["command"] == "kill_process")
    assert target["params"]["pid"] == 4892


def test_soc_terminate_invalid_pid(client: TestClient):
    """POST /api/agents/{agent_id}/terminate returns 400 for negative or non-integer pid."""
    resp = client.post("/api/agents/agent-001/terminate", json={"pid": -5})
    assert resp.status_code == 400

    resp2 = client.post("/api/agents/agent-001/terminate", json={"pid": "not-a-pid"})
    assert resp2.status_code == 400

    resp3 = client.post("/api/agents/agent-001/terminate", json={})
    assert resp3.status_code == 400


def test_soc_lock_endpoint(client: TestClient, mock_storage: MockFleetStorage):
    """POST /api/agents/{agent_id}/lock queues lock_workstation task."""
    resp = client.post("/api/agents/agent-001/lock")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["command"] == "lock_workstation"

    pending = mock_storage.get_pending_agent_tasks("agent-001")
    assert any(t["command"] == "lock_workstation" for t in pending)


def test_soc_rollback_shadow_and_directory(client: TestClient, mock_storage: MockFleetStorage):
    """POST /api/agents/{agent_id}/rollback creates create_shadow or rollback_directory."""
    # 1. Volume shadow snapshot
    resp1 = client.post("/api/agents/agent-001/rollback", json={"volume": "D:"})
    assert resp1.status_code == 200
    assert resp1.json()["command"] == "create_shadow"

    # 2. Directory rollback
    resp2 = client.post(
        "/api/agents/agent-001/rollback",
        json={"path": "C:\\Users\\Alice\\Documents", "snapshot": "HarddiskVolumeShadowCopy1"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["command"] == "rollback_directory"
    assert resp2.json()["params"]["path"] == "C:\\Users\\Alice\\Documents"


# --------------------------------------------------------------------------
# Task History & Agent Query Tests
# --------------------------------------------------------------------------


def test_get_agent_tasks_history(client: TestClient, mock_storage: MockFleetStorage):
    """GET /api/agents/{agent_id}/tasks returns list of tasks."""
    mock_storage.queue_agent_task("agent-001", "lock_workstation")
    mock_storage.queue_agent_task("agent-001", "isolate_host")

    resp = client.get("/api/agents/agent-001/tasks")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["agent_id"] == "agent-001"
    assert len(data["tasks"]) == 2


def test_get_agent_by_id(client: TestClient):
    """GET /api/agents/{agent_id} returns agent or 404."""
    resp = client.get("/api/agents/agent-001")
    assert resp.status_code == 200
    assert resp.json()["agent"]["agent_id"] == "agent-001"

    resp_404 = client.get("/api/agents/non-existent-agent")
    assert resp_404.status_code == 404


def test_dual_route_aliases(client: TestClient):
    """Verify /api/v1/... aliases respond identically."""
    resp1 = client.get("/api/v1/agents")
    assert resp1.status_code == 200
    assert resp1.json()["ok"] is True

    resp2 = client.post("/api/v1/agents/agent-001/unisolate")
    assert resp2.status_code == 200
    assert resp2.json()["ok"] is True


# --------------------------------------------------------------------------
# SQLite Integration Test for FleetRepository
# --------------------------------------------------------------------------


class _DummySQLiteStorageWrapper:
    """Wraps an in-memory SQLite connection for testing FleetRepository SQL queries."""

    def __init__(self, raw_conn: sqlite3.Connection):
        self.raw_conn = raw_conn

    def connection(self):
        class _Ctx:
            def __init__(self, adapter):
                self.adapter = adapter
            def __enter__(self):
                return self.adapter
            def __exit__(self, *args):
                pass
        return _Ctx(_SQLiteParamAdapter(self.raw_conn))


def test_fleet_repository_sqlite_sql_execution():
    """Verify FleetRepository SQL methods execute cleanly against SQLite with param adapter."""
    raw_conn = sqlite3.connect(":memory:")
    cur = raw_conn.cursor()

    # Create schema tables for SQLite
    cur.execute("""
        CREATE TABLE agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            username_last_seen TEXT,
            os_system TEXT,
            os_release TEXT,
            os_version TEXT,
            os_machine TEXT,
            first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_payload_id TEXT,
            status TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE agent_tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            command TEXT NOT NULL,
            params_json TEXT DEFAULT '{}',
            signature TEXT,
            status TEXT DEFAULT 'pending',
            exit_code INTEGER,
            message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            dispatched_at TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE agent_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            hostname TEXT,
            ip_address TEXT,
            agent_version TEXT,
            status TEXT,
            metrics_json TEXT DEFAULT '{}',
            config_version TEXT,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    raw_conn.commit()

    wrapper = _DummySQLiteStorageWrapper(raw_conn)
    repo = FleetRepository(wrapper)

    # 1. Heartbeat upsert
    repo.upsert_agent_heartbeat(
        agent_id="test-ag-99",
        hostname="WKS-TEST-99",
        ip_address="10.10.10.5",
        agent_version="2.0.0",
        status="healthy",
        metrics={"cpu_percent": 1.2, "memory_mb": 12.0},
        config_version="v1.0",
    )

    agent = repo.get_agent("test-ag-99")
    assert agent is not None
    assert agent["hostname"] == "WKS-TEST-99"

    # 2. Queue task
    tid = repo.queue_task(
        agent_id="test-ag-99",
        command="kill_process",
        params={"pid": 9999},
    )
    assert tid is not None

    # 3. Get pending tasks
    pending = repo.get_pending_tasks("test-ag-99")
    assert len(pending) == 1
    assert pending[0]["command"] == "kill_process"
    assert pending[0]["params"]["pid"] == 9999

    # 4. Mark dispatched
    repo.mark_tasks_dispatched([tid])
    pending_after = repo.get_pending_tasks("test-ag-99")
    assert len(pending_after) == 0

    # 5. Update task result
    updated = repo.update_task_result(
        agent_id="test-ag-99",
        task_id=tid,
        status="success",
        exit_code=0,
        message="Process PID 9999 terminated",
    )
    assert updated is True

    # 6. List agent tasks
    history = repo.list_agent_tasks("test-ag-99")
    assert len(history) == 1
    assert history[0]["status"] == "success"
    assert history[0]["exit_code"] == 0

    raw_conn.close()
