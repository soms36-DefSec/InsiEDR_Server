"""Counts and drill-down entries must describe the same unique fleet hosts."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import sqlite3

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from server.api.deps import get_storage
from server.api.stats import router
from server.storage.postgres_storage import PostgresStorage, _SQLiteParamAdapter
from server.storage.repositories import fleet_repo


NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def fleet(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(fleet_repo, "datetime", Clock)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE agents (agent_id TEXT PRIMARY KEY, hostname TEXT, last_seen_at TEXT)")

    @contextmanager
    def connection():
        yield _SQLiteParamAdapter(conn)

    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection = connection

    def add(agent_id, hostname, age):
        seen = (NOW - timedelta(seconds=age)).isoformat(sep=" ") if age is not None else None
        conn.execute("INSERT INTO agents VALUES (?, ?, ?)", (agent_id, hostname, seen))

    yield storage, add
    conn.close()


@pytest.mark.parametrize("use_repository", [False, True])
def test_status_excludes_blank_names_and_groups_latest_observation(fleet, use_repository):
    storage, add = fleet
    for index, blank in enumerate([None, "", "   ", "\t\r\n\f\v"]):
        add(f"blank-{index}", blank, 1)
    add("old-registration", " DESKTOP-SOMS ", 86400)
    add("new-registration", "DESKTOP-SOMS", 12)
    add("test-vm", "INSIEDR-TEST-VM", 3 * 86400)
    add("no-heartbeat", "UNSEEN", None)

    target = storage.fleet if use_repository else storage
    result = target.get_pc_status()
    assert (result["total_pcs"], result["online_pcs"], result["offline_pcs"]) == (3, 1, 2)
    assert [row["hostname"] for row in result["endpoints"]] == ["DESKTOP-SOMS", "INSIEDR-TEST-VM", "UNSEEN"]
    assert result["endpoints"][0]["status"] == "online"
    assert result["endpoints"][0]["last_seen_at"] == (NOW - timedelta(seconds=12)).isoformat(sep=" ")
    assert result["endpoints"][-1]["status"] == "offline"


def test_five_minute_boundary_and_custom_presence_window(fleet):
    storage, add = fleet
    add("recent", "RECENT", 299)
    add("boundary", "BOUNDARY", 300)
    add("older", "OLDER", 301)
    result = storage.get_pc_status()
    assert result["online_pcs"] == 1
    assert result["offline_pcs"] == 2
    assert storage.get_pc_status(seconds_since_online=600)["online_pcs"] == 3


def test_empty_fleet_has_complete_empty_breakdown(fleet):
    storage, _ = fleet
    assert storage.get_pc_status() == {
        "total_pcs": 0, "online_pcs": 0, "offline_pcs": 0, "endpoints": [],
    }


@pytest.mark.parametrize("route", ["/api/dashboard-summary", "/api/v1/dashboard-summary"])
def test_summary_breakdown_is_not_truncated_by_agent_list_limit(fleet, route):
    storage, add = fleet
    for index in range(505):
        add(str(index), f"PC-{index:04}", 12 if index == 504 else 86400)
    storage.list_agents = lambda limit, offset: [{"hostname": f"PC-{i:04}"} for i in range(limit)]
    storage.get_stats = lambda: {}
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_storage] = lambda: storage
    response = TestClient(app).get(route)
    assert response.status_code == 200
    body = response.json()
    assert len(body["agents"]) == 500
    snapshot = body["pc_status"]
    assert len(snapshot["endpoints"]) == snapshot["total_pcs"] == 505
    assert snapshot["online_pcs"] == 1
    assert snapshot["offline_pcs"] == 504
    assert snapshot["endpoints"][-1]["status"] == "online"


def test_storage_failure_is_not_reported_as_an_empty_healthy_fleet(fleet):
    storage, _ = fleet
    with storage.connection() as conn:
        conn.execute("DROP TABLE agents")
    with pytest.raises(sqlite3.OperationalError):
        storage.get_pc_status()


def test_case_insensitive_hostname_grouping(fleet):
    storage, add = fleet
    add("agent-1", "SOCL4-61", 10)
    add("agent-2", "socl4-61", 100)
    add("agent-3", "MUMU", 86400)
    add("agent-4", "MuMu", 36000)
    result = storage.get_pc_status()
    assert result["total_pcs"] == 2
    assert result["online_pcs"] == 1
    assert result["offline_pcs"] == 1
    endpoints = {e["hostname"].lower(): e for e in result["endpoints"]}
    assert "socl4-61" in endpoints
    assert endpoints["socl4-61"]["status"] == "online"
    assert "mumu" in endpoints
    assert endpoints["mumu"]["status"] == "offline"


@pytest.fixture
def full_fleet(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(fleet_repo, "datetime", Clock)
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("""
        CREATE TABLE agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            username_last_seen TEXT,
            os_system TEXT,
            os_release TEXT,
            os_version TEXT,
            os_machine TEXT,
            first_seen_at TEXT,
            last_seen_at TEXT,
            last_payload_id TEXT,
            status TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE agent_heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT,
            hostname TEXT,
            ip_address TEXT,
            agent_version TEXT,
            status TEXT,
            metrics_json TEXT,
            config_version TEXT,
            received_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE raw_payloads (
            payload_id TEXT PRIMARY KEY,
            agent_id TEXT,
            received_at TEXT,
            payload_collected_at TEXT,
            hostname TEXT
        )
    """)

    @contextmanager
    def connection():
        yield _SQLiteParamAdapter(conn)

    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection = connection
    yield storage
    conn.close()


def test_historical_telemetry_does_not_make_offline_pc_online(full_fleet):
    storage = full_fleet
    historical_time = (NOW - timedelta(hours=10)).isoformat()
    storage.fleet.upsert_agent({
        "agent_id": "historical-agent",
        "hostname": "DESKTOP-H6EAHHC",
        "collected_at": historical_time,
        "payload_id": "p-1",
    })
    status = storage.get_pc_status()
    assert status["total_pcs"] == 1
    assert status["online_pcs"] == 0
    assert status["offline_pcs"] == 1
    assert status["endpoints"][0]["status"] == "offline"


def test_fresh_telemetry_makes_pc_online(full_fleet):
    storage = full_fleet
    fresh_time = (NOW - timedelta(seconds=15)).isoformat()
    storage.fleet.upsert_agent({
        "agent_id": "active-agent",
        "hostname": "SOCL4-61",
        "collected_at": fresh_time,
        "payload_id": "p-2",
    })
    status = storage.get_pc_status()
    assert status["total_pcs"] == 1
    assert status["online_pcs"] == 1
    assert status["offline_pcs"] == 0
    assert status["endpoints"][0]["status"] == "online"


def test_delayed_telemetry_does_not_regress_newer_last_seen(full_fleet):
    storage = full_fleet
    storage.fleet.upsert_agent_heartbeat(
        agent_id="agent-soc",
        hostname="SOCL4-61",
        status="active"
    )
    assert storage.get_pc_status()["online_pcs"] == 1

    delayed_time = (NOW - timedelta(hours=2)).isoformat()
    storage.fleet.upsert_agent({
        "agent_id": "agent-soc",
        "hostname": "SOCL4-61",
        "collected_at": delayed_time,
        "payload_id": "p-old",
    })
    status = storage.get_pc_status()
    assert status["online_pcs"] == 1
    assert status["endpoints"][0]["status"] == "online"


def test_blank_hostname_does_not_erase_existing_hostname(full_fleet):
    storage = full_fleet
    storage.fleet.upsert_agent({
        "agent_id": "agent-pc",
        "hostname": "DESKTOP-H6EAHHC",
        "collected_at": NOW.isoformat(),
        "payload_id": "p-1",
    })
    storage.fleet.upsert_agent({
        "agent_id": "agent-pc",
        "hostname": "   ",
        "collected_at": NOW.isoformat(),
        "payload_id": "p-2",
    })
    status = storage.get_pc_status()
    assert status["total_pcs"] == 1
    assert status["endpoints"][0]["hostname"] == "DESKTOP-H6EAHHC"


def test_future_timestamp_clamped_to_server_time(full_fleet):
    storage = full_fleet
    future_time = (NOW + timedelta(hours=2)).isoformat()
    storage.fleet.upsert_agent({
        "agent_id": "drifting-agent",
        "hostname": "CLOCK-DRIFT",
        "collected_at": future_time,
        "payload_id": "p-drift",
    })
    assert storage.get_pc_status()["online_pcs"] == 1
    # Clamped to NOW; checking with cutoff at NOW (0s) gives offline
    assert storage.get_pc_status(seconds_since_online=0)["online_pcs"] == 0


def test_heartbeat_maintains_agent_online_without_telemetry(full_fleet):
    storage = full_fleet
    storage.fleet.upsert_agent_heartbeat(
        agent_id="silent-agent",
        hostname="SILENT-PC",
        status="healthy"
    )
    status = storage.get_pc_status()
    assert status["total_pcs"] == 1
    assert status["online_pcs"] == 1
    assert status["offline_pcs"] == 0
    assert status["endpoints"][0]["hostname"] == "SILENT-PC"
    assert status["endpoints"][0]["status"] == "online"


def test_shared_agent_id_does_not_clobber_pc_inventory(full_fleet):
    storage = full_fleet
    historical_time = (NOW - timedelta(hours=12)).isoformat()
    # Machine 1: DESKTOP-H6EAHHC sends telemetry with shared agent_id AGENT-SANDY
    storage.fleet.upsert_agent({
        "agent_id": "AGENT-SANDY",
        "hostname": "DESKTOP-H6EAHHC",
        "collected_at": historical_time,
        "payload_id": "p-desktop-1",
    })

    # Machine 2: SOCL4-61 sends heartbeat with shared agent_id AGENT-SANDY
    storage.fleet.upsert_agent_heartbeat(
        agent_id="AGENT-SANDY",
        hostname="SOCL4-61",
        status="active"
    )

    status = storage.get_pc_status()
    assert status["total_pcs"] == 2
    assert status["online_pcs"] == 1
    assert status["offline_pcs"] == 1

    hostnames = {ep["hostname"]: ep for ep in status["endpoints"]}
    assert "DESKTOP-H6EAHHC" in hostnames
    assert hostnames["DESKTOP-H6EAHHC"]["status"] == "offline"

    assert "SOCL4-61" in hostnames
    assert hostnames["SOCL4-61"]["status"] == "online"


def test_sync_discovered_agents_backfills_desktop_and_purges_loadtest(full_fleet):
    storage = full_fleet
    # Insert synthetic loadtest row into agents
    with storage.connection() as conn:
        conn.execute(
            "INSERT INTO agents (agent_id, hostname, last_seen_at) VALUES (?, ?, ?)",
            ("AGENT-loadtest-1234", "loadtest-1234", NOW.isoformat()),
        )

    # get_pc_status must exclude loadtest-1234 even before purge
    status = storage.get_pc_status()
    hostnames = [ep["hostname"] for ep in status["endpoints"]]
    assert "loadtest-1234" not in hostnames

    # sync_discovered_agents must purge loadtest rows and backfill DESKTOP-H6EAHHC
    storage.fleet.sync_discovered_agents()

    with storage.connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hostname FROM agents WHERE hostname = 'loadtest-1234'")
        assert cursor.fetchone() is None

        cursor.execute("SELECT hostname FROM agents WHERE hostname = 'DESKTOP-H6EAHHC'")
        assert cursor.fetchone() is not None

    status = storage.get_pc_status()
    hostnames = [ep["hostname"] for ep in status["endpoints"]]
    assert "DESKTOP-H6EAHHC" in hostnames
    assert "loadtest-1234" not in hostnames


def test_summary_pc_error_returns_unavailable_not_zero():
    """Unavailable inventory must NOT be presented as a confirmed zero."""
    from unittest.mock import Mock
    from server.api.cache import api_cache
    api_cache.clear()

    storage = Mock()
    storage.get_pc_status.side_effect = RuntimeError("Database connection lost")
    storage.list_agents.return_value = []
    storage.get_stats.return_value = {"collector_results": 1000}

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_storage] = lambda: storage

    client = TestClient(app)
    resp = client.get("/api/dashboard-summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    pc = body["pc_status"]
    assert pc["total_pcs"] is None
    assert pc["online_pcs"] is None
    assert pc["offline_pcs"] is None
    assert pc["status"] == "unavailable"

    # Verify failed pc_status is NOT cached, allowing immediate recovery
    storage.get_pc_status.side_effect = None
    storage.get_pc_status.return_value = {"total_pcs": 2, "online_pcs": 1, "offline_pcs": 1, "endpoints": []}
    recovery_resp = client.get("/api/dashboard-summary")
    assert recovery_resp.status_code == 200
    rec_pc = recovery_resp.json()["pc_status"]
    assert rec_pc["total_pcs"] == 2
    assert rec_pc["online_pcs"] == 1
    assert rec_pc["offline_pcs"] == 1


def test_summary_valid_empty_inventory_returns_confirmed_zero(fleet):
    """A valid successful response confirming an empty eligible inventory should display zero."""
    storage, _ = fleet
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_storage] = lambda: storage

    client = TestClient(app)
    resp = client.get("/api/dashboard-summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    pc = body["pc_status"]
    assert pc["total_pcs"] == 0
    assert pc["online_pcs"] == 0
    assert pc["offline_pcs"] == 0



