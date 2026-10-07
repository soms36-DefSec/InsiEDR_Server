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
