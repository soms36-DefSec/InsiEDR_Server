"""Sparse delivery must preserve observations, retry identity, and durable ACKs."""
from __future__ import annotations

import copy
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.api.ingest import ValidationError, validate_collector_results
from server.api.logs import router
from server.crypto.aesgcm_plugin import AESGCMPlugin, AES_GCM_AAD
from server.plugin_registry import registry
from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.hybrid_storage import HybridStorage
from server.storage.postgres_storage import PostgresStorage
from server.storage.repositories.telemetry_repo import TelemetryRepository
from shared.crypto_utils import b64encode
from shared.protocol import encrypted_payload_headers


def observation(name, metrics, at, status="success"):
    result = {"collector": name, "collected_at": at, "hostname": "HOST",
              "status": status, "payload": metrics}
    if status == "failed":
        result["error"] = {"type": "Unavailable", "message": "sensor unavailable"}
    return result


def payload(pid, collectors, at=None):
    return {
        "schema": "insiedr.agent.telemetry.v1", "protocol_version": "2.0",
        "payload_id": pid, "agent_id": "agent-a", "hostname": "HOST",
        "username": "alice", "collected_at": at or collectors[0]["collected_at"],
        "collectors": collectors,
        "summary": {"collector_count": len(collectors),
                    "success_count": sum(c["status"] == "success" for c in collectors),
                    "failed_count": sum(c["status"] in ("critical", "failed") for c in collectors)},
    }


@pytest.fixture
def pg(tmp_path):
    db = tmp_path / "telemetry.db"
    schema = (Path(__file__).parents[1] / "server/storage/migrations/001_initial_schema.sql").read_text()
    schema = schema.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY")
    with sqlite3.connect(db) as conn:
        conn.executescript(schema)
        conn.execute("CREATE UNIQUE INDEX raw_payload_identity ON raw_payloads(payload_id, received_at)")
    return PostgresStorage(connection_factory=lambda: sqlite3.connect(db))


@pytest.fixture
def client_for(monkeypatch):
    monkeypatch.setenv("INSIEDR_REQUIRE_HTTPS", "false")
    monkeypatch.delenv("INSIEDR_AGENT_BEARER_TOKEN", raising=False)

    def make(storage):
        app = FastAPI()
        app.state.storage = storage
        app.include_router(router)
        return TestClient(app)
    return make


@pytest.fixture
def encrypt(monkeypatch):
    key = os.urandom(32)
    monkeypatch.setitem(registry._plugins, "aes-256-gcm", AESGCMPlugin(key))

    def make(telemetry):
        nonce = os.urandom(12)
        envelope = {
            "protocol_version": "2.0", "scheme": "aes-256-gcm", "key_id": "test-key",
            "payload_id": telemetry["payload_id"], "created_at": telemetry["collected_at"],
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(AESGCM(key).encrypt(nonce, json.dumps(telemetry).encode(), AES_GCM_AAD)),
        }
        return envelope, encrypted_payload_headers(envelope, telemetry["agent_id"], telemetry["payload_id"])
    return make


def test_sparse_summary_preserves_critical_failure_count():
    at = datetime.now(timezone.utc).isoformat()
    telemetry = payload("sparse", [observation("process", {"count": 0}, at),
                                  observation("tamper", {"detected": True}, at, "critical")])
    validate_collector_results(telemetry)
    telemetry["summary"]["success_count"] = 2
    with pytest.raises(ValidationError, match="summary.success_count"):
        validate_collector_results(telemetry)


def test_feature_null_pruning_preserves_zero_false_and_empty_values():
    at = datetime.now(timezone.utc).isoformat()
    col = observation("process", {"missing": None, "zero": 0, "false": False,
                                  "empty_list": [], "empty_object": {}, "empty_text": ""}, at)
    rows = {row["feature_name"]: row for row in PostgresStorage._feature_rows(payload("p", [col]), col, "high")}
    assert set(rows) == {"zero", "false", "empty_list", "empty_object", "empty_text"}
    assert rows["zero"]["feature_value_numeric"] == 0.0
    assert rows["false"]["feature_value_numeric"] == 0.0
    assert rows["empty_list"]["feature_value_json"].adapted == []
    assert rows["empty_object"]["feature_value_json"].adapted == {}
    assert rows["empty_text"]["feature_value_text"] == ""


def test_clickhouse_skips_null_features_without_dropping_zero():
    ch = ClickHouseStorage.__new__(ClickHouseStorage)
    ch.is_connected = lambda: True
    ch.batcher = MagicMock()
    at = datetime.now(timezone.utc).isoformat()
    ch.store_raw_payload({}, payload("p", [observation("process", {"missing": None, "zero": 0, "false": False}, at)]))
    batches = {call.args[0]: call.args[1] for call in ch.batcher.add_many.call_args_list}
    features = {row["feature_name"]: row for row in batches["normalized_features"]}
    assert set(features) == {"zero", "false"}
    assert all(row["feature_value_numeric"] == 0.0 for row in features.values())


@pytest.mark.parametrize("plaintext", ["true", "false"])
def test_latest_state_retains_omitted_collectors_and_ignores_late_replay(pg, monkeypatch, plaintext):
    monkeypatch.setenv("INSIEDR_STORE_PLAINTEXT_PAYLOADS", plaintext)
    old = "2026-10-01T10:00:00+00:00"
    new = "2026-10-01T10:01:00+00:00"
    baseline = payload("baseline", [observation("process", {"count": 3, "retired": 5}, old),
                                    observation("network", {"connections": 0, "alert": False}, old)])
    assert pg.store_raw_payload({}, baseline) is True
    pg.store_raw_payload({}, payload("delta", [observation("process", {"count": 0}, new)]))
    pg.store_raw_payload({}, payload("late-replay", [observation("process", {"count": 99}, old)]))
    states = {s["collector"]: s for s in pg.get_latest_collector_states("agent-a")}
    assert set(states) == {"network", "process"}
    assert states["network"]["collector_collected_at"] == old
    assert states["network"]["payload_json"]["connections"] == 0
    assert states["network"]["payload_json"]["alert"] == False
    assert states["process"]["payload_json"] == {"count": 0}
    assert pg.get_latest_collector_states("other-agent") == []
    assert pg.store_raw_payload({}, baseline) is False
    assert pg.get_feature_vector("delta") == {"count": 0}


def test_latest_failed_observation_does_not_reuse_older_success(pg, monkeypatch):
    monkeypatch.setenv("INSIEDR_STORE_PLAINTEXT_PAYLOADS", "true")
    pg.store_raw_payload({}, payload("old", [observation("process", {"count": 3}, "2026-10-01T10:00:00Z")]))
    pg.store_raw_payload({}, payload("new", [observation("process", None, "2026-10-01T10:01:00Z", "failed")]))
    state = pg.get_latest_collector_states("agent-a")[0]
    assert state["status"] == "failed"
    assert state["payload_json"] is None
    assert state["error_type"] == "Unavailable"


def test_latest_state_endpoint_reports_freshness_and_keeps_dashboard_access(client_for):
    storage = MagicMock()
    storage.get_latest_collector_states.return_value = [
        {"collector": "old", "collector_collected_at": (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()},
        {"collector": "new", "collector_collected_at": datetime.now(timezone.utc).isoformat()},
        {"collector": "unknown", "collector_collected_at": None},
    ]
    client = client_for(storage)
    for url in ("/api/collector-states/agent-a", "/api/v1/collector-states/agent-a"):
        response = client.get(url)
        assert response.status_code == 200
        states = {s["collector"]: s for s in response.json()["states"]}
        assert states["old"]["stale"] is True
        assert states["new"]["stale"] is False
        assert states["unknown"]["stale"] is True
        assert states["unknown"]["age_seconds"] is None
    storage.get_latest_collector_states.assert_called_with("agent-a")


def test_hybrid_requires_pg_commit_and_does_not_ack_ram_only_replica():
    pg = MagicMock()
    pg.store_raw_payload.side_effect = RuntimeError("database unavailable")
    ch = MagicMock()
    ch.is_connected.return_value = True
    with pytest.raises(RuntimeError, match="database unavailable"):
        TelemetryRepository(pg, ch).store_payload({}, {"payload_id": "p"})
    ch.store_raw_payload.assert_not_called()


def test_atomic_pg_duplicate_skips_clickhouse_and_state_reads_use_pg():
    pg = MagicMock()
    pg.store_raw_payload.return_value = False
    pg.get_latest_collector_states.return_value = [{"collector": "process", "payload_json": {"count": 0}}]
    ch = MagicMock()
    repository = TelemetryRepository(pg, ch)
    repository.store_payload({}, {"payload_id": "p"})
    ch.store_raw_payload.assert_not_called()
    assert repository.get_latest_collector_states("a") == pg.get_latest_collector_states.return_value
    ch.get_latest_collector_states.assert_not_called()


def test_sparse_encrypted_ingestion_and_identical_scrubbed_retry(pg, client_for, encrypt):
    now = datetime.now(timezone.utc).isoformat()
    hybrid = HybridStorage(pg)
    client = client_for(hybrid)
    telemetry = payload("sparse", [observation("cmd", {"count": 0, "password": "example-secret"}, now)])
    envelope, headers = encrypt(telemetry)
    expected_ack = {"ok": True, "payload_id": "sparse", "status": "accepted"}
    for _ in range(2):
        response = client.post("/api/logs", json=envelope, headers=headers)
        assert response.status_code == 202, response.text
        assert response.json() == expected_ack
    assert pg.get_feature_vector("sparse") == {"count": 0, "password": "[REDACTED]"}
    with pg.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM collector_results").fetchone()[0] == 1
    changed, changed_headers = encrypt(telemetry)
    assert client.post("/api/logs", json=changed, headers=changed_headers).status_code == 400


def test_ingestion_storage_failure_is_not_accepted(client_for, encrypt):
    storage = MagicMock()
    storage.get_payload.return_value = None
    storage.store_raw_payload.side_effect = RuntimeError("disk unavailable")
    now = datetime.now(timezone.utc).isoformat()
    envelope, headers = encrypt(payload("p", [observation("process", {"count": 0}, now)]))
    assert client_for(storage).post("/api/logs", json=envelope, headers=headers).status_code == 503


def test_expired_offline_payload_keeps_existing_replay_policy(client_for, encrypt, monkeypatch):
    monkeypatch.setenv("INSIEDR_REPLAY_WINDOW_HOURS", "24")
    storage = MagicMock()
    old = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
    envelope, headers = encrypt(payload("p", [observation("process", {"count": 0}, old)]))
    response = client_for(storage).post("/api/logs", json=envelope, headers=headers)
    assert response.status_code == 400
    assert "replay window" in response.text
    storage.store_raw_payload.assert_not_called()
