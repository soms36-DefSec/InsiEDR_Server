"""
tests/test_hybrid_storage.py
----------------------------
Integration tests for HybridStorage coordinator routing and fallback logic.
"""
from unittest.mock import MagicMock
import pytest
from psycopg2.pool import PoolError

from server.storage.hybrid_storage import HybridStorage


def test_telemetry_backend_is_explicit_and_never_falls_back_mid_page():
    pg, ch = MagicMock(), MagicMock()
    pg.get_telemetry_page.return_value = {'logs': [], 'source': 'postgres'}
    ch.get_telemetry_page.return_value = {'logs': [], 'source': 'clickhouse'}
    ch.is_connected.return_value = True
    assert HybridStorage(pg, ch).get_telemetry_page()['source'] == 'postgres'
    ch.get_telemetry_page.assert_not_called()
    hybrid = HybridStorage(pg, ch, telemetry_read_backend='clickhouse')
    pg.reset_mock()
    assert hybrid.get_telemetry_page()['source'] == 'clickhouse'
    ch.get_telemetry_page.side_effect = RuntimeError('query failed')
    with pytest.raises(PoolError):
        hybrid.get_telemetry_page(cursor='existing-chain')
    ch.is_connected.return_value = False
    with pytest.raises(PoolError):
        hybrid.get_telemetry_page()
    pg.get_telemetry_page.assert_not_called()


class DummyPGStorage:
    def __init__(self):
        self.stored_payloads = []
        self.agents = [
            {"agent_id": "a-1", "hostname": "HOST-1", "status": "active", "os_system": "Windows"}
        ]

    def connection(self):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.__enter__.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [
            ("a-1", "HOST-1", "alice", "Windows", "10", "22H2", "x86_64", None, None, None, "active")
        ]
        mock_cursor.description = [
            ("agent_id",), ("hostname",), ("username_last_seen",), ("os_system",),
            ("os_release",), ("os_version",), ("os_machine",), ("first_seen_at",),
            ("last_seen_at",), ("last_payload_id",), ("status",)
        ]
        mock_cursor.fetchone.return_value = (5,)
        return mock_conn

    def store_raw_payload(self, env, payload):
        self.stored_payloads.append((env, payload))

    def get_stats(self):
        return {
            "agents": 1,
            "logs": 10,
            "anomalies": 0,
            "risk_events": 0,
            "baselines": 1,
        }

    def list_agents(self, limit=100, offset=0):
        return self.agents

    def list_logs(self, limit=100, offset=0, **kwargs):
        return [{"payload_id": "pg-log-1"}]

    def list_risk_events(self, limit=100, offset=0):
        return []

    def list_anomalies(self, limit=100, offset=0):
        return []

    def save_baseline(self, b):
        pass

    def load_baseline(self, u):
        return None

    def list_baselines(self, limit=100, offset=0):
        return []

    def save_model_output(self, o):
        pass

    def save_risk_event(self, e):
        pass

    def list_daily_feature_vectors(self, u, h, limit=16):
        return []

    def get_feature_vector(self, p):
        return {}

    def get_user_collectors(self, u):
        return []

    def get_user_risk_scores(self, u, limit=30):
        return []

    def get_user_predictions(self, u):
        return None

    def list_recent_risk_scores(self, u, h, limit=7):
        return []

    def get_max_risk_score_in_window(self, u, hours):
        return 0.0


def test_hybrid_storage_with_clickhouse():
    pg = DummyPGStorage()
    ch = MagicMock()
    ch.is_connected.return_value = True
    ch.list_logs.return_value = [{"payload_id": "ch-log-1"}]
    ch.get_telemetry_stats.return_value = {
        "logs": 5000,
        "collector_results": 15000,
        "anomalies": 12,
        "risk_events": 34,
        "collector_status": {"success": 15000},
        "collector_counts": {"file": 5000},
        "source_quality": {"high": 15000},
    }

    hybrid = HybridStorage(postgres_storage=pg, clickhouse_storage=ch)

    # 1. Telemetry query routed to ClickHouse
    logs = hybrid.list_logs(limit=10)
    assert logs == [{"payload_id": "ch-log-1"}]
    assert ch.list_logs.called

    # 2. Stats merged: relational agents from PG (1) + logs from ClickHouse (5000)
    stats = hybrid.get_stats()
    assert stats["agents"] == 1
    assert stats["logs"] == 5000
    assert stats["anomalies"] == 12
    assert stats["risk_events"] == 34

    # 3. Ingestion executes interceptors and calls ClickHouse
    payload = {
        "payload_id": "p-999",
        "agent_id": "a-1",
        "username": "alice",
        "hostname": "HOST-1",
        "collectors": [
            {"collector": "cmd", "status": "success", "payload": {"token": "secret_123"}}
        ],
    }
    hybrid.store_raw_payload(envelope={"scheme": "aes_gcm"}, decrypted_payload=payload)
    ch.store_raw_payload.assert_not_called()
    assert len(pg.stored_payloads) == 1


def test_hybrid_storage_fallback_without_clickhouse():
    pg = DummyPGStorage()
    hybrid = HybridStorage(postgres_storage=pg, clickhouse_storage=None)

    # Telemetry queries fall back gracefully to PG
    logs = hybrid.list_logs(limit=10)
    assert logs == [{"payload_id": "pg-log-1"}]

    stats = hybrid.get_stats()
    assert stats["agents"] == 1
    assert stats["logs"] == 10


def test_hybrid_storage_fallback_when_clickhouse_empty():
    pg = DummyPGStorage()
    ch = MagicMock()
    ch.is_connected.return_value = True
    ch.list_logs.return_value = []  # ClickHouse has no rows
    ch.list_collector_results.return_value = []

    hybrid = HybridStorage(postgres_storage=pg, clickhouse_storage=ch)

    # When ClickHouse returns empty, it falls back to PG logs
    logs = hybrid.list_logs(limit=10)
    assert logs == [{"payload_id": "pg-log-1"}]
