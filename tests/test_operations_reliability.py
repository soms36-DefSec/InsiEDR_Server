import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from scripts.validate_ingest_capacity import build_envelope
from server.crypto.aesgcm_plugin import AESGCMPlugin
from server.storage.operations import operations_snapshot
from server.storage.outbox import OutboxRepository


def test_capacity_envelopes_use_real_protocol_and_distinct_identities():
    key = os.urandom(32)
    template = {'collectors': [{'collector': 'process', 'status': 'success', 'payload': {'count': 2}}]}
    envelope, headers = build_envelope('loadtest-1', template, key)
    payload = json.loads(AESGCMPlugin(key).decrypt(envelope))
    assert payload['payload_id'] == envelope['payload_id'] == headers['X-PAYLOAD-ID']
    assert payload['agent_id'] == 'loadtest-1'
    assert payload['collectors'][0]['payload']['count'] == 2
    assert 'collected_at' not in template['collectors'][0]
    assert build_envelope('loadtest-1', template, key)[0]['payload_id'] != envelope['payload_id']


def test_operations_report_lag_and_deferred_maintenance_without_payloads(monkeypatch, tmp_path):
    monkeypatch.setenv('INSIEDR_DLQ_DIR', str(tmp_path))
    monkeypatch.setenv('INSIEDR_MAINTENANCE_ENABLED', 'true')
    (tmp_path / 'pending.jsonl').write_text('sensitive test record')
    monkeypatch.setattr(OutboxRepository, 'metrics', lambda _: {
        'pending': {'count': 3, 'oldest_age_seconds': 600, 'max_attempts': 4}})
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = (
        'degraded', datetime.now(timezone.utc), datetime.now(timezone.utc),
        {'deferred_partitions': ['raw_payloads:2026-01-05']})
    @contextmanager
    def connection():
        yield conn
    state = SimpleNamespace()
    result = operations_snapshot(SimpleNamespace(connection=connection), state)
    assert not result['ok']
    assert {'replication_lag', 'retention_requires_attention', 'dlq_pending', 'task_worker_missing'} <= set(result['alerts'])
    assert 'sensitive test record' not in json.dumps(result, default=str)


def test_operations_fail_visibly_when_database_metrics_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv('INSIEDR_DLQ_DIR', str(tmp_path))
    def unavailable(_):
        raise RuntimeError('secret connection string')
    monkeypatch.setattr(OutboxRepository, 'metrics', unavailable)
    result = operations_snapshot(None, SimpleNamespace())
    assert 'database_metrics_unavailable' in result['alerts']
    assert result['database_metrics_error'] == 'RuntimeError'
    assert 'secret' not in json.dumps(result)


def test_ensure_retention_indexes_skips_sqlite():
    from server.storage.postgres_storage import PostgresStorage
    storage = PostgresStorage.__new__(PostgresStorage)
    storage._is_sqlite = True
    storage.dsn = "sqlite:///:memory:"
    assert storage.ensure_retention_indexes() == {}

