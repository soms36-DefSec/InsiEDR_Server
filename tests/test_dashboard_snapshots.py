import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api import snapshots
from server.api.cache import TieredCache
from server.api.errors import AnalyticsUnavailableError
from server.storage.clickhouse_telemetry_queries import telemetry_histogram
from server.storage.dashboard_rollups import schema
from server.storage.reconciler import ReplicationReconciler


@pytest.fixture
def cache(monkeypatch):
    cache = TieredCache()
    monkeypatch.setattr(snapshots, 'api_cache', cache)
    monkeypatch.delenv('INSIEDR_DATABASE_DSN', raising=False)
    monkeypatch.delenv('DATABASE_DSN', raising=False)
    return cache


def test_stale_response_does_not_wait_for_slow_refresh_or_change_timestamp(cache):
    storage = object()
    first = snapshots.snapshot(storage, 'a', 'test', lambda: {'count': 7}, fresh_seconds=10)
    key = snapshots.snapshot_key(storage, 'a', 'test')
    record = cache.get(key)
    record['checked_at'] -= 20
    entered, release = threading.Event(), threading.Event()
    calls = []
    def slow():
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return {'count': 8}
    try:
        stale = snapshots.snapshot(storage, 'a', 'test', slow, fresh_seconds=10)
        assert entered.wait(1)
        for _ in range(30):
            response = snapshots.snapshot(storage, 'a', 'test', slow, fresh_seconds=10)
            assert response['count'] == 7 and response['freshness']['stale']
        assert len(calls) == 1
        assert stale['freshness']['generated_at'] == first['freshness']['generated_at']
    finally:
        release.set()
        # Join this module's background refresh before fixture teardown.
        for thread in threading.enumerate():
            if thread.name == 'analytics-snapshot':
                thread.join(2)
    assert snapshots.snapshot(storage, 'a', 'test', slow)['count'] == 8


def test_cold_concurrent_request_is_rejected_without_duplicate_query(cache):
    entered, release = threading.Event(), threading.Event()
    storage = object()
    calls = []
    def slow():
        calls.append(1)
        entered.set()
        release.wait(3)
        return {'count': 0}
    worker = threading.Thread(target=lambda: snapshots.snapshot(storage, 'a', 'cold', slow))
    worker.start()
    try:
        assert entered.wait(1)
        with pytest.raises(AnalyticsUnavailableError):
            snapshots.snapshot(storage, 'a', 'cold', slow)
        assert len(calls) == 1
    finally:
        release.set()
        worker.join(2)
    assert snapshots.snapshot(storage, 'a', 'cold', slow)['count'] == 0


def test_failed_refresh_is_backed_off_and_expired_data_is_not_served(cache):
    storage = object()
    loader = Mock(side_effect=TimeoutError('internal detail'))
    with pytest.raises(TimeoutError):
        snapshots.snapshot(storage, 'a', 'error', loader)
    with pytest.raises(AnalyticsUnavailableError):
        snapshots.snapshot(storage, 'a', 'error', loader)
    assert loader.call_count == 1
    key = snapshots.snapshot_key(storage, 'a', 'error')
    cache.set(key, {'value': {'count': 4}, 'checked_at': time.time() - 1000, 'generated_at': 'old'})
    with pytest.raises(AnalyticsUnavailableError):
        snapshots.snapshot(storage, 'a', 'error', loader, max_age=900)


def test_keys_are_worker_stable_and_actor_filter_scoped(cache, monkeypatch):
    monkeypatch.setenv('INSIEDR_DATABASE_DSN', 'postgresql://user:secret@db/example')
    assert snapshots.snapshot_key(object(), 'alice', 'hist', {'collector': 'x'}) == snapshots.snapshot_key(object(), 'alice', 'hist', {'collector': 'x'})
    assert snapshots.snapshot_key(object(), 'alice', 'hist') != snapshots.snapshot_key(object(), 'bob', 'hist')
    assert snapshots.snapshot_key(object(), 'alice', 'hist', {'collector': 'x'}) != snapshots.snapshot_key(object(), 'alice', 'hist', {'collector': 'y'})
    assert 'secret' not in snapshots.snapshot_key(object(), 'alice', 'hist')


def test_configured_redis_outage_fails_closed_without_running_loader(cache):
    cache.l2 = SimpleNamespace(_client=None, is_alive=lambda: False)
    loader = Mock()
    with pytest.raises(AnalyticsUnavailableError):
        snapshots.snapshot(object(), 'a', 'cold', loader)
    loader.assert_not_called()


def test_distributed_lease_contention_and_release(cache):
    lease = Mock()
    lease.acquire.return_value = False
    client = Mock()
    client.lock.return_value = lease
    cache.l2 = SimpleNamespace(_client=client)
    with snapshots.workload_slot('analytics') as allowed:
        assert not allowed
    lease.release.assert_not_called()
    lease.acquire.return_value = True
    with pytest.raises(ValueError):
        with snapshots.workload_slot('analytics') as allowed:
            assert allowed
            raise ValueError('work failed')
    lease.release.assert_called_once()


def test_histogram_zero_and_timeout_never_trigger_stats_or_other_table(monkeypatch):
    monkeypatch.delenv('INSIEDR_CH_ROLLUPS_ENABLED', raising=False)
    storage = SimpleNamespace(collector_schema_version=1, _query=Mock(return_value=SimpleNamespace(result_rows=[])))
    assert telemetry_histogram(storage)['total_events'] == 0
    storage._query.side_effect = TimeoutError()
    storage._query.reset_mock()
    with pytest.raises(TimeoutError):
        telemetry_histogram(storage)
    assert storage._query.call_count == 1


def test_rollup_reads_only_identity_states_and_preserves_filters(monkeypatch):
    monkeypatch.setenv('INSIEDR_CH_ROLLUPS_ENABLED', 'true')
    storage = SimpleNamespace(collector_schema_version=1, _query=Mock(return_value=SimpleNamespace(result_rows=[])))
    telemetry_histogram(storage, collector='FILE', status='error', agent_id='a')
    query, params = storage._query.call_args.args
    assert 'FROM dashboard_minutes_v1' in query and 'uniqExactMerge(event_ids)' in query
    assert 'payload_json' not in query and 'FINAL' not in query
    assert params == {'collector': 'file', 'agent_id': 'a'}
    assert "lower(status) IN" in query
    statements = schema(1)
    assert 'AggregateFunction(uniqExact, UUID)' in statements[0]
    assert 'uniqExactState(id)' in statements[1] and 'FROM collector_results' in statements[1]


def test_repeated_transient_outage_never_quarantines_acknowledged_logs():
    from tests.test_replication_reliability import outbox, record
    row = record()
    row['attempts'] = 100
    repo, ch = outbox([row]), Mock()
    ch.replicate_outbox_batch.side_effect = TimeoutError('disk busy')
    with pytest.raises(TimeoutError):
        ReplicationReconciler(None, ch, outbox=repo).reconcile_once()
    repo.quarantine.assert_not_called()
    repo.complete.assert_not_called()
    repo.release.assert_called_once()
