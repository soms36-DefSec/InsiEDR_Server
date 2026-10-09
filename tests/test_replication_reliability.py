import threading
import json
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from server.storage.clickhouse_batcher import ClickHouseBatcher
from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.reconciler import ReplicationReconciler
from server.storage.maintenance import partition_end


def record(identity=1):
    return {'outbox_id': identity, 'target_table': 'raw_payloads', 'attempts': 1,
            'created_at': datetime(2026, 1, 1, tzinfo=timezone.utc),
            'record_json': {'envelope': {}, 'payload': {'payload_id': str(identity),
                'collectors': [{'collector': 'process', 'payload': {'count': 2},
                                'status': 'success'}]}}}


def outbox(records):
    repo = Mock()
    repo.claim.return_value = records
    repo.complete.return_value = len(records)
    repo.renew.return_value = len(records)
    return repo


def test_sync_failure_never_completes_claim():
    repo, ch = outbox([record()]), Mock()
    ch.replicate_outbox_batch.side_effect = OSError('connection lost')
    worker = ReplicationReconciler(None, ch, outbox=repo)
    with pytest.raises(OSError):
        worker.reconcile_once()
    repo.complete.assert_not_called()
    repo.release.assert_called_once()
    assert worker.total_completed == 0


def test_initial_clickhouse_outage_recovers_schema_and_background_worker():
    repo, ch = outbox([]), Mock()
    ch.is_connected.side_effect = [False, True]
    assert ReplicationReconciler(None, ch, outbox=repo).reconcile_once() == 0
    ch._init_connection.assert_called_once()
    ch.ensure_schema.assert_called_once()
    ch.batcher.start.assert_called_once()


def test_sync_confirmation_precedes_fenced_completion():
    repo, ch, events = outbox([record()]), Mock(), []
    ch.replicate_outbox_batch.side_effect = lambda *a, **k: events.append('inserted')
    repo.complete.side_effect = lambda *a: events.append('completed') or 1
    worker = ReplicationReconciler(None, ch, outbox=repo)
    assert worker.reconcile_once() == 1
    assert events == ['inserted', 'completed']
    token = repo.claim.call_args.args[0]
    assert repo.complete.call_args.args == (token, [1])
    ch.flush_all.assert_not_called()


def test_stale_worker_cannot_report_completion():
    repo, ch = outbox([record()]), Mock()
    repo.complete.return_value = 0
    with pytest.raises(RuntimeError, match='expired or replaced'):
        ReplicationReconciler(None, ch, outbox=repo).reconcile_once()
    repo.release.assert_called_once()


def test_lease_loss_stops_remaining_inserts():
    repo, ch = outbox([record()]), Mock()
    renewed = threading.Event()
    def renew(*args):
        renewed.set()
        return 0
    repo.renew.side_effect = renew
    def insert(records, before_insert, **kwargs):
        assert renewed.wait(2)
        # The renew thread sets loss immediately after returning from renew.
        for _ in range(100):
            try:
                before_insert()
            except RuntimeError:
                raise
            threading.Event().wait(.001)
        pytest.fail('Lost ownership was not detected')
    ch.replicate_outbox_batch.side_effect = insert
    with pytest.raises(RuntimeError, match='ownership lost'):
        ReplicationReconciler(None, ch, outbox=repo, lease_seconds=.03).reconcile_once()
    repo.complete.assert_not_called()


def test_full_batches_adapt_without_exceeding_ceiling():
    repo, ch = outbox([record(i) for i in range(4)]), Mock()
    worker = ReplicationReconciler(None, ch, outbox=repo, batch_size=4, max_batch_size=8)
    worker.reconcile_once()
    assert worker._claim_size == 8
    repo.claim.return_value = []
    worker.reconcile_once()
    assert worker._claim_size == 4


def storage():
    ch = ClickHouseStorage(client=Mock(), batch_size=2)
    ch.batcher.stop()
    return ch


def test_replay_rows_and_tokens_are_stable_and_do_not_enter_async_buffer():
    ch = storage()
    ch.replicate_outbox_batch([record()])
    calls = list(ch._client.insert.call_args_list)
    ch._client.insert.reset_mock()
    ch.replicate_outbox_batch([record()])
    assert calls == ch._client.insert.call_args_list
    assert ch.batcher.total_queued == 0
    assert all(c.kwargs['settings']['async_insert'] == 0 for c in calls)


def test_replication_splits_rows_and_rejects_oversized_records():
    ch = storage()
    items = [dict(record(i), target_table='collector_results', record_json={'id': str(i)}) for i in range(5)]
    ch.replicate_outbox_batch(items, max_bytes=100)
    assert [len(c.kwargs['data']) for c in ch._client.insert.call_args_list] == [2, 2, 1]
    with pytest.raises(ValueError, match='exceeds'):
        ch.replicate_outbox_batch([dict(items[0], record_json={'value': 'x' * 101})], max_bytes=100)


def test_privacy_stripped_and_unknown_targets():
    ch = storage()
    item = record()
    item['record_json']['payload']['_plaintext_stripped'] = True
    ch.replicate_outbox_batch([item])
    ch._client.insert.assert_not_called()
    with pytest.raises(ValueError, match='Unsupported'):
        ch.replicate_outbox_batch([dict(item, target_table='unexpected')])


def test_strict_drain_waits_for_inflight_and_latches_background_error(tmp_path):
    entered, release = threading.Event(), threading.Event()
    def insert(*args):
        entered.set()
        assert release.wait(2)
        raise OSError('offline')
    batcher = ClickHouseBatcher(insert, batch_size=1, max_retries=1, dlq_dir=tmp_path)
    batcher.start()
    batcher.add('raw_payloads', {'id': 1})
    assert entered.wait(2)
    drained = threading.Event()
    errors = []
    def drain():
        try:
            batcher.flush_all(raise_on_error=True)
        except RuntimeError as exc:
            errors.append(exc)
        drained.set()
    waiter = threading.Thread(target=drain)
    waiter.start()
    assert not drained.wait(.05)
    release.set()
    waiter.join(2)
    batcher.stop()
    assert drained.is_set() and errors
    with pytest.raises(RuntimeError, match='unconfirmed'):
        batcher.flush_all(raise_on_error=True)


@pytest.mark.parametrize('bound,expected', [
    ('DEFAULT', None), ('FOR VALUES FROM (MINVALUE) TO (MAXVALUE)', None),
    ("FOR VALUES FROM (MINVALUE) TO ('2026-01-05 00:00:00+00')", datetime(2026, 1, 5, tzinfo=timezone.utc)),
])
def test_retention_uses_bounds_including_historical_partitions(bound, expected):
    assert partition_end(bound) == expected


def test_truncated_dlq_is_retained_even_when_remaining_lines_are_valid(tmp_path):
    insert = Mock()
    path = tmp_path / 'dlq_raw_payloads_123_456.jsonl'
    path.write_text(json.dumps({'_metadata': {'table': 'raw_payloads', 'row_count': 2}})
                    + '\n' + json.dumps({'id': 1}) + '\n')
    batcher = ClickHouseBatcher(insert, dlq_dir=tmp_path)
    assert batcher.replay_dlq() == 0
    assert path.exists()
    insert.assert_not_called()
