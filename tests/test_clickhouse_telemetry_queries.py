from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest

from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.clickhouse_telemetry_queries import telemetry_page


def test_analytics_page_decodes_payload_uses_lookahead_and_skips_count():
    storage = Mock()
    columns = ['id', 'payload_id', 'agent_id', 'collector', 'collected_at', 'hostname',
               'username', 'status', 'payload', 'received_at']
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    rows = [(UUID(int=i), str(i), 'agent', 'usb', now, 'HOST', 'alice', 'success', '{"x":1}', now)
            for i in (3, 2, 1)]
    storage._query.return_value = SimpleNamespace(column_names=columns, result_rows=rows)
    filters = dict(limit=2, include_total=False, include_enrichment=False, search_scope='metadata',
                   collector='device', search="%' OR 1=1", start_time=now)
    page = telemetry_page(storage, **filters)
    assert page['total'] is None and page['has_more']
    assert len(page['logs']) == 2 and page['logs'][0]['payload'] == {'x': 1}
    assert storage._query.call_count == 1
    sql, params = storage._query.call_args.args
    assert 'SELECT DISTINCT' in sql and 'GROUP BY payload_id' in sql
    assert "%' OR 1=1" not in sql
    assert params['limit'] == 3
    assert 'positionCaseInsensitiveUTF8(cr.payload_json' not in sql
    telemetry_page(storage, cursor=page['next_cursor'], **filters)
    sql, params = storage._query.call_args.args
    assert 'toUUID(%(cursor_id)s)' in sql
    assert params['cursor_id'] == str(UUID(int=2))
    with pytest.raises(ValueError):
        telemetry_page(storage, cursor=page['next_cursor'])


def test_empty_analytics_page_is_success_and_disconnected_insert_is_failure():
    storage = Mock()
    storage._query.return_value = SimpleNamespace(column_names=[], result_rows=[])
    page = telemetry_page(storage, include_total=False)
    assert page['logs'] == [] and page['next_cursor'] is None and not page['has_more']
    adapter = ClickHouseStorage.__new__(ClickHouseStorage)
    adapter._is_connected = False
    adapter._client = None
    with pytest.raises(RuntimeError, match='not been persisted'):
        adapter._raw_batch_insert('collector_results', [{'id': '1'}])


def test_v2_reader_uses_final_denormalized_metadata_and_rejects_legacy_cursors():
    from server.storage.telemetry_cursor import encode_cursor, filter_key
    storage = Mock()
    storage.collector_schema_version = 2
    storage._query.return_value = SimpleNamespace(column_names=[], result_rows=[])
    telemetry_page(storage, username='alice', include_total=False, include_enrichment=False)
    query, params = storage._query.call_args.args
    assert 'collector_events_v2 FINAL' in query
    assert 'SELECT DISTINCT' not in query and 'JOIN' not in query
    assert 'cr.username' in query and 'rp.' not in query
    key = filter_key(collector=None, username=None, status=None, search=None,
                     start_time=None, end_time=None, search_scope='payload')
    cursor = encode_cursor('clickhouse', key, datetime.now(timezone.utc), UUID(int=1))
    with pytest.raises(ValueError, match='Invalid telemetry cursor'):
        telemetry_page(storage, cursor=cursor, include_total=False)


def test_v2_writer_and_legacy_count_api_select_same_schema():
    from tests.test_replication_reliability import record
    client = Mock()
    client.query.return_value = SimpleNamespace(result_rows=[(1,)])
    storage = ClickHouseStorage(client=client, collector_schema_version=2)
    storage.batcher.stop()
    storage.replicate_outbox_batch([record()])
    collector_call = next(call for call in client.insert.call_args_list
                          if call.kwargs['table'] == 'collector_events_v2')
    assert {'username', 'received_at', 'version'} <= set(collector_call.kwargs['column_names'])
    assert storage.count_collector_results(username='alice') == 1
    query = client.query.call_args.args[0]
    assert 'FROM collector_events_v2 FINAL' in query
    assert 'raw_payloads' not in query
