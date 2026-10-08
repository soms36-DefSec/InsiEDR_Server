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
