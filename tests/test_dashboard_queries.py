"""Filter/count correctness uses SQL; timing against real PostgreSQL is separate."""
import json
import sqlite3
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from psycopg2.pool import PoolError
from psycopg2.errors import QueryCanceled, LockNotAvailable

from server.api import logs, stats
from server.api.deps import get_storage
from server.api.errors import register_error_handlers
from server.storage.postgres_storage import PostgresStorage, _SQLiteParamAdapter


@pytest.fixture
def database():
    connection = sqlite3.connect(':memory:')
    connection.executescript('''
        CREATE TABLE raw_payloads (payload_id TEXT PRIMARY KEY, username TEXT, received_at TEXT);
        CREATE TABLE collector_results (id INTEGER PRIMARY KEY, payload_id TEXT, agent_id TEXT,
            collector TEXT, collector_collected_at TEXT, hostname TEXT, status TEXT, payload_json TEXT);
        CREATE TABLE risk_events (id INTEGER PRIMARY KEY, payload_id TEXT, risk_level TEXT,
            summary TEXT, correlated_signals_json TEXT, risk_score REAL, created_at TEXT);
        CREATE TABLE normalized_features (payload_id TEXT, feature_name TEXT,
            feature_value_text TEXT, feature_value_numeric REAL);
    ''')
    for i in range(120):
        connection.execute('INSERT INTO raw_payloads VALUES (?, ?, ?)',
                           (str(i), 'alice' if i % 2 else 'bob', '2026-10-07T12:00:00'))
        connection.execute('INSERT INTO collector_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (i, str(i), 'agent', 'usb-monitor' if i % 2 else 'file-collector',
                            '2026-10-07T11:00:00', f'HOST-{i}', 'tampered' if i % 3 == 0 else 'success',
                            json.dumps({'path': 'needle%_' if i == 3 else 'other'})))
    # Multiple enrichments must never duplicate a telemetry row or affect totals.
    for i in range(3):
        connection.execute('INSERT INTO risk_events VALUES (?, ?, ?, ?, ?, ?, ?)',
                           (i, '3', 'high', f'risk-{i}', '{}', 50 + i, '2026-10-07T12:00:00'))

    @contextmanager
    def checkout():
        yield _SQLiteParamAdapter(connection)

    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection = checkout
    yield storage, connection
    connection.close()


def test_combined_filters_are_applied_before_pagination_and_count(database):
    storage, _ = database
    filters = dict(collector='device', username='ALICE', status='error', include_enrichment=False)
    first = storage.get_telemetry_page(limit=5, **filters)
    second = storage.get_telemetry_page(limit=5, offset=5, **filters)
    assert first['total'] == second['total'] == 20
    assert len(first['logs']) == len(second['logs']) == 5
    assert not {row['id'] for row in first['logs']} & {row['id'] for row in second['logs']}
    assert all(row['status'] == 'tampered' for row in first['logs'])
    assert [row['id'] for row in first['logs']] == [117, 111, 105, 99, 93]


@pytest.mark.parametrize('term,expected', [('HOST-119', 1), ('needle', 1), ('%', 1), ('_', 1),
                                          ("' OR 1=1 --", 0), ('ALICE', 60)])
def test_keyword_search_is_literal_and_covers_host_user_payload(database, term, expected):
    page = database[0].get_telemetry_page(search=term, include_enrichment=False)
    assert page['total'] == expected


def test_timestamp_fallback_and_empty_result(database):
    storage, conn = database
    conn.execute('UPDATE collector_results SET collector_collected_at = NULL WHERE id = 3')
    page = storage.get_telemetry_page(start_time='2026-10-07T11:30:00', include_enrichment=False)
    assert page['total'] == 1
    assert page['logs'][0]['collected_at'] == '2026-10-07T12:00:00'
    page = storage.get_telemetry_page(end_time='2026-10-06', include_enrichment=False)
    assert page['logs'] == [] and page['total'] == 0


def test_legacy_enrichment_uses_latest_risk_without_duplicate_rows(database):
    storage, conn = database
    conn.execute("UPDATE collector_results SET payload_json = '{}' WHERE id = 3")
    conn.execute("INSERT INTO normalized_features VALUES ('3', 'observed', NULL, 42)")
    page = storage.get_telemetry_page(search='HOST-3')
    row = next(row for row in page['logs'] if row['id'] == 3)
    assert page['total'] == 11
    assert row['summary'] == 'risk-2'
    assert row['payload'] == {'observed': '42.0'}
    assert 'received_at' in row


def api_client(storage):
    app = FastAPI()
    app.include_router(logs.router)
    app.include_router(stats.router)
    register_error_handlers(app)
    app.dependency_overrides[get_storage] = lambda: storage
    # Query validation tests are independent from the existing auth suite.
    for route in app.routes:
        for dependency in getattr(getattr(route, 'dependant', None), 'dependencies', []):
            if dependency.name == 'operator':
                app.dependency_overrides[dependency.call] = lambda: None
    return TestClient(app)


@pytest.mark.parametrize('query', ['limit=1001', 'offset=-1', 'start_time=nonsense',
                                  'search=' + 'x' * 257,
                                  'start_time=2026-10-08&end_time=2026-10-07T00:00:00Z'])
def test_api_rejects_invalid_or_unbounded_queries(query):
    storage = Mock()
    assert api_client(storage).get('/api/telemetry?' + query).status_code == 422
    storage.get_telemetry_page.assert_not_called()


def test_api_normalizes_date_zones_and_preserves_route_aliases():
    storage = Mock()
    storage.get_telemetry_page.return_value = {'logs': [], 'total': 0}
    for route in ('/api/telemetry', '/api/v1/telemetry'):
        response = api_client(storage).get(route, params={
            'start_time': '2026-10-01', 'end_time': '2026-10-07T00:00:00Z',
            'status': 'error', 'search': 'HOST', 'include_enrichment': 'false',
        })
        assert response.status_code == 200
        kwargs = storage.get_telemetry_page.call_args.kwargs
        assert kwargs['start_time'].tzinfo is not None
        assert kwargs['search'] == 'HOST' and not kwargs['include_enrichment']


@pytest.mark.parametrize('failure', [PoolError, QueryCanceled, LockNotAvailable])
@pytest.mark.parametrize('route', ['/api/telemetry', '/api/dashboard-summary'])
def test_capacity_and_query_timeouts_are_retryable(failure, route):
    storage = Mock()
    storage.get_telemetry_page.side_effect = failure('internal detail')
    storage.get_pc_status.side_effect = failure('internal detail')
    response = api_client(storage).get(route)
    assert response.status_code == 503
    assert response.headers['retry-after'] == '2'
    assert 'internal detail' not in response.text


@pytest.mark.parametrize('route', ['/api/stats', '/api/dashboard-summary', '/api/telemetry', '/api/v1/stream/dashboard'])
def test_dashboard_reads_require_existing_operator_auth(monkeypatch, route):
    from server.api import events
    monkeypatch.setenv('INSIEDR_AUTH_ENFORCED', 'true')
    monkeypatch.setenv('INSIEDR_OPERATOR_ROLES', 'reader:operator:read')
    app = FastAPI()
    app.include_router(logs.router)
    app.include_router(stats.router)
    app.include_router(events.router)
    register_error_handlers(app)
    response = TestClient(app).get(route)
    assert response.status_code == 401
