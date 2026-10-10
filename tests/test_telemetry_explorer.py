import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.api import logs, telemetry
from server.api.deps import get_storage
from server.api.errors import register_error_handlers
from server.storage.clickhouse_telemetry_queries import (
    telemetry_explorer,
    telemetry_event_detail,
    telemetry_histogram,
    extract_summary_preview,
)


def api_client(storage):
    app = FastAPI()
    app.include_router(telemetry.router)
    app.include_router(logs.router)
    register_error_handlers(app)
    app.dependency_overrides[get_storage] = lambda: storage
    for route in app.routes:
        for dependency in getattr(getattr(route, 'dependant', None), 'dependencies', []):
            if dependency.name == 'operator':
                app.dependency_overrides[dependency.call] = lambda: None
    return TestClient(app)


def test_extract_summary_preview_various_collectors():
    # Process
    proc = {"name": "powershell.exe", "pid": 4120, "command_line": "powershell.exe -enc AAAA"}
    assert "Process: powershell.exe" in extract_summary_preview("process", proc)
    assert "PID: 4120" in extract_summary_preview("process", proc)

    # Network
    net = {"dest_ip": "192.168.1.100", "dest_port": 443, "proto": "TCP"}
    assert "192.168.1.100:443" in extract_summary_preview("network", net)

    # HTTP
    http = {"method": "POST", "url": "https://api.evil.com/exfil"}
    assert "HTTP POST: https://api.evil.com/exfil" == extract_summary_preview("http", http)

    # File
    file_ev = {"path": "C:\\Windows\\Temp\\malware.exe", "action": "Created"}
    assert "File Created: C:\\Windows\\Temp\\malware.exe" == extract_summary_preview("file", file_ev)

    # Logon
    logon = {"username": "admin", "auth_type": "NTLM"}
    assert "Logon: admin (NTLM)" == extract_summary_preview("logon", logon)

    # USB
    usb = {"device_name": "SanDisk Cruzer", "vendor": "SanDisk"}
    assert "Device: SanDisk Cruzer" == extract_summary_preview("device", usb)


def test_clickhouse_explorer_projects_lightweight_scalars_and_seek_cursor():
    storage = Mock()
    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    columns = ['event_id', 'timestamp', 'agent_id', 'collector_name', 'hostname', 'username', 'status', 'summary_preview']
    rows = [
        (UUID(int=i), now, f'agent-{i}', 'process', 'HOST-1', 'alice', 'success', f'Process: test-{i}.exe')
        for i in (3, 2, 1)
    ]
    storage._query.return_value = SimpleNamespace(column_names=columns, result_rows=rows)

    res = telemetry_explorer(storage, limit=2, collector='process')
    assert res['has_more'] is True
    assert len(res['events']) == 2
    first = res['events'][0]
    assert 'payload' not in first
    assert 'raw_payload_json' not in first
    assert first['summary_preview'] == 'Process: test-3.exe'
    assert first['collector_name'] == 'process'
    assert first['event_id'] == str(UUID(int=3))
    assert res['next_cursor'] is not None

    # Next page query with cursor
    telemetry_explorer(storage, limit=2, collector='process', cursor=res['next_cursor'])
    sql, params = storage._query.call_args.args
    assert 'ORDER BY timestamp DESC, event_id DESC' in sql
    assert 'cursor_time' in params and 'cursor_id' in params
    assert params['cursor_id'] == str(UUID(int=2))


def test_clickhouse_explorer_fallback_when_telemetry_events_table_unpopulated():
    storage = Mock()
    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    # First query (to telemetry_events) fails or returns empty
    # Second query (to collector_results) succeeds
    fb_columns = ['event_id', 'timestamp', 'agent_id', 'collector_name', 'hostname', 'username', 'status', 'payload_json']
    fb_rows = [
        (UUID(int=1), now, 'agent-1', 'file', 'HOST-1', 'alice', 'success', json.dumps({'path': 'C:\\secret.docx', 'action': 'Read'}))
    ]
    storage._query.side_effect = [
        Exception("Table insiedr_analytics.telemetry_events doesn't exist"),
        SimpleNamespace(column_names=fb_columns, result_rows=fb_rows),
    ]

    res = telemetry_explorer(storage, limit=10)
    assert len(res['events']) == 1
    ev = res['events'][0]
    assert ev['summary_preview'] == 'File Read: C:\\secret.docx'
    assert 'payload' not in ev


def test_clickhouse_event_detail_deep_inspection():
    storage = Mock()
    eid = UUID(int=42)
    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    tel_cols = ['event_id', 'payload_id', 'agent_id', 'collector_name', 'timestamp', 'hostname', 'username', 'status', 'summary_preview', 'raw_payload_json']
    tel_row = (eid, 'p-42', 'a-1', 'process', now, 'HOST-42', 'alice', 'success', 'Process: calc.exe', json.dumps({'image': 'calc.exe', 'pid': 1234}))

    storage._query.side_effect = [
        SimpleNamespace(column_names=tel_cols, result_rows=[tel_row]),
        SimpleNamespace(column_names=['feature_name', 'val'], result_rows=[('cmd_len', 8)]),
        SimpleNamespace(column_names=['risk_level', 'summary', 'signals', 'risk_score'], result_rows=[('high', 'Unusual execution', '{}', 75.0)]),
    ]

    detail = telemetry_event_detail(storage, str(eid))
    assert detail is not None
    assert detail['event_id'] == str(eid)
    assert detail['payload'] == {'image': 'calc.exe', 'pid': 1234}
    assert detail['features'] == {'cmd_len': 8}
    assert detail['risk']['risk_score'] == 75.0


def test_clickhouse_histogram_buckets():
    storage = Mock()
    t1 = datetime(2026, 10, 10, 11, 58, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 10, 11, 59, 0, tzinfo=timezone.utc)
    storage._query.return_value = SimpleNamespace(
        column_names=['t', 'c'],
        result_rows=[(t1, 15), (t2, 28)]
    )

    # 1. Standard 1h window: must generate valid ClickHouse function call with timestamp argument
    hist = telemetry_histogram(storage, time_range='1h')
    assert hist['ok'] is True
    assert hist['total_events'] == 43
    assert len(hist['histogram']) == 2
    assert hist['histogram'][0]['count'] == 15
    assert hist['histogram'][1]['count'] == 28
    sql = storage._query.call_args[0][0]
    assert 'toStartOfMinute(timestamp)' in sql

    # 2. Custom 5m interval
    storage._query.reset_mock()
    storage._query.return_value = SimpleNamespace(column_names=['t', 'c'], result_rows=[])
    telemetry_histogram(storage, time_range='24h', interval='5m')
    sql5m = storage._query.call_args[0][0]
    assert 'toStartOfFiveMinutes(timestamp)' in sql5m

    # 3. Fallback when telemetry_events table doesn't exist
    storage._query.reset_mock()
    storage._query.side_effect = [
        Exception("Table telemetry_events doesn't exist"),
        SimpleNamespace(column_names=['t', 'c'], result_rows=[(t1, 5)]),
    ]
    fb_hist = telemetry_histogram(storage, time_range='1h')
    assert fb_hist['ok'] is True
    assert fb_hist['total_events'] == 5
    fb_sql = storage._query.call_args_list[1][0][0]
    assert 'toStartOfMinute(collector_collected_at)' in fb_sql
    assert 'FROM collector_results' in fb_sql



def test_api_endpoints_explorer_detail_histogram():
    storage = Mock()
    storage.get_telemetry_explorer.return_value = {
        'events': [{
            'event_id': 'evt-1', 'id': 'evt-1', 'timestamp': '2026-10-10T12:00:00Z',
            'agent_id': 'agent-1', 'collector_name': 'network', 'hostname': 'HOST-1',
            'username': 'bob', 'status': 'success', 'summary_preview': 'Conn: 10.0.0.1:80',
        }],
        'next_cursor': 'cur-next',
        'has_more': False,
        'source': 'clickhouse',
    }
    storage.get_telemetry_event_detail.return_value = {
        'event_id': 'evt-1', 'id': 'evt-1', 'timestamp': '2026-10-10T12:00:00Z',
        'payload': {'dest_ip': '10.0.0.1', 'dest_port': 80},
        'summary_preview': 'Conn: 10.0.0.1:80',
    }
    storage.get_telemetry_histogram.return_value = {
        'time_range': '1h',
        'interval': '1m',
        'total_events': 150,
        'histogram': [{'timestamp': '2026-10-10T12:00:00Z', 'count': 150}],
    }

    client = api_client(storage)

    # 1. Explorer list
    for route in ('/api/telemetry/explorer', '/api/v1/telemetry/explorer'):
        resp = client.get(route, params={'limit': 50, 'collector': 'network'})
        assert resp.status_code == 200
        data = resp.json()
        assert data['ok'] is True
        assert len(data['events']) == 1
        assert data['events'][0]['summary_preview'] == 'Conn: 10.0.0.1:80'
        assert 'payload' not in data['events'][0]  # Split View Rule 1

    # 2. Detail drawer
    for route in ('/api/telemetry/events/evt-1', '/api/v1/telemetry/events/evt-1'):
        resp = client.get(route)
        assert resp.status_code == 200
        data = resp.json()
        assert data['ok'] is True
        assert data['event']['payload']['dest_ip'] == '10.0.0.1'

    # 3. Detail drawer 404
    storage.get_telemetry_event_detail.return_value = None
    resp = client.get('/api/v1/telemetry/events/unknown-id')
    assert resp.status_code == 404

    # 4. Histogram aggregation
    for route in ('/api/telemetry/histogram', '/api/v1/telemetry/histogram'):
        resp = client.get(route, params={'time_range': '1h'})
        assert resp.status_code == 200
        data = resp.json()
        assert data['ok'] is True
        assert data['total_events'] == 150
        assert len(data['histogram']) == 1


def test_clickhouse_explorer_search_fallback_replaces_summary_preview():
    storage = Mock()
    now = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    fb_columns = ['event_id', 'timestamp', 'agent_id', 'collector_name', 'hostname', 'username', 'status', 'payload_json']
    fb_rows = [
        (UUID(int=1), now, 'agent-1', 'process', 'HOST-1', 'alice', 'success', json.dumps({'name': 'malware.exe'}))
    ]
    storage._query.side_effect = [
        Exception("telemetry_events not found"),
        SimpleNamespace(column_names=fb_columns, result_rows=fb_rows),
    ]

    res = telemetry_explorer(storage, limit=10, search='malware')
    assert len(res['events']) == 1
    fallback_sql = storage._query.call_args_list[1][0][0]
    assert 'summary_preview' not in fallback_sql
    assert 'cr.payload_json' in fallback_sql


def test_sqlite_postgres_telemetry_queries_live_execution():
    import sqlite3
    from contextlib import contextmanager
    from server.storage.postgres_storage import PostgresStorage, _SQLiteParamAdapter
    from server.storage.telemetry_queries import (
        telemetry_explorer as pg_explorer,
        telemetry_event_detail as pg_detail,
        telemetry_histogram as pg_histogram,
    )

    conn = sqlite3.connect(':memory:')
    conn.executescript('''
        CREATE TABLE raw_payloads (payload_id TEXT PRIMARY KEY, username TEXT, received_at TEXT);
        CREATE TABLE collector_results (id INTEGER PRIMARY KEY, payload_id TEXT, agent_id TEXT,
            collector TEXT, collector_collected_at TEXT, hostname TEXT, status TEXT, payload_json TEXT);
        CREATE TABLE risk_events (id INTEGER PRIMARY KEY, payload_id TEXT, risk_level TEXT,
            summary TEXT, correlated_signals_json TEXT, risk_score REAL, created_at TEXT);
        CREATE TABLE normalized_features (id INTEGER PRIMARY KEY, payload_id TEXT, agent_id TEXT,
            username TEXT, feature_name TEXT, feature_value_text TEXT, feature_value_numeric REAL);
    ''')

    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    for i in range(1, 11):
        conn.execute('INSERT INTO raw_payloads VALUES (?, ?, ?)', (f'p-{i}', f'user-{i}', now_str))
        conn.execute(
            'INSERT INTO collector_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (i, f'p-{i}', f'agent-{i}', 'process' if i % 2 == 0 else 'network',
             now_str, f'HOST-{i}', 'success',
             json.dumps({'cmdline': f'test-{i}.exe' if i % 2 == 0 else 'GET /'}))
        )
    conn.execute('INSERT INTO risk_events VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (1, 'p-2', 'high', 'Suspicious test command', '{}', 80.0, now_str))
    conn.execute('INSERT INTO normalized_features VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (1, 'p-2', 'agent-2', 'user-2', 'proc_depth', '3', 3.0))

    @contextmanager
    def checkout():
        yield _SQLiteParamAdapter(conn)

    storage = PostgresStorage.__new__(PostgresStorage)
    storage.connection = checkout

    # 1. Explorer query: projects lightweight scalars
    res = pg_explorer(storage, limit=5, collector='process')
    assert len(res['events']) == 5
    first = res['events'][0]
    assert 'summary_preview' in first
    assert 'payload' not in first
    assert 'raw_payload_json' not in first
    assert res['has_more'] is False

    # 2. Detail query: fetches full payload, features, and risk score
    detail = pg_detail(storage, '2')
    assert detail is not None
    assert detail['event_id'] == '2'
    assert detail['payload'] == {'cmdline': 'test-2.exe'}
    assert detail['risk']['risk_level'] == 'high'
    assert detail['features']['proc_depth'] == '3'

    # 3. Histogram query: executes CAST AS TEXT and time-bucket counts
    hist = pg_histogram(storage, time_range='1h')
    assert hist['ok'] is True
    assert hist['total_events'] == 10
    assert len(hist['histogram']) >= 1
    assert hist['histogram'][0]['count'] == 10
    assert 'T' in hist['histogram'][0]['timestamp']

    conn.close()

