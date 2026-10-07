import csv
import io
import json
import pytest
from fastapi.testclient import TestClient

from server.app import create_app
from server.api.export import (
    flatten_collector_payload,
    _build_collector_filename,
    _normalize_iso_date_bound,
)


# ------------------------------------------------------------------------------
# Unit Tests: Payload Flattening & Filename Generation
# ------------------------------------------------------------------------------

def test_flatten_collector_payload_simple():
    data = {
        "event_count": 15,
        "failed_logons": 3,
        "successful_logons": 12,
        "logon_type": 2,
    }
    flat = flatten_collector_payload(data)
    assert flat["event_count"] == 15
    assert flat["failed_logons"] == 3
    assert flat["successful_logons"] == 12
    assert flat["logon_type"] == 2


def test_flatten_collector_payload_nested():
    data = {
        "event_count": 15,
        "etw_lifecycle_events": {
            "started_count": 5,
            "stopped_count": 2,
        },
        "deep": {
            "nested": {
                "flag": True,
                "ratio": 0.85,
            }
        },
    }
    flat = flatten_collector_payload(data)
    assert flat["event_count"] == 15
    assert flat["etw_lifecycle_events_started_count"] == 5
    assert flat["etw_lifecycle_events_stopped_count"] == 2
    assert flat["deep_nested_flag"] is True
    assert flat["deep_nested_ratio"] == 0.85


def test_flatten_collector_payload_preserves_primitives_and_lists():
    data = {
        "workstations": ["PC-1", "PC-2", "PC-3"],
        "empty_list": [],
        "none_val": None,
        "is_admin": False,
    }
    flat = flatten_collector_payload(data)
    assert flat["workstations"] == "PC-1;PC-2;PC-3"
    assert flat["empty_list"] == ""
    assert flat["none_val"] == ""
    assert flat["is_admin"] is False


def test_build_collector_filename():
    # Both start and end dates
    f1 = _build_collector_filename("logon", "2026-10-01", "2026-10-03", None)
    assert f1 == "logon_2026-10-01_to_2026-10-03.csv"

    # With user filter
    f2 = _build_collector_filename("logon", "2026-10-01", "2026-10-03", "SOMS")
    assert f2 == "logon_SOMS_2026-10-01_to_2026-10-03.csv"

    # Start date only
    f3 = _build_collector_filename("file", "2026-10-01", None, None)
    assert f3 == "file_from_2026-10-01.csv"

    # No dates
    f4 = _build_collector_filename("process", None, None, "User2")
    assert f4.startswith("process_User2_dataset_")
    assert f4.endswith(".csv")


def test_normalize_iso_date_bound():
    assert _normalize_iso_date_bound("2026-10-01", is_end=False) == "2026-10-01T00:00:00Z"
    assert _normalize_iso_date_bound("2026-10-03", is_end=True) == "2026-10-03T23:59:59Z"
    assert _normalize_iso_date_bound("2026-10-01T15:30:00Z", is_end=False) == "2026-10-01T15:30:00Z"
    assert _normalize_iso_date_bound(None) is None


# ------------------------------------------------------------------------------
# Mock Storage for Collector-Specific Export Tests
# ------------------------------------------------------------------------------

class MockCollectorStorage:
    def __init__(self):
        self.records = [
            # Logon records
            {
                "payload_id": "p-logon-1",
                "agent_id": "agent-01",
                "collector": "logon",
                "collected_at": "2026-10-01T10:00:00Z",
                "hostname": "DESKTOP-SEC01",
                "username": "SOMS",
                "status": "success",
                "payload_json": {
                    "event_count": 15,
                    "failed_logons": 3,
                    "successful_logons": 12,
                    "logon_type": 2,
                    "etw_lifecycle_events": {
                        "started_count": 5,
                        "stopped_count": 2,
                    },
                },
            },
            {
                "payload_id": "p-logon-2",
                "agent_id": "agent-02",
                "collector": "logon",
                "collected_at": "2026-10-02T11:00:00Z",
                "hostname": "DESKTOP-DEV02",
                "username": "User2",
                "status": "success",
                "payload_json": {
                    "event_count": 9,
                    "failed_logons": 1,
                    "successful_logons": 8,
                    "logon_type": 2,
                    "etw_lifecycle_events": {
                        "started_count": 2,
                        "stopped_count": 1,
                    },
                },
            },
            # File records
            {
                "payload_id": "p-file-1",
                "agent_id": "agent-01",
                "collector": "file",
                "collected_at": "2026-10-01T12:00:00Z",
                "hostname": "DESKTOP-SEC01",
                "username": "SOMS",
                "status": "success",
                "payload_json": {
                    "file_access_count": 42,
                    "sensitive_file_access": 3,
                    "daily_file_access_entropy": 2.15,
                },
            },
            {
                "payload_id": "p-file-2",
                "agent_id": "agent-02",
                "collector": "file",
                "collected_at": "2026-10-02T14:00:00Z",
                "hostname": "DESKTOP-DEV02",
                "username": "User2",
                "status": "success",
                "payload_json": {
                    "file_access_count": 10,
                    "sensitive_file_access": 0,
                    "daily_file_access_entropy": 0.85,
                },
            },
        ]

    def list_collector_results(
        self,
        limit=100,
        offset=0,
        collector=None,
        username=None,
        start_time=None,
        end_time=None,
        **kwargs,
    ):
        results = []
        for r in self.records:
            if collector and r["collector"].lower() != collector.lower():
                continue
            if username and r["username"].lower() != username.lower():
                continue
            if start_time and r["collected_at"] < start_time:
                continue
            if end_time and r["collected_at"] > end_time:
                continue
            results.append(r)
        return results[offset : offset + limit]

    def get_distinct_collectors(self):
        return ["file", "logon", "process"]

    def get_distinct_usernames(self):
        return ["SOMS", "User2"]


@pytest.fixture
def mock_collector_client():
    storage = MockCollectorStorage()
    app = create_app(storage=storage, apply_migrations=False)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ------------------------------------------------------------------------------
# API Integration Tests: Collectors List & Preview
# ------------------------------------------------------------------------------

def test_get_export_collectors(mock_collector_client):
    """Verify /api/v1/export/collectors returns available collectors and usernames."""
    resp = mock_collector_client.get("/api/v1/export/collectors")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "logon" in data["collectors"]
    assert "file" in data["collectors"]
    assert "SOMS" in data["usernames"]


def test_preview_logon_collector(mock_collector_client):
    """Verify /api/v1/export/collector-preview unrolls logon features into separate columns."""
    resp = mock_collector_client.get("/api/v1/export/collector-preview?collector=logon")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["collector"] == "logon"
    assert data["total_samples"] == 2

    # Check unrolled feature columns
    cols = data["columns"]
    assert "timestamp" in cols
    assert "username" in cols
    assert "event_count" in cols
    assert "failed_logons" in cols
    assert "successful_logons" in cols
    assert "logon_type" in cols
    assert "etw_lifecycle_events_started_count" in cols
    assert "etw_lifecycle_events_stopped_count" in cols

    # Check sample rows
    rows = data["preview_rows"]
    assert len(rows) == 2
    r0 = rows[0]
    assert r0["username"] == "SOMS"
    assert r0["event_count"] == 15
    assert r0["failed_logons"] == 3
    assert r0["etw_lifecycle_events_started_count"] == 5


def test_preview_file_collector(mock_collector_client):
    """Verify /api/v1/export/collector-preview unrolls file features into separate columns."""
    resp = mock_collector_client.get("/api/v1/export/collector-preview?collector=file")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["collector"] == "file"
    assert data["total_samples"] == 2

    cols = data["columns"]
    assert "file_access_count" in cols
    assert "sensitive_file_access" in cols
    assert "daily_file_access_entropy" in cols

    rows = data["preview_rows"]
    assert rows[0]["file_access_count"] == 42


def test_preview_filtering_by_user_and_date(mock_collector_client):
    """Verify preview filters by username and date range."""
    resp = mock_collector_client.get(
        "/api/v1/export/collector-preview?collector=logon&username=User2&start_date=2026-10-02&end_date=2026-10-02"
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_samples"] == 1
    assert data["preview_rows"][0]["username"] == "User2"
    assert data["preview_rows"][0]["event_count"] == 9


# ------------------------------------------------------------------------------
# API Integration Tests: CSV Dataset Export
# ------------------------------------------------------------------------------

def test_export_logon_dataset_csv(mock_collector_client):
    """Verify /api/v1/export/collector-dataset.csv streams valid CSV with unrolled features."""
    resp = mock_collector_client.get(
        "/api/v1/export/collector-dataset.csv?collector=logon&start_date=2026-10-01&end_date=2026-10-03"
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("Content-Type", "")
    assert 'filename="logon_2026-10-01_to_2026-10-03.csv"' in resp.headers.get("Content-Disposition", "")

    content = resp.text
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)

    assert len(rows) == 2
    # Verify columns exist in CSV header
    assert "timestamp" in reader.fieldnames
    assert "username" in reader.fieldnames
    assert "event_count" in reader.fieldnames
    assert "failed_logons" in reader.fieldnames
    assert "successful_logons" in reader.fieldnames
    assert "logon_type" in reader.fieldnames
    assert "etw_lifecycle_events_started_count" in reader.fieldnames

    # Verify first row data
    row0 = rows[0]
    assert row0["username"] == "SOMS"
    assert row0["event_count"] == "15"
    assert row0["failed_logons"] == "3"
    assert row0["successful_logons"] == "12"
    assert row0["etw_lifecycle_events_started_count"] == "5"

    # Verify second row data
    row1 = rows[1]
    assert row1["username"] == "User2"
    assert row1["event_count"] == "9"
    assert row1["failed_logons"] == "1"


def test_export_file_dataset_csv_filtered_by_user(mock_collector_client):
    """Verify exporting file dataset filtered by specific user."""
    resp = mock_collector_client.get(
        "/api/v1/export/collector-dataset.csv?collector=file&username=SOMS"
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("Content-Type", "")
    assert "file_SOMS_" in resp.headers.get("Content-Disposition", "")

    content = resp.text
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)

    assert len(rows) == 1
    assert rows[0]["username"] == "SOMS"
    assert rows[0]["file_access_count"] == "42"
    assert rows[0]["sensitive_file_access"] == "3"
    assert rows[0]["daily_file_access_entropy"] == "2.15"


def test_export_collector_dataset_missing_collector(mock_collector_client):
    """Verify 400 error when collector parameter is omitted."""
    resp = mock_collector_client.get("/api/v1/export/collector-dataset.csv?collector=")
    assert resp.status_code == 400
    assert resp.json()["ok"] is False


def test_nested_event_arrays_are_discrete_columns():
    flat = flatten_collector_payload({'events': [{'pid': 42, 'meta': {'name': 'exe'}}, {'pid': 43}]})
    assert flat == {'events_0_pid': 42, 'events_0_meta_name': 'exe', 'events_1_pid': 43}


def test_csv_keeps_columns_first_seen_in_later_batch(monkeypatch):
    from server.api import export
    monkeypatch.setattr(export, 'CHUNK_BATCH_SIZE', 1)
    storage = MockCollectorStorage()
    storage.records[1]['payload_json']['new_sensor'] = {'signal': 99}
    body = ''.join(export._stream_csv_collector_dataset(storage, 'logon', {}, 10))
    reader = csv.DictReader(io.StringIO(body))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]['new_sensor_signal'] == ''
    assert rows[1]['new_sensor_signal'] == '99'
