"""
tests/test_clickhouse_storage.py
--------------------------------
Unit tests for ClickHouseBatcher, Dead-Letter Queue (DLQ), and ClickHouseStorage adapter.
"""
import time
from pathlib import Path
from unittest.mock import MagicMock

from server.storage.clickhouse_batcher import ClickHouseBatcher
from server.storage.clickhouse_storage import ClickHouseStorage, _format_dt, _json_str


def test_clickhouse_batcher_size_trigger():
    import threading

    flushed_tables = []
    flushed_records = []
    flush_event = threading.Event()

    def mock_insert(table, rows):
        flushed_tables.append(table)
        flushed_records.extend(rows)
        flush_event.set()

    batcher = ClickHouseBatcher(insert_fn=mock_insert, batch_size=3, flush_interval=10.0, dlq_enabled=False)
    batcher.start()

    # Adding 2 rows should not flush yet
    batcher.add("test_table", {"val": 1})
    batcher.add("test_table", {"val": 2})
    assert not flush_event.wait(timeout=0.05)
    assert len(flushed_records) == 0

    # Adding 3rd row triggers threshold flush
    batcher.add("test_table", {"val": 3})
    assert flush_event.wait(timeout=3.0), "Worker did not trigger size flush within timeout"
    assert len(flushed_records) == 3
    assert flushed_tables == ["test_table"]

    batcher.stop()


def test_clickhouse_batcher_interval_flush():
    flushed_records = []

    def mock_insert(table, rows):
        flushed_records.extend(rows)

    batcher = ClickHouseBatcher(insert_fn=mock_insert, batch_size=100, flush_interval=0.2, dlq_enabled=False)
    batcher.start()

    batcher.add("test_table", {"foo": "bar"})
    assert len(flushed_records) == 0

    # Wait for interval to fire
    time.sleep(0.35)
    assert len(flushed_records) == 1
    batcher.stop()


def test_clickhouse_batcher_dlq_spooling_and_replay(tmp_path: Path):
    """Test that permanent insert failures are spooled to DLQ and can be replayed."""
    fail_count = 0
    recovered_rows = []

    def failing_insert(table, rows):
        nonlocal fail_count
        fail_count += 1
        raise RuntimeError("ClickHouse connection refused (simulated)")

    def recovery_insert(table, rows):
        recovered_rows.extend(rows)

    # 1. Batcher with failing insert function
    dlq_dir = tmp_path / "dlq"
    batcher = ClickHouseBatcher(
        insert_fn=failing_insert,
        batch_size=2,
        flush_interval=0.1,
        max_retries=2,
        dlq_dir=dlq_dir,
        dlq_enabled=True,
    )
    batcher.start()

    batcher.add("raw_payloads", {"payload_id": "p-failed-1"})
    batcher.add("raw_payloads", {"payload_id": "p-failed-2"})

    # Wait for retries and spooling
    time.sleep(1.0)
    batcher.stop()

    assert batcher.total_spooled_to_dlq == 2
    dlq_files = list(dlq_dir.glob("*.jsonl"))
    assert len(dlq_files) == 1

    # 2. Recovery: replay DLQ files using healthy insert function
    batcher._insert_fn = recovery_insert
    replayed = batcher.replay_dlq(table="raw_payloads")
    assert replayed == 2
    assert len(recovered_rows) == 2
    assert recovered_rows[0]["payload_id"] == "p-failed-1"

    # DLQ file should be cleaned up after replay
    assert len(list(dlq_dir.glob("*.jsonl"))) == 0


def test_clickhouse_storage_helpers():
    now_str = "2026-09-08T10:00:00Z"
    dt = _format_dt(now_str)
    assert dt is not None
    assert dt.year == 2026

    # JSON helper
    assert _json_str({"key": 42}) == '{"key":42}'
    assert _json_str(None) == "{}"


def test_clickhouse_storage_with_mock_client():
    mock_client = MagicMock()
    mock_client.command.return_value = None
    mock_client.query.return_value.column_names = ["payload_id", "received_at"]
    mock_client.query.return_value.result_rows = [["p-1", "2026-09-08T10:00:00Z"]]

    ch = ClickHouseStorage(client=mock_client, query_timeout=25, max_memory_usage=1500000000)
    assert ch.is_connected() is True

    # Test list_logs passes query quotas
    logs = ch.list_logs(limit=10, offset=0, hostname="DESKTOP-SEC01")
    assert len(logs) == 1
    assert logs[0]["payload_id"] == "p-1"

    # Verify query guards (timeout and memory limits) were supplied to client.query
    _, kwargs = mock_client.query.call_args
    assert kwargs.get("settings", {}).get("max_execution_time") == 25
    assert kwargs.get("settings", {}).get("max_memory_usage") == 1500000000

    # Test store_raw_payload queues into batcher
    ch.store_raw_payload(
        envelope={"scheme": "aes_gcm", "key_id": "k1"},
        decrypted_payload={
            "payload_id": "p-123",
            "agent_id": "a-123",
            "hostname": "HOST-1",
            "collectors": [
                {"collector": "file", "status": "success", "payload": {"file_count": 5}}
            ],
        },
    )
    # Stop flushes batcher to client
    ch.close()
    assert mock_client.insert.called


def test_dlq_underscore_table_names_exact_routing(tmp_path: Path):
    """
    Regression test for P1 defect: DLQ table-name parsing must resolve
    multi-underscore table names like 'raw_payloads' and 'collector_results'
    rather than truncated 'raw' or 'collector'.
    """
    recorded_inserts: dict[str, list[dict]] = {}

    def mock_insert(table: str, rows: list[dict]):
        recorded_inserts.setdefault(table, []).extend(rows)

    dlq_dir = tmp_path / "dlq_routing"
    dlq_dir.mkdir(parents=True, exist_ok=True)

    batcher = ClickHouseBatcher(
        insert_fn=mock_insert,
        batch_size=10,
        dlq_dir=dlq_dir,
        dlq_enabled=True,
    )

    # 1. Test versioned DLQ file with header metadata
    batcher._spool_to_dlq("raw_payloads", [{"id": "r1"}, {"id": "r2"}], RuntimeError("simulated error"))
    batcher._spool_to_dlq("collector_results", [{"id": "c1"}], RuntimeError("simulated error"))

    # 2. Test legacy unversioned DLQ file naming format
    legacy_file = dlq_dir / "dlq_raw_payloads_1728000000_9999.jsonl"
    with open(legacy_file, "w", encoding="utf-8") as f:
        f.write('{"id": "legacy_r1"}\n')

    # Replay all DLQ files without passing explicit table
    recovered = batcher.replay_dlq()
    assert recovered == 4

    # Verify exact destination tables
    assert "raw_payloads" in recorded_inserts
    assert "collector_results" in recorded_inserts
    assert "raw" not in recorded_inserts
    assert "collector" not in recorded_inserts

    raw_ids = [r["id"] for r in recorded_inserts["raw_payloads"]]
    assert "r1" in raw_ids
    assert "r2" in raw_ids
    assert "legacy_r1" in raw_ids

    assert recorded_inserts["collector_results"][0]["id"] == "c1"


def test_clickhouse_batcher_bounded_buffer_overflow(tmp_path: Path):
    """Verify that buffer limits cap memory and trigger durable overflow spooling."""
    dlq_dir = tmp_path / "dlq_overflow"
    dlq_dir.mkdir(parents=True, exist_ok=True)

    def failing_insert(table, rows):
        raise RuntimeError("ClickHouse offline")

    # Set tight buffer limits: max 5 rows total, batch_size 2
    batcher = ClickHouseBatcher(
        insert_fn=failing_insert,
        batch_size=2,
        flush_interval=100.0,  # Do not flush automatically by timer
        dlq_dir=dlq_dir,
        dlq_enabled=True,
        max_buffer_rows=5,
    )

    # Add 10 rows without running worker (ClickHouse outage scenario)
    for i in range(10):
        batcher.add("raw_payloads", {"row": i})

    # In-memory buffer must be capped at or below max_buffer_rows
    assert len(batcher._buffers.get("raw_payloads", [])) <= 5
    # Overflow rows must have been spooled to DLQ durably
    assert batcher.total_overflow_dropped > 0
    assert len(list(dlq_dir.glob("*.jsonl"))) > 0


def test_dlq_corrupted_line_handling(tmp_path: Path):
    """Preserve corrupt DLQ files in full instead of deleting unrecoverable rows."""
    recovered_rows = []

    def recovery_insert(table, rows):
        recovered_rows.extend(rows)

    dlq_dir = tmp_path / "dlq_corrupt"
    dlq_dir.mkdir(parents=True, exist_ok=True)

    corrupt_file = dlq_dir / "dlq_raw_payloads_1728000000_1234.jsonl"
    with open(corrupt_file, "w", encoding="utf-8") as f:
        f.write('{"id": "valid_1"}\n')
        f.write('{this is NOT json corrupt garbage}\n')
        f.write('{"id": "valid_2"}\n')

    batcher = ClickHouseBatcher(
        insert_fn=recovery_insert,
        dlq_dir=dlq_dir,
        dlq_enabled=True,
    )

    count = batcher.replay_dlq()
    assert count == 0
    assert recovered_rows == []
    assert corrupt_file.exists()


def test_clickhouse_batcher_buffer_rows_validation():
    """Verify ClickHouseBatcher validates max_buffer_rows >= batch_size and defaults safely."""
    import pytest

    # 1. Default when None: should provide 2x batch_size or at least 10,000
    b1 = ClickHouseBatcher(insert_fn=lambda t, r: None, batch_size=15000, dlq_enabled=False)
    assert b1.max_buffer_rows == 30000

    b2 = ClickHouseBatcher(insert_fn=lambda t, r: None, batch_size=500, dlq_enabled=False)
    assert b2.max_buffer_rows == 10000

    # 2. Explicit valid value
    b3 = ClickHouseBatcher(insert_fn=lambda t, r: None, batch_size=15000, max_buffer_rows=30000, dlq_enabled=False)
    assert b3.max_buffer_rows == 30000

    # 3. Invalid: max_buffer_rows < batch_size must fail fast
    with pytest.raises(ValueError, match="cannot be less than batch_size"):
        ClickHouseBatcher(insert_fn=lambda t, r: None, batch_size=15000, max_buffer_rows=10000, dlq_enabled=False)


def test_clickhouse_storage_passes_max_buffer_rows():
    """Verify ClickHouseStorage correctly passes max_buffer_rows to the batcher."""
    mock_client = MagicMock()
    mock_client.command.return_value = None

    storage = ClickHouseStorage(
        client=mock_client,
        batch_size=15000,
        max_buffer_rows=30000,
    )
    assert storage.batcher.batch_size == 15000
    assert storage.batcher.max_buffer_rows == 30000


def test_clickhouse_batcher_byte_trigger():
    """Verify that exceeding the byte limit triggers an immediate flush before row threshold or timer."""
    import threading

    flushed_tables = []
    flushed_records = []
    flush_event = threading.Event()

    def mock_insert(table, rows):
        flushed_tables.append(table)
        flushed_records.extend(rows)
        flush_event.set()

    # High row threshold (1000) and long timer (10s)
    batcher = ClickHouseBatcher(
        insert_fn=mock_insert,
        batch_size=1000,
        batch_bytes=500,
        flush_interval=10.0,
        dlq_enabled=False,
    )
    batcher.start()

    # Small row (~100 bytes) - should not trigger
    batcher.add("test_table", {"payload": "A" * 80})
    assert not flush_event.wait(timeout=0.05)
    assert len(flushed_records) == 0

    # Second row (~500 bytes) pushes total table bytes past batch_bytes (500)
    batcher.add("test_table", {"payload": "B" * 450})
    # Event-driven wait eliminates timing sensitivity on slow runners
    assert flush_event.wait(timeout=3.0), "Worker did not trigger byte flush within timeout"

    # Must flush both rows immediately without waiting for 1000 rows or 10.0s timer
    assert len(flushed_records) == 2
    assert flushed_tables == ["test_table"]
    assert batcher.total_overflow_dropped == 0

    batcher.stop()


def test_clickhouse_batcher_byte_validation():
    """Verify ClickHouseBatcher validates max_buffer_bytes >= batch_bytes and defaults safely."""
    import pytest

    # 1. Default when None: should provide 2x batch_bytes or at least 25 MB
    b1 = ClickHouseBatcher(insert_fn=lambda t, r: None, batch_bytes=8 * 1024 * 1024, dlq_enabled=False)
    assert b1.batch_bytes == 8 * 1024 * 1024
    assert b1.max_buffer_bytes >= 16 * 1024 * 1024

    # 2. Explicit valid value
    b2 = ClickHouseBatcher(insert_fn=lambda t, r: None, batch_bytes=1000, max_buffer_bytes=2000, dlq_enabled=False)
    assert b2.batch_bytes == 1000
    assert b2.max_buffer_bytes == 2000

    # 3. Invalid: max_buffer_bytes < batch_bytes must fail fast
    with pytest.raises(ValueError, match="cannot be less than batch_bytes"):
        ClickHouseBatcher(insert_fn=lambda t, r: None, batch_bytes=5000, max_buffer_bytes=2000, dlq_enabled=False)


def test_clickhouse_storage_passes_byte_limits():
    """Verify ClickHouseStorage correctly passes batch_bytes and max_buffer_bytes to the batcher."""
    mock_client = MagicMock()
    mock_client.command.return_value = None

    storage = ClickHouseStorage(
        client=mock_client,
        batch_size=15000,
        batch_bytes=8388608,
        max_buffer_bytes=16777216,
        max_buffer_rows=30000,
    )
    assert storage.batcher.batch_bytes == 8388608
    assert storage.batcher.max_buffer_bytes == 16777216


def test_clickhouse_batcher_ceiling_overflow_behavior(tmp_path: Path):
    """Verify that an incoming batch exceeding remaining buffer capacity intentionally spills to DLQ."""
    dlq_dir = tmp_path / "dlq_ceiling"
    dlq_dir.mkdir(parents=True, exist_ok=True)

    # Threshold 400 bytes, hard capacity ceiling 800 bytes
    batcher = ClickHouseBatcher(
        insert_fn=lambda t, r: None,
        batch_size=100,
        batch_bytes=400,
        max_buffer_bytes=800,
        flush_interval=100.0,
        dlq_dir=dlq_dir,
        dlq_enabled=True,
    )

    # 1. Normal addition within capacity (approx 250 bytes)
    batcher.add("raw_payloads", {"msg": "X" * 200})
    assert batcher._table_bytes.get("raw_payloads", 0) <= 800
    assert batcher.total_overflow_dropped == 0

    # 2. Large addition: 3 rows of ~250 bytes each (~750 bytes). Total 250 + 750 = 1000 > 800 ceiling.
    incoming_batch = [{"msg": "Y" * 200} for _ in range(3)]
    batcher.add_many("raw_payloads", incoming_batch)

    # Buffer MUST NOT exceed 800 bytes; excess must be intentionally evicted to DLQ
    assert batcher._table_bytes.get("raw_payloads", 0) <= 800
    assert batcher.total_overflow_dropped > 0
    assert len(list(dlq_dir.glob("*.jsonl"))) > 0
