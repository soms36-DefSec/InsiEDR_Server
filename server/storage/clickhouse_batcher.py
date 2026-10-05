"""
server/storage/clickhouse_batcher.py
------------------------------------
Asynchronous Micro-Batching Buffer with Dead-Letter Queue (DLQ) for ClickHouse.

Architecture & Design:
======================
ClickHouse is an OLAP columnar database designed to ingest thousands of rows in
large block writes. Single-row inserts on every HTTP ingest call causes part
fragmentation and severe CPU overhead ("too many parts" error).

This module implements `ClickHouseBatcher`:
  - Enqueues incoming records into dedicated per-table thread-safe buffers.
  - Flushes batches to ClickHouse when:
      1. Batch size threshold is reached (default: 500 rows per table), OR
      2. Time interval expires (default: 1.0 second), OR
      3. Server shutdown is initiated (guaranteed zero data loss).
  - Exponential backoff retry logic on network or server compaction hiccups.
  - Zero Data-Loss Dead-Letter Queue (DLQ): If ClickHouse is permanently
    unreachable after all retries, the failed batch is spooled to an on-disk
    JSONL file in `data/dlq/` with restrictive permissions.
  - DLQ Replay: Provides `replay_dlq()` to re-insert spooled records once
    ClickHouse is healthy again.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("insiedr.clickhouse.batcher")


class ClickHouseBatcher:
    """
    Thread-safe asynchronous micro-batch buffer with bounded memory and on-disk
    Dead-Letter Queue (DLQ) for guaranteed telemetry durability.
    """

    def __init__(
        self,
        insert_fn: Callable[[str, List[Dict[str, Any]]], None],
        batch_size: int = 500,
        flush_interval: float = 1.0,
        max_retries: int = 3,
        dlq_dir: str | Path = "data/dlq",
        dlq_enabled: bool = True,
        max_buffer_rows: int = 10000,
        max_buffer_bytes: int = 25 * 1024 * 1024,
    ) -> None:
        self._insert_fn = insert_fn
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.max_retries = max_retries
        self.dlq_dir = Path(dlq_dir)
        self.dlq_enabled = dlq_enabled
        self.max_buffer_rows = max_buffer_rows
        self.max_buffer_bytes = max_buffer_bytes

        # Per-table record queues
        self._buffers: Dict[str, List[Dict[str, Any]]] = {}
        self._table_bytes: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._last_flush_time = time.time()

        # Set when no background flush is in-progress; cleared while _flush_loop
        # is actively inserting rows outside the lock.  flush_all() waits on this
        # event so it cannot declare success while a concurrent background insert
        # is still running on a snapshot it already dequeued.
        self._in_flight_event = threading.Event()
        self._in_flight_event.set()  # Initially no background flush is running

        # Telemetry metrics
        self.total_queued = 0
        self.total_flushed = 0
        self.total_errors = 0
        self.total_spooled_to_dlq = 0
        self.total_overflow_dropped = 0

    def start(self) -> None:
        """Start the background micro-batch worker thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(
                target=self._flush_loop,
                name="ClickHouse_BatchWorker",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("ClickHouse micro-batch worker started (batch_size=%d, interval=%.1fs, max_rows=%d, dlq=%s)",
                        self.batch_size, self.flush_interval, self.max_buffer_rows,
                        "enabled" if self.dlq_enabled else "disabled")

    def stop(self, timeout: float = 10.0) -> None:
        """Stop worker and synchronously flush all remaining buffered data."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._cond.notify_all()

        timed_out = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
            if self._worker_thread.is_alive():
                timed_out = True
                logger.warning("ClickHouse micro-batch worker timed out after %.1fs during shutdown; background thread still active", timeout)

        # Final synchronous flush
        self.flush_all()
        if not timed_out:
            logger.info("ClickHouse micro-batch worker stopped cleanly.")

    def add(self, table: str, row: Dict[str, Any]) -> None:
        """Add a single record to the table buffer."""
        self.add_many(table, [row])

    @staticmethod
    def _estimate_row_bytes(row: Dict[str, Any]) -> int:
        return len(json.dumps(row, default=str).encode("utf-8"))

    def add_many(self, table: str, rows: List[Dict[str, Any]]) -> None:
        """Add multiple records to the table buffer with strict capacity enforcement."""
        if not rows:
            return

        added_bytes = sum(self._estimate_row_bytes(r) for r in rows)
        spool_overflow: List[Dict[str, Any]] = []

        with self._lock:
            if table not in self._buffers:
                self._buffers[table] = []
                self._table_bytes[table] = 0

            # Enforce row and byte ceiling: if buffer is at capacity, trigger durable overflow policy
            current_count = len(self._buffers[table])
            current_bytes = self._table_bytes.get(table, 0)

            while (current_count + len(rows) > self.max_buffer_rows or current_bytes + added_bytes > self.max_buffer_bytes) and self._buffers[table]:
                # Evict oldest batch slice to prevent unbounded memory growth during ClickHouse outages
                evict_count = min(self.batch_size, len(self._buffers[table]))
                slice_to_evict = self._buffers[table][:evict_count]
                self._buffers[table] = self._buffers[table][evict_count:]
                evicted_bytes = sum(self._estimate_row_bytes(r) for r in slice_to_evict)
                self._table_bytes[table] = max(0, self._table_bytes[table] - evicted_bytes)
                current_count = len(self._buffers[table])
                current_bytes = self._table_bytes[table]
                spool_overflow.extend(slice_to_evict)
                self.total_overflow_dropped += len(slice_to_evict)

            # 2. Strict admission: evaluate each incoming row against remaining capacity.
            # Even if the existing buffer was completely drained, an oversized incoming batch
            # must NEVER bypass max_buffer_rows or max_buffer_bytes.
            admitted_rows: List[Dict[str, Any]] = []
            for r in rows:
                r_bytes = self._estimate_row_bytes(r)
                if (current_count + 1 <= self.max_buffer_rows and
                    current_bytes + r_bytes <= self.max_buffer_bytes):
                    admitted_rows.append(r)
                    current_count += 1
                    current_bytes += r_bytes
                else:
                    spool_overflow.append(r)
                    self.total_overflow_dropped += 1

            if admitted_rows:
                self._buffers[table].extend(admitted_rows)
                self._table_bytes[table] = current_bytes
                self.total_queued += len(admitted_rows)

            # If any table reaches batch size, wake up flush worker immediately
            if len(self._buffers[table]) >= self.batch_size:
                self._cond.notify_all()

        # Spool evicted rows directly to DLQ outside the buffer lock
        if spool_overflow and self.dlq_enabled:
            logger.warning("Buffer capacity reached for table '%s'; durably spilling %d rows to DLQ",
                           table, len(spool_overflow))
            self._spool_to_dlq(table, spool_overflow, RuntimeError("Buffer memory capacity reached; durable overflow spool"))

    def flush_all(self, raise_on_error: bool = False) -> None:
        """Synchronously flush all pending buffers across all tables.

        Waits for any concurrent background flush to complete before snapshotting
        the buffer, so this method cannot return while background inserts are
        still in progress.  This is required for the outbox reconciler to safely
        mark entries as completed.

        If raise_on_error is True and any table flush fails after retries,
        raises RuntimeError to ensure callers (such as the outbox reconciler)
        do not falsely mark replication completed.
        """
        # Wait for any in-progress background flush to finish before we snapshot.
        # This prevents flush_all from seeing an empty buffer while the background
        # thread is still mid-insert on rows it already dequeued.
        self._in_flight_event.wait(timeout=max(self.flush_interval * 3, 10.0))

        with self._lock:
            snapshot = {table: list(rows) for table, rows in self._buffers.items() if rows}
            for table in snapshot:
                self._buffers[table].clear()
                self._table_bytes[table] = 0
            self._last_flush_time = time.time()

        flush_errors: list[Exception] = []
        for table, rows in snapshot.items():
            err = self._flush_table_with_retry(table, rows)
            if err is not None:
                flush_errors.append(err)

        if flush_errors and raise_on_error:
            raise RuntimeError(f"ClickHouse batch flush failed for {len(flush_errors)} table(s): {flush_errors[0]}")

    def _flush_loop(self) -> None:
        """Continuous background loop triggering flushes on interval or threshold."""
        while True:
            with self._cond:
                self._cond.wait(timeout=self.flush_interval)
                if not self._running:
                    break

                now = time.time()
                should_flush = (now - self._last_flush_time >= self.flush_interval) or any(
                    len(rows) >= self.batch_size for rows in self._buffers.values()
                )

                if not should_flush:
                    continue

                snapshot = {table: list(rows) for table, rows in self._buffers.items() if rows}
                for table in snapshot:
                    self._buffers[table].clear()
                    self._table_bytes[table] = 0
                self._last_flush_time = now

            # Signal that a background flush is in progress.
            self._in_flight_event.clear()
            try:
                for table, rows in snapshot.items():
                    try:
                        self._flush_table_with_retry(table, rows)
                    except Exception as loop_err:
                        # _flush_table_with_retry itself only raises if DLQ write fails.
                        # Catch here so a DLQ disk-full error cannot kill the worker thread.
                        logger.critical(
                            "ClickHouse flush worker caught unexpected error for table '%s': %s",
                            table, loop_err, exc_info=True,
                        )
            finally:
                # Always signal completion so flush_all() waiters are unblocked.
                self._in_flight_event.set()

    def _flush_table_with_retry(self, table: str, rows: List[Dict[str, Any]]) -> Optional[Exception]:
        """Attempt to insert rows into ClickHouse with exponential backoff and DLQ spooling.
        Returns None on success, or the terminal Exception if all retries failed.
        """
        if not rows:
            return None

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                self._insert_fn(table, rows)
                self.total_flushed += len(rows)
                logger.debug("Successfully flushed %d rows to ClickHouse table '%s'", len(rows), table)
                return None
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "ClickHouse batch flush attempt %d/%d failed for table '%s' (%d rows): %s",
                    attempt, self.max_retries, table, len(rows), exc
                )
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** (attempt - 1)))
                else:
                    self.total_errors += len(rows)
                    if self.dlq_enabled:
                        self._spool_to_dlq(table, rows, exc)
                    else:
                        logger.error("DLQ disabled. ClickHouse batch failed permanently for table '%s' (%d rows dropped)",
                                     table, len(rows), exc_info=True)
        return last_exc

    def _spool_to_dlq(self, table: str, rows: List[Dict[str, Any]], error: Exception) -> None:
        """
        Atomically write failed telemetry rows to an on-disk Dead-Letter Queue file
        using temporary publication and versioned metadata.
        """
        try:
            self.dlq_dir.mkdir(parents=True, exist_ok=True)
            timestamp_str = int(time.time())
            unique_token = uuid.uuid4().hex[:8]
            temp_file = self.dlq_dir / f"dlq_{table}_{timestamp_str}_{os.getpid()}_{unique_token}.tmp"
            final_file = self.dlq_dir / f"dlq_{table}_{timestamp_str}_{os.getpid()}_{unique_token}.jsonl"

            with open(temp_file, "w", encoding="utf-8") as f:
                # Version 1 DLQ metadata header
                meta = {
                    "_metadata": {
                        "version": 1,
                        "table": table,
                        "row_count": len(rows),
                        "created_at": timestamp_str,
                        "pid": os.getpid(),
                        "error": str(error),
                    }
                }
                f.write(json.dumps(meta, default=str) + "\n")
                for row in rows:
                    f.write(json.dumps(row, default=str) + "\n")

            try:
                os.chmod(temp_file, 0o600)
            except Exception:
                pass

            # Atomic publication: rename .tmp to .jsonl
            temp_file.replace(final_file)
            self.total_spooled_to_dlq += len(rows)
            logger.error("Spooling %d rows to DLQ '%s' due to ClickHouse error: %s", len(rows), final_file.name, error)
        except Exception as dlq_err:
            logger.critical("Failed writing to DLQ disk storage! Error: %s", dlq_err, exc_info=True)
            raise RuntimeError(f"DLQ disk write failure: {dlq_err}") from dlq_err

    @staticmethod
    def _parse_dlq_filename_table(stem: str, fallback_table: Optional[str] = None) -> Optional[str]:
        """
        Reconstruct original table name from filename stems like:
        - 'dlq_raw_payloads_1728000000_1234' -> 'raw_payloads'
        - 'dlq_collector_results_1728000000_1234_abcd1234' -> 'collector_results'
        - 'dlq_events_1728000000_1234' -> 'events'
        """
        parts = stem.split("_")
        if not parts or parts[0] != "dlq":
            return fallback_table

        # If stem has at least 4 tokens and ending parts are numeric timestamp / pid / uuid
        # Find where table name ends
        tokens = parts[1:]
        # Remove trailing tokens that look like pid/uuid or timestamps
        while tokens and (tokens[-1].isdigit() or (len(tokens[-1]) in (6, 8, 32) and all(c in "0123456789abcdef" for c in tokens[-1].lower()))):
            tokens.pop()

        if tokens:
            return "_".join(tokens)
        return fallback_table

    def replay_dlq(self, table: Optional[str] = None) -> int:
        """
        Replay spooled DLQ files back into ClickHouse with exclusive file ownership.
        Returns total number of recovered rows.
        """
        if not self.dlq_dir.is_dir():
            return 0

        # Recover abandoned .replaying files from a previous crash.
        # If the mtime of a .replaying file is older than the flush_interval
        # threshold (with a minimum of 10 minutes), it was left by a dead
        # process and is safe to rename back to .jsonl for retry.
        stale_threshold = max(self.flush_interval * 60, 600)  # seconds
        now_ts = time.time()
        for orphan in list(self.dlq_dir.glob("*.replaying")):
            try:
                age = now_ts - orphan.stat().st_mtime
                if age > stale_threshold:
                    recovered = orphan.with_suffix(".jsonl")
                    orphan.rename(recovered)
                    logger.info(
                        "Recovered abandoned DLQ claim '%s' (age=%.0fs) → '%s'",
                        orphan.name, age, recovered.name,
                    )
            except Exception as rec_err:
                logger.warning("Could not recover DLQ .replaying file '%s': %s", orphan.name, rec_err)

        replayed_total = 0
        pattern = f"dlq_{table}_*.jsonl" if table else "dlq_*.jsonl"
        dlq_files = sorted(list(self.dlq_dir.glob(pattern)))

        for file_path in dlq_files:
            # Skip tmp and replaying files
            if file_path.suffix != ".jsonl" or file_path.name.endswith(".tmp"):
                continue

            # Atomically claim ownership by renaming to .replaying
            replaying_path = file_path.with_suffix(".replaying")
            try:
                file_path.rename(replaying_path)
            except OSError:
                # Another worker or thread claimed this file
                continue

            try:
                target_table = None
                rows: List[Dict[str, Any]] = []

                with open(replaying_path, "r", encoding="utf-8") as f:
                    for line_idx, line in enumerate(f):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            record = json.loads(line_str)
                        except json.JSONDecodeError as dec_err:
                            logger.error("Corrupted JSON line %d in DLQ file '%s': %s", line_idx, file_path.name, dec_err)
                            continue

                        # Check for versioned metadata in line 0
                        if line_idx == 0 and isinstance(record, dict) and "_metadata" in record:
                            meta = record["_metadata"]
                            if isinstance(meta, dict) and "table" in meta:
                                target_table = meta["table"]
                                continue

                        if isinstance(record, dict):
                            rows.append(record)

                if not target_table:
                    target_table = self._parse_dlq_filename_table(file_path.stem, fallback_table=table)

                if not target_table:
                    logger.warning("Could not determine target table for DLQ file '%s'; skipping", file_path.name)
                    replaying_path.rename(file_path)
                    continue

                if table and target_table != table:
                    # Filter specified by caller doesn't match file's table; release file
                    replaying_path.rename(file_path)
                    continue

                if rows:
                    self._insert_fn(target_table, rows)
                    replayed_total += len(rows)
                    logger.info("Successfully replayed %d rows to '%s' from DLQ file '%s'",
                                len(rows), target_table, file_path.name)

                # Delete DLQ file ONLY after confirmed insertion success
                replaying_path.unlink()
            except Exception as exc:
                logger.error("Failed replaying DLQ file '%s': %s", file_path.name, exc)
                # Release lock so it can be retried later
                try:
                    replaying_path.rename(file_path)
                except Exception:
                    pass

        return replayed_total
