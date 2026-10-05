"""
server/storage/reconciler.py
----------------------------
Transactional Outbox Reconciler for PostgreSQL-to-ClickHouse Replication.
Durable, recoverable replication worker ensuring ClickHouse catches up
after outages or server restarts without silently dropping records or
exhausting in-memory buffers.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger("insiedr.storage.reconciler")


class ReplicationReconciler:
    """
    Background worker that drains PostgreSQL `clickhouse_outbox` records
    and replays them into ClickHouse.

    Also periodically purges completed outbox entries that have exceeded the
    configured retention window, enforcing the ``store_plaintext_payloads``
    privacy policy by limiting how long any payload data sits in the outbox.
    """

    def __init__(
        self,
        postgres_storage: Any,
        clickhouse_storage: Any,
        poll_interval: float = 2.0,
        batch_size: int = 100,
        purge_every_n_cycles: int = 100,
    ) -> None:
        self.pg = postgres_storage
        self.ch = clickhouse_storage
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        self.purge_every_n_cycles = purge_every_n_cycles
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._cycle_count = 0

    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="insiedr-ch-reconciler",
            daemon=True,
        )
        self._thread.start()
        logger.info("ClickHouse replication reconciler started.")

    def stop(self, timeout: float = 5.0) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("ClickHouse replication reconciler stopped.")

    def reconcile_once(self) -> int:
        """Process one batch of pending outbox entries. Returns number of replicated records."""
        if self.ch is None or not getattr(self.ch, "is_connected", lambda: False)():
            return 0
        if not hasattr(self.pg, "get_pending_clickhouse_outbox"):
            return 0

        pending = self.pg.get_pending_clickhouse_outbox(limit=self.batch_size)
        if not pending:
            return 0

        replicated_ids: list[int] = []
        for item in pending:
            outbox_id = item.get("outbox_id")
            target_table = item.get("target_table")
            record_json = item.get("record_json") or {}

            try:
                if target_table == "raw_payloads":
                    env = record_json.get("envelope") or {}
                    pay = record_json.get("payload") or {}
                    # Skip replay for privacy-stripped entries — the ACID commit in
                    # PostgreSQL is the authoritative record; analytics data is
                    # already in ClickHouse via the direct write path, or deliberately
                    # excluded because store_plaintext_payloads=False.
                    if pay.get("_plaintext_stripped"):
                        logger.debug(
                            "Outbox entry %s has stripped payload (plaintext policy); marking completed without replay",
                            outbox_id,
                        )
                    else:
                        self.ch.store_raw_payload(env, pay)
                elif hasattr(self.ch, "batcher"):
                    self.ch.batcher.add(target_table, record_json)
                if outbox_id is not None:
                    replicated_ids.append(outbox_id)
            except Exception as exc:
                logger.warning("Reconciler failed to replay outbox record %s to ClickHouse: %s", outbox_id, exc)
                break  # Stop processing remaining batch on ClickHouse failure

        if not replicated_ids:
            return 0

        # Enforce confirmed ClickHouse database insertion before marking outbox completed.
        # ClickHouse in-memory buffer admission is NOT durable persistence.
        try:
            if hasattr(self.ch, "flush_all"):
                self.ch.flush_all(raise_on_error=True)
            elif hasattr(self.ch, "batcher") and hasattr(self.ch.batcher, "flush_all"):
                self.ch.batcher.flush_all(raise_on_error=True)
            elif hasattr(self.ch, "flush"):
                self.ch.flush()
        except Exception as flush_err:
            logger.warning("ClickHouse flush failed during reconciliation; records remain pending in outbox: %s", flush_err)
            if hasattr(self.pg, "increment_clickhouse_outbox_attempts"):
                self.pg.increment_clickhouse_outbox_attempts(replicated_ids, str(flush_err))
            return 0

        if hasattr(self.pg, "mark_clickhouse_outbox_completed"):
            self.pg.mark_clickhouse_outbox_completed(replicated_ids)
            logger.info("Reconciled %d records from PostgreSQL outbox to ClickHouse with confirmed persistence", len(replicated_ids))

        return len(replicated_ids)

    def _purge_completed(self) -> None:
        """Purge completed outbox entries that exceed the configured retention window."""
        try:
            if hasattr(self.pg, "purge_completed_clickhouse_outbox"):
                self.pg.purge_completed_clickhouse_outbox()
        except Exception as exc:
            logger.debug("Outbox purge non-fatal error: %s", exc)

    def _run_loop(self) -> None:
        while self._running and not self._stop_event.is_set():
            try:
                count = self.reconcile_once()
                self._cycle_count += 1

                # Periodically purge completed entries to enforce retention/privacy policy.
                if self._cycle_count % self.purge_every_n_cycles == 0:
                    self._purge_completed()

                # If we processed a full batch, check immediately for more, else wait poll_interval
                if count < self.batch_size:
                    self._stop_event.wait(self.poll_interval)
            except Exception as exc:
                logger.warning("Reconciliation loop error: %s", exc)
                self._stop_event.wait(self.poll_interval)
