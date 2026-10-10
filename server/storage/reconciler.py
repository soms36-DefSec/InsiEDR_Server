"""Leased at-least-once replication with synchronous batch acknowledgements.

Ambiguous network failures can replay rows; read-side deduplication remains
required with the legacy MergeTree schema.
"""
from __future__ import annotations

import logging
import random
import threading
import time
import uuid

from server.storage.outbox import OutboxRepository

logger = logging.getLogger('insiedr.storage.reconciler')


class ReplicationReconciler:
    def __init__(self, postgres_storage, clickhouse_storage, poll_interval=5.0,
                 batch_size=128, purge_every_n_cycles=100, max_batch_size=1024,
                 max_batch_bytes=8 * 1024 * 1024, lease_seconds=120,
                 outbox_retention_hours=24, outbox=None):
        if min(poll_interval, batch_size, purge_every_n_cycles, max_batch_bytes,
               lease_seconds, outbox_retention_hours) <= 0 or max_batch_size < batch_size:
            raise ValueError('Invalid reconciler limits')
        self.pg, self.ch = postgres_storage, clickhouse_storage
        self.outbox = outbox if outbox is not None else OutboxRepository(self.pg)
        self.poll_interval, self.batch_size = poll_interval, batch_size
        self.max_batch_size, self.max_batch_bytes = max_batch_size, max_batch_bytes
        self.lease_seconds = lease_seconds
        self.outbox_retention_hours = outbox_retention_hours
        self.purge_every_n_cycles = purge_every_n_cycles
        self._claim_size = batch_size
        self._stop_event = threading.Event()
        self._thread = None
        self._cycle_count = 0
        self._running = False
        self.last_success_at = None
        self.last_error = None
        self.total_completed = 0

    def is_running(self):
        return bool(self._thread and self._thread.is_alive())

    def start(self):
        if self.is_running():
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name='insiedr-ch-reconciler', daemon=True)
        self._thread.start()

    def stop(self, timeout=5.0):
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout)
        if self.is_running():
            logger.warning('Reconciler still finishing an insert; unfinished claims remain recoverable')

    def reconcile_once(self):
        if self.ch is None:
            return 0
        if not self.ch.is_connected():
            self.ch._init_connection()
            if not self.ch.is_connected():
                raise RuntimeError('ClickHouse is unavailable')
            self.ch.ensure_schema()
            self.ch.batcher.start()
        token = uuid.uuid4().hex
        pending = self.outbox.claim(token, self._claim_size, self.lease_seconds, self.max_batch_bytes)
        if not pending:
            self._claim_size = self.batch_size
            return 0
        heartbeat_stop, lost = threading.Event(), threading.Event()

        def keep_lease():
            while not heartbeat_stop.wait(self.lease_seconds / 3):
                try:
                    if self.outbox.renew(token, self.lease_seconds) != len(pending):
                        lost.set()
                        return
                except Exception:
                    lost.set()
                    logger.exception('Outbox lease renewal failed')
                    return

        def check_lease():
            if lost.is_set() or self._stop_event.is_set():
                raise RuntimeError('Outbox ownership lost or shutdown requested')

        heartbeat = threading.Thread(target=keep_lease, name='outbox-lease', daemon=True)
        heartbeat.start()
        started = time.monotonic()
        try:
            self.ch.replicate_outbox_batch(pending, before_insert=check_lease,
                                           max_bytes=self.max_batch_bytes)
            check_lease()
            completed = self.outbox.complete(token, [r['outbox_id'] for r in pending])
            if completed != len(pending):
                raise RuntimeError('Outbox completion rejected an expired or replaced claim')
            self.total_completed += completed
            self.last_success_at = time.time()
            self.last_error = None
            if len(pending) == self._claim_size and time.monotonic() - started < self.poll_interval:
                self._claim_size = min(self.max_batch_size, self._claim_size * 2)
            else:
                self._claim_size = max(self.batch_size, self._claim_size // 2)
            return completed
        except Exception as exc:
            self.last_error = type(exc).__name__
            poison_ids = [r['outbox_id'] for r in pending if r.get('attempts', 1) >= 5]
            if poison_ids:
                logger.error("Quarantining %d poison outbox record(s) exceeding max retries: %s", len(poison_ids), poison_ids)
                try:
                    self.outbox.quarantine(token, poison_ids, exc)
                except Exception as q_err:
                    logger.warning("Outbox quarantine failed: %s", q_err)
            attempts = max(r.get('attempts', 1) for r in pending)
            delay = min(300, 2 ** min(attempts, 8)) * random.uniform(0.8, 1.2)
            self.outbox.release(token, exc, delay)
            self._claim_size = self.batch_size
            raise
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=5)

    def _run_loop(self):
        while not self._stop_event.is_set():
            requested = self._claim_size
            try:
                count = self.reconcile_once()
                self._cycle_count += 1
                if self._cycle_count % self.purge_every_n_cycles == 0:
                    self.outbox.purge(self.outbox_retention_hours)
                if count < requested:
                    self._stop_event.wait(self.poll_interval)
            except Exception as exc:
                self.last_error = type(exc).__name__
                logger.exception('Replication cycle failed; uncompleted records remain recoverable')
                self._stop_event.wait(self.poll_interval)
