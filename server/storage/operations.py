"""Authenticated operational snapshot; no payloads or credentials are returned."""
from __future__ import annotations

import os
import shutil
import time
import threading
import logging
from pathlib import Path

from server.config import config
from server.storage.outbox import OutboxRepository


class OperationsMonitor:
    """Sample once a minute and log alert transitions without log flooding."""
    def __init__(self, storage, app_state):
        self.storage, self.state = storage, app_state
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, name='insiedr-operations', daemon=True)
        self._thread.start()

    def stop(self, timeout=20):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self):
        previous = None
        while not self._stop.wait(60):
            try:
                with self.state.operations_lock:
                    snapshot = operations_snapshot(self.storage, self.state)
                    self.state.operations_snapshot = snapshot
                current = tuple(snapshot['alerts'])
                if current != previous:
                    logging.getLogger('insiedr.operations').log(
                        logging.WARNING if current else logging.INFO, 'Operational alerts: %s', current)
                previous = current
            except Exception:
                logging.getLogger('insiedr.operations').exception('Operational sampling failed')


def operations_snapshot(storage, app_state):
    alerts, result = [], {}
    pg = getattr(storage, 'pg', storage)
    try:
        result['outbox'] = OutboxRepository(pg).metrics()
        oldest = max((v['oldest_age_seconds'] for v in result['outbox'].values()), default=0)
        if oldest > float(os.environ.get('INSIEDR_OUTBOX_ALERT_SECONDS', '300')):
            alerts.append('replication_lag')
        with pg.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT status, started_at, finished_at, details_json FROM maintenance_runs WHERE name = 'retention'")
            row = cur.fetchone()
            result['retention'] = dict(zip(('status', 'started_at', 'finished_at', 'details'), row)) if row else None
        if row and row[0] in ('failed', 'degraded'):
            alerts.append('retention_requires_attention')
        if os.environ.get('INSIEDR_MAINTENANCE_ENABLED', 'false').lower() in ('true', '1', 'yes'):
            interval = float(os.environ.get('INSIEDR_MAINTENANCE_INTERVAL_SECONDS', '3600'))
            if not row or not row[2] or time.time() - row[2].timestamp() > interval * 2:
                alerts.append('retention_overdue')
    except Exception as exc:
        result['database_metrics_error'] = type(exc).__name__
        alerts.append('database_metrics_unavailable')
    workers = {}
    for name in ('reconciler', 'maintenance_worker', 'task_queue_worker'):
        worker = getattr(app_state, name, None)
        thread = getattr(worker, '_thread', None)
        workers[name] = {'configured': worker is not None, 'alive': bool(thread and thread.is_alive())}
        if worker is not None and not workers[name]['alive']:
            alerts.append(f'{name}_stopped')
    if getattr(storage, 'ch', None) is not None and not workers['reconciler']['configured']:
        alerts.append('reconciler_missing')
    if not workers['task_queue_worker']['configured']:
        alerts.append('task_worker_missing')
    result['workers'] = workers
    path = Path(config.dlq_dir)
    try:
        probe = path if path.exists() else path.parent
        usage = shutil.disk_usage(probe)
        used = 100 * usage.used / usage.total
        result['local_disk'] = {'used_percent': round(used, 1), 'free_bytes': usage.free,
                                'scope': 'DLQ filesystem only; monitor database volumes on their host'}
        if used >= 75:
            alerts.append('local_disk_critical' if used >= 80 else 'local_disk_warning')
        files, size, truncated = 0, 0, False
        if path.is_dir():
            for entry in path.iterdir():
                if entry.suffix not in ('.jsonl', '.replaying', '.tmp'):
                    continue
                if files >= 10000:
                    truncated = True
                    break
                try:
                    size += entry.stat().st_size
                    files += 1
                except FileNotFoundError:
                    pass  # Concurrent replay.
        result['dlq'] = {'files': files, 'bytes': size, 'truncated': truncated}
        if files:
            alerts.append('dlq_pending')
    except OSError as exc:
        result['disk_metrics_error'] = type(exc).__name__
        alerts.append('disk_metrics_unavailable')
    result.update(ok=not alerts, alerts=alerts, checked_at=time.time())
    return result
