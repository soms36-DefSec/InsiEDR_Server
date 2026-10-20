"""Bounded stale-while-revalidate snapshots for interactive dashboards.

Redis leases coordinate API processes. If configured Redis is unavailable, fail
closed for new refreshes rather than start a query storm. Last good snapshots
remain usable for a bounded time. This cache is never an ingestion queue.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from server.api.cache import api_cache
from server.api.errors import AnalyticsUnavailableError

logger = logging.getLogger(__name__)
_slots = {name: threading.BoundedSemaphore(1) for name in ('fleet', 'analytics', 'replication', 'logs')}


def snapshot_key(storage, actor, name, filters=None):
    # Stable across workers; never place credentials or user filters in Redis keys.
    scope = os.environ.get('INSIEDR_DATABASE_DSN') or os.environ.get('DATABASE_DSN')
    scope = scope or f'local:{id(storage)}'
    identity = [scope, str(actor), name, filters,
                os.environ.get('INSIEDR_TELEMETRY_READ_BACKEND', 'postgres'),
                os.environ.get('INSIEDR_CH_COLLECTOR_SCHEMA_VERSION', '1'),
                os.environ.get('INSIEDR_CH_ROLLUPS_ENABLED', 'false')]
    identity.append(os.environ.get('INSIEDR_RAM_TELEMETRY_ENABLED','false'))
    return 'snapshot:v2:' + hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()


@contextmanager
def workload_slot(group):
    """One active job per workload across workers, with a renewable Redis lease."""
    slot = _slots[group]
    acquired = slot.acquire(blocking=False)
    lease = None
    stop = threading.Event()
    renewer = None
    try:
        if not acquired:
            yield False
            return
        if api_cache.l2 is not None:
            client = api_cache.l2._client
            if client is None:
                yield False
                return
            try:
                lease_timeout = 30 if group in ('fleet', 'logs') else 120
                renew_interval = 8 if group in ('fleet', 'logs') else 20
                lease = client.lock(f'insiedr:workload:v2:{group}', timeout=lease_timeout, thread_local=False)
                got_lease = lease.acquire(blocking=False)
                if got_lease:
                    api_cache.l2._is_connected = True
            except Exception:
                got_lease = False
            if not got_lease:
                lease = None
                yield False
                return

            def renew():
                while not stop.wait(renew_interval):
                    try:
                        lease.extend(lease_timeout, replace_ttl=True)
                    except Exception:
                        logger.error('Lost %s workload lease; database query limits bound remaining work', group)
                        return
            renewer = threading.Thread(target=renew, daemon=True, name=f'{group}-lease')
            renewer.start()
        yield True
    finally:
        stop.set()
        if renewer:
            renewer.join(timeout=1)
        if lease is not None:
            try:
                lease.release()
            except Exception:
                logger.warning('Could not release %s workload lease', group)
        if acquired:
            slot.release()


def _present(record, fresh_seconds):
    age = max(0, time.time() - record['checked_at'])
    return {'ok': True, **record['value'], 'freshness': {
        'generated_at': record['generated_at'], 'age_seconds': round(age, 1),
        'stale': age >= fresh_seconds, 'source': 'snapshot',
        'fresh_for_seconds': fresh_seconds,
    }}


def snapshot(storage, actor, name, loader, *, filters=None, group='analytics',
             fresh_seconds=90, max_age=900):
    key = snapshot_key(storage, actor, name, filters)
    record = api_cache.get(key)
    if record and time.time() - record['checked_at'] >= fresh_seconds and api_cache.l2 is not None:
        shared = api_cache.l2.get(key)
        if shared and shared['checked_at'] > record['checked_at']:
            record = shared
            api_cache.l1.set(key, shared, ttl=max_age)
    if record and time.time() - record['checked_at'] >= max_age:
        record = None

    def refresh():
        with workload_slot(group) as allowed:
            if not allowed:
                raise AnalyticsUnavailableError('Dashboard refresh is busy; retry shortly')
            # Recheck after acquiring the cross-worker gate.
            current = api_cache.l2.get(key) if api_cache.l2 is not None else api_cache.get(key)
            if current and time.time() - current['checked_at'] < fresh_seconds:
                return current
            if api_cache.get(key + ':backoff'):
                raise AnalyticsUnavailableError('Dashboard refresh is recovering; retry shortly')
            try:
                value = loader()
                if not isinstance(value, dict) or value.get('ok') is False:
                    raise AnalyticsUnavailableError('Dashboard data is unavailable')
                now = time.time()
                updated = {'value': value, 'checked_at': now,
                           'generated_at': datetime.fromtimestamp(now, timezone.utc).isoformat()}
                api_cache.set(key, updated, ttl=max_age)
                return updated
            except Exception:
                api_cache.set(key + ':backoff', True, ttl=5)
                raise

    if record is None:
        # Cold requests compute once; concurrent callers get a retryable 503.
        return _present(refresh(), fresh_seconds)
    if time.time() - record['checked_at'] >= fresh_seconds and not api_cache.get(key + ':backoff'):
        # Reserve locally before starting a thread: no unbounded executor queue.
        launch = _refresh_slots[group].acquire(blocking=False)
        if launch:
            def run():
                try:
                    refresh()
                except AnalyticsUnavailableError:
                    logger.debug('%s snapshot refresh deferred (lease busy)', name)
                except Exception as exc:
                    logger.warning('%s snapshot refresh deferred (%s)', name, type(exc).__name__)
                finally:
                    _refresh_slots[group].release()
            threading.Thread(target=run, daemon=True, name=f'{group}-snapshot').start()
    return _present(record, fresh_seconds)


_refresh_slots = {name: threading.BoundedSemaphore(1) for name in ('fleet', 'analytics')}
