"""Bounded PostgreSQL retention, serialized across API workers.

Each delete/drop commits independently. Default-partition relocation and attach
are atomic and capped; an oversized conflict is reported, never partly hidden.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from psycopg2 import sql
from psycopg2.extras import Json

from server.config import config
from server.storage.outbox import OutboxRepository

log = logging.getLogger('insiedr.maintenance')
LOCK_ID = 8472911
PARENTS = {'raw_payloads': 'received_at', 'collector_results': 'collector_collected_at'}


def partition_end(bound):
    """Use catalog bounds, not naming conventions, when deciding to drop data."""
    match = re.search(r"TO\s*\('([^']+)'\)", bound)
    if not match:
        return None
    try:
        value = datetime.fromisoformat(match[1])
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    except ValueError:
        return None


def _limits(cur):
    cur.execute("SET LOCAL lock_timeout = '1s'")
    cur.execute("SET LOCAL statement_timeout = '15s'")


def delete_batch(conn, table, column, cutoff, batch_size=5000):
    """ctid is only unique within a relation: include tableoid for partitions."""
    with conn.cursor() as cur:
        _limits(cur)
        cur.execute(sql.SQL('''WITH expired AS (
            SELECT tableoid, ctid FROM {} WHERE {} < %s
            ORDER BY {} LIMIT %s FOR UPDATE SKIP LOCKED
            ) DELETE FROM {} d USING expired e
              WHERE d.tableoid = e.tableoid AND d.ctid = e.ctid''').format(
                  sql.Identifier(table), sql.Identifier(column), sql.Identifier(column),
                  sql.Identifier(table)), (cutoff, batch_size))
        count = cur.rowcount
    conn.commit()
    return count


def partitions(conn, parent):
    with conn.cursor() as cur:
        cur.execute('''SELECT n.nspname, c.relname, pg_get_expr(c.relpartbound, c.oid)
            FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE i.inhparent = to_regclass(%s)''', (parent,))
        result = cur.fetchall()
    conn.commit()
    return result


def create_partition(conn, parent, column, start, move_limit=5000):
    end = start + timedelta(days=7)
    name = f'{parent}_w_{start:%Y_%m_%d}'
    children = partitions(conn, parent)
    if any(child == name for _, child, _ in children):
        return True
    defaults = [(schema, child) for schema, child, bound in children if bound == 'DEFAULT']
    if not children:
        return True  # Nonpartitioned test/legacy table.
    try:
        with conn.cursor() as cur:
            _limits(cur)
            # Serialize routing and partition DDL while preserving visibility.
            cur.execute(sql.SQL('LOCK TABLE {} IN ACCESS EXCLUSIVE MODE').format(sql.Identifier(parent)))
            if defaults:
                default = sql.Identifier(*defaults[0])
                cur.execute(sql.SQL('SELECT 1 FROM {} WHERE {} >= %s AND {} < %s LIMIT %s').format(
                    default, sql.Identifier(column), sql.Identifier(column)), (start, end, move_limit + 1))
                if len(cur.fetchall()) > move_limit:
                    conn.rollback()
                    return False
            cur.execute(sql.SQL('CREATE TABLE {} (LIKE {} INCLUDING DEFAULTS INCLUDING CONSTRAINTS)').format(
                sql.Identifier(name), sql.Identifier(parent)))
            if defaults:
                cur.execute(sql.SQL('''WITH moved AS (
                    DELETE FROM {} WHERE {} >= %s AND {} < %s RETURNING *
                    ) INSERT INTO {} SELECT * FROM moved''').format(
                        default, sql.Identifier(column), sql.Identifier(column), sql.Identifier(name)), (start, end))
            cur.execute(sql.SQL('ALTER TABLE {} ATTACH PARTITION {} FOR VALUES FROM (%s) TO (%s)').format(
                sql.Identifier(parent), sql.Identifier(name)), (start, end))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise


class MaintenanceWorker:
    def __init__(self, storage, interval_seconds=3600, batch_size=5000,
                 max_batches=1000, batch_pause=0.05, max_run_seconds=120):
        if min(interval_seconds, batch_size, max_batches, max_run_seconds) <= 0 or batch_pause < 0:
            raise ValueError('Invalid maintenance limits')
        self.storage, self.interval_seconds = storage, interval_seconds
        self.batch_size, self.max_batches = batch_size, max_batches
        self.batch_pause, self.max_run_seconds = batch_pause, max_run_seconds
        self.outbox_retention_hours = int(os.environ.get('INSIEDR_OUTBOX_RETENTION_HOURS', '24'))
        if self.outbox_retention_hours < 1:
            raise ValueError('Outbox retention must be positive')
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, name='insiedr-maintenance', daemon=True)
        self._thread.start()

    def stop(self, timeout=5):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def is_running(self):
        return bool(self._thread and self._thread.is_alive())

    def _loop(self):
        while not self._stop.wait(60):
            try:
                self.run_once()
            except Exception:
                log.exception('Maintenance failed; inspect maintenance_runs and retry after repair')

    def run_once(self, force=False):
        details = {'deleted': {}, 'dropped': [], 'deferred_partitions': [], 'errors': []}
        began = time.monotonic()

        def expired():
            return self._stop.is_set() or time.monotonic() - began >= self.max_run_seconds

        with self.storage.connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT pg_try_advisory_lock(%s)', (LOCK_ID,))
                acquired = cur.fetchone()[0]
            conn.commit()
            if not acquired:
                return {'status': 'busy'}
            try:
                with conn.cursor() as cur:
                    cur.execute('''SELECT finished_at > NOW() - %s * INTERVAL '1 second'
                        FROM maintenance_runs WHERE name = 'retention' ''', (self.interval_seconds,))
                    recent = cur.fetchone()
                    if not force and recent and recent[0]:
                        conn.commit()
                        return {'status': 'not_due'}
                    cur.execute('''INSERT INTO maintenance_runs(name, started_at, status)
                        VALUES ('retention', NOW(), 'running') ON CONFLICT (name)
                        DO UPDATE SET started_at = NOW(), status = 'running' ''')
                conn.commit()
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(days=config.payload_retention_days)
                feature_cutoff = now - timedelta(days=config.feature_retention_days)
                for parent, column in PARENTS.items():
                    for schema, child, bound in partitions(conn, parent):
                        if expired():
                            break
                        upper = partition_end(bound)
                        if upper and upper <= cutoff:
                            try:
                                with conn.cursor() as cur:
                                    _limits(cur)
                                    cur.execute(sql.SQL('DROP TABLE {}').format(sql.Identifier(schema, child)))
                                conn.commit()
                                details['dropped'].append(child)
                            except Exception as exc:
                                conn.rollback()
                                details['errors'].append(f'drop {child}: {type(exc).__name__}')
                    monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
                    for i in range(5):
                        if expired():
                            break
                        start = monday + timedelta(weeks=i)
                        try:
                            if not create_partition(conn, parent, column, start, self.batch_size):
                                details['deferred_partitions'].append(f'{parent}:{start.date()}')
                        except Exception as exc:
                            details['errors'].append(f'partition {parent}: {type(exc).__name__}')
                # Includes DEFAULT, old_data and the partial week at the cutoff.
                tables = [(p, c, cutoff) for p, c in PARENTS.items()]
                tables += [(t, 'created_at', cutoff) for t in ('model_outputs', 'anomalies', 'risk_events')]
                tables += [('normalized_features', 'created_at', feature_cutoff)]
                # Round-robin to prevent one large backlog starving other tables.
                active = list(tables)
                for _ in range(self.max_batches):
                    cycle_deleted = 0
                    next_active = []
                    for table, column, threshold in active:
                        if expired():
                            next_active.extend(item for item in active if item not in next_active)
                            break
                        try:
                            count = delete_batch(conn, table, column, threshold, self.batch_size)
                            cycle_deleted += count
                            details['deleted'][table] = details['deleted'].get(table, 0) + count
                        except Exception as exc:
                            conn.rollback()
                            details['errors'].append(f'delete {table}: {type(exc).__name__}')
                            count = 0
                        if count:
                            self._stop.wait(self.batch_pause)
                        if count == self.batch_size:
                            next_active.append((table, column, threshold))
                    active = next_active
                    if expired():
                        break
                    purged = OutboxRepository(self.storage).purge(
                        retention_hours=self.outbox_retention_hours, batch_size=self.batch_size)
                    details['deleted']['completed_outbox'] = details['deleted'].get('completed_outbox', 0) + purged
                    if cycle_deleted + purged == 0:
                        break
                details['time_budget_exhausted'] = expired()
                details['tables_with_backlog'] = [t for t, _, _ in active]
                status = 'degraded' if details['errors'] or details['deferred_partitions'] or expired() or active else 'ok'
                with conn.cursor() as cur:
                    cur.execute('''UPDATE maintenance_runs SET finished_at = NOW(), status = %s,
                        details_json = %s WHERE name = 'retention' ''', (status, Json(details)))
                conn.commit()
                log.log(logging.WARNING if status != 'ok' else logging.INFO, 'Retention %s: %s', status, details)
                return {'status': status, **details}
            except Exception as exc:
                conn.rollback()
                with conn.cursor() as cur:
                    cur.execute('''UPDATE maintenance_runs SET finished_at = NOW(), status = 'failed',
                        details_json = %s WHERE name = 'retention' ''',
                        (Json({'error': type(exc).__name__}),))
                conn.commit()
                raise
            finally:
                conn.rollback()
                with conn.cursor() as cur:
                    cur.execute('SELECT pg_advisory_unlock(%s)', (LOCK_ID,))
                conn.commit()
