"""Real PostgreSQL lease/retention checks, isolated from application schemas.

Requires INSIEDR_TEST_POSTGRES_DSN. A skip is not evidence of correctness on PG.
"""
import os
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
from psycopg2 import sql
import pytest

from server.storage.postgres_storage import PostgresStorage
from server.storage.migration_runner import run_sql_script
from server.storage.outbox import OutboxRepository
from server.storage.maintenance import create_partition, delete_batch


@pytest.fixture
def pg():
    dsn = os.environ.get('INSIEDR_TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('INSIEDR_TEST_POSTGRES_DSN not configured')
    schema = 'insiedr_reliability_' + uuid.uuid4().hex
    admin = psycopg2.connect(dsn, connect_timeout=5)
    admin.autocommit = True
    storage = None
    try:
        with admin.cursor() as cur:
            cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        storage = PostgresStorage(dsn, minconn=1, maxconn=4)
        checkout = storage.connection
        @contextmanager
        def isolated():
            with checkout() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
                yield conn
        storage.connection = isolated
        with storage.connection() as conn, conn.cursor() as cur:
            cur.execute('''CREATE TABLE clickhouse_outbox (
                outbox_id BIGSERIAL PRIMARY KEY, target_table TEXT NOT NULL,
                record_json JSONB NOT NULL, status TEXT DEFAULT 'pending', attempts INT DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT NOW(), processed_at TIMESTAMPTZ, last_error TEXT)''')
            migration = Path(__file__).parents[1] / 'server/storage/migrations/014_outbox_leases_pg.sql'
            run_sql_script(conn, migration.read_text())
            cur.execute('''CREATE TABLE raw_payloads (id INT, received_at TIMESTAMPTZ)
                PARTITION BY RANGE(received_at)''')
            cur.execute('CREATE TABLE raw_payloads_default PARTITION OF raw_payloads DEFAULT')
            conn.commit()
        yield storage
    finally:
        if storage:
            storage.close()
        with admin.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        admin.close()


def seed(pg, count):
    with pg.connection() as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO clickhouse_outbox(target_table, record_json)
            SELECT 'raw_payloads', jsonb_build_object('id', i) FROM generate_series(1, %s) i""", (count,))
        conn.commit()


def test_concurrent_claims_remain_exclusive_after_commit(pg):
    seed(pg, 20)
    repo = OutboxRepository(pg)
    with ThreadPoolExecutor(max_workers=2) as pool:
        batches = list(pool.map(lambda token: repo.claim(token, 10), ('one', 'two')))
    first, second = [{r['outbox_id'] for r in b} for b in batches]
    assert len(first) == len(second) == 10 and first.isdisjoint(second)
    assert repo.claim('third', 10) == []


def test_crash_expiry_and_stale_completion_fencing(pg):
    seed(pg, 1)
    repo = OutboxRepository(pg)
    ids = [r['outbox_id'] for r in repo.claim('old')]
    with pg.connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE clickhouse_outbox SET lease_expires_at = NOW() - INTERVAL '1 second'")
        conn.commit()
    assert repo.renew('old', 120) == 0
    assert len(repo.claim('new')) == 1
    assert repo.complete('old', ids) == 0
    repo.release('old', 'late failure', 1)
    assert repo.complete('new', ids) == 1


def test_failure_backoff_and_purge_preserve_pending(pg):
    seed(pg, 3)
    repo = OutboxRepository(pg)
    claimed = repo.claim('failed', 1)
    repo.release('failed', 'offline', 300)
    others = repo.claim('ok', 10)
    assert len(others) == 2
    assert claimed[0]['outbox_id'] not in [r['outbox_id'] for r in others]
    repo.complete('ok', [r['outbox_id'] for r in others])
    with pg.connection() as conn, conn.cursor() as cur:
        cur.execute("UPDATE clickhouse_outbox SET processed_at = NOW() - INTERVAL '2 days' WHERE status = 'completed'")
        conn.commit()
    assert repo.purge(24, 1) == 1
    assert repo.purge(24, 1) == 1
    assert repo.metrics()['pending']['count'] == 1


def test_default_partition_moves_are_atomic_and_bounded(pg):
    start = datetime(2026, 1, 5, tzinfo=timezone.utc)
    with pg.connection() as conn, conn.cursor() as cur:
        cur.executemany('INSERT INTO raw_payloads VALUES (%s, %s)', [(1, start), (2, start)])
        conn.commit()
        assert not create_partition(conn, 'raw_payloads', 'received_at', start, move_limit=1)
        cur.execute('SELECT COUNT(*) FROM raw_payloads_default')
        assert cur.fetchone()[0] == 2
        conn.commit()
        assert create_partition(conn, 'raw_payloads', 'received_at', start, move_limit=2)
        cur.execute('SELECT COUNT(*) FROM raw_payloads')
        assert cur.fetchone()[0] == 2
        cur.execute('SELECT COUNT(*) FROM raw_payloads_default')
        assert cur.fetchone()[0] == 0


def test_chunked_retention_is_partition_safe_and_commits(pg):
    now = datetime.now(timezone.utc)
    with pg.connection() as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE raw_payloads_old PARTITION OF raw_payloads FOR VALUES FROM (MINVALUE) TO ('2025-01-01')")
        cur.executemany('INSERT INTO raw_payloads VALUES (%s, %s)',
            [(1, datetime(2024, 1, 1, tzinfo=timezone.utc)), (2, now - timedelta(days=2)), (3, now)])
        conn.commit()
        assert delete_batch(conn, 'raw_payloads', 'received_at', now - timedelta(days=1), 1) == 1
        conn.rollback()  # A later failure cannot undo earlier committed work.
    with pg.connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT id FROM raw_payloads ORDER BY id')
        assert cur.fetchall() == [(2,), (3,)]
