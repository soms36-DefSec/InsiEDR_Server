"""Opt-in PostgreSQL validation in a uniquely named, disposable test schema.

Set INSIEDR_TEST_POSTGRES_DSN to a TEST database. The default suite skips these
checks instead of treating SQLite/mocks as evidence of PostgreSQL performance.
"""
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import psycopg2
from psycopg2 import sql
from psycopg2.errors import LockNotAvailable, QueryCanceled
import pytest

from server.storage.postgres_storage import PostgresStorage
from server.storage.migration_runner import run_sql_script


@pytest.fixture(scope='module')
def live_pg():
    dsn = os.environ.get('INSIEDR_TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('INSIEDR_TEST_POSTGRES_DSN is required for real PostgreSQL validation')
    schema = 'insiedr_audit_' + uuid.uuid4().hex
    admin = psycopg2.connect(dsn, connect_timeout=5)
    admin.autocommit = True
    storage = None
    try:
        with admin.cursor() as cur:
            cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        storage = PostgresStorage(dsn, minconn=2, maxconn=4)
        checkout = storage.connection

        @contextmanager
        def isolated():
            with checkout() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql.SQL('SET search_path TO {}, public').format(sql.Identifier(schema)))
                yield conn

        storage.connection = isolated
        migrations = Path(__file__).parents[1] / 'server/storage/migrations'
        with storage.connection() as conn:
            run_sql_script(conn, (migrations / '001_initial_schema.sql').read_text())
            run_sql_script(conn, (migrations / '013_dashboard_indexes_pg.sql').read_text())
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO agents(agent_id, hostname, last_seen_at)
                    SELECT i::text, 'HOST-' || i, NOW() - (i % 600) * INTERVAL '1 second'
                    FROM generate_series(1, 5000) i""")
                cur.execute("""INSERT INTO raw_payloads(payload_id, agent_id, username)
                    SELECT i::text, ((i % 5000) + 1)::text, 'analyst'
                    FROM generate_series(1, 50000) i""")
                cur.execute("""INSERT INTO collector_results(payload_id, agent_id, hostname, collector,
                    collector_collected_at, status, payload_json)
                    SELECT i::text, ((i % 5000) + 1)::text, 'HOST-' || ((i % 5000) + 1),
                    'file-collector', NOW() - i * INTERVAL '1 second', 'success', '{"count": 1}'::jsonb
                    FROM generate_series(1, 50000) i""")
                cur.execute('ANALYZE agents; ANALYZE collector_results; ANALYZE raw_payloads')
            conn.commit()
        yield storage
    finally:
        if storage:
            storage.close()
        # Only the schema created above is removed; no existing application tables.
        with admin.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        admin.close()


def test_real_rollback_timeout_and_reuse(live_pg):
    with live_pg.connection() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO agents(agent_id) VALUES ('uncommitted')")
    with live_pg.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM agents WHERE agent_id = 'uncommitted'")
        assert cur.fetchone()[0] == 0
    with pytest.raises(QueryCanceled):
        with live_pg.connection() as conn, conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '50ms'")
            cur.execute('SELECT pg_sleep(1)')
    with live_pg.connection() as conn, conn.cursor() as cur:
        cur.execute('SELECT 1')
        assert cur.fetchone()[0] == 1


def test_real_lock_wait_is_bounded_and_pool_recovers(live_pg):
    with live_pg.connection() as owner, owner.cursor() as cur:
        cur.execute("UPDATE agents SET status = 'active' WHERE agent_id = '1'")
        with pytest.raises(LockNotAvailable):
            with live_pg.connection() as waiter, waiter.cursor() as waiting:
                waiting.execute("SET LOCAL lock_timeout = '50ms'")
                waiting.execute("UPDATE agents SET status = 'offline' WHERE agent_id = '1'")
    assert live_pg.get_pc_status()['total_pcs'] == 5000


def test_real_concurrency_and_query_latency(live_pg):
    def query(_):
        start = time.perf_counter()
        page = live_pg.get_telemetry_page(limit=50, include_enrichment=False)
        assert page['total'] == 50000 and len(page['logs']) == 50
        return (time.perf_counter() - start) * 1000
    with ThreadPoolExecutor(max_workers=24) as workers:
        timings = sorted(workers.map(query, range(120)))
    fleet = []
    for _ in range(20):
        start = time.perf_counter()
        assert live_pg.get_pc_status()['total_pcs'] == 5000
        fleet.append((time.perf_counter() - start) * 1000)
    fleet.sort()
    print(f'PostgreSQL 24 clients/50k rows: page p50={timings[60]:.2f}ms p95={timings[114]:.2f}ms; '
          f'5k-host fleet p50={fleet[10]:.2f}ms p95={fleet[19]:.2f}ms')
    assert live_pg._pool_slots._value == 4
