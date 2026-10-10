"""PostgreSQL outbox claims. No database transaction spans a network insert."""
from __future__ import annotations

from contextlib import closing


class OutboxRepository:
    def __init__(self, storage):
        self.storage = storage

    def claim(self, token, limit=500, lease_seconds=120, max_bytes=8 * 1024 * 1024):
        if limit < 1 or lease_seconds < 1 or max_bytes < 1:
            raise ValueError('Outbox limits must be positive')
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            # Lock a bounded candidate set, then bound the JSON returned to Python.
            # Always admit one oversized envelope so it cannot starve the queue.
            cur.execute("""
                WITH candidates AS MATERIALIZED (
                    SELECT outbox_id, octet_length(record_json::text) AS bytes
                    FROM clickhouse_outbox
                    WHERE (status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= NOW()))
                       OR (status = 'processing' AND lease_expires_at <= NOW())
                    ORDER BY outbox_id LIMIT %s FOR UPDATE SKIP LOCKED
                ), bounded AS (
                    SELECT outbox_id, SUM(bytes) OVER (ORDER BY outbox_id) AS total_bytes,
                           ROW_NUMBER() OVER (ORDER BY outbox_id) AS position
                    FROM candidates
                )
                UPDATE clickhouse_outbox o
                SET status = 'processing', claim_token = %s,
                    lease_expires_at = NOW() + %s * INTERVAL '1 second',
                    attempts = COALESCE(o.attempts, 0) + 1
                FROM bounded b WHERE o.outbox_id = b.outbox_id
                    AND (b.total_bytes <= %s OR b.position = 1)
                RETURNING o.outbox_id, o.target_table, o.record_json, o.created_at, o.attempts
                """, (limit, token, lease_seconds, max_bytes))
            names = [c[0] for c in cur.description]
            records = [dict(zip(names, row)) for row in cur.fetchall()]
            conn.commit()
            return sorted(records, key=lambda r: r['outbox_id'])

    def renew(self, token, lease_seconds):
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute("""UPDATE clickhouse_outbox
                SET lease_expires_at = NOW() + %s * INTERVAL '1 second'
                WHERE claim_token = %s AND status = 'processing' AND lease_expires_at > NOW()
                """, (lease_seconds, token))
            count = cur.rowcount
            conn.commit()
            return count

    def complete(self, token, ids):
        if not ids:
            return 0
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute("""UPDATE clickhouse_outbox SET status = 'completed', processed_at = NOW(),
                claim_token = NULL, lease_expires_at = NULL, last_error = NULL
                WHERE claim_token = %s AND outbox_id = ANY(%s) AND status = 'processing'
                    AND lease_expires_at > NOW()""", (token, ids))
            count = cur.rowcount
            conn.commit()
            return count

    def quarantine(self, token, ids, error):
        """Move permanently failed or poison records to clickhouse_outbox_quarantine (I09)."""
        if not ids:
            return 0
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            try:
                cur.execute("""
                    INSERT INTO clickhouse_outbox_quarantine (outbox_id, target_table, record_json, error_reason, attempts)
                    SELECT outbox_id, target_table, record_json, %s, attempts
                    FROM clickhouse_outbox
                    WHERE claim_token = %s AND outbox_id = ANY(%s) AND status = 'processing'
                """, (str(error)[:1000], token, ids))
            except Exception:
                pass
            cur.execute("""UPDATE clickhouse_outbox SET status = 'quarantined', processed_at = NOW(),
                claim_token = NULL, lease_expires_at = NULL, last_error = %s
                WHERE claim_token = %s AND outbox_id = ANY(%s) AND status = 'processing'""",
                (str(error)[:500], token, ids))
            count = cur.rowcount
            conn.commit()
            return count

    def release(self, token, error, delay_seconds):
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute("""UPDATE clickhouse_outbox SET status = 'pending', claim_token = NULL,
                lease_expires_at = NULL, last_error = %s,
                next_attempt_at = NOW() + %s * INTERVAL '1 second'
                WHERE claim_token = %s AND status = 'processing'""",
                (str(error)[:500], delay_seconds, token))
            conn.commit()

    def purge(self, retention_hours=24, batch_size=5000):
        if retention_hours < 1 or batch_size < 1:
            raise ValueError('Outbox retention and batch size must be positive')
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute("""WITH expired AS (
                SELECT outbox_id FROM clickhouse_outbox WHERE status = 'completed'
                    AND processed_at < NOW() - %s * INTERVAL '1 hour'
                ORDER BY processed_at, outbox_id LIMIT %s FOR UPDATE SKIP LOCKED
                ) DELETE FROM clickhouse_outbox o USING expired e
                  WHERE o.outbox_id = e.outbox_id""", (retention_hours, batch_size))
            count = cur.rowcount
            conn.commit()
            return count

    def metrics(self):
        with self.storage.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute("""SELECT status, COUNT(*),
                EXTRACT(EPOCH FROM (NOW() - MIN(created_at))), MAX(attempts)
                FROM clickhouse_outbox WHERE status <> 'completed' GROUP BY status""")
            return {s: {'count': n, 'oldest_age_seconds': float(age or 0), 'max_attempts': tries}
                    for s, n, age, tries in cur.fetchall()}
