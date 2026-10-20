"""Restartable PostgreSQL chunk archival; never delete an unverified source day."""
from __future__ import annotations

from contextlib import closing
from datetime import timedelta
import hashlib
import json
import threading
import zlib

from server.storage.ingest_journal import canonical
from server.storage.ram_telemetry import matches, utc


class PostgresArchive:
    def __init__(self, pg, *, chunk_rows=1000, chunk_bytes=4*1024**2,
                 query_bytes=32*1024**2, query_chunks=128):
        self.pg = pg
        self.chunk_rows, self.chunk_bytes = chunk_rows, chunk_bytes
        self.query_bytes, self.query_chunks = query_bytes, query_chunks
        self._lock = threading.Lock()

    def ensure_schema(self):
        with self.pg.connection() as conn, closing(conn.cursor()) as cur:
            if getattr(self.pg,'_is_sqlite',None) is False:
                for setting in ('fsync','synchronous_commit'):
                    cur.execute('SHOW '+setting)
                    if cur.fetchone()[0]!='on':
                        raise RuntimeError(f'archive requires PostgreSQL {setting}=on')
            cur.execute('''CREATE TABLE IF NOT EXISTS telemetry_archive_days (
              day TEXT PRIMARY KEY, state TEXT NOT NULL, record_count BIGINT NOT NULL,
              checksum TEXT NOT NULL)''')
            cur.execute('''CREATE TABLE IF NOT EXISTS telemetry_archive_chunks (
              day TEXT NOT NULL, ordinal INTEGER NOT NULL, first_id TEXT NOT NULL,
              last_id TEXT NOT NULL, min_collected TEXT NOT NULL, max_collected TEXT NOT NULL,
              record_count INTEGER NOT NULL, plain_bytes INTEGER NOT NULL,
              checksum TEXT NOT NULL, data BYTEA NOT NULL,
              last_time TEXT NOT NULL, cursor_id TEXT NOT NULL, verified INTEGER NOT NULL,
              PRIMARY KEY(day,ordinal))''')
            cur.execute('''CREATE INDEX IF NOT EXISTS telemetry_archive_time
                           ON telemetry_archive_chunks(min_collected,max_collected)''')
            cur.execute('''CREATE INDEX IF NOT EXISTS telemetry_archive_ids
                           ON telemetry_archive_chunks(first_id,last_id)''')
            cur.execute('''CREATE TABLE IF NOT EXISTS telemetry_archive_latest (
                agent_id TEXT NOT NULL,collector TEXT NOT NULL,collected_at TEXT NOT NULL,
                event_id TEXT NOT NULL,username TEXT NOT NULL,day TEXT NOT NULL,
                PRIMARY KEY(agent_id,collector))''')
            cur.execute('CREATE INDEX IF NOT EXISTS telemetry_archive_latest_user ON telemetry_archive_latest(username)')
            cur.execute('''CREATE TABLE IF NOT EXISTS telemetry_archive_totals (
                day TEXT NOT NULL,collector TEXT NOT NULL,status TEXT NOT NULL,record_count BIGINT NOT NULL,
                PRIMARY KEY(day,collector,status))''')
            conn.commit()

    def _write_chunk(self, day, ordinal, rows):
        plain = canonical(rows)
        if len(plain) > self.chunk_bytes:
            raise ValueError('archive chunk exceeds configured byte cap')
        values = (day, ordinal, min(r['id'] for r in rows), max(r['id'] for r in rows),
                  min(r['collected_at'] for r in rows), max(r['collected_at'] for r in rows),
                  len(rows), len(plain), hashlib.sha256(plain).hexdigest(), zlib.compress(plain, 3),
                  rows[-1]['collected_at'],rows[-1]['id'],0)
        with self.pg.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute('''INSERT INTO telemetry_archive_chunks
                (day,ordinal,first_id,last_id,min_collected,max_collected,record_count,plain_bytes,checksum,data,last_time,cursor_id,verified)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(day,ordinal) DO UPDATE SET
                first_id=EXCLUDED.first_id,last_id=EXCLUDED.last_id,
                min_collected=EXCLUDED.min_collected,max_collected=EXCLUDED.max_collected,
                record_count=EXCLUDED.record_count,plain_bytes=EXCLUDED.plain_bytes,
                checksum=EXCLUDED.checksum,data=EXCLUDED.data,last_time=EXCLUDED.last_time,
                cursor_id=EXCLUDED.cursor_id,verified=0''', values)
            conn.commit()
            cur.execute('''SELECT checksum,record_count,plain_bytes,data FROM telemetry_archive_chunks
                           WHERE day=%s AND ordinal=%s''',(day,ordinal))
            item=cur.fetchone()
            self._decode(*item)
            cur.execute('UPDATE telemetry_archive_chunks SET verified=1 WHERE day=%s AND ordinal=%s',(day,ordinal))
            conn.commit()

    def _decode(self, checksum, count, size, data):
        if size > self.chunk_bytes:
            raise ValueError('stored archive chunk exceeds decompression budget')
        decoder = zlib.decompressobj()
        plain = decoder.decompress(bytes(data), size+1)
        if (len(plain) != size or not decoder.eof or decoder.unused_data
                or hashlib.sha256(plain).hexdigest() != checksum):
            raise RuntimeError('archive checksum, size or compression verification failed')
        rows = json.loads(plain)
        if len(rows) != count:
            raise RuntimeError('archive count verification failed')
        return rows

    def archive_day(self, source, day, *, continue_work=lambda: True):
        """Caller must seal the received-day against replay/new writes before calling.

        Rebuilding the same immutable day after a crash is idempotent. PostgreSQL
        commit and readback verification precede the source DROP, even on retries.
        """
        with self._lock:
            # Set building before touching chunks. Query readers include building
            # chunks and deduplicate against source; source cannot be dropped yet.
            with self.pg.connection() as conn, closing(conn.cursor()) as cur:
                cur.execute('''INSERT INTO telemetry_archive_days VALUES (%s,'building',0,'')
                    ON CONFLICT(day) DO UPDATE SET state='building' ''', (day,))
                conn.commit()
            after, ordinal, count = '', 0, 0
            exported = hashlib.sha256()
            # Chunk readback verification is itself durably checkpointed. A
            # metadata hash chain resumes without repeatedly decompressing an
            # already copied multi-GB prefix on every 20-second work slice.
            with self.pg.connection() as conn,closing(conn.cursor()) as cur:
                cur.execute('''SELECT ordinal,checksum,record_count,last_time,cursor_id,verified
                    FROM telemetry_archive_chunks WHERE day=%s ORDER BY ordinal LIMIT 100001''',(day,))
                saved=cur.fetchall()
            if len(saved)>100000:
                raise ValueError('archive day exceeds chunk manifest budget')
            for index,checksum,records,last_time,cursor_id,verified in saved:
                if index!=ordinal or not verified:
                    # An interrupted chunk is overwritten from its predecessor.
                    break
                if len(checksum)!=64:
                    raise RuntimeError('archive checksum verification failed')
                exported.update(canonical([ordinal,checksum,records]))
                count+=records
                after=(last_time,cursor_id)
                ordinal+=1
            while True:
                if not continue_work():
                    return False
                page_size=self.chunk_rows
                while True:
                    try:
                        rows = source.partition_rows(day, after, page_size)
                        break
                    except Exception as exc:
                        if page_size<=1 or not any(s in str(exc).lower() for s in ('limit','result','memory')):
                            raise
                        page_size=max(1,page_size//2)
                if not rows:
                    break
                # Split by bytes as well as rows; never buffer a whole hour/day.
                chunk = []
                for row in rows:
                    if len(canonical([row])) > self.chunk_bytes:
                        raise ValueError('one archive event exceeds chunk byte cap')
                    if chunk and len(canonical(chunk+[row])) > self.chunk_bytes:
                        self._write_chunk(day, ordinal, chunk)
                        exported.update(canonical([ordinal,hashlib.sha256(canonical(chunk)).hexdigest(),len(chunk)]))
                        ordinal += 1
                        chunk = []
                    chunk.append(row)
                    count += 1
                if chunk:
                    self._write_chunk(day, ordinal, chunk)
                    exported.update(canonical([ordinal,hashlib.sha256(canonical(chunk)).hexdigest(),len(chunk)]))
                    ordinal += 1
                after = (rows[-1]['collected_at'],rows[-1]['id'])
            if not count:
                # A retry after successful DROP must preserve the existing verified
                # archive, rather than replacing its manifest with an empty day.
                raise RuntimeError('source day empty; refusing archive replacement')
            restored, restored_count = hashlib.sha256(), 0
            with self.pg.connection() as conn, closing(conn.cursor()) as cur:
                cur.execute('DELETE FROM telemetry_archive_chunks WHERE day=%s AND ordinal>=%s', (day,ordinal))
                cur.execute('''SELECT ordinal,checksum,record_count,verified FROM telemetry_archive_chunks
                               WHERE day=%s ORDER BY ordinal LIMIT 100001''',(day,))
                metadata=cur.fetchall()
                if len(metadata)!=ordinal:
                    raise RuntimeError('archive manifest chunk count verification failed')
                for index,checksum,records,verified in metadata:
                    if not verified:
                        raise RuntimeError('unverified archive chunk; source retained')
                    restored.update(canonical([index,checksum,records]))
                    restored_count+=records
                if (restored_count != count or restored.hexdigest() != exported.hexdigest()
                        or source.count_day(day)!=count):
                    raise RuntimeError('archive day reconciliation failed; source retained')
                cur.execute('''UPDATE telemetry_archive_days SET state='verified',record_count=%s,
                               checksum=%s WHERE day=%s''', (count, restored.hexdigest(), day))
                conn.commit()
            # Recheck cancellation immediately before the only destructive operation.
            if not continue_work():
                return False
            states=source.state_index(day)
            from datetime import datetime,timezone
            summary=source.aggregate({'received_day':day},datetime.now(timezone.utc).isoformat())
            if sum(r['count'] for r in summary)!=count:
                raise RuntimeError('archive summary reconciliation failed; source retained')
            with self.pg.connection() as conn,closing(conn.cursor()) as cur:
                cur.execute('DELETE FROM telemetry_archive_totals WHERE day=%s',(day,))
                for group in summary:
                    cur.execute('INSERT INTO telemetry_archive_totals VALUES (%s,%s,%s,%s)',
                                (day,group['collector'],group['status'],group['count']))
                for state in states:
                    cur.execute('''INSERT INTO telemetry_archive_latest
                        (agent_id,collector,collected_at,event_id,username,day) VALUES (%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(agent_id,collector) DO UPDATE SET
                        collected_at=EXCLUDED.collected_at,event_id=EXCLUDED.event_id,
                        username=EXCLUDED.username,day=EXCLUDED.day
                        WHERE (EXCLUDED.collected_at,EXCLUDED.event_id)>
                              (telemetry_archive_latest.collected_at,telemetry_archive_latest.event_id)''',
                        (state['agent_id'],state['collector'],state['collected_at'],state['id'],state['username'],day))
                conn.commit()
            source.drop_day(day)
            return True

    def query(self, filters, snapshot, limit):
        clauses, params = ['min_collected<=%s', 'max_collected>=%s'], [
            utc(filters['end_time']).isoformat(timespec='milliseconds'),
            utc(filters['start_time']).isoformat(timespec='milliseconds')]
        if filters.get('event_id'):
            clauses += ['first_id<=%s','last_id>=%s']
            params += [filters['event_id'],filters['event_id']]
        if filters.get('received_day'):
            clauses.append('day=%s')
            params.append(filters['received_day'])
        if filters.get('exclude_days'):
            clauses.append('day NOT IN ('+','.join(['%s']*len(filters['exclude_days']))+')')
            params+=list(filters['exclude_days'])
        rows, size = [], 0
        with self.pg.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute('''SELECT day,ordinal,checksum,record_count,plain_bytes FROM telemetry_archive_chunks WHERE '''+
                        ' AND '.join(clauses)+' ORDER BY day,ordinal LIMIT %s', tuple(params+[self.query_chunks+1]))
            metadata = cur.fetchall()
            size = sum(item[4] for item in metadata)
            if len(metadata)>self.query_chunks or size>self.query_bytes:
                raise ValueError('archive query exceeds byte/chunk budget; narrow time range')
            for day, ordinal, checksum, count, plain_size in metadata:
                cur.execute('SELECT data FROM telemetry_archive_chunks WHERE day=%s AND ordinal=%s',(day,ordinal))
                item = cur.fetchone()
                if item is None:
                    raise RuntimeError('archive chunk disappeared during query')
                rows.extend(r for r in self._decode(checksum,count,plain_size,item[0]) if matches(r, filters, snapshot))
                # Keep memory bounded while scanning every eligible chunk for correctness.
                rows = sorted({r['id']:r for r in rows}.values(),
                              key=lambda r:(r['collected_at'],r['id']), reverse=True)[:limit]
        return rows

    def totals(self,exclude_days=(),filters=None):
        filters=filters or {}
        clauses,params=[],[]
        if exclude_days:
            clauses.append('day NOT IN ('+','.join(['%s']*len(exclude_days))+')')
            params+=list(exclude_days)
        for field in ('collector','status'):
            if filters.get(field):
                clauses.append(field+'=%s')
                params.append(filters[field])
        if any(filters.get(f) for f in ('agent_id','hostname','username','search','payload_id','event_id')):
            raise ValueError('filtered archive counts require explicit time bounds')
        with self.pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('SELECT collector,status,SUM(record_count) FROM telemetry_archive_totals'+
                        (' WHERE '+' AND '.join(clauses) if clauses else '')+' GROUP BY collector,status',tuple(params))
            return [dict(collector=c,status=s,bucket=0,count=int(n)) for c,s,n in cur.fetchall()]

    def retained_days(self):
        with self.pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('SELECT DISTINCT day FROM telemetry_archive_chunks')
            return [r[0] for r in cur.fetchall()]

    def latest(self,agent_id=None,username=None):
        clauses,params=[],[]
        for name,value in (('agent_id',agent_id),('username',username)):
            if value:
                clauses.append(name+'=%s')
                params.append(value)
        with self.pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('SELECT event_id,collected_at FROM telemetry_archive_latest'+
                        (' WHERE '+' AND '.join(clauses) if clauses else '')+' LIMIT 1001',tuple(params))
            states=cur.fetchall()
        if len(states)>1000:
            raise ValueError('collector state query exceeds budget; specify an agent')
        rows=[]
        from datetime import datetime,timezone
        snapshot=datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        for event_id,at in states:
            rows+=self.query(dict(event_id=event_id,start_time=at,end_time=at),snapshot,1)
        return rows

    def expire(self, cutoff):
        # Only days wholly outside retention, only after verified archival.
        day = utc(cutoff).date().isoformat()
        with self.pg.connection() as conn, closing(conn.cursor()) as cur:
            cur.execute("SELECT day FROM telemetry_archive_days WHERE day<%s AND state='verified' ORDER BY day LIMIT 1", (day,))
            item = cur.fetchone()
            if item:
                cur.execute('DELETE FROM telemetry_archive_chunks WHERE day=%s', (item[0],))
                cur.execute('DELETE FROM telemetry_archive_latest WHERE day=%s',(item[0],))
                cur.execute('DELETE FROM telemetry_archive_totals WHERE day=%s',(item[0],))
                cur.execute('DELETE FROM telemetry_archive_days WHERE day=%s', (item[0],))
            conn.commit()
