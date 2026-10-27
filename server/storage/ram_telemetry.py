"""Opt-in server telemetry plane. Legacy operational repositories remain delegated.

One process owns the journal; CPU-heavy ClickHouse operations have bounded threads.
Redis is entirely expendable. Only successful FULL journal commits produce ACKs.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
import queue
import threading
import time
import uuid

from server.storage.ingest_journal import IngestJournal, canonical, digest
from server.storage.interceptors import interceptor_pipeline
from server.storage.storage_pressure import PressureController, POLICY, Level

log = logging.getLogger(__name__)
TABLE = 'server_telemetry_v3'
COLUMNS = ('id', 'payload_id', 'agent_id', 'collector', 'collected_at', 'received_at',
           'hostname', 'username', 'status', 'payload_json', 'summary_preview',
           'features_json', 'error_type', 'error_message', 'source_quality', 'accepted_seq')


def utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def project(payload, received_at, store_plaintext, accepted_seq=0):
    """One canonical event copy; deterministic IDs survive regrouped retries."""
    from server.storage.clickhouse_telemetry_queries import extract_summary_preview
    from server.storage.postgres_storage import PostgresStorage
    counts, rows = {}, []
    for collector in payload.get('collectors', []):
        name = collector['collector']
        ordinal = counts.get(name, 0)
        counts[name] = ordinal + 1
        eid = str(uuid.uuid5(uuid.NAMESPACE_OID, f"{payload['payload_id']}:col:{name}" +
                             (f':{ordinal}' if ordinal else '')))
        body = collector.get('payload', {}) if store_plaintext else {'_redacted': True}
        metrics = collector.get('payload')
        quality = (PostgresStorage._collector_source_quality(collector) if isinstance(metrics,dict)
                   else 'unknown' if collector['status']=='success' else 'low')
        # Store each observed value once. Repeated per-feature agent/host metadata
        # is reconstructed on read rather than serialized for every metric.
        features = ({k:v for k,v in metrics.items() if v is not None}
                    if isinstance(metrics,dict) and not store_plaintext else {})
        error = collector.get('error') if isinstance(collector.get('error'),dict) else {}
        rows.append(dict(id=eid, payload_id=str(payload['payload_id']),
                         agent_id=str(payload['agent_id']), collector=name,
                         collected_at=utc(collector.get('collected_at') or payload['collected_at']).isoformat(timespec='milliseconds'),
                         received_at=utc(received_at).isoformat(timespec='milliseconds'),
                         hostname=str(collector.get('hostname') or payload.get('hostname') or ''),
                         username=str(payload.get('username') or ''), status=collector['status'],
                         payload_json=canonical(body).decode(),
                         summary_preview=extract_summary_preview(name, body),
                         features_json=canonical(features).decode(),source_quality=quality,
                         error_type=str(error.get('type') or ''),
                         accepted_seq=accepted_seq,
                         error_message=str(error.get('message') or '') if store_plaintext else ''))
    return rows


class ClickHouseEvents:
    def __init__(self, storage):
        self.storage = storage

    def ensure_schema(self):
        # No TTL: archival verification is the only source-data deletion gate.
        sql = f'''CREATE TABLE IF NOT EXISTS {TABLE} (
          id UUID, payload_id String, agent_id String, collector LowCardinality(String),
          collected_at DateTime64(3,'UTC'), received_at DateTime64(3,'UTC'),
          hostname LowCardinality(String), username LowCardinality(String),
          status LowCardinality(String), payload_json String CODEC(ZSTD(1)),
          summary_preview String CODEC(ZSTD(1)),features_json String CODEC(ZSTD(1)),
          error_type String,error_message String CODEC(ZSTD(1)),
          source_quality LowCardinality(String),accepted_seq UInt64) ENGINE=ReplacingMergeTree
          PARTITION BY toDate(received_at)
          ORDER BY (collected_at,id)
          SETTINGS non_replicated_deduplication_window=10000,
                   fsync_after_insert=1,fsync_part_directory=1'''
        with self.storage._client_lock:
            self.storage._client.command(sql)
            self.storage._client.command(f'ALTER TABLE {TABLE} MODIFY SETTING fsync_after_insert=1,fsync_part_directory=1')
            result=self.storage._client.query(f'''SELECT engine,partition_key,sorting_key,create_table_query
                FROM system.tables WHERE database=currentDatabase() AND name='{TABLE}' ''')
            if not result.result_rows:
                raise RuntimeError('v3 table metadata could not be verified')
            engine,partition,sorting,definition=result.result_rows[0]
            if (engine!='ReplacingMergeTree' or partition!='toDate(received_at)'
                    or sorting.replace(' ','').strip('()')!='collected_at,id' or ' TTL ' in definition.upper()):
                raise RuntimeError('incompatible v3 table schema; migrate explicitly before startup')
            columns=self.storage._client.query(f'''SELECT name FROM system.columns
                WHERE database=currentDatabase() AND table='{TABLE}' ''').result_rows
            if {r[0] for r in columns}!=set(COLUMNS):
                raise RuntimeError('incompatible v3 columns; migrate explicitly before startup')

    def insert(self, rows):
        if not rows:
            return
        # Do not use the legacy in-memory batcher or create duplicate telemetry tables.
        converted = [dict(r, collected_at=utc(r['collected_at']), received_at=utc(r['received_at'])) for r in rows]
        self.storage._raw_batch_insert(TABLE, converted)

    def where(self, filters, snapshot):
        clauses, params = ['received_at <= %(snapshot)s'], {'snapshot': utc(snapshot)}
        if 'snapshot_seq' in filters:
            params['snapshot_seq']=filters['snapshot_seq']
            clauses.append('accepted_seq <= %(snapshot_seq)s')
        for name, op in (('start_time', '>='), ('end_time', '<=')):
            if filters.get(name):
                params[name] = utc(filters[name])
                clauses.append(f'collected_at {op} %({name})s')
        for field in ('collector', 'agent_id', 'hostname', 'username', 'status', 'event_id', 'payload_id'):
            if filters.get(field):
                params[field] = filters[field]
                clauses.append(f"{'id' if field == 'event_id' else field} = " +
                               (f'toUUID(%({field})s)' if field == 'event_id' else f'%({field})s'))
        if filters.get('search'):
            params['search'] = filters['search']
            fields = ['collector', 'hostname', 'username']
            if filters.get('search_scope') == 'payload':
                fields.append('payload_json')
            clauses.append('(' + ' OR '.join(f'positionCaseInsensitiveUTF8({f}, %(search)s)>0' for f in fields) + ')')
        if filters.get('before'):
            params['before_time'], params['before_id'] = utc(filters['before'][0]), filters['before'][1]
            clauses.append('(collected_at,id) < (%(before_time)s,toUUID(%(before_id)s))')
        if filters.get('exclude_ids'):
            params['exclude_ids']=filters['exclude_ids']
            clauses.append('id NOT IN %(exclude_ids)s')
        if filters.get('received_day'):
            params['received_day']=filters['received_day']
            clauses.append('toDate(received_at)=toDate(%(received_day)s)')
        return ' AND '.join(clauses),params

    def query(self, filters, snapshot, limit,*,metadata_only=False):
        where,params=self.where(filters,snapshot)
        params['limit']=limit
        columns=[c for c in COLUMNS if not metadata_only or c not in
                 ('payload_json','features_json','error_message','accepted_seq')]
        result = self.storage._query(f"SELECT DISTINCT {','.join(columns)} FROM {TABLE} WHERE " +
            where + ''' ORDER BY collected_at DESC,id DESC LIMIT %(limit)s
            SETTINGS max_result_bytes=33554432,result_overflow_mode='throw' ''', params)
        return [normalize(dict(zip(result.column_names, row))) for row in result.result_rows]

    def aggregate(self,filters,snapshot,seconds=0):
        where,params=self.where(filters,snapshot)
        bucket=f'intDiv(toUnixTimestamp(collected_at),{int(seconds)})*{int(seconds)}' if seconds else '0'
        result=self.storage._query(f'''SELECT collector,status,{bucket} AS bucket,count() AS count
            FROM {TABLE} FINAL WHERE {where} GROUP BY collector,status,bucket''',params)
        return [dict(zip(('collector','status','bucket','count'),row)) for row in result.result_rows]

    def latest(self,agent_id=None,username=None):
        filters={k:v for k,v in dict(agent_id=agent_id,username=username).items() if v}
        where,params=self.where(filters,datetime.now(timezone.utc).isoformat())
        result=self.storage._query(f'''SELECT {','.join(COLUMNS)} FROM {TABLE}
            WHERE {where} ORDER BY collected_at DESC,id DESC LIMIT 1 BY collector''',params)
        return [normalize(dict(zip(result.column_names,row))) for row in result.result_rows]

    def partition_rows(self, day, after='', limit=1000):
        day = utc(day).date().isoformat()
        params=dict(day=day,limit=limit)
        extra=''
        if after:
            params.update(after_time=utc(after[0]),after_id=after[1])
            extra=' AND (collected_at,id)>(%(after_time)s,toUUID(%(after_id)s))'
        # FINAL is restricted to one sealed day for offline archival. Primary-key
        # cursor order avoids sorting an entire day by random UUID in RAM.
        result = self.storage._query(f'''SELECT {','.join(COLUMNS)} FROM {TABLE} FINAL
            WHERE toDate(received_at)=toDate(%(day)s){extra}
            ORDER BY collected_at,id LIMIT %(limit)s
            SETTINGS max_result_bytes=33554432,result_overflow_mode='throw' ''', params)
        return [normalize(dict(zip(result.column_names, row))) for row in result.result_rows]

    def days_before(self, cutoff):
        result = self.storage._query(f'''SELECT DISTINCT toDate(received_at) FROM {TABLE}
            WHERE received_at < %(cutoff)s ORDER BY 1''', {'cutoff': utc(cutoff)})
        return [r[0].isoformat() for r in result.result_rows]

    def count_day(self,day):
        result=self.storage._query(f'''SELECT count() FROM {TABLE} FINAL
            WHERE toDate(received_at)=toDate(%(day)s)''',{'day':day})
        return int(result.result_rows[0][0])

    def state_index(self,day):
        result=self.storage._query(f'''SELECT agent_id,collector,
            argMax(tuple(collected_at,toString(id),username),(collected_at,id))
            FROM {TABLE} WHERE toDate(received_at)=toDate(%(day)s)
            GROUP BY agent_id,collector SETTINGS max_result_rows=50001,result_overflow_mode='throw' ''',{'day':day})
        if len(result.result_rows)>50000:
            raise ValueError('collector state index exceeds archive budget')
        return [dict(agent_id=a,collector=c,collected_at=utc(v[0]).isoformat(timespec='milliseconds'),
                     id=v[1],username=v[2]) for a,c,v in result.result_rows]

    def pressure_metrics(self):
        result=self.storage._query(f'''SELECT max(parts) FROM (SELECT count() AS parts
            FROM system.parts WHERE database=currentDatabase() AND table='{TABLE}' AND active GROUP BY partition)''')
        maximum=int(result.result_rows[0][0] or 0)
        threshold=self.storage._query("SELECT value FROM system.merge_tree_settings WHERE name='parts_to_delay_insert'").result_rows
        return {'merge_ratio':maximum/max(1,int(threshold[0][0])),'max_parts_per_partition':maximum}

    def drop_day(self, day):
        # Strictly validate before interpolating DDL, whose parameters vary by CH version.
        day = datetime.strptime(day, '%Y-%m-%d').date().isoformat()
        with self.storage._client_lock:
            self.storage._client.command(f"ALTER TABLE {TABLE} DROP PARTITION toDate('{day}')")


def normalize(row):
    row = dict(row)
    row['id'] = str(row['id'])
    for name in ('collected_at', 'received_at'):
        row[name] = utc(row[name]).isoformat(timespec='milliseconds')
    return row


def feature_rows(row):
    from server.storage.postgres_storage import PostgresStorage
    values=json.loads(row['features_json'])
    body=json.loads(row['payload_json'])
    if body != {'_redacted':True}:
        values=body
    payload={k:row[k] for k in ('payload_id','agent_id','hostname','username')}
    payload['collected_at']=row['collected_at']
    if not isinstance(values,dict):
        return
    for name,value in values.items():
        collector=dict(collector=row['collector'],collected_at=row['collected_at'],payload={name:value})
        for f in PostgresStorage._feature_rows(payload,collector,row['source_quality']):
            yield {k:(v.adapted if hasattr(v,'adapted') else v) for k,v in f.items()}


def matches(row, f, snapshot):
    if row['received_at'] > snapshot:
        return False
    if row.get('accepted_seq',0)>f.get('snapshot_seq',float('inf')):
        return False
    if row['id'] in f.get('exclude_ids',()):
        return False
    if f.get('received_day') and row['received_at'][:10]!=f['received_day']:
        return False
    for name, op in (('start_time', lambda a,b: a >= b), ('end_time', lambda a,b: a <= b)):
        if f.get(name) and not op(utc(row['collected_at']), utc(f[name])):
            return False
    if f.get('event_id') and row['id'] != f['event_id']:
        return False
    for key in ('collector', 'agent_id', 'hostname', 'username', 'status', 'payload_id'):
        if f.get(key) and str(row.get(key, '')) != f[key]:
            return False
    if f.get('before') and (row['collected_at'], row['id']) >= tuple(f['before']):
        return False
    if f.get('search'):
        fields = ['hostname', 'username', 'collector']
        if f.get('search_scope') == 'payload':
            fields.append('payload_json')
        if not any(f['search'].casefold() in str(row.get(k, '')).casefold() for k in fields):
            return False
    return True


class RecentRedis:
    """Expendable versioned result cache and bounded replay stream; no acceptance queue."""
    def __init__(self, client=None, prefix='insiedr:v3:', maxlen=150000,async_client=None):
        self.client, self.prefix, self.maxlen = client, prefix, maxlen
        self.async_client=async_client

    def publish(self, receipt):
        if self.client is None:
            return
        # Notification contains identifiers only; authenticated REST retrieves redacted data.
        self.client.xadd(self.prefix+'live', {'payload_id': receipt['payload_id'], 'state': receipt.get('state','accepted')},
                         maxlen=self.maxlen, approximate=False)

    def resync(self):
        if self.client is not None:
            self.client.xadd(self.prefix+'live',{'state':'resync','reason':'snapshot_refreshed'},
                             maxlen=self.maxlen,approximate=False)

    def mark_searchable(self,ids):
        if self.client is None or not ids:
            return
        script='''for _,id in ipairs(cjson.decode(ARGV[1])) do
            local value=redis.call('HGET',KEYS[1],id)
            if value then local row=cjson.decode(value); row.ingest_state='searchable';
              redis.call('HSET',KEYS[1],id,cjson.encode(row)) end
            end return 1'''
        try:
            self.client.eval(script,1,self.prefix+'rows',canonical(ids))
        except Exception:
            self.invalidate()

    def get(self, key):
        try:
            value = self.client.get(self.prefix+'query:'+key) if self.client else None
            return json.loads(value) if value else None
        except Exception:
            return None

    def event(self,event_id):
        try:
            value=self.client.hget(self.prefix+'rows',event_id) if self.client else None
            return json.loads(value) if value else None
        except Exception:
            return None

    def remember(self,rows):
        try:
            if self.client:
                pipe=self.client.pipeline(transaction=False)
                for row in rows:
                    pipe.set(self.prefix+'locator:'+row['id'],canonical(
                        [row['received_at'][:10],row['collected_at']]),ex=300)
                pipe.execute()
        except Exception:
            pass

    def locate(self,event_id):
        try:
            value=self.client.get(self.prefix+'locator:'+event_id) if self.client else None
            return json.loads(value) if value else None
        except Exception:
            return None

    def put(self, key, value):
        try:
            data = canonical(value)
            if self.client and len(data) <= 1024**2:
                self.client.set(self.prefix+'query:'+key, data, ex=2)
        except Exception:
            pass

    def seed(self, rows, revision, floor):
        """Seed only from a complete bounded query; interrupted seeds stay invalid."""
        if self.client is None:
            return
        meta, index, data, pending = [self.prefix+k for k in ('meta','time','rows','pending')]
        try:
            # One transaction prevents readers observing a partially seeded snapshot.
            pipe = self.client.pipeline(transaction=True)
            pipe.delete(meta,index,data,pending)
            if rows:
                pipe.hset(data, mapping={r['id']:canonical(r) for r in rows})
                pipe.zadd(index, {r['id']:utc(r['collected_at']).timestamp() for r in rows})
            pipe.hset(meta, mapping={'revision':revision,'floor':floor,'count':len(rows)})
            for k in (meta,index,data):
                pipe.expire(k,120)
            pipe.execute()
        except Exception:
            self.invalidate()

    def invalidate(self):
        try:
            if self.client:
                self.client.delete(self.prefix+'meta')
        except Exception:
            pass

    def append_rows(self, rows, revision):
        if self.client is None:
            return
        # CAS sequence prevents concurrent requests publishing out of commit order
        # from declaring incomplete caches complete. No secondary index can leak.
        script = '''
          local rev=redis.call('HGET',KEYS[1],'revision')
          local count=tonumber(redis.call('HGET',KEYS[1],'count'))
          if not rev or
             redis.call('ZCARD',KEYS[2])~=count or redis.call('HLEN',KEYS[3])~=count then
            redis.call('DEL',KEYS[1]); return 0
          end
          if tonumber(ARGV[1])<=tonumber(rev) then return 1 end
          local rows=cjson.decode(ARGV[3])
          for _,r in ipairs(rows) do
            redis.call('HSET',KEYS[3],r.id,r.data)
            redis.call('ZADD',KEYS[2],r.score,r.id)
          end
          local excess=redis.call('ZCARD',KEYS[2])-tonumber(ARGV[2])
          if excess>0 then
            local old=redis.call('ZRANGE',KEYS[2],0,excess-1,'WITHSCORES')
            local floor=tonumber(redis.call('HGET',KEYS[1],'floor'))
            for i=1,#old,2 do
              floor=math.max(floor,tonumber(old[i+1]))
              redis.call('HDEL',KEYS[3],old[i]); redis.call('ZREM',KEYS[2],old[i])
            end
            redis.call('HSET',KEYS[1],'floor',floor)
          end
          redis.call('ZADD',KEYS[4],ARGV[1],ARGV[1])
          local next=tonumber(rev)+1
          while redis.call('ZSCORE',KEYS[4],tostring(next)) do
            redis.call('ZREM',KEYS[4],tostring(next)); next=next+1
          end
          if redis.call('ZCARD',KEYS[4])>1024 then redis.call('DEL',KEYS[1]); return 0 end
          redis.call('HSET',KEYS[1],'revision',next-1)
          redis.call('HSET',KEYS[1],'count',redis.call('ZCARD',KEYS[2]))
          for _,key in ipairs(KEYS) do redis.call('EXPIRE',key,120) end
          return 1
        '''
        try:
            self.client.eval(script,4,self.prefix+'meta',self.prefix+'time',self.prefix+'rows',self.prefix+'pending',
                revision,self.maxlen,canonical([dict(id=r['id'], data=canonical(r).decode(),
                    score=utc(r['collected_at']).timestamp()) for r in rows]))
        except Exception:
            self.invalidate()

    def recent(self, filters, snapshot, count, revision):
        if self.client is None:
            return None
        try:
            script = '''
              local rev=redis.call('HGET',KEYS[1],'revision')
              local count=tonumber(redis.call('HGET',KEYS[1],'count'))
              if not rev or tonumber(rev)~=tonumber(ARGV[1]) or
                 redis.call('ZCARD',KEYS[2])~=count or redis.call('HLEN',KEYS[3])~=count then return {} end
              local scan=tonumber(ARGV[4])
              local ids=redis.call('ZREVRANGEBYSCORE',KEYS[2],ARGV[2],ARGV[3],'LIMIT',0,scan+1)
              local result={redis.call('HGET',KEYS[1],'floor'),tostring(#ids>scan)}
              local bytes=0
              for _,id in ipairs(ids) do
                local row=redis.call('HGET',KEYS[3],id)
                if not row then return {} end
                bytes=bytes+#row
                if bytes>8388608 then result[2]='true'; break end
                table.insert(result,row)
              end
              return result
            '''
            result = self.client.eval(script,3,self.prefix+'meta',self.prefix+'time',self.prefix+'rows',
                revision,utc(filters['end_time']).timestamp(),utc(filters['start_time']).timestamp(),
                min(10000,max(256,count*4)))
            if not result:
                return None
            floor, truncated, values = float(result[0]), result[1] in (b'true','true'), result[2:]
            rows = [json.loads(v) for v in values]
            rows = sorted([r for r in rows if matches(r,filters,snapshot)],
                          key=lambda r:(r['collected_at'],r['id']),reverse=True)
            # Either every requested event is covered, or a full page lies strictly
            # above all trimmed events. Equal timestamps require persistent fallback.
            if ((not truncated and utc(filters['start_time']).timestamp() > floor) or
                    (len(rows)>=count and utc(rows[count-1]['collected_at']).timestamp()>floor)):
                return rows[:count]
        except Exception:
            return None
        return None


class RAMTelemetryStorage:
    risk_in_replay = True
    def __init__(self, legacy, journal, events, archive, *, cache=None,
                 store_plaintext=False, replay_hours=72, active_days=30,retention_days=90,start=True):
        if not 1<=active_days<retention_days:
            raise ValueError('retention must be greater than positive active-storage days')
        self.legacy, self.journal, self.events, self.archive = legacy, journal, events, archive
        self.pg, self.ch = legacy.pg, legacy.ch
        self.cache = cache or RecentRedis()
        self.store_plaintext, self.replay_hours = store_plaintext, replay_hours
        self.active_days,self.retention_days=active_days,retention_days
        self.controller = PressureController()
        self._stop = threading.Event()
        self._maintenance_lock = threading.RLock()
        self._queries = threading.BoundedSemaphore(3)
        self._active_ingest = 0
        self._active_ingest_bytes=0
        self._active_queries = 0
        self._searchable_revision=0
        self._live_revision=0
        self._live_lock=threading.Lock()
        self._live_queue=queue.Queue(maxsize=256)
        self._warm_requested=threading.Event()
        self._warm_requested.set()
        self._live_thread=None
        self._admission_lock = threading.Lock()
        self.last_error = None
        self._metrics = {}
        self._accepted_bytes = self._drained_bytes = 0
        self._last_sample = time.monotonic()-2
        self._last_totals = (0,0)
        self._last_disk = None
        self._last_external_sample=0
        self._thread = None
        if start:
            if self.cache.client is not None:
                self._live_thread=threading.Thread(target=self._live_loop,name='TelemetryLiveBridge',daemon=True)
                self._live_thread.start()
            self._thread = threading.Thread(target=self._run, name='TelemetryReplay', daemon=True)
            self._thread.start()

    def __getattr__(self, name):
        return getattr(self.legacy, name)

    @property
    def cache_revision(self):
        return f"{self.journal.cache_namespace}:{self.journal.revision}:{self._searchable_revision}:{self._live_revision}"

    def enter_ingest(self,request_bytes=None):
        from server.config import config
        size=config.max_request_bytes if request_bytes is None else max(4096,min(config.max_request_bytes,request_bytes))
        reserved=size*24  # Conservative parse/copy/projection allowance, not wire bytes alone.
        with self._admission_lock:
            if (self._active_ingest >= POLICY[self.controller.level].admission
                    or self._active_ingest_bytes+reserved>384*1024**2):
                return 0
            self._active_ingest += 1
            self._active_ingest_bytes+=reserved
            return reserved

    def leave_ingest(self,reserved):
        with self._admission_lock:
            self._active_ingest -= 1
            self._active_ingest_bytes-=reserved

    def get_payload(self, pid):
        # The pre-cutover retry horizon is seeded once at migration. New payload
        # admission never synchronously consults PostgreSQL or Redis.
        return self.journal.lookup(pid)

    def store_raw_payload(self, envelope, payload):
        # Check required interceptors before accepting, but retain original encrypted
        # payload for replay. No raw plaintext is persisted by SQLite.
        context = interceptor_pipeline.process(copy.deepcopy(envelope), copy.deepcopy(payload))
        if context.is_dropped:
            raise ValueError('telemetry rejected by interceptor')
        if any(context.decrypted_payload.get(k)!=payload.get(k) for k in ('payload_id','agent_id')):
            raise ValueError('storage interceptor changed authenticated payload identity')
        # Validate the exact projection before accepting an otherwise replay-
        # poisoning record. The durable journal remains the acceptance boundary.
        rows=project(context.decrypted_payload,datetime.now(timezone.utc).isoformat(),self.store_plaintext)
        if any(len(canonical(row))>POLICY[Level.NORMAL].batch_bytes for row in rows):
            raise ValueError('one telemetry event exceeds batch byte budget')
        accepted = self.journal.append(envelope, payload,projection=rows,stored_payload=context.decrypted_payload)
        if accepted:
            self._accepted_bytes += len(canonical([envelope,payload]))
            self._queue_live(accepted)
        return bool(accepted)

    def _queue_live(self,seq):
        if self.cache.client is None:
            return
        try:
            self._live_queue.put_nowait(seq)  # Identifiers only, never full payloads.
        except queue.Full:
            self._warm_requested.set()

    def ensure_live(self,payload_id):
        receipt=self.journal.lookup(payload_id)
        if receipt:
            self._queue_live(receipt['seq'])

    def _record_rows(self,record):
        projection=record.get('projection')
        if projection is None:
            # Compatibility for low-level journal records written before v3
            # acceptance captured a projection; production requests always do.
            ctx=interceptor_pipeline.process(copy.deepcopy(record['envelope']),copy.deepcopy(record['payload']))
            if ctx.is_dropped:
                raise RuntimeError('accepted legacy record rejected during replay; retained for recovery')
            projection=project(ctx.decrypted_payload,record['received_at'],self.store_plaintext)
        return [dict(r,received_at=record['received_at'],accepted_seq=record['seq']) for r in projection]

    def _live_loop(self):
        while not self._stop.is_set():
            try:
                seq=self._live_queue.get(timeout=.2)
            except queue.Empty:
                continue
            try:
                with self._live_lock:
                    record=self.journal.record(seq)
                    if record is None:
                        continue
                    if record.get('payload') is not None:
                        rows=self._record_rows(record)
                    else:
                        rows=self.events.query(dict(payload_id=record['payload_id'],received_day=record['received_at'][:10]),
                                               datetime.now(timezone.utc).isoformat(),10001)
                    state='searchable' if record['analytics_done'] else 'accepted'
                    self.cache.append_rows([dict(r,ingest_state=state) for r in rows],seq)
                    if record['analytics_done']:
                        self.cache.mark_searchable([r['id'] for r in rows])
                    self.cache.publish(dict(payload_id=record['payload_id'],state=state))
                    self._live_revision+=1
                    self._metrics['live_seconds']=max(0,(datetime.now(timezone.utc)-utc(record['received_at'])).total_seconds())
                from server.api.events import dispatch_telemetry_event
                dispatch_telemetry_event(record['payload_id'],invalidate=False)
            except Exception:
                self._warm_requested.set()
                log.warning('live notification deferred; authoritative journal/storage retained')

    def replay_once(self):
        limits = POLICY[self.controller.level]
        with self._maintenance_lock:
            records = self.journal.pending(limit=min(limits.rows, 1024), max_bytes=max(limits.batch_bytes,self.journal.max_record_bytes))
            if not records:
                return 0
            rows = []
            for record in records:
                if record['analytics_done']:
                    continue
                rows.extend(self._record_rows(record))
            started = time.monotonic()
            # Bounded per-insert rows/bytes, including a single payload's many collectors.
            batch, size = [], 0
            for row in rows:
                cost = len(canonical(row))
                if cost > limits.batch_bytes:
                    raise ValueError('event exceeds ClickHouse batch byte cap')
                if batch and (len(batch) >= limits.rows or size + cost > limits.batch_bytes):
                    self.events.insert(batch)
                    batch, size = [], 0
                batch.append(row)
                size += cost
            if batch:
                self.events.insert(batch)
            if any(not r['analytics_done'] for r in records):
                self.journal.mark_analytics([r['seq'] for r in records])
                self._searchable_revision+=1
                for record in records:
                    self._queue_live(record['seq'])
                try:
                    from server.api.events import dispatch_telemetry_event
                    dispatch_telemetry_event(records[-1]['payload_id'],invalidate=False)
                except Exception:
                    pass
            self._metrics['insert_seconds'] = time.monotonic()-started
            # Metadata and risk remain asynchronous to agent ACK, but retry on failure.
            # No accepted journal record is reclaimed until all required consumers succeed.
            latest = {}
            for record in records:
                pid = record['payload']['agent_id']
                if pid not in latest or record['payload']['collected_at']>latest[pid]['collected_at']:
                    latest[pid] = record['payload']
            if getattr(type(self.pg),'_upsert_agent',None) is not None:
                from contextlib import closing
                with self.pg.connection() as conn,closing(conn.cursor()) as cur:
                    for p in latest.values():
                        self.pg._upsert_agent(cur,p)
                    # Small operational payload pointers preserve existing risk
                    # joins/foreign keys without retaining raw telemetry, feature
                    # rows or a second telemetry outbox in PostgreSQL.
                    for record in records:
                        p,e=record['payload'],record['envelope']
                        identity=self.journal.lookup(record['payload_id'])
                        cur.execute('''INSERT INTO raw_payloads(payload_id,agent_id,received_at,
                            envelope_created_at,payload_collected_at,hostname,username,crypto_scheme,key_id,
                            ciphertext_hash,decrypted_payload_hash,encrypted_envelope_json,validation_status)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'{}','accepted')
                            ON CONFLICT(payload_id,received_at) DO NOTHING''',
                            (p['payload_id'],p['agent_id'],record['received_at'],e.get('created_at'),p['collected_at'],
                             p.get('hostname'),p.get('username'),e.get('scheme'),e.get('key_id'),
                             identity['ciphertext_hash'],identity['decrypted_payload_hash']))
                    conn.commit()
            else:
                for p in latest.values():
                    self.legacy.fleet.upsert_agent(p)
            from server.config import config
            if config.enable_detection_pipeline:
                for record in records:
                    from server.risk.pipeline import process_telemetry_risk
                    process_telemetry_risk(self.legacy, record['payload'])
            self.journal.complete([r['seq'] for r in records])
            self._searchable_revision+=1
            self._drained_bytes += sum(len(canonical([r['envelope'],r['payload']])) for r in records)
            return len(records)

    def sample_pressure(self):
        import psutil
        import shutil
        stats=self.journal.stats()
        now=time.monotonic()
        elapsed=max(.001,now-self._last_sample)
        if elapsed<2:
            return POLICY[self.controller.level],stats
        disk=psutil.disk_io_counters()
        latency=0
        throughput=0
        if disk and self._last_disk:
            operations=(disk.read_count+disk.write_count-self._last_disk.read_count-self._last_disk.write_count)
            latency=(disk.read_time+disk.write_time-self._last_disk.read_time-self._last_disk.write_time)/max(1,operations)
            throughput=(disk.read_bytes+disk.write_bytes-self._last_disk.read_bytes-self._last_disk.write_bytes)/elapsed
        self._last_disk=disk
        m=dict(self._metrics,memory_ratio=psutil.virtual_memory().percent/100,
            free_bytes=shutil.disk_usage(self.journal.directory).free,
            reserve_bytes=self.journal.reserve_bytes,queue_ratio=stats['disk_bytes']/self.journal.max_bytes,
            oldest_age=stats['oldest_age'],queue_bytes=stats['pending_bytes'],
            disk_latency_ms=latency,disk_bytes_sec=throughput,
            arrival_bytes_sec=(self._accepted_bytes-self._last_totals[0])/elapsed,
            drain_bytes_sec=(self._drained_bytes-self._last_totals[1])/elapsed)
        if now-self._last_external_sample>=30:
            try:
                m.update(self.events.pressure_metrics())
                m['merge_metrics_available']=True
            except Exception:
                m['merge_metrics_available']=False
            try:
                if self.cache.client:
                    info=self.cache.client.info('memory')
                    m['cache_ratio']=info['used_memory']/max(1,info['maxmemory'])
            except Exception:
                m['cache_metrics_available']=False
            self._last_external_sample=now
        self._last_sample=now
        self._last_totals=(self._accepted_bytes,self._drained_bytes)
        self._metrics=m
        limits=self.controller.sample(m)
        self.cache.maxlen=limits.cache_entries
        return limits,stats

    def _run(self):
        last_archive = last_compact = last_warm = 0
        while not self._stop.is_set():
            try:
                limits,stats=self.sample_pressure()
                self.replay_once()
                if self._warm_requested.is_set() or time.monotonic()-last_warm>60:
                    self._warm_requested.clear()
                    self.warm_recent()
                    last_warm=time.monotonic()
                if time.monotonic()-last_compact > 3600:
                    days=self.events.days_before(datetime.now(timezone.utc)+timedelta(days=1))+self.archive.retained_days()
                    floor=(min(days) if days else (datetime.now(timezone.utc)+timedelta(days=1)).date().isoformat())+'T00:00:00.000+00:00'
                    self.journal.compact(max(self.replay_hours,self.retention_days*24)+1,floor)
                    last_compact = time.monotonic()
                if limits.archive and time.monotonic()-last_archive > 3600:
                    if self.archive_once():
                        last_archive = time.monotonic()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
                log.warning('telemetry worker retained durable backlog: %s', exc)
            self._stop.wait(POLICY[self.controller.level].flush_seconds)

    def warm_recent(self):
        if self.cache.client is None or self.controller.level != Level.NORMAL:
            return
        with self._maintenance_lock,self._live_lock:
            revision = self.journal.revision
            now = datetime.now(timezone.utc)
            start = now-timedelta(hours=24)
            snapshot = now.isoformat(timespec='milliseconds')
            filters = dict(start_time=start.isoformat(),end_time=(now+timedelta(minutes=5)).isoformat(),snapshot_seq=revision)
            seed_limit=min(self.cache.maxlen,10000)
            rows = self.events.query(filters,snapshot,seed_limit+1)
            rows += self.archive.query(filters,snapshot,seed_limit+1)
            rows += self._pending_rows(filters,snapshot)
            rows = sorted({r['id']:r for r in rows}.values(),key=lambda r:(r['collected_at'],r['id']),reverse=True)
            floor = start.timestamp()
            if len(rows)>seed_limit:
                floor = utc(rows[seed_limit]['collected_at']).timestamp()
            # The live bridge is paused while the snapshot is seeded. New commits
            # queue identifiers and advance this sequence after the lock releases.
            self.cache.seed([dict(r,ingest_state=r.get('ingest_state','searchable')) for r in rows[:seed_limit]],revision,floor)
            self.cache.resync()
            from server.api.events import broadcaster
            broadcaster.publish('telemetry','resync',{'reason':'snapshot_refreshed'})

    def archive_once(self, now=None):
        with self._maintenance_lock:
            # A single owner and no pending acceptance records make old received-day
            # partitions immutable. Late event time cannot reopen a received-day partition.
            now = now or datetime.now(timezone.utc)
            deadline=time.monotonic()+20
            cutoff = (now - timedelta(days=self.active_days)).replace(hour=0, minute=0, second=0, microsecond=0)
            oldest=self.journal.stats()['oldest_received']
            if oldest and utc(oldest)<cutoff:
                return False
            for day in self.events.days_before(cutoff):
                if self._stop.is_set() or self.controller.level != Level.NORMAL:
                    return False
                completed=self.archive.archive_day(self.events, day, continue_work=lambda:
                    not self._stop.is_set() and time.monotonic()<deadline
                    and self.sample_pressure()[0].archive)
                if not completed:
                    return False
            self.archive.expire(now - timedelta(days=self.retention_days))
            return True

    def _pending_rows(self, filters, snapshot):
        # Bounded fallback: never silently truncate an unpersisted backlog.
        cap=filters.get('snapshot_seq',self.journal.revision)
        records = self.journal.pending(limit=10001, max_bytes=32*1024**2,before_seq=cap)
        if len(records) >= 10001 or len(records) != self.journal.stats(before_seq=cap)['pending']:
            raise RuntimeError('pending query budget exceeded; narrow query or wait for recovery')
        rows = []
        for r in records:
            rows.extend(dict(row,ingest_state='searchable' if r['analytics_done'] else 'accepted')
                        for row in self._record_rows(r)
                        if matches(row, filters, snapshot))
        return rows

    def get_telemetry_page(self, limit=100, offset=0, cursor=None, include_total=False,
                           include_enrichment=False,_metadata_only=False,_raw_rows=False, **filters):
        if not 1 <= limit <= 1000 or offset < 0 or offset > 10000:
            raise ValueError('query page exceeds bounded budget')
        if cursor and offset:
            raise ValueError('cursor and offset cannot be combined')
        filters = {k: v for k,v in filters.items() if v is not None}
        if filters.get('search_scope', 'metadata') not in ('metadata', 'payload'):
            raise ValueError('invalid search scope')
        filters.setdefault('search_scope', 'metadata')
        key = digest(filters)
        snapshot = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        snapshot_seq=self.journal.revision
        if cursor:
            try:
                token = json.loads(base64.urlsafe_b64decode(cursor))
                if token['key'] != key:
                    raise ValueError()
                snapshot = utc(token['snapshot']).isoformat(timespec='milliseconds')
                snapshot_seq=int(token['snapshot_seq'])
                if not 0<=snapshot_seq<=self.journal.revision:
                    raise ValueError()
                filters['before'] = token['before']
                uuid.UUID(filters['before'][1])
                utc(filters['before'][0])
            except Exception:
                raise ValueError('invalid telemetry cursor') from None
        filters.setdefault('end_time', snapshot)
        filters['snapshot_seq']=snapshot_seq
        filters.setdefault('start_time', (utc(snapshot)-timedelta(hours=24)).isoformat(timespec='milliseconds'))
        if utc(filters['start_time']) > utc(filters['end_time']):
            raise ValueError('start time must precede end time')
        if (filters.get('search') and filters['search_scope'] == 'payload'
                and (utc(filters['end_time'])-utc(filters['start_time']) > timedelta(hours=6)
                     or not (filters.get('collector') or filters.get('hostname')))):
            raise ValueError('payload search requires <=6 hours and collector or hostname')
        cache_key = digest([key,cursor,limit,offset,self.cache_revision,include_total,include_enrichment,
                            _metadata_only,_raw_rows])
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        count=limit+offset+1
        rows=self.cache.recent(filters,snapshot,count,self.journal.revision)
        acquired=False
        if rows is None:
          with self._admission_lock:
            if self._active_queries<POLICY[self.controller.level].analytical_queries:
                acquired=self._queries.acquire(blocking=False)
                if acquired:
                    self._active_queries+=1
        if rows is None and not acquired:
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError('analytical query capacity exhausted; retry')
        started = time.monotonic()
        try:
            if rows is None:
              if not self._maintenance_lock.acquire(timeout=1):
                raise RuntimeError('telemetry maintenance is active; retry')
              try:
                # Query both stores: actual manifests, not an assumed age boundary,
                # determine coverage during archival and outages.
                rows = [dict(r,ingest_state='archived') for r in self.archive.query(filters, snapshot, count)]
                rows += [dict(r,ingest_state='searchable') for r in self.events.query(filters, snapshot, count,
                                                                                  metadata_only=_metadata_only)]
                rows += self._pending_rows(filters, snapshot)
              finally:
                self._maintenance_lock.release()
            unique = {r['id']: r for r in rows}
            rows = sorted(unique.values(), key=lambda r: (r['collected_at'], r['id']), reverse=True)
            more = len(rows) > offset + limit
            rows = rows[offset:offset+limit]
            next_cursor = base64.urlsafe_b64encode(canonical(dict(key=key, snapshot=snapshot,snapshot_seq=snapshot_seq,
                before=[rows[-1]['collected_at'],rows[-1]['id']]))).decode() if more else None
            output = []
            for row in rows:
                if _raw_rows:
                    output.append(row)
                    continue
                item={k:v for k,v in row.items() if k not in ('payload_json','features_json','accepted_seq')}
                if not _metadata_only:
                    item['payload']=json.loads(row['payload_json'])
                item.update(event_id=row['id'],timestamp=row['collected_at'],collector_name=row['collector'])
                output.append(item)
            enrichment=None
            if include_enrichment and output:
                from contextlib import closing
                try:
                    pids=list({r['payload_id'] for r in output})
                    with self.pg.connection() as conn,closing(conn.cursor()) as cur:
                        cur.execute('''SELECT payload_id,risk_level,summary,correlated_signals_json,risk_score FROM (
                            SELECT payload_id,risk_level,summary,correlated_signals_json,risk_score,
                            row_number() OVER(PARTITION BY payload_id ORDER BY created_at DESC,id DESC) AS rank
                            FROM risk_events WHERE payload_id IN ('''+','.join(['%s']*len(pids))+''')) r WHERE rank=1''',tuple(pids))
                        risks={r[0]:dict(zip(('risk_level','summary','correlated_signals_json','risk_score'),r[1:])) for r in cur.fetchall()}
                    for row in output:
                        row.update(risks.get(row['payload_id'],{}))
                    enrichment=True
                except Exception:
                    enrichment=False
            total=None
            if include_total:
                count_filters={k:v for k,v in filters.items() if k!='before'}
                total=sum(r['count'] for r in self._aggregate(count_filters,snapshot=snapshot))
            result = dict(logs=output, events=output, has_more=more, next_cursor=next_cursor,
                          total=total, limit=limit, offset=offset, source='server-v3',
                          as_of=snapshot, total_available=include_total,enrichment_available=enrichment)
            self.cache.put(cache_key, result)
            self.cache.remember(output)
            return result
        except ValueError:
            raise
        except Exception as exc:
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError('telemetry data unavailable; no partial result returned') from exc
        finally:
            self._metrics['query_seconds'] = time.monotonic()-started
            if acquired:
                self._queries.release()
                with self._admission_lock:
                    self._active_queries-=1

    def get_telemetry_explorer(self, **filters):
        return self.get_telemetry_page(_metadata_only=True,**filters)

    def list_logs(self, limit=100, offset=0, **filters):
        return self.get_telemetry_page(limit=limit, offset=offset, **filters)['logs']

    def list_collector_results(self, limit=100, offset=0, **filters):
        return self.list_logs(limit=limit,offset=offset,**filters)

    def list_normalized_features(self,limit=1000,offset=0,feature_name=None,**filters):
        # Explicit bounded derivation from the canonical event copy, including
        # normalized metrics retained when raw plaintext bodies are disabled.
        if limit<1 or limit>10000 or offset<0 or offset>10000:
            raise ValueError('feature page exceeds budget')
        features=[]
        cursor=None
        pages=0
        while len(features)<offset+limit:
            pages+=1
            if pages>32:
                raise ValueError('feature query exceeds scan budget; narrow time range')
            page=self.get_telemetry_page(limit=1000,cursor=cursor,_raw_rows=True,**filters)
            for row in page['logs']:
                for f in feature_rows(row):
                    if not feature_name or f['feature_name']==feature_name:
                        features.append(f)
                    if len(features)>=offset+limit:
                        break
                if len(features)>=offset+limit:
                    break
            cursor=page['next_cursor']
            if not cursor:
                break
            if len(features)>100000:
                raise ValueError('feature query exceeds budget; narrow time range')
        return features[offset:offset+limit]

    def list_daily_feature_vectors(self,username=None,hostname=None,limit=16):
        if not username and not hostname:
            return []
        rows=self.list_normalized_features(limit=min(10000,limit*128),username=username,hostname=hostname,
            start_time=(datetime.now(timezone.utc)-timedelta(days=self.retention_days)).isoformat())
        grouped={}
        for f in rows:
            day=str(f['feature_timestamp'])[:10]
            value=next((f[k] for k in ('feature_value_numeric','feature_value_text','feature_value_json') if f[k] is not None),None)
            grouped.setdefault(day,{}).setdefault(f['feature_name'],value)
        return [dict(date=day,features=grouped[day]) for day in sorted(grouped)[-limit:]]

    def get_feature_vector(self,payload_id):
        page=self.get_telemetry_page(limit=1000,payload_id=payload_id,_raw_rows=True,start_time='1970-01-01T00:00:00+00:00')
        vector={}
        for row in page['logs']:
            for f in feature_rows(row):
                value=next((f.get(k) for k in ('feature_value_numeric','feature_value_text','feature_value_json')
                            if f.get(k) is not None),None)
                vector[f['feature_name']]=value
        return vector

    def get_latest_collector_states(self,agent_id):
        return self._latest_states(agent_id=agent_id)

    def get_user_collectors(self,username):
        return self._latest_states(username=username)

    def _aggregate(self,filters,seconds=0,snapshot=None):
        if self.controller.level==Level.CRITICAL:
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError('persistent analytics deferred under critical pressure')
        if not self._maintenance_lock.acquire(timeout=1):
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError('analytics refresh busy; retry')
        try:
            snapshot=snapshot or datetime.now(timezone.utc).isoformat(timespec='milliseconds')
            filters=dict(filters)
            filters.setdefault('snapshot_seq',self.journal.revision)
            pending=self._pending_rows(filters,snapshot)
            pending=list({r['id']:r for r in pending}.values())
            filtered=dict(filters,exclude_ids=tuple(r['id'] for r in pending))
            result=self.events.aggregate(filtered,snapshot,seconds)
            days=self.events.days_before(datetime.now(timezone.utc)+timedelta(days=1))
            if not filters.get('start_time') and not filters.get('end_time') and not seconds:
                result+=self.archive.totals(days,filters)
                cold=[]
            else:
                cold=self.archive.query(dict(filtered,exclude_days=days),snapshot,2**31-1)
            counts={}
            for item in result:
                key=(item['collector'],item['status'],item['bucket'])
                counts[key]=counts.get(key,0)+int(item['count'])
            for row in cold+pending:
                bucket=int(utc(row['collected_at']).timestamp())//seconds*seconds if seconds else 0
                key=(row['collector'],row['status'],bucket)
                counts[key]=counts.get(key,0)+1
            return [dict(collector=k[0],status=k[1],bucket=k[2],count=n) for k,n in counts.items()]
        finally:
            self._maintenance_lock.release()

    def count_collector_results(self,**filters):
        filters.pop('exact_collector',None)
        return sum(r['count'] for r in self._aggregate({k:v for k,v in filters.items() if v}))

    def get_stats(self):
        result=self.pg.get_stats(include_telemetry=False)
        groups=self._aggregate({})
        collectors,statuses={},{}
        for r in groups:
            collectors[r['collector']]=collectors.get(r['collector'],0)+r['count']
            statuses[r['status']]=statuses.get(r['status'],0)+r['count']
        result.update(collector_results=sum(collectors.values()),logs=sum(collectors.values()),
                      collector_counts=collectors,collector_status=statuses,
                      count_semantics='retained_collector_observations')
        return result

    def get_distinct_collectors(self):
        return sorted({r['collector'] for r in self._aggregate({})})

    def get_telemetry_histogram(self,time_range='1h',interval=None,**filters):
        windows={'15m':(900,'1m'),'1h':(3600,'1m'),'24h':(86400,'15m'),
                 '7d':(604800,'2h'),'all':(2592000,'1d')}
        intervals={'1m':60,'5m':300,'10m':600,'15m':900,'1h':3600,'2h':7200,'1d':86400}
        if time_range not in windows or (interval and interval not in intervals):
            raise ValueError('invalid histogram range or interval')
        window,default=windows[time_range]
        interval=interval or default
        now=datetime.now(timezone.utc)
        filters={k:v for k,v in filters.items() if v}
        filters.update(start_time=(now-timedelta(seconds=window)).isoformat(),end_time=now.isoformat())
        groups=self._aggregate(filters,intervals[interval])
        buckets={}
        for r in groups:
            buckets[r['bucket']]=buckets.get(r['bucket'],0)+r['count']
        return dict(ok=True,time_range=time_range,interval=interval,total_events=sum(buckets.values()),
                    histogram=[dict(timestamp=datetime.fromtimestamp(t,timezone.utc).isoformat(),count=n)
                               for t,n in sorted(buckets.items())])

    def _latest_states(self,agent_id=None,username=None):
        if self.controller.level==Level.CRITICAL:
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError('collector-state refresh deferred under critical pressure')
        if not self._maintenance_lock.acquire(timeout=1):
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError('collector state refresh busy; retry')
        try:
            snapshot=datetime.now(timezone.utc).isoformat(timespec='milliseconds')
            filters={k:v for k,v in dict(agent_id=agent_id,username=username).items() if v}
            rows=self.events.latest(**filters)+self.archive.latest(**filters)
            rows+=self._pending_rows(filters,snapshot)
            latest={}
            for row in rows:
                c=row['collector']
                if c not in latest or (row['collected_at'],row['id'])>(latest[c]['collected_at'],latest[c]['id']):
                    latest[c]=row
            return [dict(r,collector_collected_at=r['collected_at'],payload_json=
                         json.loads(r['features_json']) if json.loads(r['payload_json'])=={'_redacted':True}
                         else json.loads(r['payload_json'])) for r in latest.values()]
        finally:
            self._maintenance_lock.release()

    def get_telemetry_event_detail(self, event_id):
        if str(event_id).isdigit():
            return self.legacy.get_telemetry_event_detail(event_id)
        uuid.UUID(event_id)
        row=self.cache.event(event_id)
        if row and utc(row['received_at'])<datetime.now(timezone.utc)-timedelta(days=self.retention_days):
            row=None
        filters={'event_id':event_id}
        locator=self.cache.locate(event_id)
        if locator:
            filters.update(received_day=locator[0],start_time=locator[1],end_time=locator[1])
        if row is None:
            if self.controller.level==Level.CRITICAL:
                from server.api.errors import AnalyticsUnavailableError
                raise AnalyticsUnavailableError('persistent event detail deferred under critical pressure')
            if not self._maintenance_lock.acquire(timeout=1):
                from server.api.errors import AnalyticsUnavailableError
                raise AnalyticsUnavailableError('event detail busy; retry')
            try:
                snapshot=datetime.now(timezone.utc).isoformat(timespec='milliseconds')
                found=self.events.query(filters,snapshot,1)
                if not found:
                    found=self._pending_rows(filters,snapshot)
                if not found:
                    filters.setdefault('start_time','1970-01-01T00:00:00+00:00')
                    filters.setdefault('end_time',snapshot)
                    found=self.archive.query(filters,snapshot,1)
                row=found[0] if found else None
            except ValueError:
                raise
            except Exception as exc:
                from server.api.errors import AnalyticsUnavailableError
                raise AnalyticsUnavailableError('event detail is temporarily unavailable') from exc
            finally:
                self._maintenance_lock.release()
        if row:
            event=dict(row,event_id=row['id'],timestamp=row['collected_at'],collector_name=row['collector'],
                       raw_payload_json=row['payload_json'],payload=json.loads(row['payload_json']))
            vector={}
            for f in feature_rows(row):
                vector[f['feature_name']]=next((f[k] for k in ('feature_value_numeric','feature_value_text','feature_value_json') if f[k] is not None),None)
            return dict(event=event,features=vector,risk=None)
        return None

    async def aclose_cache(self):
        if self.cache.async_client is not None:
            await self.cache.async_client.aclose()

    def close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=30)
            if self._thread.is_alive():
                raise RuntimeError('telemetry worker still active; journal retained, do not close dependencies')
        if self._live_thread:
            self._live_thread.join(timeout=20)
            if self._live_thread.is_alive():
                raise RuntimeError('live bridge still active; journal retained')
        self.journal.close()
        if self.cache.client is not None:
            self.cache.client.close()
        self.legacy.close()


def build_ram_storage(legacy):
    """Fail startup closed rather than silently enable a partially migrated path."""
    from server.config import config
    from server.storage.telemetry_archive import PostgresArchive
    if legacy is None or not getattr(legacy, 'ch', None) or not legacy.ch.is_connected():
        raise RuntimeError('RAM telemetry requires a connected ClickHouse instance')
    if getattr(legacy.pg, '_is_sqlite', False):
        raise RuntimeError('RAM telemetry requires PostgreSQL for operational data and archives')
    key = base64.b64decode(os.environ.get('INSIEDR_JOURNAL_KEY', ''), validate=True)
    if len(key) != 32:
        raise ValueError('set INSIEDR_JOURNAL_KEY to a persistent base64-encoded 32-byte secret')
    if os.environ.get('INSIEDR_V3_CUTOVER_READY') != 'true':
        raise RuntimeError('complete and verify v3 backfill before setting INSIEDR_V3_CUTOVER_READY=true')
    active_days=int(os.environ.get('INSIEDR_TELEMETRY_ACTIVE_DAYS','30'))
    retention_days=int(os.environ.get('INSIEDR_TELEMETRY_TOTAL_RETENTION_DAYS','90'))
    if not 1<=active_days<retention_days:
        raise ValueError('retention must be greater than positive active-storage days')
    events = ClickHouseEvents(legacy.ch)
    events.ensure_schema()
    archive = PostgresArchive(legacy.pg)
    archive.ensure_schema()
    client = None
    async_client=None
    url = os.environ.get('INSIEDR_REDIS_URL')
    if url:
        import redis
        client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        import redis.asyncio
        async_client=redis.asyncio.Redis.from_url(url,socket_timeout=3,socket_connect_timeout=2,max_connections=64)
    journal = IngestJournal(os.environ.get('INSIEDR_JOURNAL_DIR', 'data/ingest-journal'), key,
        max_bytes=int(os.environ.get('INSIEDR_JOURNAL_MAX_BYTES', str(20*1024**3))),
        reserve_bytes=int(os.environ.get('INSIEDR_DISK_RESERVE_BYTES', str(50*1024**3))),
        max_record_bytes=max(16*1024**2,config.max_request_bytes*4),
        queue_size=max(1,min(32,(512*1024**2)//max(16*1024**2,config.max_request_bytes*4))))
    try:
        if journal.setting('v3_backfill_verified')!='true':
            raise RuntimeError('journal has no verified offline backfill marker; complete telemetry_v3.py backfill first')
        if not journal.setting('legacy_receipts_seeded'):
            seed_legacy_receipts(legacy.pg,journal,config.replay_window_hours)
    except Exception:
        journal.close()
        raise
    return RAMTelemetryStorage(legacy, journal, events, archive, cache=RecentRedis(client,
                               prefix='insiedr:v3:'+journal.cache_namespace+':'+
                                      ('plain:' if config.store_plaintext_payloads else 'redacted:'),async_client=async_client),
                               store_plaintext=config.store_plaintext_payloads,
                               replay_hours=config.replay_window_hours,
                               active_days=active_days,retention_days=retention_days)


def seed_legacy_receipts(pg,journal,replay_hours):
    from contextlib import closing
    after=''
    hashed=[]
    cutoff=datetime.now(timezone.utc)-timedelta(hours=replay_hours+1)
    while True:
        with pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('''SELECT payload_id,agent_id,encrypted_envelope_json,
                decrypted_payload_hash,ciphertext_hash,received_at FROM raw_payloads
                WHERE received_at>=%s AND payload_id>%s ORDER BY payload_id LIMIT 16''',(cutoff,after))
            batch=cur.fetchall()
        if not batch:
            break
        for pid,agent,envelope,plain_hash,cipher_hash,received in batch:
            envelope=json.loads(envelope) if isinstance(envelope,str) else envelope
            hashed.append((pid,agent,digest(envelope),plain_hash,cipher_hash,received))
        if len(hashed)>=1000:
            journal.seed_receipts(hashed[:1000],hashed=True)
            hashed=hashed[1000:]
        after=batch[-1][0]
    if hashed:
        journal.seed_receipts(hashed,hashed=True)
    journal.set_setting('legacy_receipts_seeded',datetime.now(timezone.utc).isoformat())
