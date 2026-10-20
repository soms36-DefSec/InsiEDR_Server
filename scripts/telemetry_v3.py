"""Offline migration/rollback tooling. Never run against a serving writer.

Credentials come from environment. No inferred endpoints, service restarts or
source deletion. Backfill and rollback retain their source until verified.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
from pathlib import Path
import sys
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from server.storage.ingest_journal import canonical, IngestJournal
from server.storage.ram_telemetry import COLUMNS, TABLE, ClickHouseEvents, normalize, feature_rows, utc
from server.storage.telemetry_archive import PostgresArchive


def legacy_row(row):
    """Convert one legacy collector to the compact canonical representation."""
    row=dict(row)
    if isinstance(row.get('payload_json'),str):
        row['payload_json']=json.loads(row['payload_json'])
    body=row.get('payload_json')
    from server.config import config
    from server.storage.clickhouse_telemetry_queries import extract_summary_preview
    from server.storage.interceptors import interceptor_pipeline
    col=dict(collector=row['collector'],collected_at=str(row['collected_at']),
             status=row['status'],hostname=row['hostname'],payload=body or {},
             error={'type':row.get('error_type') or '', 'message':row.get('error_message') or ''})
    payload=dict(payload_id=row['payload_id'],agent_id=row['agent_id'],hostname=row['hostname'],
                 username=row.get('username') or '',collected_at=str(row['collected_at']),collectors=[col])
    ctx=interceptor_pipeline.process({},payload)
    if ctx.is_dropped:
        raise RuntimeError('legacy record rejected by required interceptor')
    clean=ctx.decrypted_payload['collectors'][0]['payload']
    metrics=row.get('metrics') or clean
    if body is None and int(row.get('occurrences') or 1)>1:
        # Legacy normalized_features lacks a collector-result foreign key. An
        # aggregate cannot safely assign different repeated-collector snapshots.
        from server.plugin_registry import registry
        envelope=row.get('raw_envelope_json')
        envelope=json.loads(envelope) if isinstance(envelope,str) else envelope
        try:
            plugin=registry.get(envelope['scheme'])
            original=json.loads(plugin.decrypt(envelope))
            if original['payload_id']!=row['payload_id'] or original['agent_id']!=row['agent_id']:
                raise ValueError('identity mismatch')
            observations=[c for c in original['collectors'] if c['collector']==row['collector']]
            metrics=observations[int(row.get('ordinal') or 1)-1].get('payload') or {}
        except Exception:
            raise RuntimeError('ambiguous legacy collector features require the original decryptable envelope') from None
    if isinstance(metrics,str):
        metrics=json.loads(metrics)
    # The interceptor also applies to retained normalized values.
    col['payload']=metrics
    metrics=interceptor_pipeline.process({},dict(payload,collectors=[col])).decrypted_payload['collectors'][0]['payload']
    body=clean if config.store_plaintext_payloads and body is not None else {'_redacted':True}
    ordinal=int(row.get('ordinal') or 1)-1
    suffix=f"{row['payload_id']}:col:{row['collector']}"+(f':{ordinal}' if ordinal else '')
    return normalize(dict(id=str(uuid.uuid5(uuid.NAMESPACE_OID,suffix)),
        payload_id=str(row['payload_id']),agent_id=str(row['agent_id'] or ''),collector=row['collector'],
        collected_at=row['collected_at'],received_at=row.get('received_at') or row['collected_at'],
        hostname=row['hostname'] or '',username=row.get('username') or '',status=row['status'] or 'unknown',
        payload_json=canonical(body).decode(),features_json=canonical(metrics if body=={'_redacted':True} else {}).decode(),
        summary_preview=extract_summary_preview(row['collector'],body),error_type=col['error']['type'],
        error_message=col['error']['message'] if config.store_plaintext_payloads else '',
        source_quality=row.get('source_quality') or 'unknown',accepted_seq=0))


def connect():
    from server.config import config
    from server.storage.postgres_storage import PostgresStorage
    from server.storage.clickhouse_storage import ClickHouseStorage
    from server.plugin_registry import registry
    registry.initialize()
    pg=PostgresStorage(config.database_dsn)
    if pg._is_sqlite:
        raise RuntimeError('migration requires a PostgreSQL deployment')
    pg.ensure_migrations()
    ch=ClickHouseStorage(host=config.clickhouse_host,port=config.clickhouse_port,
        username=config.clickhouse_user,password=config.clickhouse_password,database=config.clickhouse_db,
        secure=config.clickhouse_secure,query_timeout=config.clickhouse_query_timeout,
        max_memory_usage=config.clickhouse_max_memory,dlq_enabled=False)
    if not ch.is_connected():
        pg.close()
        raise RuntimeError('ClickHouse connection unavailable')
    return pg,ch


def pg_rows(pg):
    # Named cursor bounds libpq buffering. The database sorts offline within its
    # configured work_mem; migration may use temporary disk, budgeted separately.
    with pg.connection() as conn,closing(conn.cursor(name='v3_backfill')) as cur:
        cur.itersize=16
        cur.execute('''SELECT cr.payload_id,cr.agent_id,cr.collector,
            COALESCE(cr.collector_collected_at,rp.received_at) AS collected_at,
            rp.received_at,cr.hostname,rp.username,cr.status,cr.payload_json,
            cr.error_type,cr.error_message,cr.source_quality,
            row_number() OVER(PARTITION BY cr.payload_id,cr.collector ORDER BY cr.id) AS ordinal,
            count(*) OVER(PARTITION BY cr.payload_id,cr.collector) AS occurrences,rp.encrypted_envelope_json AS raw_envelope_json,
            (SELECT jsonb_object_agg(nf.feature_name,COALESCE(to_jsonb(nf.feature_value_numeric),
                to_jsonb(nf.feature_value_text),nf.feature_value_json))
             FROM normalized_features nf WHERE nf.payload_id=cr.payload_id AND nf.collector=cr.collector) AS metrics
            FROM collector_results cr LEFT JOIN
             (SELECT DISTINCT ON(payload_id) payload_id,received_at,username,encrypted_envelope_json FROM raw_payloads
              ORDER BY payload_id,received_at) rp ON rp.payload_id=cr.payload_id
            ORDER BY cr.id''')
        columns=[c[0] for c in cur.description]
        for row in cur:
            yield legacy_row(dict(zip(columns,row)))


def ch_rows(ch):
    version=ch.collector_schema_version
    after=None
    page_size=500
    while True:
        params={'limit':page_size}
        where=''
        if after:
            params.update(time=utc(after[0]),id=after[1])
            where='WHERE (collector_collected_at,id)>(%(time)s,toUUID(%(id)s))'
        table='collector_events_v2 FINAL' if version==2 else 'collector_results'
        user='username' if version==2 else "'' AS username"
        received='received_at' if version==2 else 'collector_collected_at AS received_at'
        try:
            result=ch._query(f'''SELECT DISTINCT id,payload_id,agent_id,collector,
                collector_collected_at AS collected_at,{received},hostname,{user},status,
                payload_json,error_type,error_message,source_quality
                FROM {table} {where} ORDER BY collector_collected_at,id LIMIT %(limit)s
                SETTINGS max_result_bytes=16777216,result_overflow_mode='throw' ''',params)
        except Exception as exc:
            if page_size<=1 or not any(s in str(exc).lower() for s in ('limit','result','memory')):
                raise
            page_size=max(1,page_size//2)
            continue
        rows=[dict(zip(result.column_names,r)) for r in result.result_rows]
        if not rows:
            return
        for row in rows:
            # Scope legacy caller-supplied UUIDs to their actual payload. A sensor
            # reusing an ID across snapshots must not collapse unrelated logs.
            converted=legacy_row(row)
            converted['id']=str(uuid.uuid5(uuid.NAMESPACE_OID,
                f"legacy-ch:{row['payload_id']}:{row['collector']}:{row['id']}:{converted['collected_at']}"))
            yield converted
        after=(rows[-1]['collected_at'],str(rows[-1]['id']))


def key(row):
    return tuple(row[k] for k in ('payload_id','collector','collected_at','hostname','status'))


def batches(rows,size=500,max_bytes=8*1024**2):
    batch=[]
    used=0
    for row in rows:
        cost=len(canonical(row))
        if cost>max_bytes:
            raise ValueError('one migration event exceeds byte budget')
        if batch and used+cost>max_bytes:
            yield batch
            batch=[]
            used=0
        batch.append(row)
        used+=cost
        if len(batch)>=size:
            yield batch
            batch=[]
            used=0
    if batch:
        yield batch


def check_space(extra=0):
    directory=Path(os.environ.get('INSIEDR_JOURNAL_DIR','data/ingest-journal'))
    if not directory.is_dir():
        raise RuntimeError('provision/mount the deployment journal directory before migration')
    reserve=int(os.environ.get('INSIEDR_DISK_RESERVE_BYTES',str(50*1024**3)))
    if shutil.disk_usage(directory).free<reserve+extra:
        raise RuntimeError('migration disk reserve exhausted; source retained')


def backfill(pg,ch,events,journal):
    """PG is authoritative for retained snapshots; CH supplies older-only events.

    A staging identity table deduplicates legacy aliases and verifies every
    source observation. It contains metadata/hashes only, not payload copies.
    """
    from psycopg2.extras import execute_batch
    from server.storage.ram_telemetry import seed_legacy_receipts
    from server.config import config
    journal.set_setting('v3_backfill_verified','false')
    seed_legacy_receipts(pg,journal,config.replay_window_hours)
    with pg.connection() as conn,closing(conn.cursor()) as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS telemetry_v3_import_manifest (
            source TEXT NOT NULL, identity TEXT NOT NULL, event_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,logical_key TEXT NOT NULL,run_id TEXT NOT NULL,
            PRIMARY KEY(source,identity))''')
        cur.execute('CREATE INDEX IF NOT EXISTS telemetry_v3_import_run ON telemetry_v3_import_manifest(run_id,source,logical_key)')
        conn.commit()
    run_id=str(uuid.uuid4())
    report={}
    for source,reader in (('postgres',pg_rows(pg)),('clickhouse',ch_rows(ch))):
        count=0
        for batch in batches(reader):
            check_space(4*sum(len(canonical(r)) for r in batch))
            selected=[]
            # Read target logical multiplicity so an existing PG copy is not
            # duplicated merely because a legacy CH record used another UUID.
            params={'pids':list({r['payload_id'] for r in batch})}
            found=ch._query(f'''SELECT payload_id,collector,collected_at,hostname,status,count()
                FROM {TABLE} FINAL WHERE payload_id IN %(pids)s
                GROUP BY payload_id,collector,collected_at,hostname,status''',params)
            multiplicity={tuple([str(r[0]),r[1],utc(r[2]).isoformat(timespec='milliseconds'),r[3],r[4]]):int(r[5]) for r in found.result_rows}
            logical_keys=list({canonical(key(r)).decode() for r in batch})
            with pg.connection() as conn,closing(conn.cursor()) as cur:
                cur.execute('''SELECT logical_key,count(*) FROM telemetry_v3_import_manifest
                    WHERE source=%s AND run_id=%s AND logical_key IN ('''+
                    ','.join(['%s']*len(logical_keys))+') GROUP BY logical_key',tuple([source,run_id]+logical_keys))
                seen={tuple(json.loads(k)):int(n) for k,n in cur.fetchall()}
            scheduled={}
            for row in batch:
                logical=key(row)
                # PG batches are inserted by stable canonical IDs; CH copies are
                # admitted only if their logical multiplicity is not represented.
                seen[logical]=seen.get(logical,0)+1
                if source=='postgres' or seen[logical]>multiplicity.get(logical,0)+scheduled.get(logical,0):
                    selected.append(row)
                    scheduled[logical]=scheduled.get(logical,0)+1
            events.insert(selected)
            if selected:
                copied=ch._query(f"SELECT {','.join(COLUMNS)} FROM {TABLE} FINAL WHERE id IN %(ids)s",
                                {'ids':[r['id'] for r in selected]})
                copies={str(r[0]):normalize(dict(zip(copied.column_names,r))) for r in copied.result_rows}
                if any(r['id'] not in copies or canonical(copies[r['id']])!=canonical(r) for r in selected):
                    raise RuntimeError('backfill content checksum verification failed; cutover forbidden')
            # Verify accepted ID OR its logically identical PG representative.
            verified=ch._query(f'''SELECT payload_id,collector,collected_at,hostname,status,count()
                FROM {TABLE} FINAL WHERE payload_id IN %(pids)s
                GROUP BY payload_id,collector,collected_at,hostname,status''',params)
            available={tuple([str(r[0]),r[1],utc(r[2]).isoformat(timespec='milliseconds'),r[3],r[4]]):int(r[5]) for r in verified.result_rows}
            if any(available.get(k,0)<n for k,n in seen.items()):
                raise RuntimeError('backfill verification failed; cutover forbidden')
            with pg.connection() as conn,closing(conn.cursor()) as cur:
                execute_batch(cur,'''INSERT INTO telemetry_v3_import_manifest VALUES (%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(source,identity) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,
                    logical_key=EXCLUDED.logical_key,run_id=EXCLUDED.run_id''',
                    [(source,r['id'],r['id'],hashlib.sha256(canonical(r)).hexdigest(),canonical(key(r)).decode(),run_id) for r in batch])
                conn.commit()
            # Older identities become tombstones; active retry identities seeded
            # above keep their exact authenticated-envelope hashes.
            journal.seed_receipts([(r['payload_id'],r['agent_id'],{},'',None,r['received_at']) for r in batch])
            count+=len(batch)
        report[source]=count
    after=''
    while True:
        with pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('''SELECT logical_key,max(n) FROM (
                SELECT source,logical_key,count(*) AS n FROM telemetry_v3_import_manifest
                WHERE run_id=%s AND logical_key>%s GROUP BY source,logical_key) q
                GROUP BY logical_key ORDER BY logical_key LIMIT 500''',(run_id,after))
            expected=cur.fetchall()
        if not expected:
            break
        pids=list({json.loads(k)[0] for k,n in expected})
        result=ch._query(f'''SELECT payload_id,collector,collected_at,hostname,status,count()
            FROM {TABLE} FINAL WHERE payload_id IN %(pids)s
            GROUP BY payload_id,collector,collected_at,hostname,status''',{'pids':pids})
        actual={tuple([str(r[0]),r[1],utc(r[2]).isoformat(timespec='milliseconds'),r[3],r[4]]):int(r[5]) for r in result.result_rows}
        if any(actual.get(tuple(json.loads(k)),0)!=int(n) for k,n in expected):
            raise RuntimeError('canonical source-union count verification failed; cutover forbidden')
        after=expected[-1][0]
    report['verified']=True
    report['overlap_policy']='PostgreSQL canonical observations take precedence; ClickHouse supplies missing history'
    report['verified_at']=datetime.now(timezone.utc).isoformat()
    journal.set_setting('v3_backfill_verified','true')
    return report


def all_events(events,archive):
    from datetime import timedelta
    for day in events.days_before(datetime.now(timezone.utc)+timedelta(days=1)):
        after=''
        size=500
        while True:
            try:
                rows=events.partition_rows(day,after,size)
            except Exception as exc:
                if size<=1 or not any(s in str(exc).lower() for s in ('limit','memory','result')):
                    raise
                size=max(1,size//2)
                continue
            if not rows:
                break
            yield from rows
            after=(rows[-1]['collected_at'],rows[-1]['id'])
    # One BYTEA at a time, never all archive bodies in a client cursor result.
    with archive.pg.connection() as conn,closing(conn.cursor()) as cur:
        cur.execute('SELECT day,ordinal FROM telemetry_archive_chunks ORDER BY day,ordinal')
        keys=cur.fetchall()
    for day,ordinal in keys:
        with archive.pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('''SELECT checksum,record_count,plain_bytes,data FROM telemetry_archive_chunks
                           WHERE day=%s AND ordinal=%s''',(day,ordinal))
            yield from archive._decode(*cur.fetchone())


def rollback_export(pg,events,archive,journal):
    """Restore queryable legacy telemetry before any old-image downgrade.

    Agent transport envelopes are not reconstructed. Original retry hashes are
    retained for the active protocol retry horizon; canonical logs/features are
    restored transactionally per payload. Sources and staging are retained.
    """
    from psycopg2.extras import execute_batch,Json
    with pg.connection() as conn,closing(conn.cursor()) as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS telemetry_v3_rollback_stage (
            id TEXT PRIMARY KEY,payload_id TEXT NOT NULL,body JSONB NOT NULL)''')
        cur.execute('CREATE INDEX IF NOT EXISTS telemetry_v3_rollback_payload ON telemetry_v3_rollback_stage(payload_id)')
        conn.commit()
    for batch in batches(all_events(events,archive)):
        check_space(8*sum(len(canonical(r)) for r in batch))
        with pg.connection() as conn,closing(conn.cursor()) as cur:
            execute_batch(cur,'''INSERT INTO telemetry_v3_rollback_stage VALUES (%s,%s,%s)
                ON CONFLICT(id) DO NOTHING''',[(r['id'],r['payload_id'],Json(r)) for r in batch])
            conn.commit()
            ids=[r['id'] for r in batch]
            cur.execute('SELECT id,body FROM telemetry_v3_rollback_stage WHERE id IN ('+
                        ','.join(['%s']*len(ids))+')',tuple(ids))
            stored=dict(cur.fetchall())
            if any(canonical(stored[r['id']])!=canonical(r) for r in batch):
                raise RuntimeError('rollback staging checksum mismatch; downgrade forbidden')
    after=''
    count=0
    while True:
        with pg.connection() as conn,closing(conn.cursor()) as cur:
            cur.execute('''SELECT payload_id FROM telemetry_v3_rollback_stage WHERE payload_id>%s
                           GROUP BY payload_id ORDER BY payload_id LIMIT 1''',(after,))
            item=cur.fetchone()
            if item is None:
                break
            pid=item[0]
            cur.execute('SELECT body FROM telemetry_v3_rollback_stage WHERE payload_id=%s ORDER BY id',(pid,))
            rows=[r[0] for r in cur.fetchall()]
            if len(rows)>4096 or len(canonical(rows))>32*1024**2:
                raise ValueError('rollback payload exceeds restore memory budget')
            check_space(20*len(canonical(rows)))
            cur.execute('SELECT count(*) FROM collector_results WHERE payload_id=%s',(pid,))
            existing=cur.fetchone()[0]
            if existing and existing!=len(rows):
                raise RuntimeError('rollback source/legacy collector count mismatch; downgrade forbidden')
            if not existing:
                first=rows[0]
                cur.execute('INSERT INTO agents(agent_id,hostname) VALUES (%s,%s) ON CONFLICT(agent_id) DO NOTHING',
                            (first['agent_id'],first['hostname']))
                receipt=journal.lookup(pid) or {}
                plain_hash=receipt.get('decrypted_payload_hash') or hashlib.sha256(canonical(rows)).hexdigest()
                cur.execute('''INSERT INTO raw_payloads(payload_id,agent_id,received_at,payload_collected_at,
                    hostname,username,encrypted_envelope_json,validation_status,ciphertext_hash,decrypted_payload_hash)
                    VALUES (%s,%s,%s,%s,%s,%s,'{}','accepted',%s,%s)
                    ON CONFLICT(payload_id,received_at) DO NOTHING''',
                    (pid,first['agent_id'],first['received_at'],first['collected_at'],first['hostname'],first['username'],
                     receipt.get('ciphertext_hash'),plain_hash))
                execute_batch(cur,'''INSERT INTO collector_results(payload_id,agent_id,collector,
                    collector_collected_at,hostname,status,payload_json,error_type,error_message,source_quality)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    [(pid,r['agent_id'],r['collector'],r['collected_at'],r['hostname'],r['status'],
                      None if json.loads(r['payload_json'])=={'_redacted':True} else Json(json.loads(r['payload_json'])),
                      r['error_type'],r['error_message'],r['source_quality']) for r in rows])
                for r in rows:
                    features=feature_rows(r)
                    execute_batch(cur,'''INSERT INTO normalized_features(payload_id,agent_id,username,hostname,
                        collector,entity_user,feature_name,feature_value_numeric,feature_value_text,feature_value_json,
                        feature_timestamp,source_quality,quality_notes) VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        [(f['payload_id'],f['agent_id'],f['username'],f['hostname'],f['collector'],f['entity_user'],
                          f['feature_name'],f['feature_value_numeric'],f['feature_value_text'],
                          Json(f['feature_value_json']) if f['feature_value_json'] is not None else None,
                          f['feature_timestamp'],f['source_quality'],f['quality_notes']) for f in features])
                cur.execute('''INSERT INTO payload_registry(payload_id,agent_id,ciphertext_hash,decrypted_hash)
                               VALUES (%s,%s,%s,%s) ON CONFLICT(payload_id) DO NOTHING''',
                            (pid,first['agent_id'],receipt.get('ciphertext_hash'),plain_hash))
                cur.execute('SELECT count(*) FROM collector_results WHERE payload_id=%s',(pid,))
                if cur.fetchone()[0]!=len(rows):
                    raise RuntimeError('rollback verification failed; downgrade forbidden')
                conn.commit()
            # Count alone is insufficient: validate the complete metadata multiset.
            from collections import Counter
            cur.execute('''SELECT agent_id,collector,collector_collected_at,hostname,status,payload_json FROM collector_results
                           WHERE payload_id=%s''',(pid,))
            restored_rows=cur.fetchall()
            actual=Counter((r[0],r[1],utc(r[2]).isoformat(timespec='milliseconds'),r[3] or '',r[4] or 'unknown') for r in restored_rows)
            expected=Counter((r['agent_id'],r['collector'],r['collected_at'],r['hostname'],r['status']) for r in rows)
            if actual!=expected:
                raise RuntimeError('rollback metadata verification failed; downgrade forbidden')
            actual_bodies=Counter((r[0],r[1],utc(r[2]).isoformat(timespec='milliseconds'),
                canonical(json.loads(r[5]) if isinstance(r[5],str) else r[5])) for r in restored_rows)
            expected_bodies=Counter((r['agent_id'],r['collector'],r['collected_at'],canonical(json.loads(r['payload_json'])))
                for r in rows if json.loads(r['payload_json'])!={'_redacted':True})
            if any(actual_bodies[k]<n for k,n in expected_bodies.items()):
                raise RuntimeError('rollback payload verification failed; downgrade forbidden')
            cur.execute('''SELECT collector,feature_name,feature_value_numeric,feature_value_text,
                feature_value_json,feature_timestamp,entity_user FROM normalized_features
                WHERE payload_id=%s LIMIT 200001''',(pid,))
            features=cur.fetchall()
            if len(features)>200000:
                raise ValueError('rollback feature verification exceeds budget')
            actual_features=Counter(canonical([r[0],r[1],r[2],r[3],
                json.loads(r[4]) if isinstance(r[4],str) else r[4],
                utc(r[5]).isoformat(timespec='milliseconds'),r[6] or '']) for r in features)
            expected_features=Counter(canonical([f['collector'],f['feature_name'],f['feature_value_numeric'],
                f['feature_value_text'],f['feature_value_json'],utc(f['feature_timestamp']).isoformat(timespec='milliseconds'),
                f['entity_user'] or '']) for row in rows for f in feature_rows(row))
            if actual_features!=expected_features:
                raise RuntimeError('rollback feature verification failed; downgrade forbidden')
            after=pid
            count+=len(rows)
    return dict(verified=True,records=count,verified_at=datetime.now(timezone.utc).isoformat())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['backfill','rollback-export'])
    parser.add_argument('--offline',action='store_true',help='Assert every backend writer has been stopped')
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    if not args.offline:
        parser.error('--offline is required; stop backend writers before migration')
    pg,ch=connect()
    journal=None
    try:
        events=ClickHouseEvents(ch)
        events.ensure_schema()
        archive=PostgresArchive(pg)
        archive.ensure_schema()
        if args.operation=='backfill':
            import base64
            journal=IngestJournal(os.environ.get('INSIEDR_JOURNAL_DIR','data/ingest-journal'),
                base64.b64decode(os.environ['INSIEDR_JOURNAL_KEY'],validate=True),
                max_bytes=int(os.environ.get('INSIEDR_JOURNAL_MAX_BYTES',str(20*1024**3))),
                reserve_bytes=int(os.environ.get('INSIEDR_DISK_RESERVE_BYTES',str(50*1024**3))))
            with pg.connection() as conn,closing(conn.cursor()) as cur:
                cur.execute("SELECT count(*) FROM clickhouse_outbox WHERE status IN ('pending','processing')")
                if cur.fetchone()[0]:
                    raise RuntimeError('drain the legacy outbox before stopping backend writers')
            result=backfill(pg,ch,events,journal)
        else:
            import base64
            directory=os.environ.get('INSIEDR_JOURNAL_DIR','data/ingest-journal')
            if not (Path(directory)/'journal.sqlite3').is_file():
                raise RuntimeError('existing deployment journal is required for rollback')
            journal=IngestJournal(directory,
                base64.b64decode(os.environ['INSIEDR_JOURNAL_KEY'],validate=True))
            if journal.stats()['pending']:
                raise RuntimeError('drain the journal with the current image before rollback-export')
            if journal.setting('v3_backfill_verified')!='true':
                raise RuntimeError('deployment journal has no verified backfill marker')
            result=rollback_export(pg,events,archive,journal)
        path=Path(args.report)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result))
    finally:
        if journal:
            journal.close()
        ch.close()
        pg.close()


if __name__=='__main__':
    main()
