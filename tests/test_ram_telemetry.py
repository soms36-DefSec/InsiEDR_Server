"""Independent fault/recovery checks for the opt-in telemetry plane."""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock
import uuid

import pytest

from server.storage.ingest_journal import IngestJournal, canonical
from server.storage.ram_telemetry import RAMTelemetryStorage, project, matches, RecentRedis
from server.storage.storage_pressure import PressureController, Level
from server.storage.telemetry_archive import PostgresArchive


def payload(pid=None, timestamp=None):
    now = timestamp or datetime.now(timezone.utc).isoformat()
    return dict(payload_id=pid or str(uuid.uuid4()), agent_id='agent-1', collected_at=now,
                hostname='host', username='user', collectors=[dict(collector='process',
                hostname='host', status='success', collected_at=now,
                payload={'password': 'secret-value', 'count': 42})])


@pytest.fixture
def journal(tmp_path):
    j = IngestJournal(tmp_path/'journal', b'k'*32, reserve_bytes=0, group_seconds=.001)
    yield j
    j.close()


class Source:
    def __init__(self):
        self.rows = []
        self.fail = False
        self.dropped = []

    def insert(self, rows):
        if self.fail:
            raise OSError('ClickHouse offline')
        self.rows.extend(copy.deepcopy(rows))

    def query(self, filters, snapshot, limit,*,metadata_only=False):
        rows = {r['id']: r for r in self.rows if matches(r, filters, snapshot)}
        return sorted(rows.values(), key=lambda r:(r['collected_at'],r['id']), reverse=True)[:limit]

    def partition_rows(self, day, after='', limit=1000):
        rows = {r['id']:r for r in self.rows if r['received_at'][:10] == day
                and (not after or (r['collected_at'],r['id']) > tuple(after))}
        return sorted(rows.values(), key=lambda r:(r['collected_at'],r['id']))[:limit]

    def drop_day(self, day):
        self.dropped.append(day)
        self.rows = [r for r in self.rows if r['received_at'][:10] != day]

    def count_day(self,day):
        return len({r['id'] for r in self.rows if r['received_at'][:10]==day})

    def state_index(self,day):
        latest={}
        for r in self.rows:
            if r['received_at'][:10]!=day:
                continue
            key=(r['agent_id'],r['collector'])
            if key not in latest or (r['collected_at'],r['id'])>(latest[key]['collected_at'],latest[key]['id']):
                latest[key]=r
        return list(latest.values())

    def latest(self,agent_id=None,username=None):
        rows=[r for r in self.rows if (not agent_id or r['agent_id']==agent_id)
              and (not username or r['username']==username)]
        latest={}
        for r in rows:
            if r['collector'] not in latest or (r['collected_at'],r['id'])>(latest[r['collector']]['collected_at'],latest[r['collector']]['id']):
                latest[r['collector']]=r
        return list(latest.values())

    def aggregate(self,filters,snapshot,seconds=0):
        rows={r['id']:r for r in self.rows if matches(r,filters,snapshot)}
        from server.storage.ram_telemetry import utc
        counts={}
        for r in rows.values():
            bucket=int(utc(r['collected_at']).timestamp())//seconds*seconds if seconds else 0
            key=(r['collector'],r['status'],bucket)
            counts[key]=counts.get(key,0)+1
        return [dict(collector=k[0],status=k[1],bucket=k[2],count=n) for k,n in counts.items()]

    def days_before(self, cutoff):
        return sorted({r['received_at'][:10] for r in self.rows if r['received_at'][:10] < cutoff.date().isoformat()})


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, sql, params=()):
        return self.cursor.execute(sql.replace('%s', '?'), params)

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class PG:
    """Exercise actual SQL/transactions with SQLite's compatible test subset.

    This is NOT a PostgreSQL integration test; target-engine validation is separate.
    """
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)

    @contextmanager
    def connection(self):
        class Connection:
            def cursor(inner):
                return Cursor(self.db.cursor())
            def commit(inner):
                return self.db.commit()
        try:
            yield Connection()
        finally:
            self.db.rollback()


@pytest.fixture
def archive(tmp_path):
    pg = PG(tmp_path/'archive.sqlite')
    result = PostgresArchive(pg, chunk_rows=2, chunk_bytes=4096)
    result.ensure_schema()
    yield result
    pg.db.close()


def storage(journal, archive):
    legacy = SimpleNamespace(pg=archive.pg, ch=Mock(), fleet=Mock(),
                             get_payload=lambda pid: None, close=Mock())
    return RAMTelemetryStorage(legacy, journal, Source(), archive, start=False)


def test_journal_encrypts_and_rejects_conflicting_retry(journal):
    p = payload()
    assert journal.append({'ciphertext':'encrypted'}, p)
    assert journal.append({'ciphertext':'encrypted'}, p) is False
    assert journal.pending()[0]['payload'] == p
    with pytest.raises(ValueError, match='duplicate'):
        journal.append({'ciphertext':'changed'}, p)
    for file in journal.directory.glob('journal.sqlite3*'):
        assert b'secret-value' not in file.read_bytes()


def test_completed_record_reclaims_body_but_preserves_retry_receipt(journal):
    p = payload()
    seq = journal.append({}, p)
    journal.complete([seq])
    assert journal.pending() == []
    assert journal.lookup(p['payload_id'])
    assert journal.append({}, p) is False


def test_journal_survives_abrupt_process_exit(tmp_path):
    directory = str(tmp_path/'crash')
    code = """import os,sys
from server.storage.ingest_journal import IngestJournal
j=IngestJournal(sys.argv[1],b'k'*32,reserve_bytes=0,group_seconds=.001)
j.append({'ciphertext':'cipher'},{'payload_id':'durable','agent_id':'a'})
os._exit(0)
"""
    subprocess.run([sys.executable, '-c', code, directory], check=True,
                   cwd=Path(__file__).resolve().parents[1])
    j = IngestJournal(directory,b'k'*32,reserve_bytes=0,group_seconds=.001)
    try:
        assert j.pending()[0]['payload_id'] == 'durable'
        assert j.lookup('durable')
    finally:
        j.close()


def test_owner_lock_and_key_validation(journal):
    with pytest.raises(RuntimeError, match='owned'):
        IngestJournal(journal.directory,b'k'*32,reserve_bytes=0)
    directory = journal.directory
    journal.close()
    with pytest.raises(ValueError, match='key'):
        IngestJournal(directory,b'x'*32,reserve_bytes=0)


def test_full_journal_refuses_new_data_without_evicting_existing(journal):
    first = payload()
    journal.append({}, first)
    journal.max_bytes = 1
    with pytest.raises(RuntimeError, match='capacity'):
        journal.append({}, payload())
    assert journal.pending()[0]['payload_id'] == first['payload_id']


def test_failed_clickhouse_write_keeps_accepted_record(journal, archive):
    store = storage(journal, archive)
    p = payload()
    store.store_raw_payload({}, p)
    store.events.fail = True
    with pytest.raises(OSError):
        store.replay_once()
    assert journal.stats()['pending'] == 1


def test_queries_include_pending_and_redact_payload(journal, archive):
    store = storage(journal, archive)
    p = payload()
    store.store_raw_payload({},p)
    page = store.get_telemetry_page()
    assert len(page['logs']) == 1
    assert page['logs'][0]['payload'] == {'_redacted': True}
    assert 'secret-value' not in str(page)


def test_regrouped_replay_deduplicates_before_pagination(journal, archive):
    store = storage(journal, archive)
    now = datetime.now(timezone.utc)
    for i in range(5):
        p = payload(timestamp=(now-timedelta(seconds=i)).isoformat())
        store.events.rows.extend(project(p,now.isoformat(),True)*2)
    first = store.get_telemetry_page(limit=2)
    second = store.get_telemetry_page(limit=2,cursor=first['next_cursor'])
    third = store.get_telemetry_page(limit=2,cursor=second['next_cursor'])
    ids = [r['id'] for page in (first,second,third) for r in page['logs']]
    assert len(ids) == len(set(ids)) == 5
    assert not third['has_more']


def archived_source(count=5):
    source = Source()
    now = datetime.now(timezone.utc)-timedelta(days=31)
    for _ in range(count):
        source.rows.extend(project(payload(timestamp=now.isoformat()),now.isoformat(),True))
    return source,now.date().isoformat()


def test_archive_verifies_all_chunks_before_drop_and_reads_old_data(archive):
    source,day = archived_source()
    assert archive.archive_day(source,day)
    assert source.dropped == [day]
    filters = dict(start_time=day+'T00:00:00+00:00',end_time=day+'T23:59:59+00:00')
    rows = archive.query(filters, datetime.now(timezone.utc).isoformat(),100)
    assert len(rows) == 5
    assert archive.pg.db.execute('SELECT state,record_count FROM telemetry_archive_days').fetchone() == ('verified',5)


def test_archive_interruption_is_restartable_and_never_drops_partial_day(archive):
    source,day = archived_source()
    ticks = iter([True,False])
    assert archive.archive_day(source,day,continue_work=lambda:next(ticks)) is False
    assert archive.pg.db.execute('SELECT count(*) FROM telemetry_archive_chunks').fetchone()[0]==1
    assert source.dropped == []
    assert archive.archive_day(source,day)
    assert source.dropped == [day]


def test_corrupt_archive_prevents_source_deletion(archive):
    source,day = archived_source()
    original = archive._write_chunk
    def corrupt(*args):
        original(*args)
        archive.pg.db.execute("UPDATE telemetry_archive_chunks SET checksum='bad'")
        archive.pg.db.commit()
    archive._write_chunk = corrupt
    with pytest.raises(RuntimeError,match='verification|reconciliation'):
        archive.archive_day(source,day)
    assert source.dropped == []


def test_archive_query_budget_never_silently_truncates(archive):
    source,day = archived_source()
    archive.archive_day(source,day)
    archive.query_bytes = 1
    with pytest.raises(ValueError,match='budget'):
        archive.query(dict(start_time=day+'T00:00:00+00:00',end_time=day+'T23:59:59+00:00'),
                      datetime.now(timezone.utc).isoformat(),100)


def test_pressure_hysteresis_and_immediate_hard_limit():
    c = PressureController()
    for _ in range(2):
        c.sample({'disk_latency_ms':100})
        assert c.level == Level.NORMAL
    c.sample({'disk_latency_ms':100})
    assert c.level == Level.PRESSURED
    c.sample({'memory_ratio':.99})
    assert c.level == Level.CRITICAL
    for _ in range(5):
        limits=c.sample({})
    assert c.level == Level.NORMAL and limits.archive


def test_redis_cache_failure_is_expendable():
    client = Mock()
    client.get.side_effect = OSError('offline')
    client.set.side_effect = OSError('offline')
    cache = RecentRedis(client)
    assert cache.get('key') is None
    cache.put('key',{'logs':[]})


def test_failed_postgres_metadata_does_not_reinsert_durable_clickhouse_batch(journal,archive,monkeypatch):
    store=storage(journal,archive)
    store.store_raw_payload({},payload())
    store.legacy.fleet.upsert_agent.side_effect=OSError('PostgreSQL offline')
    with pytest.raises(OSError):
        store.replay_once()
    assert journal.pending()[0]['analytics_done']
    assert len(store.events.rows)==1
    store.legacy.fleet.upsert_agent.side_effect=None
    monkeypatch.setattr('server.risk.pipeline.process_telemetry_risk',Mock())
    assert store.replay_once()==1
    assert len(store.events.rows)==1
    assert journal.stats()['pending']==0


def test_pre_cutover_retry_receipts_survive_postgres_outage(journal,archive):
    from server.storage.ingest_journal import digest
    from server.api.ingest import _check_duplicate_policy
    p=payload()
    envelope={'ciphertext':'original'}
    journal.seed_receipts([(p['payload_id'],p['agent_id'],envelope,'original-hash',None,p['collected_at'])])
    store=storage(journal,archive)
    store.legacy.get_payload=Mock(side_effect=OSError('PostgreSQL offline'))
    assert _check_duplicate_policy(store,envelope,p)
    store.legacy.get_payload.assert_not_called()


def test_source_count_mismatch_blocks_partition_drop(archive):
    source,day=archived_source()
    source.count_day=lambda day:6
    with pytest.raises(RuntimeError,match='reconciliation'):
        archive.archive_day(source,day)
    assert source.dropped==[]


def test_feature_vectors_preserve_zero_and_false_without_plaintext_body(journal,archive):
    store=storage(journal,archive)
    p=payload()
    p['collectors'][0]['payload']={'zero':0,'flag':False,'missing':None}
    store.store_raw_payload({},p)
    vector=store.get_feature_vector(p['payload_id'])
    assert vector=={'zero':0.0,'flag':0.0}


def test_encrypted_http_ack_matches_real_agent_and_is_durable_before_return(journal,archive,monkeypatch):
    import base64
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server.api.logs import router
    from server.crypto.aesgcm_plugin import AESGCMPlugin,AES_GCM_AAD
    from server.plugin_registry import registry
    from shared.protocol import encrypted_payload_headers
    monkeypatch.setenv('INSIEDR_REQUIRE_HTTPS','false')
    monkeypatch.setenv('INSIEDR_AUTH_ENFORCED','false')
    monkeypatch.setenv('INSIEDR_AGENT_AUTH_ENFORCED','false')
    monkeypatch.setenv('INSIEDR_ENABLE_LOG_INGESTION','true')
    store=storage(journal,archive)
    app=FastAPI()
    app.state.storage=store
    app.include_router(router)
    key=b'e'*32
    monkeypatch.setitem(registry._plugins,'aes-256-gcm',AESGCMPlugin(key))
    p=payload()
    p.update(schema='insiedr.agent.telemetry.v1',protocol_version='2.0',
             summary={'collector_count':1,'success_count':1,'failed_count':0})
    nonce=os.urandom(12)
    envelope=dict(protocol_version='2.0',scheme='aes-256-gcm',key_id='test',payload_id=p['payload_id'],
                  created_at=p['collected_at'],nonce=base64.b64encode(nonce).decode(),
                  ciphertext=base64.b64encode(AESGCM(key).encrypt(nonce,json.dumps(p).encode(),AES_GCM_AAD)).decode())
    headers=encrypted_payload_headers(envelope,p['agent_id'],p['payload_id'])
    risk=Mock()
    monkeypatch.setattr('server.risk.pipeline.process_telemetry_risk',risk)
    with TestClient(app) as client:
        response=client.post('/api/logs',json=envelope,headers=headers)
        assert response.status_code==202,response.text
        assert response.json()=={'ok':True,'payload_id':p['payload_id'],'status':'accepted'}
        assert journal.lookup(p['payload_id']) and journal.stats()['pending']==1
        assert client.post('/api/logs',json=envelope,headers=headers).status_code==202
        assert journal.stats()['pending']==1
    risk.assert_not_called()


def test_identity_cleanup_waits_for_actual_data_expiry(journal):
    old=datetime.now(timezone.utc)-timedelta(days=100)
    journal.seed_receipts([('retained','agent',{},'',None,old.isoformat())])
    journal.compact(90*24,(old-timedelta(days=1)).isoformat())
    assert journal.lookup('retained')
    journal.compact(90*24,(old+timedelta(days=1)).isoformat())
    assert journal.lookup('retained') is None
    previous=journal.revision
    assert journal.append({},payload())==previous+1


def test_payload_identity_cannot_be_reused_during_retention(journal,archive):
    from server.api.ingest import _check_duplicate_policy,IngestError
    p=payload()
    journal.seed_receipts([(p['payload_id'],p['agent_id'],{},'',None,
                           (datetime.now(timezone.utc)-timedelta(days=20)).isoformat())])
    with pytest.raises(IngestError,match='different'):
        _check_duplicate_policy(storage(journal,archive),{'ciphertext':'new-content'},p)


def test_collector_supplied_ids_cannot_collapse_different_payloads():
    p1,p2=payload(),payload()
    reused=str(uuid.uuid4())
    p1['collectors'][0]['id']=p2['collectors'][0]['id']=reused
    at=datetime.now(timezone.utc).isoformat()
    assert project(p1,at,False)[0]['id']!=project(p2,at,False)[0]['id']


def test_archive_preserves_sparse_collector_state_and_summary_counts(journal,archive):
    source,day=archived_source()
    assert archive.archive_day(source,day)
    store=storage(journal,archive)
    store.events=source
    assert store.count_collector_results()==5
    states=store.get_latest_collector_states('agent-1')
    assert len(states)==1 and states[0]['collector']=='process'


def test_partial_archive_overlap_is_not_double_counted(journal,archive):
    source,day=archived_source()
    source.drop_day=Mock()
    assert archive.archive_day(source,day)
    store=storage(journal,archive)
    store.events=source
    assert store.count_collector_results()==5


def test_exact_page_total_counts_pending_events(journal,archive):
    store=storage(journal,archive)
    store.store_raw_payload({},payload())
    page=store.get_telemetry_page(include_total=True,include_enrichment=True)
    assert page['total']==1 and page['total_available']
    assert page['enrichment_available'] is False


def test_cursor_snapshot_excludes_new_acceptance_in_same_millisecond(journal,archive,monkeypatch):
    fixed=datetime.now(timezone.utc).replace(microsecond=0)
    class Frozen(datetime):
        @classmethod
        def now(cls,tz=None):
            return fixed
    monkeypatch.setattr('server.storage.ram_telemetry.datetime',Frozen)
    monkeypatch.setattr('server.storage.ingest_journal.datetime',Frozen)
    store=storage(journal,archive)
    old=[]
    for second in (1,2,3):
        p=payload(timestamp=(fixed-timedelta(seconds=second)).isoformat())
        old.append(p['payload_id'])
        store.store_raw_payload({},p)
    first=store.get_telemetry_page(limit=1)
    new=payload(timestamp=(fixed-timedelta(seconds=2.5)).isoformat())
    store.store_raw_payload({},new)
    rest=store.get_telemetry_page(limit=100,cursor=first['next_cursor'])
    assert {r['payload_id'] for r in rest['logs']}==set(old[1:])


def test_unprojectable_or_nonfinite_record_is_not_acknowledged(journal,archive):
    store=storage(journal,archive)
    p=payload()
    p['collectors'][0]['collected_at']='not-a-timestamp'
    with pytest.raises(ValueError):
        store.store_raw_payload({},p)
    assert journal.stats()['pending']==0
    p=payload()
    p['collectors'][0]['payload']={'count':float('nan')}
    with pytest.raises(ValueError):
        store.store_raw_payload({},p)
    assert journal.stats()['pending']==0


def test_legacy_randomized_token_retry_keeps_original_plaintext_identity(journal,archive):
    from server.api.ingest import _check_duplicate_policy
    store=storage(journal,archive)
    p=payload()
    journal.append({'token':'first-encryption'},p)
    assert _check_duplicate_policy(store,{'token':'second-encryption'},p)


def test_journals_have_distinct_persistent_cache_namespaces(tmp_path):
    first=IngestJournal(tmp_path/'one',b'k'*32,reserve_bytes=0)
    second=IngestJournal(tmp_path/'two',b'k'*32,reserve_bytes=0)
    namespace=first.cache_namespace
    assert namespace!=second.cache_namespace
    first.close()
    first=IngestJournal(tmp_path/'one',b'k'*32,reserve_bytes=0)
    assert first.cache_namespace==namespace
    first.close()
    second.close()


def test_ambiguous_commit_error_keeps_committed_receipt_and_highwater(journal):
    original=journal._db
    class CommitError:
        failed=False
        def __getattr__(self,name):
            return getattr(original,name)
        def commit(self):
            original.commit()
            if not self.failed:
                self.failed=True
                raise OSError('commit completed but response was lost')
    journal._db=CommitError()
    p=payload()
    with pytest.raises(OSError):
        journal.append({},p)
    assert journal.lookup(p['payload_id'])
    assert journal.revision==journal.pending()[0]['seq']
    assert journal.append({},p) is False


def test_durable_acceptance_does_not_wait_for_a_slow_redis_bridge(journal,archive,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    entered,release=threading.Event(),threading.Event()
    class SlowCache(RecentRedis):
        def append_rows(self,rows,revision):
            entered.set()
            assert release.wait(5)
        def seed(self,*args):
            pass
        def publish(self,*args):
            pass
        def mark_searchable(self,*args):
            pass
    legacy=SimpleNamespace(pg=archive.pg,ch=Mock(),fleet=Mock(),close=Mock())
    store=RAMTelemetryStorage(legacy,journal,Source(),archive,
        cache=SlowCache(SimpleNamespace(close=Mock())),start=True)
    monkeypatch.setattr('server.risk.pipeline.process_telemetry_risk',Mock())
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            result=executor.submit(store.store_raw_payload,{},payload())
            assert entered.wait(2)
            assert result.result(timeout=.5) is True
            assert not release.is_set()
    finally:
        release.set()
        store.close()


def test_error_credentials_are_scrubbed_before_canonical_storage(journal,archive):
    store=storage(journal,archive)
    store.store_plaintext=True
    p=payload()
    p['collectors'][0]['error']={'type':'Failure','message':'tool --password=private-value'}
    store.store_raw_payload({},p)
    page=store.get_telemetry_page()
    assert 'private-value' not in str(page)
    assert '[REDACTED]' in page['logs'][0]['error_message']


def test_critical_pressure_blocks_persistent_analytics(journal,archive):
    from server.api.errors import AnalyticsUnavailableError
    store=storage(journal,archive)
    store.controller.level=Level.CRITICAL
    with pytest.raises(AnalyticsUnavailableError):
        store.get_telemetry_histogram()
    with pytest.raises(AnalyticsUnavailableError):
        store.get_telemetry_event_detail(str(uuid.uuid4()))


def test_accepted_projection_is_stable_when_interceptors_change(journal,archive,monkeypatch):
    from server.storage.interceptors import interceptor_pipeline
    monkeypatch.setattr(interceptor_pipeline,'_interceptors',list(interceptor_pipeline._interceptors))
    state={'count':73}
    def enrich(ctx):
        ctx.decrypted_payload['collectors'][0]['payload']['count']=state['count']
        return ctx
    interceptor_pipeline.register(enrich,order=999,required=True)
    store=storage(journal,archive)
    store.store_raw_payload({},payload())
    record=journal.pending()[0]
    before=store._record_rows(record)
    state['count']=99
    assert store._record_rows(record)==before
    assert record['payload']['collectors'][0]['payload']['count']==73
    assert 'secret-value' not in str(record['payload'])


def test_ingest_admission_reserves_parsed_memory(journal,archive):
    from server.config import config
    store=storage(journal,archive)
    first=store.enter_ingest(config.max_request_bytes)
    assert first>0
    assert store.enter_ingest(config.max_request_bytes)==0
    store.leave_ingest(first)
    small=[store.enter_ingest(4096) for _ in range(16)]
    assert all(small)
    assert store.enter_ingest(4096)==0
    for reservation in small:
        store.leave_ingest(reservation)
    assert store._active_ingest_bytes==0
