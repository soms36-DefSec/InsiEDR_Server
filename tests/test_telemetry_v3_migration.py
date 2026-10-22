"""Migration algorithm checks; target-engine SQL remains an integration gate."""
import copy
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import telemetry_v3 as migration
from server.storage.ram_telemetry import COLUMNS,project
from test_ram_telemetry import PG,Source,payload,journal
from server.storage.telemetry_archive import PostgresArchive


class CHModel:
    def __init__(self,events):
        self.events=events

    def _query(self,sql,params):
        rows=list({r['id']:r for r in self.events.rows}.values())
        if 'ids' in params:
            rows=[r for r in rows if r['id'] in params['ids']]
            return SimpleNamespace(column_names=list(COLUMNS),result_rows=[tuple(r[c] for c in COLUMNS) for r in rows])
        groups={}
        for row in rows:
            if row['payload_id'] in params['pids']:
                key=migration.key(row)
                groups[key]=groups.get(key,0)+1
        return SimpleNamespace(result_rows=[tuple(k)+(n,) for k,n in groups.items()])


@pytest.fixture
def backfill_model(tmp_path,monkeypatch):
    pg=PG(tmp_path/'manifest.sqlite')
    events=Source()
    p=payload()
    p['collectors']=[copy.deepcopy(p['collectors'][0]) for _ in range(5)]
    rows=project(p,p['collected_at'],False)
    ch_rows=[dict(r,id=str(__import__('uuid').uuid4())) for r in rows]
    monkeypatch.setattr(migration,'pg_rows',lambda pg:iter(rows[:2]))
    monkeypatch.setattr(migration,'ch_rows',lambda ch:iter(ch_rows))
    monkeypatch.setattr(migration,'check_space',lambda extra:None)
    original=migration.batches
    monkeypatch.setattr(migration,'batches',lambda rows:original(rows,size=2))
    monkeypatch.setattr('server.storage.ram_telemetry.seed_legacy_receipts',
                        lambda pg,j,h:j.set_setting('legacy_receipts_seeded','true'))
    monkeypatch.setattr('psycopg2.extras.execute_batch',
                        lambda cur,sql,values:[cur.execute(sql,row) for row in values])
    yield pg,CHModel(events),events
    pg.db.close()


def test_backfill_counts_repeated_collectors_across_batch_boundaries(backfill_model,journal):
    pg,ch,events=backfill_model
    report=migration.backfill(pg,ch,events,journal)
    assert report['verified'] and report['postgres']==2 and report['clickhouse']==5
    assert len({r['id'] for r in events.rows})==5
    assert journal.setting('v3_backfill_verified')=='true'


def test_backfill_can_resume_without_duplicating_logical_observations(backfill_model,journal):
    pg,ch,events=backfill_model
    assert migration.backfill(pg,ch,events,journal)['verified']
    assert migration.backfill(pg,ch,events,journal)['verified']
    assert len({r['id'] for r in events.rows})==5


def test_backfill_refuses_a_corrupted_destination_and_clears_ready_marker(backfill_model,journal):
    pg,ch,events=backfill_model
    original=events.insert
    def corrupt(rows):
        original(rows)
        events.rows[-1]['payload_json']='{"corrupted":true}'
    events.insert=corrupt
    journal.set_setting('v3_backfill_verified','true')
    with pytest.raises(RuntimeError,match='checksum'):
        migration.backfill(pg,ch,events,journal)
    assert journal.setting('v3_backfill_verified')=='false'


def test_legacy_projection_scrubs_credentials_and_preserves_zero(monkeypatch):
    monkeypatch.setenv('INSIEDR_STORE_PLAINTEXT_PAYLOADS','false')
    at=datetime.now(timezone.utc).isoformat()
    row=migration.legacy_row(dict(payload_id='p',agent_id='a',collector='process',hostname='host',
        username='u',status='success',collected_at=at,received_at=at,payload_json=None,
        metrics={'count':0,'password':'private-secret'}))
    assert row['payload_json']=='{"_redacted":true}'
    assert 'private-secret' not in str(row)
    assert '"count":0' in row['features_json']


def test_ambiguous_legacy_metrics_are_not_assigned_to_arbitrary_observations():
    at=datetime.now(timezone.utc).isoformat()
    with pytest.raises(RuntimeError,match='ambiguous'):
        migration.legacy_row(dict(payload_id='p',agent_id='a',collector='process',hostname='host',
            status='success',collected_at=at,payload_json=None,occurrences=2,ordinal=1,
            metrics={'count':42}))


def test_migration_batches_are_bounded_by_bytes():
    rows=[{'data':'x'*100} for _ in range(10)]
    chunks=list(migration.batches(rows,size=500,max_bytes=250))
    assert len(chunks)==5 and all(len(c)==2 for c in chunks)


def test_main_compose_does_not_enable_ram_telemetry_by_default():
    yaml=pytest.importorskip('yaml')
    root=Path(__file__).resolve().parents[1]
    compose=yaml.safe_load((root/'docker-compose.yml').read_text())
    backend=compose['services']['backend']
    environment=backend.get('environment', {})
    assert environment.get('INSIEDR_RAM_TELEMETRY_ENABLED') not in (True, 'true', '1')


class RestorePG(PG):
    @contextmanager
    def connection(self):
        database=self.db
        class Cursor:
            def __init__(self):
                self.raw=database.cursor()
            def execute(self,sql,args=()):
                args=tuple(json.dumps(v.adapted) if hasattr(v,'adapted') else v for v in args)
                return self.raw.execute(sql.replace('%s','?'),args)
            def decode(self,row):
                if row is None:
                    return None
                return tuple(json.loads(v) if self.raw.description[i][0]=='body' and isinstance(v,str) else v
                             for i,v in enumerate(row))
            def fetchone(self):
                return self.decode(self.raw.fetchone())
            def fetchall(self):
                return [self.decode(r) for r in self.raw.fetchall()]
            def close(self):
                self.raw.close()
        class Connection:
            def cursor(self):
                return Cursor()
            def commit(self):
                database.commit()
        try:
            yield Connection()
        finally:
            database.rollback()

    def _upsert_agent(self,cur,p):
        cur.execute('INSERT INTO agents(agent_id,hostname) VALUES (%s,%s) ON CONFLICT(agent_id) DO NOTHING',
                    (p['agent_id'],p['hostname']))


@pytest.fixture
def restore_model(tmp_path,monkeypatch):
    path=tmp_path/'legacy.sqlite'
    pg=RestorePG(path)
    pg.db.executescript('''
      CREATE TABLE agents(agent_id TEXT PRIMARY KEY,hostname TEXT);
      CREATE TABLE raw_payloads(payload_id TEXT,agent_id TEXT,received_at TEXT,
        envelope_created_at TEXT,payload_collected_at TEXT,hostname TEXT,username TEXT,
        crypto_scheme TEXT,key_id TEXT,ciphertext_hash TEXT,decrypted_payload_hash TEXT,
        encrypted_envelope_json JSONB,validation_status TEXT,PRIMARY KEY(payload_id,received_at));
      CREATE TABLE collector_results(id INTEGER PRIMARY KEY,payload_id TEXT,agent_id TEXT,collector TEXT,
        collector_collected_at TEXT,hostname TEXT,status TEXT,payload_json JSONB,error_type TEXT,
        error_message TEXT,source_quality TEXT);
      CREATE TABLE normalized_features(id INTEGER PRIMARY KEY,payload_id TEXT,agent_id TEXT,username TEXT,
        hostname TEXT,collector TEXT,entity_user TEXT,feature_name TEXT,feature_value_numeric REAL,
        feature_value_text TEXT,feature_value_json JSONB,feature_timestamp TEXT,source_quality TEXT,quality_notes TEXT);
      CREATE TABLE payload_registry(payload_id TEXT PRIMARY KEY,agent_id TEXT,ciphertext_hash TEXT,decrypted_hash TEXT);
    ''')
    archive=PostgresArchive(pg)
    archive.ensure_schema()
    monkeypatch.setattr(migration,'check_space',lambda extra:None)
    monkeypatch.setattr('psycopg2.extras.execute_batch',
                        lambda cur,sql,values:[cur.execute(sql,row) for row in values])
    yield pg,archive,path
    pg.db.close()


def test_rollback_restores_metadata_features_and_legacy_retry_identity(restore_model,journal):
    from server.storage.postgres_storage import PostgresStorage
    from server.api.ingest import _check_duplicate_policy
    pg,archive,path=restore_model
    p=payload()
    p['collectors'][0]['payload']={'zero':0,'flag':False}
    envelope={'ciphertext':'sealed-original'}
    seq=journal.append(envelope,p)
    received=journal.lookup(p['payload_id'])['received_at']
    events=Source()
    events.rows=project(p,received,False,seq)
    journal.complete([seq])
    assert migration.rollback_export(pg,events,archive,journal)['verified']
    assert pg.db.execute('SELECT count(*) FROM collector_results').fetchone()[0]==1
    values=dict(pg.db.execute('SELECT feature_name,feature_value_numeric FROM normalized_features').fetchall())
    assert values=={'zero':0.0,'flag':0.0}
    old_storage=PostgresStorage(connection_factory=lambda:sqlite3.connect(path))
    assert _check_duplicate_policy(old_storage,envelope,p)
    assert migration.rollback_export(pg,events,archive,journal)['verified']
    assert pg.db.execute('SELECT count(*) FROM collector_results').fetchone()[0]==1
    assert len(events.rows)==1


def test_rollback_verification_refuses_corrupted_legacy_feature_values(restore_model,journal):
    pg,archive,path=restore_model
    p=payload()
    p['collectors'][0]['payload']={'zero':0}
    seq=journal.append({},p)
    events=Source()
    events.rows=project(p,journal.lookup(p['payload_id'])['received_at'],False,seq)
    journal.complete([seq])
    migration.rollback_export(pg,events,archive,journal)
    pg.db.execute("UPDATE normalized_features SET feature_value_numeric=99 WHERE feature_name='zero'")
    pg.db.commit()
    with pytest.raises(RuntimeError,match='feature verification'):
        migration.rollback_export(pg,events,archive,journal)
    assert len(events.rows)==1


def test_fleet_and_payload_pointers_share_one_operational_commit(restore_model,journal,monkeypatch):
    from server.storage.ram_telemetry import RAMTelemetryStorage
    from unittest.mock import Mock
    pg,archive,path=restore_model
    legacy=SimpleNamespace(pg=pg,ch=Mock(),fleet=Mock())
    store=RAMTelemetryStorage(legacy,journal,Source(),archive,start=False)
    for _ in range(3):
        store.store_raw_payload({'ciphertext':'sealed'},payload())
    statements=[]
    pg.db.set_trace_callback(statements.append)
    monkeypatch.setattr('server.risk.pipeline.process_telemetry_risk',Mock())
    assert store.replay_once()==3
    pg.db.set_trace_callback(None)
    assert sum(s=='COMMIT' for s in statements)==1
    assert pg.db.execute('SELECT count(*) FROM raw_payloads').fetchone()[0]==3
    assert pg.db.execute('SELECT count(*) FROM collector_results').fetchone()[0]==0
    assert pg.db.execute('SELECT count(*) FROM normalized_features').fetchone()[0]==0
    assert all(r[0]=='{}' for r in pg.db.execute('SELECT encrypted_envelope_json FROM raw_payloads'))
