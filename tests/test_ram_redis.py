"""Run the actual Lua cache scripts against Redis emulation with Lua enabled."""
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

fakeredis=pytest.importorskip('fakeredis')

from server.storage.ram_telemetry import RecentRedis, project
from server.api.live_telemetry import replay_stream


def event(sequence, seconds=0):
    now=datetime.now(timezone.utc)-timedelta(seconds=seconds)
    payload=dict(payload_id=f'payload-{sequence}',agent_id='agent',hostname='host',username='u',
                 collected_at=now.isoformat(),collectors=[dict(collector='process',status='success',
                 collected_at=now.isoformat(),payload={'count':sequence})])
    return project(payload,now.isoformat(),False,sequence)[0]


@pytest.fixture
def cache():
    return RecentRedis(fakeredis.FakeRedis(),maxlen=3)


def query(cache,revision,start_hours=24,count=2):
    now=datetime.now(timezone.utc)
    filters=dict(start_time=(now-timedelta(hours=start_hours)).isoformat(),
                 end_time=now.isoformat(),snapshot_seq=revision)
    return cache.recent(filters,now.isoformat(),count,revision)


def test_atomic_cache_append_serves_recent_data_without_persistent_read(cache):
    floor=(datetime.now(timezone.utc)-timedelta(days=1)).timestamp()
    cache.seed([],0,floor)
    cache.append_rows([event(1)],1)
    rows=query(cache,1,count=1)
    assert len(rows)==1 and rows[0]['payload_id']=='payload-1'


def test_out_of_order_publication_advances_only_contiguous_sequences(cache):
    cache.seed([],0,0)
    cache.append_rows([event(2)],2)
    assert query(cache,2,count=1) is None
    cache.append_rows([event(1)],1)
    assert len(query(cache,2,count=2))==2


def test_missing_or_evicted_index_never_returns_an_incomplete_empty_page(cache):
    cache.seed([event(1)],1,0)
    cache.client.delete(cache.prefix+'time')
    assert query(cache,1,count=1) is None


def test_evicted_payload_hash_never_claims_complete_coverage(cache):
    cache.seed([event(1)],1,0)
    cache.client.delete(cache.prefix+'rows')
    assert query(cache,1,count=1) is None


def test_trimming_cleans_all_references_and_reports_incomplete_history(cache):
    cache.seed([],0,0)
    for sequence in range(1,8):
        cache.append_rows([event(sequence,seconds=8-sequence)],sequence)
    assert cache.client.zcard(cache.prefix+'time')==3
    assert cache.client.hlen(cache.prefix+'rows')==3
    assert query(cache,7,count=4) is None
    assert len(query(cache,7,count=2))==2


def test_query_cache_revision_mismatch_falls_back(cache):
    cache.seed([event(1)],1,0)
    assert query(cache,2,count=1) is None


def test_redis_result_cache_is_short_lived_and_json_serializable(cache):
    cache.put('sample',{'logs':[event(1)]})
    assert cache.get('sample')['logs'][0]['payload_id']=='payload-1'
    assert 0 < cache.client.ttl(cache.prefix+'query:sample')<=2


@pytest.mark.asyncio
async def test_sse_replays_more_than_one_page_without_resetting_cursor(cache):
    for i in range(250):
        cache.client.xadd(cache.prefix+'live',{'payload_id':str(i)},id=f'{1000+i}-0')
    class Request:
        async def is_disconnected(self):
            return False
    stream=replay_stream(Request(),cache,'1000-0')
    delivered=[]
    try:
        for _ in range(249):
            item=await anext(stream)
            assert 'event: resync' not in item
            delivered.append(item.splitlines()[0])
    finally:
        await stream.aclose()
    assert len(delivered)==len(set(delivered))==249
    assert delivered[-1]=='id: 1249-0'


@pytest.mark.asyncio
async def test_expired_sse_cursor_reports_gap(cache):
    cache.client.xadd(cache.prefix+'live',{'payload_id':'retained'},id='1000-0')
    request=SimpleNamespace()
    stream=replay_stream(request,cache,'1-0')
    assert 'cursor_expired' in await anext(stream)
    await stream.aclose()


def test_searchable_transition_and_metadata_only_detail_locator(cache):
    row=dict(event(1),ingest_state='accepted')
    cache.seed([row],1,0)
    cache.mark_searchable([row['id']])
    assert cache.event(row['id'])['ingest_state']=='searchable'
    cache.remember([row])
    locator=cache.locate(row['id'])
    assert locator==[row['received_at'][:10],row['collected_at']]
    assert 'payload_json' not in str(locator)


@pytest.mark.asyncio
async def test_async_sse_does_not_consume_the_ingestion_thread_pool(monkeypatch):
    server=fakeredis.FakeServer()
    sync=fakeredis.FakeRedis(server=server)
    asynchronous=fakeredis.FakeAsyncRedis(server=server)
    cache=RecentRedis(sync,async_client=asynchronous)
    sync.xadd(cache.prefix+'live',{'payload_id':'first'},id='1000-0')
    sync.xadd(cache.prefix+'live',{'payload_id':'second'},id='1001-0')
    async def forbidden(*args,**kwargs):
        raise AssertionError('SSE borrowed an ingestion thread')
    monkeypatch.setattr('anyio.to_thread.run_sync',forbidden)
    class Request:
        async def is_disconnected(self):
            return False
    stream=replay_stream(Request(),cache,'1000-0')
    try:
        assert 'id: 1001-0' in await anext(stream)
    finally:
        await stream.aclose()
        await asynchronous.aclose()
