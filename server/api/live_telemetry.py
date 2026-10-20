"""Authenticated, bounded SSE replay for v3 acceptance notifications."""
import asyncio
import json
import re
import threading

import anyio
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from server.api.deps import get_storage, require_operator, OperatorPrincipal
from server.api.errors import ServiceUnavailableError, ValidationError

router = APIRouter(prefix='/api', tags=['Real-Time Streaming (SSE)'])
_clients = threading.BoundedSemaphore(64)


@router.get('/telemetry/storage-health')
async def storage_health(storage=Depends(get_storage),
        operator: OperatorPrincipal=Depends(require_operator('operator:read'))):
    if getattr(type(storage),'cache_revision',None) is None:
        return {'mode':'legacy','enabled':False}
    status=await anyio.to_thread.run_sync(storage.journal.stats)
    return dict(mode='server-v3',enabled=True,journal=status,
                pressure=storage.controller.level.name,metrics=storage._metrics,
                last_worker_error=storage.last_error)


def text(value):
    return value.decode() if isinstance(value,bytes) else str(value)


async def replay_stream(request, cache, cursor):
    client, key = cache.client, cache.prefix+'live'
    async def command(name,*args,**kwargs):
        if getattr(cache,'async_client',None) is not None:
            return await getattr(cache.async_client,name)(*args,**kwargs)
        return await anyio.to_thread.run_sync(lambda:getattr(client,name)(*args,**kwargs))
    try:
        tail = await command('xrevrange',key,count=1)
        boundary=text(tail[0][0]) if tail else '0-0'
        first = await command('xrange',key,count=1)
        if cursor and first and tuple(map(int,cursor.split('-'))) < tuple(map(int,text(first[0][0]).split('-'))):
            yield 'event: resync\ndata: {"reason":"cursor_expired","action":"refresh_logs"}\n\n'
            cursor = text(first[0][0])
            # Include the first retained notification after reporting the gap.
            yield f'id: {cursor}\nevent: telemetry_changed\ndata: {json.dumps({text(k):text(v) for k,v in first[0][1].items()})}\n\n'
        if cursor is None:
            cursor = text(tail[0][0]) if tail else '0-0'
        if tuple(map(int,cursor.split('-')))>tuple(map(int,boundary.split('-'))):
            cursor=boundary
            yield f'id: {cursor}\nevent: resync\ndata: {{"reason":"cursor_ahead","action":"refresh_logs"}}\n\n'
        snapshot_requested=False
        if tuple(map(int,cursor.split('-')))>=tuple(map(int,boundary.split('-'))):
            snapshot_requested=True
            yield 'event: resync\ndata: {"reason":"snapshot_required","action":"refresh_logs"}\n\n'
        while not await request.is_disconnected():
            first = await command('xrange',key,count=1)
            if first and tuple(map(int,cursor.split('-'))) < tuple(map(int,text(first[0][0]).split('-'))):
                yield 'event: resync\ndata: {"reason":"cursor_expired","action":"refresh_logs"}\n\n'
            # XREAD from the last delivered ID handles arbitrarily many replay
            # pages and closes the replay-to-live race. Never reset to '$'.
            result = await command('xread',{key:cursor},count=100,block=1000)
            if not result:
                yield ': ping\n\n'
                continue
            for _,entries in result:
                for eid, fields in entries:
                    cursor = text(eid)
                    data = {text(k):text(v) for k,v in fields.items()}
                    event='resync' if data.get('state')=='resync' else 'telemetry_changed'
                    yield f'id: {cursor}\nevent: {event}\ndata: {json.dumps(data)}\n\n'
            if not snapshot_requested and tuple(map(int,cursor.split('-')))>=tuple(map(int,boundary.split('-'))):
                snapshot_requested=True
                yield 'event: resync\ndata: {"reason":"snapshot_required","action":"refresh_logs"}\n\n'
    except asyncio.CancelledError:
        raise
    except Exception:
        yield 'event: resync\ndata: {"reason":"redis_unavailable","action":"refresh_logs"}\n\n'


async def bounded_stream(request, cache, cursor):
    try:
        async for chunk in replay_stream(request,cache,cursor):
            yield chunk
    finally:
        _clients.release()


@router.get('/events/live-telemetry')
async def live_telemetry(request: Request, storage=Depends(get_storage),
        operator: OperatorPrincipal=Depends(require_operator('operator:read'))):
    cache = getattr(storage,'cache',None)
    if cache is None or cache.client is None:
        raise ServiceUnavailableError('live replay is unavailable; use existing telemetry polling')
    cursor = request.headers.get('last-event-id')
    if cursor is not None and not re.fullmatch(r'\d{1,20}-\d{1,20}',cursor):
        raise ValidationError('invalid Last-Event-ID')
    if cursor is not None and any(int(v)>2**64-1 for v in cursor.split('-')):
        raise ValidationError('invalid Last-Event-ID')
    if not _clients.acquire(blocking=False):
        raise ServiceUnavailableError('live connection capacity exhausted')
    # Existing deployment has global operator RBAC, not tenant-scoped principals.
    # Only identifiers are emitted; data remains behind the authenticated REST API.
    return StreamingResponse(bounded_stream(request,cache,cursor),media_type='text/event-stream',
        headers={'Cache-Control':'no-cache, no-transform','X-Accel-Buffering':'no'})
