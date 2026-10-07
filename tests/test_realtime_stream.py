import asyncio
import time
from unittest.mock import Mock

import pytest
from server.api import events


@pytest.mark.asyncio
async def test_stream_cancel_cleans_subscriber(monkeypatch):
    bus = events.EventBroadcaster(redis_url='')
    monkeypatch.setattr(events, 'broadcaster', bus)
    stream = events._sse_generator('dashboard')
    assert 'connected' in await anext(stream)
    waiting = asyncio.create_task(anext(stream))
    await asyncio.sleep(0)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert bus._subscribers['dashboard'] == []


@pytest.mark.asyncio
async def test_bounded_slow_consumer_and_resync(monkeypatch):
    bus = events.EventBroadcaster(redis_url='')
    monkeypatch.setattr(events, 'broadcaster', bus)
    stream = events._sse_generator('dashboard')
    await anext(stream)
    for i in range(10000):
        bus.publish('telemetry', 'telemetry_changed', {'payload_id': str(i)})
    sub = bus._subscribers['dashboard'][0]
    assert sub.buffer.qsize() == 100
    assert 'event: resync' in await anext(stream)
    assert '9900' in await anext(stream)
    await stream.aclose()


@pytest.mark.asyncio
async def test_idle_clients_dont_consume_thread_workers_and_delivery_is_prompt(monkeypatch):
    bus = events.EventBroadcaster(redis_url='')
    monkeypatch.setattr(events, 'broadcaster', bus)
    subscriptions = [bus.subscribe('dashboard', async_mode=True) for _ in range(250)]
    waiting = [asyncio.create_task(sub.get()) for sub in subscriptions]
    await asyncio.sleep(0)
    start = time.perf_counter()
    await asyncio.to_thread(bus.publish, 'telemetry', 'telemetry_changed', {'payload_id': 'committed'})
    messages = await asyncio.wait_for(asyncio.gather(*waiting), timeout=1)
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f'250-client local fan-out: {elapsed_ms:.2f}ms')
    assert all(message['data']['payload_id'] == 'committed' for message in messages)
    for sub in subscriptions:
        bus.unsubscribe('dashboard', sub)
    assert not bus._subscribers['dashboard']


@pytest.mark.asyncio
async def test_local_delivery_does_not_wait_for_redis_io():
    bus = events.EventBroadcaster(redis_url='')
    bus._redis_client = Mock()
    sub = bus.subscribe('telemetry', async_mode=True)
    bus.publish('telemetry', 'telemetry_changed', {'payload_id': 'x'})
    assert (await asyncio.wait_for(sub.get(), .5))['data']['payload_id'] == 'x'
    bus._redis_client.publish.assert_not_called()
    assert bus._outbound.qsize() == 1
    bus.unsubscribe('telemetry', sub)


@pytest.mark.asyncio
async def test_stream_keepalive_and_unstarted_generator_do_not_leak(monkeypatch):
    bus = events.EventBroadcaster(redis_url='')
    monkeypatch.setattr(events, 'broadcaster', bus)
    stream = events._sse_generator('dashboard')
    assert 'dashboard' not in bus._subscribers
    await anext(stream)

    async def timeout(awaitable, timeout):
        awaitable.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(events.asyncio, 'wait_for', timeout)
    assert (await anext(stream)).startswith(': ping ')
    await stream.aclose()


def test_telemetry_event_never_contains_unfiltered_payload(monkeypatch):
    bus = events.EventBroadcaster(redis_url='')
    monkeypatch.setattr(events, 'broadcaster', bus)
    subscriber = bus.subscribe('telemetry')
    events.dispatch_telemetry_event('payload-id')
    assert subscriber.get_nowait()['data'] == {'payload_id': 'payload-id'}


def test_sse_headers_disable_proxy_buffering():
    response = events._stream_response('telemetry')
    assert response.headers['x-accel-buffering'] == 'no'
    assert 'no-transform' in response.headers['cache-control']


@pytest.mark.asyncio
async def test_64_real_http_streams_leave_worker_capacity_and_disconnect_cleanly(monkeypatch):
    import socket
    import httpx
    import uvicorn
    from fastapi import FastAPI

    bus = events.EventBroadcaster(redis_url='')
    monkeypatch.setattr(events, 'broadcaster', bus)
    app = FastAPI()

    @app.get('/stream')
    async def stream():
        return events._stream_response('dashboard')

    @app.get('/probe')
    def probe():
        return {'ok': True}  # Requires a free AnyIO worker, unlike an async probe.

    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='error', lifespan='off'))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    readers = []
    connected = 0
    delivery_start = 0
    all_connected = asyncio.Event()
    try:
        async with asyncio.timeout(5):
            while not server.started:
                await asyncio.sleep(.01)
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}', trust_env=False,
                                     limits=httpx.Limits(max_connections=80), timeout=5) as client:
            async def consume():
                nonlocal connected
                async with client.stream('GET', '/stream') as response:
                    async for line in response.aiter_lines():
                        if line.startswith(': connected'):
                            connected += 1
                            if connected == 64:
                                all_connected.set()
                        if line.startswith('data:'):
                            return line, (time.perf_counter() - delivery_start) * 1000

            readers = [asyncio.create_task(consume()) for _ in range(64)]
            await asyncio.wait_for(all_connected.wait(), 5)
            response = await asyncio.wait_for(client.get('/probe'), 2)
            assert response.status_code == 200
            delivery_start = time.perf_counter()
            bus.publish('telemetry', 'telemetry_changed', {'payload_id': 'http-committed'})
            delivered = await asyncio.wait_for(asyncio.gather(*readers), 3)
            timings = sorted(elapsed for _, elapsed in delivered)
            print(f'64-client HTTP SSE receipt: p50={timings[32]:.2f}ms, p95={timings[60]:.2f}ms')
            assert all('http-committed' in line for line, _ in delivered)
        async with asyncio.timeout(2):
            while bus._subscribers['dashboard']:
                await asyncio.sleep(.01)
    finally:
        for reader in readers:
            reader.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        server.should_exit = True
        await asyncio.wait_for(serving, 5)
        sock.close()
