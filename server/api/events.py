from __future__ import annotations

import asyncio
import json
import uuid
import logging
import os
import queue
import threading
import time
from typing import Any, AsyncGenerator
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from server.api.deps import require_operator, OperatorPrincipal

logger = logging.getLogger("insiedr.api.events")

router = APIRouter(prefix="/api", tags=["Real-Time Streaming (SSE)"])
bp = router  # Backward compatibility alias

REDIS_CHANNEL_PREFIX = "insiedr:events:"


class EventSubscription:
    """Bounded thread-safe buffer with an async wakeup, not a blocked worker."""
    def __init__(self, capacity: int = 100):
        self.loop = asyncio.get_running_loop()
        self.buffer: queue.Queue = queue.Queue(maxsize=capacity)
        self.ready = asyncio.Event()
        self.lock = threading.Lock()
        self.pending = False
        self.closed = False
        self.dropped = 0

    def offer(self, message):
        with self.lock:
            if self.closed:
                return
            if self.buffer.full():
                self.buffer.get_nowait()
                self.dropped += 1
            self.buffer.put_nowait(message)
            if not self.pending:
                self.pending = True
                try:
                    self.loop.call_soon_threadsafe(self.ready.set)
                except RuntimeError:
                    self.closed = True

    async def get(self):
        while True:
            with self.lock:
                if self.closed:
                    raise StopAsyncIteration
                try:
                    return self.buffer.get_nowait()
                except queue.Empty:
                    self.ready.clear()
                    self.pending = False
            await self.ready.wait()

    def close(self):
        with self.lock:
            self.closed = True
        try:
            self.loop.call_soon_threadsafe(self.ready.set)
        except RuntimeError:
            pass


class EventBroadcaster:
    """
    Thread-safe pub/sub event broadcaster supporting in-memory queues and
    distributed Redis 7 Pub/Sub.
    
    When Redis is configured, broadcasts span across all cluster replicas so
    any SOC dashboard connected to any backend replica receives instant alerts.
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._subscribers: dict[str, list[EventSubscription]] = {
            "threats": [],
            "agents": [],
        }
        self._lock = threading.Lock()
        self.redis_url = redis_url or os.environ.get("INSIEDR_REDIS_URL") or os.environ.get("REDIS_URL")
        self._redis_client: Any = None
        self._pubsub_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._origin = uuid.uuid4().hex
        self._outbound: queue.Queue = queue.Queue(maxsize=1000)
        self._publisher_thread: threading.Thread | None = None

    def start(self) -> None:
        if self._pubsub_thread and self._pubsub_thread.is_alive():
            return
        self._stop_event.clear()
        self._init_redis()

    def _init_redis(self) -> None:
        if not self.redis_url:
            return
        try:
            import redis
            self._redis_client = redis.Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_timeout=3.0,
                socket_connect_timeout=3.0,
            )
            self._redis_client.ping()
            self._start_redis_listener()
            self._publisher_thread = threading.Thread(target=self._forward_redis, name="SSE_RedisPublisher", daemon=True)
            self._publisher_thread.start()
            logger.info("EventBroadcaster hooked into Redis 7 Pub/Sub bus.")
        except Exception as exc:
            self._redis_client = None
            logger.warning("Redis 7 Pub/Sub bus unavailable (%s). Operating with in-memory broadcasting.", exc)

    def _start_redis_listener(self) -> None:
        def _listen():
            pubsub = self._redis_client.pubsub()
            pubsub.psubscribe(f"{REDIS_CHANNEL_PREFIX}*")
            while not self._stop_event.is_set():
                try:
                    msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg and msg.get("type") == "pmessage":
                        channel = str(msg.get("channel", ""))
                        topic = channel.replace(REDIS_CHANNEL_PREFIX, "")
                        data_str = msg.get("data")
                        if data_str:
                            payload = json.loads(data_str)
                            if payload.get("origin") != self._origin:
                                self._dispatch_local(topic, payload)
                except Exception as exc:
                    if not self._stop_event.is_set():
                        logger.debug("Redis pubsub listener loop notice: %s", exc)
                        self._stop_event.wait(1.0)

            pubsub.close()

        self._pubsub_thread = threading.Thread(target=_listen, name="SSE_RedisPubSubListener", daemon=True)
        self._pubsub_thread.start()

    def _forward_redis(self):
        while not self._stop_event.is_set():
            try:
                topic, message = self._outbound.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._redis_client.publish(f"{REDIS_CHANNEL_PREFIX}{topic}", json.dumps(message, default=str))
            except Exception as exc:
                logger.warning("SSE Redis forwarding failed; clients recover via REST: %s", exc)

    def subscribe(self, topic: str, *, async_mode: bool = False):
        # Preserve synchronous subscribers used by workers and existing callers;
        # HTTP streams explicitly select the non-blocking subscription.
        subscriber = EventSubscription() if async_mode else queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.setdefault(topic, []).append(subscriber)
        return subscriber

    def unsubscribe(self, topic: str, subscriber: EventSubscription) -> None:
        if isinstance(subscriber, EventSubscription):
            subscriber.close()
        with self._lock:
            if subscriber in self._subscribers.get(topic, []):
                self._subscribers[topic].remove(subscriber)

    def _dispatch_local(self, topic: str, message: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers.get(topic, []))
            if topic != "dashboard":
                subscribers += list(self._subscribers.get("dashboard", []))
        for subscriber in subscribers:
            if isinstance(subscriber, EventSubscription):
                subscriber.offer(message)
            else:
                try:
                    subscriber.put_nowait(message)
                except queue.Full:
                    try:
                        subscriber.get_nowait()
                        subscriber.put_nowait(message)
                    except (queue.Empty, queue.Full):
                        pass

    def publish(self, topic: str, event: str, data: dict[str, Any]) -> None:
        message = {"event": event, "data": data, "timestamp": time.time(), "origin": self._origin}
        # Local delivery never waits for Redis I/O or its pubsub listener.
        self._dispatch_local(topic, message)
        if self._redis_client:
            try:
                self._outbound.put_nowait((topic, message))
            except queue.Full:
                logger.warning("SSE Redis buffer full; remote clients recover via REST")

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            subscribers = [s for group in self._subscribers.values() for s in group]
            self._subscribers = {topic: [] for topic in self._subscribers}
        for subscriber in subscribers:
            if isinstance(subscriber, EventSubscription):
                subscriber.close()
        for worker in (self._pubsub_thread, self._publisher_thread):
            if worker:
                worker.join(timeout=4)
        if self._redis_client:
            self._redis_client.close()
            self._redis_client = None


# Singleton broadcaster instance
broadcaster = EventBroadcaster()


def dispatch_threat_event(event_dict: dict[str, Any]) -> None:
    """Convenience helper to broadcast a live threat detection."""
    broadcaster.publish("threats", "threat_alert", event_dict)


def dispatch_agent_event(agent_dict: dict[str, Any]) -> None:
    """Convenience helper to broadcast an agent status transition."""
    broadcaster.publish("agents", "agent_status", agent_dict)


def dispatch_telemetry_event(payload_id: str) -> None:
    # An invalidation carries no unsanitized collector payload. The authenticated
    # REST query remains authoritative for privacy policy and current filters.
    broadcaster.publish("telemetry", "telemetry_changed", {"payload_id": payload_id})


async def _sse_generator(topic: str) -> AsyncGenerator[str, None]:
    subscriber = broadcaster.subscribe(topic, async_mode=True)
    try:
        yield f": connected to {topic} stream\n\n"
        while True:
            try:
                message = await asyncio.wait_for(subscriber.get(), timeout=15)
                if subscriber.dropped:
                    subscriber.dropped = 0
                    yield 'event: resync\ndata: {"reason":"slow_consumer"}\n\n'
                yield f"event: {message['event']}\ndata: {json.dumps(message['data'], default=str)}\n\n"
            except asyncio.TimeoutError:
                yield f": ping {int(time.time())}\n\n"
            except StopAsyncIteration:
                return
    finally:
        broadcaster.unsubscribe(topic, subscriber)


def _stream_response(topic: str) -> StreamingResponse:
    return StreamingResponse(
        _sse_generator(topic), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@router.get("/v1/stream/telemetry")
@router.get("/stream/telemetry")
async def stream_telemetry(operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    return _stream_response("telemetry")


@router.get("/v1/stream/dashboard")
@router.get("/stream/dashboard")
async def stream_dashboard(operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    """One connection for telemetry, fleet and threat notifications."""
    return _stream_response("dashboard")


@router.get("/v1/stream/threats")
@router.get("/stream/threats")
async def stream_threats(operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    """Server-Sent Events endpoint streaming real-time threat alerts and ML anomaly scores."""
    return _stream_response("threats")


@router.get("/v1/stream/agents")
@router.get("/stream/agents")
async def stream_agents(operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    """Server-Sent Events endpoint streaming real-time agent status, heartbeats, and tamper events."""
    return _stream_response("agents")


@router.post("/v1/stream/test-broadcast")
async def test_broadcast(
    request: Request,
    operator: OperatorPrincipal = Depends(require_operator("admin")),
):
    """Dev/Admin endpoint to test broadcasting a synthetic alert over SSE."""
    payload = None
    try:
        payload = await request.json()
    except Exception:
        pass
    if not payload:
        payload = {
            "summary": "Synthetic Test Alert",
            "risk_level": "medium",
            "risk_score": 45.0,
            "username": "test.analyst",
        }
    dispatch_threat_event(payload)
    return {"ok": True, "message": "Event dispatched to active SSE subscribers"}
