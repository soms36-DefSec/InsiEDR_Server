from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from typing import Any, Generator
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from server.api.deps import require_operator, OperatorPrincipal

logger = logging.getLogger("insiedr.api.events")

router = APIRouter(prefix="/api", tags=["Real-Time Streaming (SSE)"])
bp = router  # Backward compatibility alias

REDIS_CHANNEL_PREFIX = "insiedr:events:"


class EventBroadcaster:
    """
    Thread-safe pub/sub event broadcaster supporting in-memory queues and
    distributed Redis 7 Pub/Sub.
    
    When Redis is configured, broadcasts span across all cluster replicas so
    any SOC dashboard connected to any backend replica receives instant alerts.
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._subscribers: dict[str, list[queue.Queue]] = {
            "threats": [],
            "agents": [],
        }
        self._lock = threading.Lock()
        self.redis_url = redis_url or os.environ.get("INSIEDR_REDIS_URL") or os.environ.get("REDIS_URL")
        self._redis_client: Any = None
        self._pubsub_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
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
                            self._dispatch_local(topic, payload)
                except Exception as exc:
                    if not self._stop_event.is_set():
                        logger.debug("Redis pubsub listener loop notice: %s", exc)
                        time.sleep(1.0)

        self._pubsub_thread = threading.Thread(target=_listen, name="SSE_RedisPubSubListener", daemon=True)
        self._pubsub_thread.start()

    def subscribe(self, topic: str) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            if topic not in self._subscribers:
                self._subscribers[topic] = []
            self._subscribers[topic].append(q)
        logger.debug("New subscriber attached to topic '%s' (total: %d)", topic, len(self._subscribers[topic]))
        return q

    def unsubscribe(self, topic: str, q: queue.Queue) -> None:
        with self._lock:
            if topic in self._subscribers and q in self._subscribers[topic]:
                self._subscribers[topic].remove(q)
        logger.debug("Subscriber detached from topic '%s'", topic)

    def _dispatch_local(self, topic: str, message: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers.get(topic, []))

        for q in subscribers:
            try:
                q.put_nowait(message)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(message)
                except Exception:
                    pass

    def publish(self, topic: str, event: str, data: dict[str, Any]) -> None:
        """Broadcast an event to all active SSE subscribers locally and via Redis 7 cluster."""
        message = {
            "event": event,
            "data": data,
            "timestamp": time.time(),
        }

        # If Redis is active, publish to channel (listener dispatches to local queues)
        published_to_redis = False
        if self._redis_client:
            try:
                self._redis_client.publish(
                    f"{REDIS_CHANNEL_PREFIX}{topic}",
                    json.dumps(message, default=str),
                )
                published_to_redis = True
            except Exception as exc:
                logger.debug("Failed publishing SSE message to Redis Pub/Sub: %s", exc)

        # If not published to Redis, dispatch directly to local subscribers
        if not published_to_redis:
            self._dispatch_local(topic, message)

    def stop(self) -> None:
        self._stop_event.set()


# Singleton broadcaster instance
broadcaster = EventBroadcaster()


def dispatch_threat_event(event_dict: dict[str, Any]) -> None:
    """Convenience helper to broadcast a live threat detection."""
    broadcaster.publish("threats", "threat_alert", event_dict)


def dispatch_agent_event(agent_dict: dict[str, Any]) -> None:
    """Convenience helper to broadcast an agent status transition."""
    broadcaster.publish("agents", "agent_status", agent_dict)


def _sse_generator(topic: str, q: queue.Queue) -> Generator[str, None, None]:
    """Generator yielding formatted Server-Sent Events (SSE) text chunks.
    
    Guarantees cleanup of the subscriber queue on client disconnection or stream cancellation
    via a try/finally block, preventing memory leaks in high-churn monitoring dashboards.
    """
    try:
        # Send initial connection handshake comment
        yield f": connected to {topic} stream\n\n"

        while True:
            try:
                # 15s timeout sends periodic keep-alive pings to prevent proxy idle timeouts
                msg = q.get(timeout=15.0)
                event_type = msg.get("event", "message")
                data_json = json.dumps(msg.get("data", {}), default=str)
                yield f"event: {event_type}\ndata: {data_json}\n\n"
            except queue.Empty:
                # Keep-alive heartbeat ping to keep connection alive
                yield f": ping {int(time.time())}\n\n"
    except GeneratorExit:
        logger.debug("SSE client initiated clean disconnect from topic '%s'", topic)
    except Exception as exc:
        logger.warning("SSE client disconnected with error from topic '%s': %s", topic, exc)
    finally:
        broadcaster.unsubscribe(topic, q)
        logger.debug("Cleaned up SSE subscriber queue for topic '%s'", topic)


def _stream_response(topic: str) -> StreamingResponse:
    q = broadcaster.subscribe(topic)
    headers = {
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "Access-Control-Allow-Origin": "*",
    }
    return StreamingResponse(
        _sse_generator(topic, q),
        media_type="text/event-stream",
        headers=headers,
    )


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
