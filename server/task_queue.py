"""
server/task_queue.py
--------------------
Durable task queue with a two-tier backend:

  1. RedisTaskQueue  (preferred): Uses a Redis List for immediate tasks and a
     Sorted Set for delayed/retry tasks. Offers sub-millisecond enqueue latency,
     which decouples the HTTP ingestion path from the ML inference pipeline.

  2. PgTaskQueue (fallback): PostgreSQL-backed queue using FOR UPDATE SKIP LOCKED.
     Used automatically when REDIS_URL / INSIEDR_REDIS_URL is not set.

Shared infrastructure:
  - TaskWorker   : A daemon thread that continuously polls the active queue and
                   dispatches tasks to registered handler functions.
  - start_worker : Factory that auto-selects the backend, wires handlers, and
                   starts the background thread.
"""
from __future__ import annotations

import json
import logging
import socket
import threading
import time
import uuid
from contextlib import closing
from typing import Any, Callable

log = logging.getLogger("insiedr.task_queue")

# Unique identity for this process so multiple servers can share one queue
_WORKER_ID = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"

# How many seconds to sleep between polls when the queue is empty
_POLL_INTERVAL = 2.0

_REDIS_KEY_PENDING    = "insiedr:tasks:pending"      # LIST  – RPUSH / BRPOPLPUSH
_REDIS_KEY_PROCESSING = "insiedr:tasks:processing"   # LIST  – in-flight claim buffer
_REDIS_KEY_RETRY      = "insiedr:tasks:retry"        # ZSET  – scored by scheduled_at (epoch float)
_REDIS_KEY_RUNNING    = "insiedr:tasks:running"      # HASH  – task_id -> serialised task


class PgTaskQueue:
    """Thin wrapper around the task_queue table for enqueue / dequeue operations."""

    def __init__(self, storage) -> None:
        self._storage = storage

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enqueue(self, task_type: str, payload: dict[str, Any], max_attempts: int = 3) -> int | None:
        """
        Insert a new task into the queue.
        Returns the new task ID, or None on failure.
        """
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        INSERT INTO task_queue (task_type, payload_json, max_attempts)
                        VALUES (%s, %s, %s)
                        RETURNING id
                        """,
                        (task_type, json.dumps(payload), max_attempts),
                    )
                    row = cur.fetchone()
                    conn.commit()
                    return row[0] if row else None
        except Exception as exc:
            log.error("Failed to enqueue task '%s': %s", task_type, exc)
            return None

    def claim_next(self) -> dict[str, Any] | None:
        """
        Atomically claim one pending/retry task using SKIP LOCKED.
        Returns the task dict, or None if the queue is empty.
        """
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        UPDATE task_queue
                        SET status    = 'running',
                            locked_at = CURRENT_TIMESTAMP,
                            locked_by = %s,
                            attempts  = attempts + 1
                        WHERE id = (
                            SELECT id FROM task_queue
                            WHERE status IN ('pending', 'retry')
                              AND scheduled_at <= CURRENT_TIMESTAMP
                            ORDER BY scheduled_at
                            LIMIT 1
                            FOR UPDATE SKIP LOCKED
                        )
                        RETURNING id, task_type, payload_json, attempts, max_attempts
                        """,
                        (_WORKER_ID,),
                    )
                    row = cur.fetchone()
                    conn.commit()
                    if not row:
                        return None
                    task_id, task_type, payload_json, attempts, max_attempts = row
                    payload = (
                        payload_json if isinstance(payload_json, dict)
                        else json.loads(payload_json or "{}")
                    )
                    return {
                        "id": task_id,
                        "task_type": task_type,
                        "payload": payload,
                        "attempts": attempts,
                        "max_attempts": max_attempts,
                    }
        except Exception as exc:
            log.error("Failed to claim task: %s", exc)
            return None

    def complete(self, task_id: int) -> None:
        """Mark a task as successfully completed."""
        self._update_status(task_id, "completed", completed=True)

    def fail(self, task_id: int, task: dict[str, Any], error: str) -> None:
        """
        Mark a task as failed.
        If retries remain, reschedule it as 'retry' with exponential back-off.
        Otherwise mark it permanently 'failed'.
        """
        attempts = task.get("attempts", 1)
        max_attempts = task.get("max_attempts", 3)
        if attempts < max_attempts:
            # Exponential back-off: 10s, 40s, 160s …
            delay_seconds = 10 * (4 ** (attempts - 1))
            self._reschedule(task_id, error, delay_seconds)
        else:
            self._update_status(task_id, "failed", error=error)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_status(self, task_id: int, status: str, *, error: str = None, completed: bool = False) -> None:
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        UPDATE task_queue
                        SET status       = %s,
                            error_message = %s,
                            completed_at  = CASE WHEN %s THEN CURRENT_TIMESTAMP ELSE completed_at END
                        WHERE id = %s
                        """,
                        (status, error, completed, task_id),
                    )
                    conn.commit()
        except Exception as exc:
            log.error("Failed to update task %s status to '%s': %s", task_id, status, exc)

    def _reschedule(self, task_id: int, error: str, delay_seconds: int) -> None:
        try:
            with self._storage.connection() as conn:
                with closing(conn.cursor()) as cur:
                    cur.execute(
                        """
                        UPDATE task_queue
                        SET status        = 'retry',
                            locked_at     = NULL,
                            locked_by     = NULL,
                            scheduled_at  = CURRENT_TIMESTAMP + (%s * INTERVAL '1 second'),
                            error_message = %s
                        WHERE id = %s
                        """,
                        (delay_seconds, error, task_id),
                    )
                    conn.commit()
                log.info("Task %s rescheduled for retry in %ds", task_id, delay_seconds)
        except Exception as exc:
            log.error("Failed to reschedule task %s: %s", task_id, exc)


class RedisTaskQueue:
    """
    Redis-backed task queue.

    Pending tasks are stored in a Redis List (RPUSH/LPOP) for O(1) enqueue and
    non-blocking dequeue. Delayed/retry tasks live in a Sorted Set scored by their
    scheduled epoch timestamp — a promotion step moves matured items into the
    pending list before each poll.

    Each task is a JSON-encoded dict with the same shape as PgTaskQueue tasks so
    that TaskWorker can use either backend interchangeably.
    """
    
    is_blocking = True

    def __init__(self, redis_url: str) -> None:
        import redis as redis_lib  # local import so the package is optional
        self._client = redis_lib.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        
        # Lua script: atomically promote matured retry tasks into the pending list.
        # Runs server-side so multiple replicas can never double-promote the same task.
        self._promote_script = self._client.register_script("""
            local matured = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
            if #matured > 0 then
                for _, raw in ipairs(matured) do
                    redis.call('RPUSH', KEYS[2], raw)
                    redis.call('ZREM', KEYS[1], raw)
                end
            end
            return #matured
        """)

        # Lua script: atomically reap tasks stuck in the running hash for > stale_seconds.
        # Handles the crash-recovery gap: if the server hard-crashes while processing a
        # task (after BLPOP, before complete()/fail()), the task is re-queued here.
        # Each task in the running hash carries a 'claimed_at' epoch float set by claim_next().
        self._reap_script = self._client.register_script("""
            local stale_cutoff = tonumber(ARGV[1])
            local reaped = 0
            local entries = redis.call('HGETALL', KEYS[1])
            for i = 1, #entries, 2 do
                local task_id = entries[i]
                local raw     = entries[i + 1]
                local ok, task = pcall(cjson.decode, raw)
                if ok and task['claimed_at'] and tonumber(task['claimed_at']) < stale_cutoff then
                    redis.call('HDEL', KEYS[1], task_id)
                    redis.call('RPUSH', KEYS[2], raw)
                    reaped = reaped + 1
                end
            end
            if KEYS[3] then
                local proc = redis.call('LRANGE', KEYS[3], 0, -1)
                for _, raw in ipairs(proc) do
                    local ok, task = pcall(cjson.decode, raw)
                    local task_time = nil
                    if ok and type(task) == 'table' then
                        task_time = tonumber(task['claimed_at']) or tonumber(task['enqueued_at'])
                    end
                    -- Only reap if the task has exceeded the stale cutoff; never steal active in-flight claims
                    if task_time and task_time < stale_cutoff then
                        redis.call('LREM', KEYS[3], 1, raw)
                        redis.call('RPUSH', KEYS[2], raw)
                        reaped = reaped + 1
                    end
                end
            end
            return reaped
        """)

        log.info("RedisTaskQueue connected to %s", redis_url)

    # ------------------------------------------------------------------
    # Public API (mirrors PgTaskQueue)
    # ------------------------------------------------------------------

    def enqueue(
        self,
        task_type: str,
        payload: dict[str, Any],
        max_attempts: int = 3,
    ) -> str | None:
        """Push a new task onto the pending list. Returns the task ID or None."""
        task_id = str(uuid.uuid4())
        task = {
            "id": task_id,
            "task_type": task_type,
            "payload": payload,
            "attempts": 0,
            "max_attempts": max_attempts,
            "enqueued_at": time.time(),
        }
        try:
            self._client.rpush(_REDIS_KEY_PENDING, json.dumps(task))
            return task_id
        except Exception as exc:
            log.error("RedisTaskQueue: failed to enqueue task '%s': %s", task_type, exc)
            return None

    def claim_next(self) -> dict[str, Any] | None:
        """Promote any matured retry tasks, then atomically pop one pending task.

        Enqueue uses RPUSH (right/tail), so FIFO pop must take from the left
        (head).  BLMOVE source LEFT destination RIGHT atomically pops from the
        source head and pushes onto the destination tail, preserving ordering.

        The processing-list entry is stamped with claimed_at (not enqueued_at)
        so the stale-reaper correctly measures lease age from the time of claim.
        """
        self._promote_retries()
        try:
            # BLMOVE LEFT RIGHT: left-pop (FIFO head) → right-push onto processing list
            # Falls back to BRPOPLPUSH for Redis < 6.2 compatibility.
            try:
                raw = self._client.blmove(
                    _REDIS_KEY_PENDING, _REDIS_KEY_PROCESSING,
                    timeout=2, src="LEFT", dest="RIGHT",
                )
            except Exception:
                # Redis < 6.2 fallback (note: this is LIFO — upgrade Redis when possible)
                raw = self._client.brpoplpush(_REDIS_KEY_PENDING, _REDIS_KEY_PROCESSING, timeout=2)

            if raw is None:
                return None
            task: dict[str, Any] = json.loads(raw)
            task["attempts"] = task.get("attempts", 0) + 1
            claimed_at = time.time()
            task["claimed_at"] = claimed_at

            # Build a processing-list entry stamped with claimed_at so the
            # stale-reaper measures age from claim time, not enqueue time.
            processing_entry = dict(task)
            processing_entry["claimed_at"] = claimed_at
            processing_entry_raw = json.dumps(processing_entry)

            # Atomically: remove the original (enqueued_at-stamped) item from
            # processing list, add claimed_at-stamped entry, and register in running hash.
            pipe = self._client.pipeline(transaction=True)
            pipe.lrem(_REDIS_KEY_PROCESSING, 1, raw)
            pipe.rpush(_REDIS_KEY_PROCESSING, processing_entry_raw)
            pipe.hset(_REDIS_KEY_RUNNING, task["id"], json.dumps(task))
            pipe.execute()

            return task
        except Exception as exc:
            log.error("RedisTaskQueue: failed to claim task: %s", exc)
            return None

    def complete(self, task_id: str) -> None:  # type: ignore[override]
        """Remove the task from the in-flight tracking hash."""
        try:
            self._client.hdel(_REDIS_KEY_RUNNING, task_id)
        except Exception as exc:
            log.error("RedisTaskQueue: failed to mark task %s complete: %s", task_id, exc)

    def fail(self, task_id: str, task: dict[str, Any], error: str) -> None:  # type: ignore[override]
        """
        Atomically transition task from running hash. If retries remain, schedule onto
        the retry sorted set with exponential back-off; otherwise drop the task and log.
        Uses a transactional pipeline so HDEL and ZADD execute atomically without crash windows.
        """
        attempts = task.get("attempts", 1)
        max_attempts = task.get("max_attempts", 3)
        pipe = self._client.pipeline(transaction=True)
        pipe.hdel(_REDIS_KEY_RUNNING, task_id)

        if attempts < max_attempts:
            delay_seconds = 10 * (4 ** (attempts - 1))
            scheduled_at = time.time() + delay_seconds
            retry_task = dict(task)  # preserve current attempt count
            pipe.zadd(
                _REDIS_KEY_RETRY,
                {json.dumps(retry_task): scheduled_at},
            )
            try:
                pipe.execute()
                log.info(
                    "RedisTaskQueue: task %s rescheduled for retry in %ds (attempt %s/%s)",
                    task_id, delay_seconds, attempts, max_attempts,
                )
            except Exception as exc:
                log.error("RedisTaskQueue: failed to reschedule task %s: %s", task_id, exc)
        else:
            try:
                pipe.execute()
            except Exception:
                pass
            log.warning(
                "RedisTaskQueue: task %s permanently failed after %s attempts: %s",
                task_id, attempts, error,
            )

    def ping(self) -> bool:
        """Return True if the Redis connection is healthy."""
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _promote_retries(self) -> None:
        """Move all retry tasks whose scheduled_at <= now into the pending list atomically."""
        try:
            now = time.time()
            promoted_count = self._promote_script(
                keys=[_REDIS_KEY_RETRY, _REDIS_KEY_PENDING],
                args=[now],
            )
            if promoted_count and promoted_count > 0:
                log.debug("RedisTaskQueue: promoted %s tasks from retry to pending", promoted_count)
        except Exception as exc:
            log.error("RedisTaskQueue: failed to promote retry tasks: %s", exc)

    def reap_stale(self, stale_seconds: float = 600.0) -> int:
        """
        Crash-recovery reaper.

        Scans the 'running' hash for tasks whose claimed_at timestamp is older
        than `stale_seconds` (default 10 minutes) and re-queues them into the
        pending list for re-processing.

        This closes the crash-recovery gap: if the server hard-crashes while a task
        is in-flight (popped from Redis but not yet complete/failed), the task would
        be permanently lost without this reaper.

        Returns the number of tasks recovered.
        """
        try:
            stale_cutoff = time.time() - stale_seconds
            reaped = self._reap_script(
                keys=[_REDIS_KEY_RUNNING, _REDIS_KEY_PENDING, _REDIS_KEY_PROCESSING],
                args=[stale_cutoff],
            )
            reaped = int(reaped or 0)
            if reaped > 0:
                log.warning(
                    "RedisTaskQueue: reaped %s stale task(s) (stuck > %ds) — "
                    "likely caused by a previous server crash",
                    reaped, stale_seconds,
                )
            return reaped
        except Exception as exc:
            log.error("RedisTaskQueue: reap_stale failed: %s", exc)
            return 0


class TaskWorker:
    """
    Background daemon thread that polls the active task queue and dispatches
    tasks to registered handler functions. Compatible with both PgTaskQueue
    and RedisTaskQueue.
    """

    def __init__(self, queue: PgTaskQueue | RedisTaskQueue, poll_interval: float = _POLL_INTERVAL) -> None:
        self._queue = queue
        self._poll_interval = poll_interval
        self._handlers: dict[str, Callable[[dict[str, Any]], None]] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def register(self, task_type: str, handler: Callable[[dict[str, Any]], None]) -> None:
        """Register a handler function for a given task_type string."""
        self._handlers[task_type] = handler
        log.info("Registered handler for task type '%s'", task_type)

    def start(self) -> None:
        """Start the background polling thread."""
        self._thread = threading.Thread(
            target=self._run,
            name="TaskWorker",
            daemon=True,
        )
        self._thread.start()
        backend = type(self._queue).__name__
        log.info("TaskWorker started (backend=%s, worker_id=%s, poll=%.1fs)", backend, _WORKER_ID, self._poll_interval)

    def stop(self, timeout: float = 5.0) -> bool:
        """Signal the worker to stop and wait for active task to drain."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                log.warning("TaskWorker thread did not terminate within %.1fs timeout", timeout)
                return False
        return True

    # ------------------------------------------------------------------
    # Internal polling loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        is_blocking_queue = getattr(self._queue, "is_blocking", False)
        reap_fn = getattr(self._queue, "reap_stale", None)
        _REAP_INTERVAL = 60.0   # run the crash-recovery reaper once per minute
        _last_reap = time.time()

        while not self._stop_event.is_set():
            # ---- Crash-recovery reaper (runs every 60 seconds) ----
            now = time.time()
            if callable(reap_fn) and (now - _last_reap) >= _REAP_INTERVAL:
                reap_fn()           # re-queues tasks stuck in running > 10 min
                _last_reap = now

            # ---- Normal task dispatch ----
            task = self._queue.claim_next()
            if task is None:
                # If the queue didn't block internally, sleep before polling again
                if not is_blocking_queue:
                    self._stop_event.wait(timeout=self._poll_interval)
                else:
                    # Queue blocked internally (e.g. BLPOP); yield briefly to prevent tight loops on errors
                    self._stop_event.wait(timeout=0.05)
                continue
            self._dispatch(task)

    def _dispatch(self, task: dict[str, Any]) -> None:
        task_id = task["id"]
        task_type = task["task_type"]
        handler = self._handlers.get(task_type)
        if handler is None:
            log.warning("No handler registered for task type '%s' (id=%s)", task_type, task_id)
            self._queue.fail(task_id, task, f"No handler for task_type '{task_type}'")
            return
        try:
            log.debug("Dispatching task %s (type=%s, attempt=%s)", task_id, task_type, task["attempts"])
            handler(task["payload"])
            self._queue.complete(task_id)
            log.debug("Task %s completed successfully", task_id)
        except Exception as exc:
            log.error("Task %s (type=%s) failed on attempt %s: %s", task_id, task_type, task["attempts"], exc)
            self._queue.fail(task_id, task, str(exc))


def start_worker(storage, app) -> TaskWorker:
    """
    Factory: auto-select the queue backend, register all known task handlers,
    attach the queue to the FastAPI app, start the worker thread, and return it.

    Backend selection:
      - RedisTaskQueue is used when REDIS_URL / INSIEDR_REDIS_URL is configured.
      - PgTaskQueue (PostgreSQL) is used as a fallback when Redis is not available.
    """
    from server.config import config
    from server.utils.webhook import _send_webhook

    # --- Select queue backend ---
    queue: PgTaskQueue | RedisTaskQueue
    if config.redis_url:
        try:
            rq = RedisTaskQueue(config.redis_url)
            if rq.ping():
                queue = rq
                from shared.crypto_utils import redact_url_credentials
                log.info("start_worker: using RedisTaskQueue (%s)", redact_url_credentials(config.redis_url))
            else:
                raise ConnectionError("Redis ping failed")
        except Exception as exc:
            log.warning(
                "start_worker: Redis unavailable (%s) — falling back to PgTaskQueue", exc
            )
            queue = PgTaskQueue(storage)
    else:
        queue = PgTaskQueue(storage)
        log.info("start_worker: using PgTaskQueue (no REDIS_URL configured)")

    # ---- Handler: Webhook alert ----
    def handle_webhook_alert(payload: dict[str, Any]) -> None:
        _send_webhook(payload)

    worker = TaskWorker(queue)
    worker.register("webhook_alert", handle_webhook_alert)
    worker.start()

    # Make the queue accessible from app.state (FastAPI) and app.extensions (legacy)
    if hasattr(app, "state"):
        app.state.task_queue = queue
    if hasattr(app, "extensions"):
        app.extensions["task_queue"] = queue

    return worker
