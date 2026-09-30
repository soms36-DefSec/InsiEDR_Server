from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from server.plugin_registry import registry
from server.api.events import broadcaster
from server.api.deps import get_storage, get_task_queue

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias


@router.get("/health")
@router.get("/v1/health")
async def health(
    storage=Depends(get_storage),
    task_queue=Depends(get_task_queue),
):
    database = "not_configured"
    if storage is not None:
        try:
            storage.get_stats()
            database = "ok"
        except Exception:
            database = "error"

    schemes = registry.schemes()
    crypto = "ok" if ("hpke" in schemes or "aes-256-gcm" in schemes) else "unconfigured"
    plaintext = "enabled" if "plaintext" in schemes else "disabled"

    queue_status = "unavailable"
    queue_backend = "none"
    if task_queue is not None:
        queue_backend = task_queue.__class__.__name__
        if hasattr(task_queue, "ping") and callable(task_queue.ping):
            queue_status = "ok" if task_queue.ping() else "degraded"
        else:
            queue_status = "ok"

    sse_subscribers = {
        topic: len(queues) for topic, queues in broadcaster._subscribers.items()
    }

    return {
        "ok": database != "error" and crypto == "ok",
        "database": database,
        "crypto": crypto,
        "crypto_schemes": schemes,
        "plaintext_crypto": plaintext,
        "migrations": "ok" if storage is not None else "not_configured",
        "telemetry_collection": "ok",
        "queue_backend": queue_backend,
        "queue_status": queue_status,
        "sse_subscribers": sse_subscribers,
        "auth": "not_configured",
    }


@router.get("/v1/queue/metrics")
@router.get("/queue/metrics")
async def queue_metrics(task_queue=Depends(get_task_queue)):
    """Inspect status and depth of the task queue."""
    if task_queue is None:
        return JSONResponse({"ok": False, "error": "Task queue not initialized"}, status_code=503)

    backend_name = task_queue.__class__.__name__
    metrics = {
        "ok": True,
        "backend": backend_name,
        "is_redis": "Redis" in backend_name,
    }

    if hasattr(task_queue, "_client"):
        try:
            r = task_queue._client
            metrics["pending_count"] = r.llen("insiedr:tasks:pending")
            metrics["running_count"] = r.hlen("insiedr:tasks:running")
            metrics["retry_count"] = r.zcard("insiedr:tasks:retry")
            metrics["dlq_count"] = r.llen("insiedr:tasks:dlq")
        except Exception as exc:
            metrics["redis_error"] = str(exc)

    return metrics

