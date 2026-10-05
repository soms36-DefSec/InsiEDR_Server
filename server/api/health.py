from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from server.plugin_registry import registry
from server.api.events import broadcaster
from server.api.deps import get_storage, get_task_queue, require_operator, OperatorPrincipal

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias


@router.get("/health/live")
@router.get("/v1/health/live")
async def liveness(request: Request):
    """Lightweight Kubernetes liveness probe."""
    if getattr(request.app.state, "shutting_down", False):
        return JSONResponse({"status": "shutting_down", "live": False}, status_code=503)
    return {"status": "live", "ok": True}


@router.get("/health/ready")
@router.get("/v1/health/ready")
async def readiness(
    storage=Depends(get_storage),
    task_queue=Depends(get_task_queue),
):
    """Lightweight Kubernetes readiness probe."""
    # No storage configured — instance cannot serve requests that require persistence.
    if storage is None:
        return JSONResponse(
            {"status": "not_ready", "ok": False, "database": "not_configured"},
            status_code=503,
        )

    db_ok = False
    try:
        if hasattr(storage, "ping"):
            db_ok = storage.ping()
        elif hasattr(storage, "connection"):
            with storage.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            db_ok = True
        else:
            db_ok = True
    except Exception:
        db_ok = False

    if not db_ok:
        return JSONResponse({"status": "not_ready", "ok": False, "database": "error"}, status_code=503)

    return {"status": "ready", "ok": True, "database": "ok"}


@router.get("/health")
@router.get("/v1/health")
async def health(
    request: Request,
    storage=Depends(get_storage),
    task_queue=Depends(get_task_queue),
):
    database = "not_configured"
    db_healthy = True
    if storage is not None:
        try:
            if hasattr(storage, "ping") and callable(storage.ping):
                db_healthy = storage.ping()
                database = "ok" if db_healthy else "error"
            else:
                storage.get_stats()
                database = "ok"
        except Exception:
            database = "error"
            db_healthy = False

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

    status_ok = (database != "error" and crypto == "ok")
    resp_body = {
        "ok": status_ok,
        "database": database,
        "crypto": crypto,
        "crypto_schemes": schemes,
        "plaintext_crypto": plaintext,
        "migrations": "ok" if storage is not None else "not_configured",
        "telemetry_collection": "ok",
        "queue_backend": queue_backend,
        "queue_status": queue_status,
        "sse_subscribers": sse_subscribers,
        "auth": "configured" if getattr(request.app.state, "auth_enforced", False) else "not_enforced",
    }
    status_code = 200 if status_ok else 503
    return JSONResponse(content=resp_body, status_code=status_code)


@router.get("/v1/queue/metrics")
@router.get("/queue/metrics")
async def queue_metrics(
    task_queue=Depends(get_task_queue),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
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

