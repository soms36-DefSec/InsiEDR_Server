from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from server.config import config
from server.plugin_registry import registry
from server.api.events import broadcaster
from server.api.deps import get_storage, get_task_queue, require_operator, OperatorPrincipal
from server.api.contracts import HealthResponse

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias


@router.get('/operations/health')
@router.get('/v1/operations/health')
def operations_health(request: Request, storage=Depends(get_storage),
                      operator: OperatorPrincipal = Depends(require_operator('operator:read'))):
    from server.storage.operations import operations_snapshot
    import time
    import threading
    # Serialize sampling and cache it per worker: monitoring should not itself
    # repeatedly scan the outbox or a large DLQ during an incident.
    lock = getattr(request.app.state, 'operations_lock', None)
    if lock is None:
        lock = request.app.state.operations_lock = threading.Lock()
    with lock:
        cached = getattr(request.app.state, 'operations_snapshot', None)
        if cached is None or time.time() - cached['checked_at'] > 60:
            cached = operations_snapshot(storage, request.app.state)
            request.app.state.operations_snapshot = cached
    from fastapi.encoders import jsonable_encoder
    return JSONResponse(jsonable_encoder(cached), status_code=200 if cached['ok'] else 503)


@router.get("/health/live")
@router.get("/v1/health/live")
async def liveness(request: Request):
    """Lightweight Kubernetes liveness probe."""
    if getattr(request.app.state, "shutting_down", False):
        return JSONResponse({"status": "shutting_down", "live": False}, status_code=503)
    return {"status": "live", "ok": True}


@router.get("/health/ready")
@router.get("/v1/health/ready")
def readiness(
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


@router.get("/health", response_model=HealthResponse)
@router.get("/v1/health", response_model=HealthResponse)
def health(
    request: Request,
    response: Response,
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

    analytics = "disabled"
    if storage is not None:
        if hasattr(storage, "ping_analytics") and callable(storage.ping_analytics):
            ana_status = storage.ping_analytics()
            if ana_status is True:
                analytics = "ok"
            elif ana_status is False:
                analytics = "unavailable"
            else:
                analytics = "disabled"
        elif hasattr(storage, "ch") and storage.ch is not None:
            analytics = "ok" if getattr(storage.ch, "is_connected", lambda: False)() else "unavailable"

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
        "analytics": analytics,
        "telemetry_backend": getattr(storage, "telemetry_read_backend", "postgres") if storage is not None else "none",
        "crypto": crypto,
        "crypto_schemes": schemes,
        "plaintext_crypto": plaintext,
        "migrations": "ok" if storage is not None else "not_configured",
        "telemetry_collection": "ok" if config.enable_log_ingestion else "paused",
        "log_ingestion_enabled": config.enable_log_ingestion,
        "queue_backend": queue_backend,
        "queue_status": queue_status,
        "sse_subscribers": sse_subscribers,
        "auth": "configured" if getattr(request.app.state, "auth_enforced", False) else "not_enforced",
    }
    response.status_code = 200 if status_ok else 503
    return resp_body


@router.post("/operations/pause-ingestion")
@router.post("/v1/operations/pause-ingestion")
def pause_ingestion(operator: OperatorPrincipal = Depends(require_operator("operator:write"))):
    """Dynamically pause telemetry log ingestion on this server."""
    config.set_ingestion_enabled(False)
    return {
        "ok": True,
        "log_ingestion_enabled": False,
        "status": "paused",
        "message": "Telemetry log ingestion has been paused.",
    }


@router.post("/operations/resume-ingestion")
@router.post("/v1/operations/resume-ingestion")
def resume_ingestion(operator: OperatorPrincipal = Depends(require_operator("operator:write"))):
    """Dynamically resume telemetry log ingestion on this server."""
    config.set_ingestion_enabled(True)
    return {
        "ok": True,
        "log_ingestion_enabled": True,
        "status": "active",
        "message": "Telemetry log ingestion has been resumed.",
    }


@router.get("/v1/queue/metrics")
@router.get("/queue/metrics")
def queue_metrics(
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

