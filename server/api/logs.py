from __future__ import annotations

import anyio
import inspect
from typing import Literal
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from server.api.ingest import process_encrypted_request, IngestError
from server.api.deps import get_storage, require_operator, OperatorPrincipal

router = APIRouter(prefix="/api", tags=["Telemetry & Ingestion"])
bp = router  # Backward compatibility alias


@router.get("/collector-states/{agent_id}")
@router.get("/v1/collector-states/{agent_id}")
async def get_collector_states(
    agent_id: str,
    stale_after_seconds: int = Query(600, ge=1),
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """Current observations across sparse payloads, with explicit freshness.

    An omitted collector keeps its last observation; it is never synthesized as
    zero. Timestamps describe collection time, and failures remain visible.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "states": []}, status_code=503)
    states = await anyio.to_thread.run_sync(
        lambda: storage.get_latest_collector_states(agent_id)
    ) if hasattr(storage, "get_latest_collector_states") else []
    now = datetime.now(timezone.utc)
    for state in states:
        observed = state.get("collector_collected_at")
        try:
            if isinstance(observed, str):
                observed = datetime.fromisoformat(observed.replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            age = max(0.0, (now - observed).total_seconds())
        except (AttributeError, TypeError, ValueError):
            age = None
        state["age_seconds"] = age
        state["stale"] = age is None or age > stale_after_seconds
    return {"ok": True, "agent_id": agent_id, "states": states,
            "as_of": now, "stale_after_seconds": stale_after_seconds}


@router.post("/logs")
@router.post("/v1/logs")
async def post_logs(request: Request):
    try:
        status_code, body = await process_encrypted_request(request)
        return JSONResponse(content=body, status_code=status_code)
    except IngestError as exc:
        return JSONResponse(content={"ok": False, "error": str(exc)}, status_code=exc.status_code)


@router.get("/logs")
@router.get("/v1/logs")
async def get_logs(
    request: Request,
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    agent_id: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    collector: str | None = None,
    status: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "logs": []}, status_code=503)

    filters = {
        "agent_id": agent_id,
        "hostname": hostname,
        "username": username,
        "collector": collector,
        "status": status,
        "start_time": start_time,
        "end_time": end_time,
    }
    sig = inspect.signature(storage.list_logs)
    accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    valid_filters = {
        k: v for k, v in filters.items()
        if v and (accepts_kwargs or k in sig.parameters)
    }

    logs = await anyio.to_thread.run_sync(
        lambda: storage.list_logs(limit=limit, offset=offset, **valid_filters)
    ) if hasattr(storage, "list_logs") else []
    return {"ok": True, "logs": logs}


@router.get("/telemetry")
@router.get("/v1/telemetry")
async def get_telemetry(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    collector: str | None = None,
    username: str | None = None,
    status: str | None = None,
    search: str | None = Query(None, max_length=256),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    include_enrichment: bool = True,
    include_total: bool = True,
    cursor: str | None = Query(None, max_length=1024),
    search_scope: Literal['metadata', 'payload'] = 'payload',
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured", "telemetry": []}, status_code=503)

    try:
        if cursor and offset:
            return JSONResponse({'ok': False, 'error': 'cursor and offset cannot be combined'}, status_code=422)
        # Interpret timezone-free API dates as UTC before comparing bounds.
        if start_time and start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        if start_time and end_time and start_time > end_time:
            return JSONResponse({"ok": False, "error": "start_time must precede end_time"}, status_code=422)
        if callable(getattr(storage, "get_telemetry_page", None)):
            page = await anyio.to_thread.run_sync(lambda: storage.get_telemetry_page(
                limit=limit, offset=offset, collector=collector, username=username,
                status=status, search=search,
                start_time=start_time, end_time=end_time,
                include_enrichment=include_enrichment,
                cursor=cursor, include_total=include_total, search_scope=search_scope,
            ))
            return {"ok": True, **page}
        telemetry = await anyio.to_thread.run_sync(
            lambda: storage.list_collector_results(limit=limit, offset=offset, collector=collector, username=username)
        )
        total = await anyio.to_thread.run_sync(
            lambda: getattr(storage, "count_collector_results", lambda **kw: len(telemetry))(collector=collector, username=username)
        )
    except ValueError as exc:
        return JSONResponse({'ok': False, 'error': str(exc)}, status_code=422)
    except AttributeError:
        return JSONResponse({"ok": False, "error": "storage method not implemented", "telemetry": []}, status_code=501)
    return {"ok": True, "logs": telemetry, "total": total, "offset": offset, "limit": limit}


from server.api.telemetry import (
    get_telemetry_explorer,
    get_telemetry_event_detail,
    get_telemetry_histogram,
)

router.add_api_route("/telemetry/explorer", get_telemetry_explorer, methods=["GET"])
router.add_api_route("/v1/telemetry/explorer", get_telemetry_explorer, methods=["GET"])
router.add_api_route("/telemetry/events/{event_id}", get_telemetry_event_detail, methods=["GET"])
router.add_api_route("/v1/telemetry/events/{event_id}", get_telemetry_event_detail, methods=["GET"])
router.add_api_route("/telemetry/histogram", get_telemetry_histogram, methods=["GET"])
router.add_api_route("/v1/telemetry/histogram", get_telemetry_histogram, methods=["GET"])

