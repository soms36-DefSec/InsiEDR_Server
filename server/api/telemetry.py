from __future__ import annotations

import anyio
import logging
from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from server.api.errors import AnalyticsUnavailableError
from server.api.deps import get_storage, require_operator, OperatorPrincipal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Telemetry Explorer & Analytics"])
bp = router  # Backward compatibility alias


@router.get("/telemetry/explorer")
@router.get("/v1/telemetry/explorer")
async def get_telemetry_explorer(
    limit: int = Query(50, ge=1, le=1000),
    cursor: str | None = Query(None, max_length=1024),
    collector: str | None = None,
    username: str | None = None,
    status: str | None = None,
    search: str | None = Query(None, max_length=256),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    agent_id: str | None = None,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """
    Split-View Telemetry Explorer List Endpoint (Industrial CQRS Read Engine).
    Projects ONLY 5 lightweight scalar columns (event_id, timestamp, agent_id, collector_name, summary_preview)
    plus display metadata (hostname, username, status).
    Returns response size < 20KB for 50 rows in < 15ms with deterministic seek/cursor pagination.
    Full nested raw payloads and features are deferred to on-demand detail drawer (/api/v1/telemetry/events/{id}).
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "Telemetry storage is unavailable"}, status_code=503)

    try:
        # Interpret timezone-free API dates as UTC before comparing bounds
        if start_time and start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        if start_time and end_time and start_time > end_time:
            return JSONResponse({"ok": False, "error": "start_time must precede end_time"}, status_code=422)

        from server.api.cache import api_cache
        actor = getattr(operator, "actor", "anon")
        cache_key = (
            f"telemetry:explorer:{actor}:{limit}:{cursor or ''}:{collector or ''}:{username or ''}:"
            f"{status or ''}:{search or ''}:{start_time.isoformat() if start_time else ''}:"
            f"{end_time.isoformat() if end_time else ''}:{agent_id or ''}"
        )
        hit = api_cache.get(cache_key)
        if hit is not None:
            return hit

        if callable(getattr(storage, "get_telemetry_explorer", None)):
            try:
                def read_page():
                    from server.api.snapshots import workload_slot
                    with workload_slot('logs') as allowed:
                        if not allowed:
                            raise AnalyticsUnavailableError('Telemetry reader is busy; retry shortly')
                        return storage.get_telemetry_explorer(
                            limit=limit, cursor=cursor, collector=collector, username=username,
                            status=status, search=search, start_time=start_time, end_time=end_time,
                            agent_id=agent_id)
                result = await anyio.to_thread.run_sync(read_page)
                res = {
                    "ok": True,
                    "events": result.get("events", []),
                    "logs": result.get("events", []),
                    "next_cursor": result.get("next_cursor"),
                    "has_more": result.get("has_more", False),
                    "limit": limit,
                    "source": result.get("source", "clickhouse"),
                }
                api_cache.set(cache_key, res, ttl=5.0)
                return res
            except Exception as exc:
                raise AnalyticsUnavailableError("Telemetry query is temporarily unavailable") from exc

        # Fallback to get_telemetry_page if explorer query is not implemented or failed
        if callable(getattr(storage, "get_telemetry_page", None)):
            try:
                page = await anyio.to_thread.run_sync(lambda: storage.get_telemetry_page(
                    limit=limit, offset=0, collector=collector, username=username,
                    status=status, search=search, start_time=start_time, end_time=end_time,
                    cursor=cursor, include_total=False, include_enrichment=False,
                ))
            except Exception as pg_exc:
                logger.warning("PostgreSQL get_telemetry_page fallback also failed: %s", pg_exc)
                raise AnalyticsUnavailableError("Telemetry query is temporarily unavailable") from pg_exc
            logs = page.get("logs", [])
            from server.storage.clickhouse_telemetry_queries import extract_summary_preview
            projected = []
            for row in logs:
                eid = str(row.get("id") or row.get("event_id") or "")
                cname = str(row.get("collector") or row.get("collector_name") or "")
                ts = row.get("collected_at") or row.get("timestamp") or ""
                ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
                projected.append({
                    "event_id": eid,
                    "id": eid,
                    "timestamp": ts_str,
                    "collected_at": ts_str,
                    "agent_id": str(row.get("agent_id") or ""),
                    "collector_name": cname,
                    "collector": cname,
                    "hostname": str(row.get("hostname") or ""),
                    "username": str(row.get("username") or ""),
                    "status": str(row.get("status") or "success"),
                    "summary_preview": row.get("summary_preview") or extract_summary_preview(cname, row.get("payload")),
                })
            res = {
                "ok": True,
                "events": projected,
                "logs": projected,
                "next_cursor": page.get("next_cursor"),
                "has_more": page.get("has_more", False),
                "limit": limit,
                "source": page.get("source", "postgres"),
            }
            api_cache.set(cache_key, res, ttl=5.0)
            return res

        return {"ok": True, "events": [], "logs": [], "limit": limit, "source": "none"}
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)


@router.get("/telemetry/events/{event_id}")
@router.get("/v1/telemetry/events/{event_id}")
async def get_telemetry_event_detail(
    event_id: str,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """
    On-Demand Deep Forensic Telemetry Drawer Endpoint.
    Fetches the full nested raw JSON collector payload, decrypted attributes,
    and associated threat features ONLY when an analyst clicks on a specific row.
    """
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        from server.api.cache import api_cache
        actor = getattr(operator, "actor", "anon")
        cache_key = f"telemetry:event:{actor}:{event_id}"
        hit = api_cache.get(cache_key)
        if hit is not None:
            return hit

        event = None
        if callable(getattr(storage, "get_telemetry_event_detail", None)):
            res_event = await anyio.to_thread.run_sync(lambda: storage.get_telemetry_event_detail(event_id))
            if isinstance(res_event, dict):
                event = res_event

        if not event and callable(getattr(storage, "get_payload", None)):
            try:
                raw_payload = await anyio.to_thread.run_sync(lambda: storage.get_payload(event_id))
                if isinstance(raw_payload, dict):
                    event = raw_payload
            except Exception:
                pass

        if not event:
            if callable(getattr(storage, "list_logs", None)):
                try:
                    logs = await anyio.to_thread.run_sync(lambda: storage.list_logs(limit=50, offset=0))
                    if isinstance(logs, list):
                        for log in logs:
                            if str(log.get("id")) == str(event_id) or str(log.get("payload_id")) == str(event_id):
                                event = log
                                break
                except Exception:
                    pass

        if not event:
            return JSONResponse({"ok": False, "error": "Telemetry event not found"}, status_code=404)

        res = {"ok": True, "event": event}
        api_cache.set(cache_key, res, ttl=60.0)
        return res
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)


@router.get("/telemetry/histogram")
@router.get("/v1/telemetry/histogram")
async def get_telemetry_histogram(
    time_range: str = Query("1h", pattern="^(15m|1h|24h|7d|all)$"),
    interval: str | None = None,
    collector: str | None = None,
    status: str | None = None,
    agent_id: str | None = None,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    """Timestamped histogram snapshot; one bounded refresh across API workers."""
    from server.api.snapshots import snapshot
    if storage is None or not callable(getattr(storage, 'get_telemetry_histogram', None)):
        raise AnalyticsUnavailableError('Telemetry storage is unavailable')
    filters = dict(time_range=time_range, interval=interval, collector=collector,
                   status=status, agent_id=agent_id)
    actor = getattr(operator, 'actor', 'anon')
    return await anyio.to_thread.run_sync(lambda: snapshot(
        storage, actor, 'histogram', lambda: storage.get_telemetry_histogram(**filters),
        filters=filters, fresh_seconds=90, group='analytics'))
