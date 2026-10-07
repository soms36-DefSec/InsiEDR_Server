from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from server.api.cache import api_cache
from server.api.responses import api_error
from server.api.deps import get_storage

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias


@router.get("/stats")
@router.get("/v1/stats")
async def get_stats(request: Request, storage=Depends(get_storage)):
    """Returns aggregated fleet overview stats, protected by 5s in-memory TTL caching."""
    cached_stats = api_cache.get("fleet_stats")
    if cached_stats is not None:
        return cached_stats

    if storage is None:
        return api_error(
            code="STORAGE_UNAVAILABLE",
            message="Storage is not configured",
            status_code=503,
            error="storage is not configured",
        )

    stats = storage.get_stats()
    api_cache.set("fleet_stats", stats, ttl=5.0)
    return stats


@router.get("/dashboard-summary")
@router.get("/v1/dashboard-summary")
async def dashboard_summary(storage=Depends(get_storage)):
    """Fleet overview with a complete hostname snapshot in pc_status.endpoints.

    The separate agents array remains a bounded list of agent registrations;
    fleet card drill-downs use the same unique-host snapshot as their counts.
    """
    if storage is None:
        return api_error(
            code="STORAGE_UNAVAILABLE",
            message="Storage is not configured",
            status_code=503,
            error="storage is not configured",
        )

    try:
        pc_status = storage.get_pc_status(seconds_since_online=300) if hasattr(storage, "get_pc_status") else {}
        agents = storage.list_agents(limit=500, offset=0) if hasattr(storage, "list_agents") else []
        stats = storage.get_stats() if hasattr(storage, "get_stats") else {}
        return {
            "ok": True,
            "pc_status": pc_status,
            "agents": agents,
            "stats": stats,
            "risk_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "risk_events": [],
            "anomalies": [],
        }
    except Exception as exc:
        return api_error(
            code="INTERNAL_ERROR",
            message=str(exc),
            status_code=500,
            error=str(exc),
        )


