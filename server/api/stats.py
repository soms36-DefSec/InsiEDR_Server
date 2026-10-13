from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Request
from server.api.cache import api_cache
from server.api.responses import api_error
from server.api.deps import get_storage, require_operator, OperatorPrincipal
from psycopg2.pool import PoolError
from psycopg2.errors import QueryCanceled, LockNotAvailable

logger = logging.getLogger("insiedr.api.stats")

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias


def _fleet_stats(storage):
    # Dashboard refreshes must not repeat full-table aggregate counts for every
    # SSE notification. Scope cache entries to this storage instance.
    key = f"fleet_stats:{id(storage)}"
    cached = api_cache.get(key)
    if cached is not None:
        return cached
    result = storage.get_stats()
    api_cache.set(key, result, ttl=5.0)
    return result


@router.get("/stats")
@router.get("/v1/stats")
def get_stats(request: Request, storage=Depends(get_storage),
              operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    """Returns aggregated fleet overview stats, protected by 5s in-memory TTL caching."""
    if storage is None:
        return api_error(
            code="STORAGE_UNAVAILABLE",
            message="Storage is not configured",
            status_code=503,
            error="storage is not configured",
        )

    return _fleet_stats(storage)


@router.get("/dashboard-summary")
@router.get("/v1/dashboard-summary")
def dashboard_summary(storage=Depends(get_storage),
                      operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
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
        actor = getattr(operator, "actor", "anon")
        cache_key = f"dashboard_summary:{actor}:{id(storage)}"
        cached = api_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            pc_status = storage.get_pc_status(seconds_since_online=300) if hasattr(storage, "get_pc_status") else {}
            if not isinstance(pc_status, dict):
                pc_status = {}
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as pc_err:
            logger.warning("Non-fatal: get_pc_status error: %s", pc_err)
            pc_status = {"total_pcs": 0, "online_pcs": 0, "offline_pcs": 0, "endpoints": []}

        try:
            agents = storage.list_agents(limit=500, offset=0) if hasattr(storage, "list_agents") else []
            if not isinstance(agents, list):
                agents = []
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as agents_err:
            logger.warning("Non-fatal: list_agents error: %s", agents_err)
            agents = []

        try:
            stats = _fleet_stats(storage) if hasattr(storage, "get_stats") else {}
            if not isinstance(stats, dict):
                stats = {}
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as stats_err:
            logger.warning("Non-fatal: fleet stats calculation error: %s", stats_err)
            stats = {"ok": False, "error": str(stats_err)}

        res = {
            "ok": True,
            "pc_status": pc_status,
            "agents": agents,
            "stats": stats,
            "risk_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "risk_events": [],
            "anomalies": [],
        }
        try:
            api_cache.set(cache_key, res, ttl=4.0)
        except Exception as cache_err:
            logger.debug("Non-fatal: dashboard_summary cache set failed: %s", cache_err)

        from fastapi.encoders import jsonable_encoder
        return jsonable_encoder(res)
    except (PoolError, QueryCanceled, LockNotAvailable):
        raise  # Central handler returns a retryable 503, not a generic 500.
    except Exception:
        raise  # Central handler logs details and returns a non-sensitive error.


