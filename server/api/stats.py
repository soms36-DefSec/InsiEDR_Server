from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Request
from server.api.responses import api_error
from server.api.deps import get_storage, require_operator, OperatorPrincipal
from psycopg2.pool import PoolError
from psycopg2.errors import QueryCanceled, LockNotAvailable
from server.config import config

logger = logging.getLogger("insiedr.api.stats")

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias

from server.api.snapshots import snapshot


def _fleet_stats(storage, actor="anon"):
    return snapshot(storage, actor, 'fleet-stats', storage.get_stats,
                    fresh_seconds=90, group='analytics')


@router.get("/stats")
@router.get("/v1/stats")
def get_stats(request: Request, storage=Depends(get_storage),
              operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    """Returns aggregated fleet overview stats, served from coordinated 90-second snapshots."""
    if storage is None:
        return api_error(
            code="STORAGE_UNAVAILABLE",
            message="Storage is not configured",
            status_code=503,
            error="storage is not configured",
        )

    return _fleet_stats(storage, getattr(operator, "actor", "anon"))


@router.get("/dashboard-summary")
@router.get("/v1/dashboard-summary")
def dashboard_summary(include_stats: bool = True, storage=Depends(get_storage),
                      operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    """Fleet overview with a complete hostname snapshot in pc_status.endpoints.

    The separate agents array remains a bounded list of agent registrations;
    fleet card drill-downs use the same unique-host snapshot as their counts.
    Fleet snapshots refresh independently of historical analytics.
    """

    if storage is None:
        return api_error(
            code="STORAGE_UNAVAILABLE",
            message="Storage is not configured",
            status_code=503,
            error="storage is not configured",
        )

    actor = getattr(operator, "actor", "anon")

    def load_summary():
        pc_failed = False
        try:
            threshold = getattr(config, "agent_online_threshold_seconds", 300)
            pc_status = storage.get_pc_status(seconds_since_online=threshold) if hasattr(storage, "get_pc_status") else {}
            if not isinstance(pc_status, dict):
                pc_status = {}
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as pc_err:
            logger.warning("Non-fatal: get_pc_status error: %s", pc_err)
            pc_status = {
                "total_pcs": None,
                "online_pcs": None,
                "offline_pcs": None,
                "endpoints": [],
                "status": "unavailable",
            }
            pc_failed = True

        agents_failed = False
        try:
            agents = storage.list_agents(limit=500, offset=0) if hasattr(storage, "list_agents") else []
            if not isinstance(agents, list):
                agents = []
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as agents_err:
            logger.warning("Non-fatal: list_agents error: %s", agents_err)
            agents = []
            agents_failed = True

        risk_events = []
        try:
            if hasattr(storage, "list_risk_events"):
                res = storage.list_risk_events(limit=50, offset=0)
                if isinstance(res, (list, tuple)):
                    risk_events = res
                else:
                    risk_events = []
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as risk_err:
            logger.warning("Non-fatal: list_risk_events error: %s", risk_err)
            risk_events = []

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        # Risk belongs to an endpoint. Shared usernames must not spread it to other hosts.
        host_latest_risk: dict[str, dict] = {}
        agent_latest_risk: dict[str, dict] = {}

        for event in risk_events:
            score = float(event.get("risk_score") or 0.0)
            if score >= 85.0:
                level = "CRITICAL"
            elif score >= 60.0:
                level = "HIGH"
            elif score >= 35.0:
                level = "MEDIUM"
            else:
                level = "LOW"
            event["risk_level"] = level
            event["_computed_level"] = level

            h = event.get("hostname")
            aid = event.get("agent_id")

            if h and h not in host_latest_risk:
                host_latest_risk[h] = event
            if aid and aid not in agent_latest_risk:
                agent_latest_risk[aid] = event

        # Monitored endpoints are distinct physical/virtual endpoints identified by HOSTNAME
        seen_hosts = set()
        for a in agents:
            hostname = a.get("hostname") or a.get("agent_id") or a.get("username_last_seen")
            if not hostname or hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)

            ev = agent_latest_risk.get(a.get("agent_id")) or host_latest_risk.get(hostname)

            if ev:
                lvl = (ev.get("_computed_level") or ev.get("risk_level") or "LOW").upper()
                if lvl == "CRITICAL":
                    critical_count += 1
                elif lvl == "HIGH":
                    high_count += 1
                elif lvl == "MEDIUM":
                    medium_count += 1
                else:
                    low_count += 1
            else:
                low_count += 1

        if not seen_hosts:
            fallback_map = agent_latest_risk or host_latest_risk
            critical_count = sum(1 for e in fallback_map.values() if e.get("_computed_level") == "CRITICAL")
            high_count = sum(1 for e in fallback_map.values() if e.get("_computed_level") == "HIGH")
            medium_count = sum(1 for e in fallback_map.values() if e.get("_computed_level") == "MEDIUM")
            low_count = sum(1 for e in fallback_map.values() if e.get("_computed_level") == "LOW")

        res = {
            "ok": True,
            "pc_status": pc_status,
            "agents": agents,
            "stats": {},
            "agents_available": not agents_failed,
            "risk_counts": {"critical": critical_count, "high": high_count, "medium": medium_count, "low": low_count},
            "risk_events": risk_events,
            "anomalies": [],
        }

        if pc_failed:
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError("Fleet inventory is temporarily unavailable")
        from fastapi.encoders import jsonable_encoder
        return jsonable_encoder(res)

    result = snapshot(storage, actor, 'dashboard-summary', load_summary,
                      fresh_seconds=30, group='fleet')
    if include_stats:
        try:
            result['stats'] = _fleet_stats(storage, actor)
        except Exception:
            result['stats'] = {'ok': False, 'freshness': {'stale': True, 'generated_at': None}}
    return result
