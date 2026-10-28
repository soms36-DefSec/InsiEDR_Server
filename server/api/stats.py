from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Request
from server.api.responses import api_error
from server.api.contracts import DashboardSummaryResponse, StatsResponse
from server.api.deps import get_storage, require_operator, OperatorPrincipal
from psycopg2.pool import PoolError
from psycopg2.errors import QueryCanceled, LockNotAvailable
from server.config import config
from server.risk.presentation import annotate_risk_event, is_test_risk_event

logger = logging.getLogger("insiedr.api.stats")

router = APIRouter(prefix="/api", tags=["System & Observability"])
bp = router  # Backward compatibility alias

from server.api.snapshots import snapshot


def _fleet_stats(storage, actor="anon"):
    return snapshot(storage, actor, 'fleet-stats', storage.get_stats,
                    fresh_seconds=90, group='analytics')


@router.get("/stats", response_model=StatsResponse)
@router.get("/v1/stats", response_model=StatsResponse)
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


@router.get("/dashboard-summary", response_model=DashboardSummaryResponse)
@router.get("/v1/dashboard-summary", response_model=DashboardSummaryResponse)
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
            agents = []
            if hasattr(storage, "list_agents"):
                page = storage.list_agents(limit=500, offset=0)
                if isinstance(page, list):
                    agents = page
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as agents_err:
            logger.warning("Non-fatal: list_agents error: %s", agents_err)
            agents = []
            agents_failed = True

        risk_events = []
        try:
            agent_ids = [str(agent["agent_id"]) for agent in agents if agent.get("agent_id")]
            if hasattr(storage, "get_latest_risk_events_for_agents"):
                risk_events = storage.get_latest_risk_events_for_agents(agent_ids)
            elif hasattr(storage, "list_risk_events"):
                # Legacy storage adapters should implement the fleet lookup above.
                recent_rows = storage.list_risk_events(limit=10000, offset=0)
                seen_agent_ids = set()
                for event in recent_rows:
                    agent_id = event.get("agent_id")
                    if agent_id and agent_id in agent_ids and agent_id not in seen_agent_ids:
                        risk_events.append(event)
                        seen_agent_ids.add(agent_id)
            if not isinstance(risk_events, (list, tuple)):
                risk_events = []
        except (PoolError, QueryCanceled, LockNotAvailable):
            raise
        except Exception as risk_err:
            logger.warning("Fleet risk lookup failed: %s", risk_err)
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError("Fleet risk assessment is temporarily unavailable") from risk_err

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        # Risk belongs to an endpoint. Shared usernames must not spread it to other hosts.
        host_latest_risk: dict[str, dict] = {}
        agent_latest_risk: dict[str, dict] = {}

        test_agent_ids = config.test_agent_ids
        test_hostnames = {
            str(agent.get("hostname") or "").casefold()
            for agent in agents if str(agent.get("agent_id") or "") in test_agent_ids
        }
        normal_hostnames = {
            str(agent.get("hostname") or "").casefold()
            for agent in agents if str(agent.get("agent_id") or "") not in test_agent_ids
        }
        test_only_hosts = test_hostnames - normal_hostnames
        if test_only_hosts and isinstance(pc_status.get("endpoints"), list):
            pc_status["endpoints"] = [
                endpoint for endpoint in pc_status["endpoints"]
                if str(endpoint.get("hostname") or "").casefold() not in test_only_hosts
            ]
            pc_status["total_pcs"] = len(pc_status["endpoints"])
            pc_status["online_pcs"] = sum(
                endpoint.get("status") == "online" for endpoint in pc_status["endpoints"]
            )
            pc_status["offline_pcs"] = pc_status["total_pcs"] - pc_status["online_pcs"]
        for event in risk_events:
            annotate_risk_event(event)
            event["is_test"] = is_test_risk_event(event, test_agent_ids)

            h = event.get("hostname")
            aid = event.get("agent_id")

            if h and h not in host_latest_risk:
                host_latest_risk[h] = event
            if aid and aid not in agent_latest_risk:
                agent_latest_risk[aid] = event

        # Monitored endpoints are distinct physical/virtual endpoints identified by HOSTNAME
        seen_hosts = set()
        for a in agents:
            a["is_test"] = str(a.get("agent_id") or "") in test_agent_ids
            if a["is_test"]:
                continue
            hostname = a.get("hostname") or a.get("agent_id") or a.get("username_last_seen")
            if not hostname or hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)

            ev = (agent_latest_risk.get(a.get("agent_id")) if a.get("agent_id")
                  else host_latest_risk.get(hostname))

            if ev:
                lvl = ev.get("active_risk_level") or "LOW"
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
        if agents_failed:
            from server.api.errors import AnalyticsUnavailableError
            raise AnalyticsUnavailableError("Fleet agent inventory is temporarily unavailable")
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
