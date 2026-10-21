"""Operator read API for isolated scenario-replay model results."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import json
import os
import uuid
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from psycopg2.errors import InvalidSchemaName, UndefinedTable

from server.api.deps import OperatorPrincipal, get_storage, require_operator
from server.config import config

router = APIRouter(prefix="/api/v1/detection/ml/scenario", tags=["Scenario Replay"])


def _enabled() -> None:
    if (config.environment != "staging" or os.environ.get("INSIEDR_SCENARIO_REPLAY_ENABLED") != "true"
            or not urlparse(config.database_dsn or "").path.lstrip("/").endswith("_scenario")
            or not config.clickhouse_db.endswith("_scenario")):
        raise HTTPException(status_code=404, detail="Not found")


def _connection(storage: Any):
    pg = getattr(storage, "pg", storage)
    factory = getattr(pg, "connection", None)
    if not callable(factory):
        raise HTTPException(status_code=503, detail="Scenario storage unavailable")
    return factory()


def _latest_run(cur):
    try:
        cur.execute("SELECT run_id, as_of, summary_json, created_at FROM scenario_replay.runs "
                    "ORDER BY created_at DESC, run_id DESC LIMIT 1")
    except (InvalidSchemaName, UndefinedTable):
        return None
    return cur.fetchone()


def _float(value):
    if value in (None, "", "nan", "NaN"):
        return None
    return float(value)


def _score(row: dict[str, Any]) -> dict[str, Any]:
    complete = str(row.get("observation_complete", "0")).lower() in ("1", "true")
    return {"review_date": row["date"], "threat_probability": _float(row.get("threat_probability")),
            "if_risk": _float(row.get("if_risk")), "fused_risk": _float(row.get("fused_risk")),
            "forecasted_risk": _float(row.get("forecasted_risk")),
            "drift_error": _float(row.get("drift_error")),
            "predicted_scenario": row.get("predicted_scenario"),
            "observation_complete": complete,
            "selection_status": "complete" if complete else "incomplete",
            "missing_sensors": []}


def _evidence_dates(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


@router.get("/hosts")
def hosts(storage=Depends(get_storage), _operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    _enabled()
    with _connection(storage) as conn, conn.cursor() as cur:
        run = _latest_run(cur)
        if run is None:
            return {"ok": True, "hosts": [], "as_of": None, "run_id": None}
        run_id, as_of, summary, created_at = run
        cur.execute("SELECT s.agent_id, s.score_json, q.rank, r.item_json "
                    "FROM scenario_replay.daily_scores s "
                    "LEFT JOIN scenario_replay.review_queue q ON q.run_id=s.run_id AND q.agent_id=s.agent_id "
                    "LEFT JOIN scenario_replay.host_rankings r ON r.run_id=s.run_id AND r.agent_id=s.agent_id "
                    "WHERE s.run_id=%s AND s.review_date=%s AND s.agent_id=ANY(%s) ORDER BY s.agent_id",
                    (run_id, as_of, summary.get("scenario_agents", [])))
        rows = cur.fetchall()
        result = []
        for agent_id, score, rank, ranking in rows:
            cur.execute("SELECT risk_score, risk_level, summary, created_at FROM risk_events "
                        "WHERE agent_id=%s AND created_at >= %s ORDER BY created_at DESC LIMIT 1", (agent_id, created_at))
            live = cur.fetchone()
            cur.execute("SELECT MAX(risk_score) FROM risk_events WHERE agent_id=%s AND created_at >= %s",
                        (agent_id, created_at))
            peak = cur.fetchone()[0]
            result.append({"agent_id": agent_id, "hostname": agent_id.removeprefix("AGENT-"),
                           "model": _score(score), "pair_threat_score": _float(ranking.get("pair_threat")) if ranking else None,
                           "rank": rank, "live_risk_score": float(live[0]) if live and live[0] is not None else None,
                           "live_peak_risk_score": float(peak) if peak is not None else None,
                           "live_risk_level": live[1] if live else None,
                           "live_summary": live[2] if live else None,
                           "live_at": live[3].isoformat() if live and live[3] else None})
    return {"ok": True, "run_id": run_id, "as_of": as_of.isoformat(), "summary": summary, "hosts": result}


@router.get("/review-queue")
def review_queue(storage=Depends(get_storage), _operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    _enabled()
    with _connection(storage) as conn, conn.cursor() as cur:
        run = _latest_run(cur)
        if run is None:
            return {"ok": True, "as_of": None, "count": 0, "queue": []}
        run_id, as_of, _, _ = run
        cur.execute("SELECT agent_id, rank, item_json FROM scenario_replay.review_queue "
                    "WHERE run_id=%s ORDER BY rank", (run_id,))
        items = []
        for agent_id, rank, raw in cur.fetchall():
            cur.execute("SELECT score_json FROM scenario_replay.daily_scores "
                        "WHERE run_id=%s AND agent_id=%s AND review_date=%s", (run_id, agent_id, as_of))
            score = cur.fetchone()[0]
            items.append({"as_of_date": as_of.isoformat(), "rank": rank, "agent_id": agent_id,
                          "hostname": agent_id.removeprefix("AGENT-"),
                          "pair_threat_score": _float(raw["pair_threat"]),
                          "primary_hypothesis": score["predicted_scenario"],
                          "evidence_dates": _evidence_dates(raw.get("evidence_dates")),
                          "analyst_status": "needs_investigation", "analyst_note": None})
    return {"ok": True, "as_of": as_of.isoformat(), "count": len(items), "queue": items}


@router.get("/endpoints/{agent_id}/trajectory")
def trajectory(agent_id: str, storage=Depends(get_storage),
               _operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    _enabled()
    with _connection(storage) as conn, conn.cursor() as cur:
        run = _latest_run(cur)
        if run is None:
            day = datetime.now(timezone.utc).date() - timedelta(days=1)
            return {"ok": True, "agent_id": agent_id, "as_of": day.isoformat(),
                    "consecutive_complete_days": 0, "review_eligible": False, "history": []}
        run_id, as_of, _, _ = run
        cur.execute("SELECT score_json FROM scenario_replay.daily_scores "
                    "WHERE run_id=%s AND agent_id=%s ORDER BY review_date DESC LIMIT 30", (run_id, agent_id))
        history = [_score(row[0]) for row in cur.fetchall()]
    days = {date.fromisoformat(row["review_date"]) for row in history if row["observation_complete"]}
    cursor, consecutive = as_of, 0
    while cursor in days:
        consecutive += 1
        cursor -= timedelta(days=1)
    return {"ok": True, "agent_id": agent_id, "as_of": as_of.isoformat(),
            "consecutive_complete_days": consecutive, "review_eligible": consecutive >= 22,
            "history": history}


@router.get("/events/{event_id}/provenance")
def event_provenance(event_id: str, storage=Depends(get_storage),
                     _operator: OperatorPrincipal = Depends(require_operator("operator:read"))):
    _enabled()
    try:
        uuid.UUID(event_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid event ID") from exc
    ch = getattr(storage, "ch", None)
    if ch is None or not ch.is_connected():
        raise HTTPException(status_code=503, detail="Telemetry storage unavailable")
    result = ch._query("SELECT payload_id FROM telemetry_events WHERE event_id=toUUID(%(id)s) LIMIT 1",
                       {"id": event_id})
    if not result.result_rows:
        raise HTTPException(status_code=404, detail="Event not found")
    payload_id = result.result_rows[0][0]
    quality = ch._query("SELECT agent_quality_json FROM collector_results WHERE payload_id=%(pid)s "
                        "AND agent_quality_json != '' LIMIT 1", {"pid": payload_id})
    details = json.loads(quality.result_rows[0][0]) if quality.result_rows else {}
    return {"ok": True, "event_id": event_id, "payload_id": payload_id, "provenance": details}
