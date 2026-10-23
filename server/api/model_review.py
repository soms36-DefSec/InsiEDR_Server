"""Authenticated analyst access to Model V3 shadow reviews."""
from __future__ import annotations

from datetime import date, timedelta, timezone, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from server.api.deps import OperatorPrincipal, get_storage, require_operator
from server.storage.repositories.model_repo import ModelReviewRepository

router = APIRouter(prefix="/api/v1/detection/ml", tags=["Model V3 Review"])


class TriageUpdate(BaseModel):
    analyst_status: Literal[
        "needs_investigation", "benign_context", "confirmed_incident",
        "acknowledged_suppressed",
    ]
    analyst_note: str | None = Field(default=None, max_length=2000)


def _repo(storage) -> ModelReviewRepository:
    if storage is None:
        raise HTTPException(status_code=503, detail="Storage unavailable")
    return ModelReviewRepository(storage)


@router.get("/review-queue")
def get_review_queue(
    as_of: date | None = Query(default=None),
    storage=Depends(get_storage),
    _operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    items = _repo(storage).get_latest_review_queue(as_of)
    return {"ok": True, "as_of": as_of.isoformat() if as_of else
            (items[0]["as_of_date"] if items else None), "count": len(items), "queue": items}


@router.patch("/review-queue/{as_of}/{agent_id}")
def update_review_queue(
    as_of: date, agent_id: str, body: TriageUpdate,
    storage=Depends(get_storage),
    operator: OperatorPrincipal = Depends(require_operator("analyst")),
):
    if not _repo(storage).update_queue_triage(as_of, agent_id, body.analyst_status,
                                              body.analyst_note, operator.actor):
        raise HTTPException(status_code=404, detail="Review candidate not found")
    return {"ok": True, "updated": True}


@router.get("/endpoints/{agent_id}/trajectory")
def get_endpoint_trajectory(
    agent_id: str, as_of: date | None = Query(default=None),
    limit: int = Query(default=30, ge=1, le=90),
    storage=Depends(get_storage),
    _operator: OperatorPrincipal = Depends(require_operator("operator:read")),
):
    day = as_of or (datetime.now(timezone.utc).date() - timedelta(days=1))
    rows = _repo(storage).get_endpoint_trajectory(agent_id, limit)
    latest = next((row for row in rows if row["review_date"] <= day.isoformat()), None)
    complete_dates = {date.fromisoformat(row["review_date"]) for row in rows
                      if row["observation_complete"]}
    consecutive = 0
    cursor = day
    while cursor in complete_dates:
        consecutive += 1
        cursor -= timedelta(days=1)
    return {"ok": True, "agent_id": agent_id, "as_of": day.isoformat(),
            "prediction": latest,
            "model_state": ("stale" if latest and (day - date.fromisoformat(latest["review_date"])).days > 0
                            else "available" if latest and latest.get("threat_probability") is not None
                            else "no_input" if latest is None
                            else "invalid_coverage" if not latest.get("observation_complete")
                            else "temporal_warmup"),
            "freshness_days": ((day - date.fromisoformat(latest["review_date"])).days
                               if latest else None),
            "consecutive_complete_days": consecutive,
            "forecast_ready": consecutive >= 8, "review_eligible": consecutive >= 22,
            "history": rows}
