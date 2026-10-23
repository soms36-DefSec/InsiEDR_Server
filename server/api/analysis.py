from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from server.api.cache import api_cache
from server.api.deps import get_storage
from server.risk.presentation import annotate_risk_event

router = APIRouter(prefix="/api", tags=["Threat Intelligence & Analysis"])
bp = router  # Backward compatibility alias


@router.get("/pc-status")
@router.get("/v1/pc-status")
async def get_pc_status(
    seconds: int = Query(300, ge=1),
    storage=Depends(get_storage),
):
    """Returns PC online/offline status"""
    cache_key = f"pc_status_{seconds}"
    cached_val = api_cache.get(cache_key)
    if cached_val is not None:
        return cached_val

    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        status = storage.get_pc_status(seconds_since_online=seconds)
        resp_data = {"ok": True, **status}
        api_cache.set(cache_key, resp_data, ttl=3.0)
        return resp_data
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/user-collectors/{username}")
@router.get("/v1/user-collectors/{username}")
async def get_user_collectors(username: str, storage=Depends(get_storage)):
    """Returns all collectors and their latest data for a user"""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        collectors = storage.get_user_collectors(username)
        return {"ok": True, "username": username, "collectors": collectors}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/user-risk-scores/{username}")
@router.get("/v1/user-risk-scores/{username}")
async def get_user_risk_scores(
    username: str,
    limit: int = Query(50, ge=1),
    storage=Depends(get_storage),
):
    """Returns historical risk scores for a user"""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        risk_scores = storage.get_user_risk_scores(username, limit=limit)
        for rs in risk_scores:
            _patch_risk_level(rs)
        return {"ok": True, "username": username, "risk_scores": risk_scores}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/user-predictions/{username}")
@router.get("/v1/user-predictions/{username}")
async def get_user_predictions(username: str, storage=Depends(get_storage)):
    """Returns latest model predictions for a user, enriched for UI consumption"""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        raw_predictions = storage.get_user_predictions(username)
        if raw_predictions is None:
            return {"ok": True, "username": username, "predictions": None, "message": "No predictions available"}

        st = raw_predictions.get("short_term") or {}
        contrib = st.get("contributions") or {}

        scenario_name = contrib.get("predicted_scenario") or "normal"
        scenario_conf = float(contrib.get("scenario_confidence", st.get("confidence", 0.0)))
        rvfl_err = float(contrib.get("rvfl_error", 0.0))
        score = float(st.get("score", 0.0))

        # Determine behavioral risk level and recommended protocol
        if rvfl_err >= 0.08 or score >= 90.0:
            b_risk = "CRITICAL" if score >= 90.0 else "HIGH"
            action = "Isolate endpoint and revoke active sessions immediately."
        elif rvfl_err >= 0.03 or score >= 70.0:
            b_risk = "HIGH" if score >= 70.0 else "MEDIUM"
            action = "Escalate for analyst review; monitor telemetry closely."
        elif score >= 40.0:
            b_risk = "MEDIUM"
            action = "Minor baseline variance detected; standard monitoring."
        else:
            b_risk = "LOW"
            action = "Normal baseline behavior; no action required."

        predictions = {
            "behavioral_risk": b_risk,
            "rvfl_error": rvfl_err,
            "score": score,
            "confidence": scenario_conf,
            "predicted_scenario": {
                "scenario": scenario_name,
                "confidence": scenario_conf,
            },
            "recommended_action": action,
            "domain_scores": contrib.get("domain_scores", {}),
            "summary": st.get("summary", ""),
            "short_term": st,
            "long_term": raw_predictions.get("long_term"),
        }
        return {"ok": True, "username": username, "predictions": predictions}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@router.get("/user-analysis/{username}")
@router.get("/v1/user-analysis/{username}")
async def get_user_analysis(username: str, storage=Depends(get_storage)):
    """Combined endpoint: returns collectors, risk scores, and predictions for a user"""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        collectors = storage.get_user_collectors(username)
        risk_scores = storage.get_user_risk_scores(username, limit=50)
        for rs in risk_scores:
            _patch_risk_level(rs)
        predictions = storage.get_user_predictions(username)

        return {
            "ok": True,
            "username": username,
            "collectors": collectors,
            "risk_scores": risk_scores,
            "predictions": predictions,
        }
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


def _patch_risk_level(event: dict):
    annotate_risk_event(event)


@router.get("/risk-events")
@router.get("/v1/risk-events")
async def get_risk_events(
    limit: int = Query(500, ge=1),
    offset: int = Query(0, ge=0),
    storage=Depends(get_storage),
):
    """Returns paginated risk events for historical timeline views."""
    if storage is None:
        return JSONResponse({"ok": False, "error": "storage is not configured"}, status_code=503)

    try:
        risk_events = storage.list_risk_events(limit=limit, offset=offset)
        for event in risk_events:
            _patch_risk_level(event)
        return {"ok": True, "risk_events": risk_events}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)



