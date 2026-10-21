"""Bounded lookup and validation of precomputed Model V3 endpoint context."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
import json
import math
from typing import Any, Mapping

from server.config import config
from server.risk.daily_adapter import SCHEMA_PATH

CLASSES = frozenset(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["classes"])


@lru_cache(maxsize=4)
def _redis_client(url: str):
    import redis
    return redis.Redis.from_url(url, socket_connect_timeout=0.02, socket_timeout=0.02,
                                decode_responses=True)


def detector_from_cached_prior(raw: Mapping[str, Any], as_of: str,
                               *, shadow: bool) -> dict[str, Any] | None:
    """Return no detector for stale, malformed, or warming model state."""
    if not raw or raw.get("as_of") != as_of:
        return None
    try:
        if int(raw["history_days"]) < 22:
            return None
        threat = float(raw["threat_probability"])
        fused = float(raw["fused_risk"])
        drift = float(raw["drift_error"])
        pair = float(raw["pair_threat"])
        scenario = str(raw["predicted_scenario"])
        probabilities = json.loads(raw["scenario_probabilities_json"])
        if (not all(math.isfinite(x) and 0 <= x <= 1 for x in (threat, fused, drift, pair))
                or scenario not in CLASSES or set(probabilities) != CLASSES
                or not all(isinstance(p, (int, float)) and math.isfinite(p) and 0 <= p <= 1
                           for p in probabilities.values())):
            return None
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None
    return {
        "detector_name": "ml_pipeline",
        "score": threat * 100.0,
        "confidence": 0.85,
        "is_anomaly": threat >= 0.5247461037635804 or drift >= 0.37640477627357144,
        "reason": f"Model V3 host hypothesis: {scenario}",
        "predicted_scenario": scenario,
        "is_shadow": shadow,
        "evidence": {"probabilities": probabilities, "fused_risk": fused,
                     "drift_error": drift, "pair_threat": pair,
                     "as_of": as_of, "model_version": raw.get("model_version", "Model V3")},
    }


def get_cached_ml_detector(agent_id: str) -> dict[str, Any] | None:
    if not agent_id or not config.redis_url:
        return None
    expected = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    try:
        raw = _redis_client(config.redis_url).hgetall(f"insiedr:ml:endpoint:{agent_id}")
    except Exception:
        return None
    return detector_from_cached_prior(raw, expected,
                                      shadow=not config.enable_model_pipeline)
