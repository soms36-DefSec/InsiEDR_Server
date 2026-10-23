"""Shared risk presentation policy for API responses and fleet snapshots."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Mapping


ACTIVE_RISK_WINDOW = timedelta(minutes=30)


def is_test_risk_event(event: Mapping[str, Any], test_agent_ids: frozenset[str]) -> bool:
    """Honor both the current allowlist and a marker retained on the event."""
    if str(event.get("agent_id") or "") in test_agent_ids:
        return True
    signals = event.get("correlated_signals_json")
    if isinstance(signals, str):
        try:
            signals = json.loads(signals)
        except json.JSONDecodeError:
            return False
    return isinstance(signals, dict) and signals.get("source_kind") == "synthetic_test"


def risk_level(score: Any) -> str:
    """Match the thresholds used when RiskAggregator persists a risk event."""
    try:
        value = float(score or 0)
    except (TypeError, ValueError):
        value = 0.0
    if value >= 90:
        return "CRITICAL"
    if value >= 70:
        return "HIGH"
    if value >= 40:
        return "MEDIUM"
    return "LOW"


def risk_event_is_active(event: Mapping[str, Any], now: datetime | None = None) -> bool:
    """A stored finding is active only during its explicit presentation window."""
    timestamp = event.get("created_at")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return False
    if not isinstance(timestamp, datetime):
        return False
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age = current - timestamp.astimezone(timezone.utc)
    return timedelta(minutes=-2) <= age <= ACTIVE_RISK_WINDOW


def annotate_risk_event(event: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Keep historical score intact and add the current fleet presentation state."""
    event["risk_level"] = risk_level(event.get("risk_score"))
    event["_computed_level"] = event["risk_level"]
    event["is_active"] = risk_event_is_active(event, now)
    event["active_risk_score"] = event.get("risk_score") if event["is_active"] else 0.0
    event["active_risk_level"] = event["risk_level"] if event["is_active"] else "LOW"
    return event
