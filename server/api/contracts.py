"""Response contracts for primary dashboard data paths."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel


class OpenResponse(BaseModel):
    class Config:
        extra = "allow"


class StatsResponse(OpenResponse):
    ok: bool
    freshness: dict[str, Any] | None = None


class DashboardSummaryResponse(OpenResponse):
    ok: bool
    pc_status: dict[str, Any]
    agents: list[dict[str, Any]]
    agents_available: bool
    risk_counts: dict[str, int]
    risk_events: list[dict[str, Any]]
    stats: dict[str, Any]
    anomalies: list[Any]
    total_risk_events: int | None = None
    freshness: dict[str, Any] | None = None


class HealthResponse(OpenResponse):
    ok: bool
    database: str
    analytics: str
    telemetry_collection: str
    log_ingestion_enabled: bool
    queue_status: str


class TelemetryExplorerEventResponse(OpenResponse):
    event_id: str
    timestamp: str
    collector_name: str
    status: str
    summary_preview: str | None = None
    id: str | None = None
    collected_at: str | None = None
    agent_id: str | None = None
    collector: str | None = None
    hostname: str | None = None
    username: str | None = None


class TelemetryExplorerResponse(OpenResponse):
    ok: bool
    events: list[TelemetryExplorerEventResponse]
    logs: list[TelemetryExplorerEventResponse]
    next_cursor: str | None = None
    has_more: bool = False
    limit: int | None = None
    source: str | None = None
