"""
server/storage/hybrid_storage.py
--------------------------------
Enterprise Hybrid Storage Coordinator for InsiEDR.

Architecture & Design:
======================
Implements the Facade and Repository pattern over dual database engines:
  1. PostgreSQL 16 (OLTP):
     - ACID transactions for fleet agents, users, baselines, G-model daily risk memory.
  2. ClickHouse 24+ (OLAP):
     - High-velocity columnar storage for raw payloads, collector results,
       features, model outputs, risk events, and anomalies with native TTL retention.

Developer & Team Extensibility:
===============================
  - Inherits from `BaseStorage` to maintain 100% backwards compatibility with
    all FastAPI endpoints, streaming exporters, detectors, and unit tests.
  - Pluggable Telemetry Interceptor Pipeline executes on every incoming payload.
  - Domain Repositories (`fleet`, `telemetry`, `threat`) are accessible directly
    for modular service development.
  - Resilient Graceful Degradation: If ClickHouse is disabled or unreachable
    (e.g., lightweight testing environments), falls back automatically to
    PostgreSQL or SQLite with zero errors.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from server.storage.base import BaseStorage
from server.storage.interceptors import interceptor_pipeline
from server.storage.repositories import FleetRepository, TelemetryRepository, ThreatRepository

logger = logging.getLogger("insiedr.storage.hybrid")


class HybridStorage(BaseStorage):
    """
    Unified Storage Coordinator uniting PostgreSQL 16 and ClickHouse.
    """

    def __init__(
        self,
        postgres_storage: Any,
        clickhouse_storage: Optional[Any] = None,
    ) -> None:
        self.pg = postgres_storage
        self.ch = clickhouse_storage

        # Domain Repositories
        self.fleet = FleetRepository(self.pg)
        self.telemetry = TelemetryRepository(self.pg, self.ch)
        self.threat = ThreatRepository(self.pg, self.ch)

        logger.info("HybridStorage initialized (Postgres: %s, ClickHouse: %s)",
                    "Active", "Active" if (self.ch and getattr(self.ch, "is_connected", lambda: False)()) else "Disabled/Fallback")

    # Expose underlying connection context for legacy dependencies
    def connection(self):
        return self.pg.connection()

    @property
    def dsn(self):
        return getattr(self.pg, "dsn", None)

    def ensure_migrations(self) -> None:
        """Apply PostgreSQL schema migrations and ClickHouse table schemas."""
        if hasattr(self.pg, "ensure_migrations"):
            try:
                self.pg.ensure_migrations()
            except Exception as exc:
                logger.warning("PostgreSQL migration warning: %s", exc)

        if self.ch and hasattr(self.ch, "ensure_schema"):
            try:
                self.ch.ensure_schema()
            except Exception as exc:
                logger.warning("ClickHouse schema warning: %s", exc)

    def close(self) -> None:
        """Close connection pools and stop background batchers."""
        if self.ch and hasattr(self.ch, "close"):
            try:
                self.ch.close()
            except Exception:
                pass
        if hasattr(self.pg, "close"):
            try:
                self.pg.close()
            except Exception:
                pass

    # --------------------------------------------------------------------------
    # Telemetry Ingestion (with Interceptors & Dual-Routing)
    # --------------------------------------------------------------------------

    def store_raw_payload(self, envelope: Dict[str, Any], decrypted_payload: Dict[str, Any]) -> None:
        """
        Process telemetry payload:
          1. Runs pre-storage interceptors (PII scrubber, enrichers).
          2. Upserts agent identity to PostgreSQL 16 (ACID).
          3. Emits high-volume telemetry to ClickHouse (or PG fallback).
        """
        # 1. Run pluggable interceptors
        ctx = interceptor_pipeline.process(envelope, decrypted_payload)
        if ctx.is_dropped:
            logger.info("Payload '%s' was dropped before storage: %s",
                        decrypted_payload.get("payload_id"), ctx.drop_reason)
            return

        clean_envelope = ctx.envelope
        clean_payload = ctx.decrypted_payload

        # 2. Update Fleet State in PostgreSQL 16
        try:
            self.fleet.upsert_agent(clean_payload)
        except Exception as exc:
            logger.error("Failed upserting agent to PostgreSQL: %s", exc)

        # 3. Store High-Frequency Telemetry in ClickHouse (or PG fallback)
        try:
            self.telemetry.store_payload(clean_envelope, clean_payload)
        except Exception as exc:
            logger.error("Failed storing telemetry payload: %s", exc)
            raise

    def get_payload(self, payload_id: str) -> Optional[Dict[str, Any]]:
        return self.pg.get_payload(payload_id)

    # --------------------------------------------------------------------------
    # Fleet Management
    # --------------------------------------------------------------------------

    def list_agents(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.fleet.list_agents(limit=limit, offset=offset)

    def get_pc_status(self, seconds_since_online: int = 300) -> Dict[str, Any]:
        return self.fleet.get_pc_status(seconds_since_online=seconds_since_online)

    def get_agent(self, agent_id: str) -> Dict[str, Any] | None:
        return self.fleet.get_agent(agent_id)

    def upsert_agent_heartbeat(
        self,
        agent_id: str,
        hostname: str,
        ip_address: str | None = None,
        agent_version: str | None = None,
        status: str = "active",
        metrics: dict[str, Any] | None = None,
        config_version: str | None = None,
    ) -> None:
        self.fleet.upsert_agent_heartbeat(
            agent_id=agent_id,
            hostname=hostname,
            ip_address=ip_address,
            agent_version=agent_version,
            status=status,
            metrics=metrics,
            config_version=config_version,
        )

    def queue_agent_task(
        self,
        agent_id: str,
        command: str,
        params: dict[str, Any] | None = None,
        signature: str | None = None,
        task_id: str | None = None,
    ) -> str:
        return self.fleet.queue_task(
            agent_id=agent_id,
            command=command,
            params=params,
            signature=signature,
            task_id=task_id,
        )

    def get_pending_agent_tasks(self, agent_id: str) -> List[Dict[str, Any]]:
        return self.fleet.get_pending_tasks(agent_id)

    def mark_tasks_dispatched(self, task_ids: List[str]) -> None:
        self.fleet.mark_tasks_dispatched(task_ids)

    def update_agent_task_result(
        self,
        agent_id: str,
        task_id: str,
        status: str,
        exit_code: int,
        message: str,
        completed_at: str | None = None,
    ) -> bool:
        return self.fleet.update_task_result(
            agent_id=agent_id,
            task_id=task_id,
            status=status,
            exit_code=exit_code,
            message=message,
            completed_at=completed_at,
        )

    def list_agent_tasks(self, agent_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        return self.fleet.list_agent_tasks(agent_id=agent_id, limit=limit, offset=offset)


    # --------------------------------------------------------------------------
    # Telemetry & Logs
    # --------------------------------------------------------------------------

    def list_logs(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        return self.telemetry.list_logs(limit=limit, offset=offset, **filters)

    def list_collector_results(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        return self.telemetry.list_collector_results(limit=limit, offset=offset, **filters)

    def get_feature_vector(self, payload_id: str) -> Dict[str, Any]:
        return self.telemetry.get_feature_vector(payload_id)

    def list_daily_feature_vectors(self, username: str | None, hostname: str | None, limit: int = 16) -> List[Dict[str, Any]]:
        return self.telemetry.list_daily_feature_vectors(username=username, hostname=hostname, limit=limit)

    def list_normalized_features(self, limit: int = 1000, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        return self.pg.list_normalized_features(limit=limit, offset=offset, **filters)

    def get_user_collectors(self, username: str) -> List[Dict[str, Any]]:
        return self.pg.get_user_collectors(username)


    # --------------------------------------------------------------------------
    # Threat Intelligence, Models & Baselines
    # --------------------------------------------------------------------------

    def save_baseline(self, baseline: Dict[str, Any]) -> None:
        self.threat.save_baseline(baseline)

    def load_baseline(self, username: str) -> Optional[Dict[str, Any]]:
        return self.threat.load_baseline(username)

    def list_baselines(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.threat.list_baselines(limit=limit, offset=offset)

    def save_model_output(self, output: Dict[str, Any]) -> None:
        self.threat.save_model_output(output)

    def save_risk_event(self, event: Dict[str, Any]) -> None:
        self.threat.save_risk_event(event)

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.threat.list_risk_events(limit=limit, offset=offset)

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.threat.list_anomalies(limit=limit, offset=offset)

    def list_recent_risk_scores(self, username: str | None, hostname: str | None, limit: int = 7) -> List[Dict[str, Any]]:
        return self.threat.list_recent_risk_scores(username=username, hostname=hostname, limit=limit)

    def get_max_risk_score_in_window(self, username: str, hours: int) -> float:
        return self.threat.get_max_risk_score_in_window(username=username, hours=hours)

    def get_user_risk_scores(self, username: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self.threat.get_user_risk_scores(username=username, limit=limit)

    def get_user_predictions(self, username: str) -> Optional[Dict[str, Any]]:
        return self.threat.get_user_predictions(username)

    # --------------------------------------------------------------------------
    # Fleet & Analytics Aggregations
    # --------------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """
        Aggregated fleet overview stats:
          - Relational counts (agents, baselines) from PostgreSQL 16.
          - Telemetry & anomaly counts from ClickHouse (or PG fallback).
        """
        # Baseline stats from PostgreSQL
        pg_stats = self.pg.get_stats()

        if self.ch and getattr(self.ch, "is_connected", lambda: False)():
            ch_stats = self.ch.get_telemetry_stats()
            # Overlay ClickHouse high-precision telemetry counts
            for k in ("logs", "collector_results", "anomalies", "risk_events"):
                if k in ch_stats and ch_stats[k] > 0:
                    pg_stats[k] = ch_stats[k]
            if ch_stats.get("collector_status"):
                pg_stats["collector_status"] = ch_stats["collector_status"]
            if ch_stats.get("collector_counts"):
                pg_stats["collector_counts"] = ch_stats["collector_counts"]
            if ch_stats.get("source_quality"):
                pg_stats["source_quality"] = ch_stats["source_quality"]

        return pg_stats
