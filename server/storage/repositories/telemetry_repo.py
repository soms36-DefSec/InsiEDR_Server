"""
server/storage/repositories/telemetry_repo.py
---------------------------------------------
Telemetry & Logs Repository.
Coordinates high-throughput telemetry ingestion and analytical queries,
routing to ClickHouse when available, with resilient fallback to PostgreSQL.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("insiedr.storage.telemetry_repo")


class TelemetryRepository:
    """Encapsulates raw payload logs, collector execution data, and normalized features."""

    def __init__(self, postgres_storage: Any, clickhouse_storage: Optional[Any] = None) -> None:
        self.pg = postgres_storage
        self.ch = clickhouse_storage

    def _has_ch(self) -> bool:
        return self.ch is not None and getattr(self.ch, "is_connected", lambda: False)()

    def store_payload(self, envelope: Dict[str, Any], decrypted_payload: Dict[str, Any]) -> None:
        """Store telemetry with dual-write resilience: ACID persistence in PostgreSQL + high-velocity OLAP in ClickHouse."""
        pg_success = False
        if self.pg:
            try:
                self.pg.store_raw_payload(envelope, decrypted_payload)
                pg_success = True
            except Exception as pg_err:
                logger.error("PostgreSQL store_raw_payload failed: %s", pg_err)
                if not self._has_ch():
                    raise

        if self._has_ch():
            try:
                self.ch.store_raw_payload(envelope, decrypted_payload)
            except Exception as ch_err:
                logger.warning("ClickHouse store_raw_payload failed: %s", ch_err)
                if not pg_success:
                    raise

    def list_logs(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        """Query raw payload logs. Tries ClickHouse first, falling back to PostgreSQL if empty or on error."""
        if self._has_ch():
            try:
                rows = self.ch.list_logs(limit=limit, offset=offset, **filters)
                if rows:
                    return rows
            except Exception as exc:
                logger.warning("ClickHouse list_logs query failed, falling back to PostgreSQL: %s", exc)
        return self.pg.list_logs(limit=limit, offset=offset, **filters)

    def list_collector_results(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        """Query collector observation history. Tries ClickHouse first, falling back to PostgreSQL if empty or on error."""
        if self._has_ch():
            try:
                rows = self.ch.list_collector_results(limit=limit, offset=offset, **filters)
                if rows:
                    return rows
            except Exception as exc:
                logger.warning("ClickHouse list_collector_results query failed, falling back to PostgreSQL: %s", exc)
        return self.pg.list_collector_results(limit=limit, offset=offset, **filters)

    def get_feature_vector(self, payload_id: str) -> Dict[str, Any]:
        """Retrieve all normalized features for a given payload."""
        if self._has_ch():
            try:
                feats = self.ch.get_feature_vector(payload_id)
                if feats:
                    return feats
            except Exception as exc:
                logger.warning("ClickHouse get_feature_vector query failed, falling back to PostgreSQL: %s", exc)
        return self.pg.get_feature_vector(payload_id)

    def list_daily_feature_vectors(self, username: str | None, hostname: str | None, limit: int = 16) -> List[Dict[str, Any]]:
        """Retrieve day-bucketed feature vectors for time-series anomaly models."""
        return self.pg.list_daily_feature_vectors(username=username, hostname=hostname, limit=limit)
