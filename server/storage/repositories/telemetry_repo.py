"""
server/storage/repositories/telemetry_repo.py
---------------------------------------------
Telemetry & Logs Repository.
Coordinates durable PostgreSQL ingestion and telemetry reads from the
explicitly selected PostgreSQL or ClickHouse backend.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("insiedr.storage.telemetry_repo")


class TelemetryRepository:
    """Encapsulates raw payload logs, collector execution data, and normalized features."""

    def __init__(
        self,
        postgres_storage: Any,
        clickhouse_storage: Optional[Any] = None,
        telemetry_read_backend: str = "postgres",
    ) -> None:
        self.pg = postgres_storage
        self.ch = clickhouse_storage
        self.telemetry_read_backend = telemetry_read_backend

    def _has_ch(self) -> bool:
        return self.ch is not None and getattr(self.ch, "is_connected", lambda: False)()

    def store_payload(self, envelope: Dict[str, Any], decrypted_payload: Dict[str, Any]) -> bool:
        """Require a durable PG commit before the caller can acknowledge telemetry.

        ClickHouse's in-memory batch queue is an asynchronous analytics replica,
        not sufficient evidence for an agent to discard its durable spool entry.
        """
        if self.pg is None:
            raise RuntimeError("durable PostgreSQL telemetry storage is unavailable")
        inserted = self.pg.store_raw_payload(envelope, decrypted_payload)
        if inserted is False:
            return False  # A concurrent retry must not duplicate ClickHouse event rows.

        # The transactional outbox is the sole telemetry replication path.
        # A second enqueue here duplicates observations and bypasses the
        # plaintext policy applied when the outbox entry is created.
        return True

    def get_latest_collector_states(self, agent_id: str) -> List[Dict[str, Any]]:
        # PostgreSQL contains every acknowledged observation. ClickHouse may be
        # behind or partially flushed; using it here could resurrect old state.
        return self.pg.get_latest_collector_states(agent_id)

    def list_logs(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        """Keep one configured source for a complete pagination sequence."""
        if self.telemetry_read_backend == "clickhouse":
            if not self._has_ch():
                from server.api.errors import AnalyticsUnavailableError
                raise AnalyticsUnavailableError("ClickHouse analytics is unavailable")
            return self.ch.list_logs(limit=limit, offset=offset, **filters)
        return self.pg.list_logs(limit=limit, offset=offset, **filters)

    def list_collector_results(self, limit: int = 100, offset: int = 0, **filters) -> List[Dict[str, Any]]:
        """Keep collector history reads on the configured source."""
        if self.telemetry_read_backend == "clickhouse":
            if not self._has_ch():
                from server.api.errors import AnalyticsUnavailableError
                raise AnalyticsUnavailableError("ClickHouse analytics is unavailable")
            return self.ch.list_collector_results(limit=limit, offset=offset, **filters)
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

    def get_feature_vectors(self, payload_ids: list[str]) -> Dict[str, Dict[str, Any]]:
        """Read a page of feature vectors from the configured telemetry source."""
        if self.telemetry_read_backend == "clickhouse":
            if not self._has_ch():
                from server.api.errors import AnalyticsUnavailableError
                raise AnalyticsUnavailableError("ClickHouse analytics is unavailable")
            return self.ch.get_feature_vectors(payload_ids)
        if hasattr(self.pg, "get_feature_vectors"):
            return self.pg.get_feature_vectors(payload_ids)
        return {
            payload_id: self.pg.get_feature_vector(payload_id)
            for payload_id in payload_ids
        }

    def list_daily_feature_vectors(self, username: str | None, hostname: str | None, limit: int = 16) -> List[Dict[str, Any]]:
        """Retrieve day-bucketed feature vectors for time-series anomaly models."""
        return self.pg.list_daily_feature_vectors(username=username, hostname=hostname, limit=limit)

    def get_distinct_collectors(self) -> List[str]:
        if self._has_ch():
            try:
                cols = self.ch.get_distinct_collectors()
                if cols:
                    return cols
            except Exception:
                pass
        return getattr(self.pg, "get_distinct_collectors", lambda: [])()

    def get_distinct_usernames(self) -> List[str]:
        if hasattr(self.pg, "get_distinct_usernames"):
            try:
                users = self.pg.get_distinct_usernames()
                if users:
                    return users
            except Exception:
                pass
        if self._has_ch():
            try:
                users = self.ch.get_distinct_usernames()
                if users:
                    return users
            except Exception:
                pass
        return getattr(self.pg, "get_distinct_usernames", lambda: [])()

    def count_collector_results(self, **filters) -> int:
        if self._has_ch():
            try:
                cnt = self.ch.count_collector_results(**filters)
                if cnt > 0:
                    return cnt
            except Exception:
                pass
        return getattr(self.pg, "count_collector_results", lambda **kw: 0)(**filters)
