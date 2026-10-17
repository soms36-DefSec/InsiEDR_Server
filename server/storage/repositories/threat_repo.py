"""
server/storage/repositories/threat_repo.py
------------------------------------------
Threat Intelligence & Detection Events Repository.
Coordinates baselines, model inference outputs, anomalies, and risk events.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("insiedr.storage.threat_repo")


class ThreatRepository:
    """Encapsulates baselines, detection anomalies, and correlated risk events."""

    def __init__(self, postgres_storage: Any, clickhouse_storage: Optional[Any] = None) -> None:
        self.pg = postgres_storage
        self.ch = clickhouse_storage

    def _has_ch(self) -> bool:
        return self.ch is not None and getattr(self.ch, "is_connected", lambda: False)()

    # Baselines (ACID: stored in PostgreSQL 16)
    def save_baseline(self, baseline: Dict[str, Any]) -> None:
        self.pg.save_baseline(baseline)

    def load_baseline(self, username: str) -> Optional[Dict[str, Any]]:
        return self.pg.load_baseline(username)

    def list_baselines(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.pg.list_baselines(limit=limit, offset=offset)

    # Model Outputs & Inferences
    def save_model_output(self, output: Dict[str, Any]) -> None:
        if self._has_ch():
            self.ch.save_model_output(output)
        self.pg.save_model_output(output)

    # Risk Events & Anomalies
    def save_risk_event(self, event: Dict[str, Any]) -> None:
        if self._has_ch():
            self.ch.save_risk_event(event)
        self.pg.save_risk_event(event)

    def list_risk_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        if self._has_ch():
            res = self.ch.list_risk_events(limit=limit, offset=offset)
            if res:
                return res
        return self.pg.list_risk_events(limit=limit, offset=offset)

    def list_anomalies(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        if self._has_ch():
            res = self.ch.list_anomalies(limit=limit, offset=offset)
            if res:
                return res
        return self.pg.list_anomalies(limit=limit, offset=offset)

    def list_recent_risk_scores(self, username: str | None, hostname: str | None, limit: int = 7) -> List[Dict[str, Any]]:
        return self.pg.list_recent_risk_scores(username=username, hostname=hostname, limit=limit)

    def get_max_risk_score_in_window(self, username: str, hours: int) -> float:
        return self.pg.get_max_risk_score_in_window(username=username, hours=hours)

    def get_recent_risk_events_in_window(self, username: str, hours: int = 4, limit: int = 50) -> List[Dict[str, Any]]:
        return self.pg.get_recent_risk_events_in_window(username=username, hours=hours, limit=limit)

    def get_user_risk_scores(self, username: str, limit: int = 30) -> List[Dict[str, Any]]:
        if self._has_ch():
            scores = self.ch.get_user_risk_scores(username=username, limit=limit)
            if scores:
                return scores
        return self.pg.get_user_risk_scores(username=username, limit=limit)

    def get_user_predictions(self, username: str) -> Optional[Dict[str, Any]]:
        return self.pg.get_user_predictions(username)

    def acquire_entity_lock(self, entity_id: str):
        return self.pg.acquire_entity_lock(entity_id)
