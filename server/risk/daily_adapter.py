"""Admission boundary for observed Model V3 daily40 rows.

Source aggregation must populate endpoint_daily_feature_rollups with verified
counter windows and sensor coverage. This module never guesses missing values.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA_PATH = Path(__file__).resolve().parents[2] / "model" / "run" / "schema.json"
RAW_FEATURES: tuple[str, ...] = tuple(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["raw_features"])
CONTRACT_VERSION = "v3_daily40_observed_v1"
RATIOS = ("after_hours_logon_ratio", "after_hours_usb_ratio", "external_domain_ratio")
SUBSETS = (
    ("unique_pc_count", "successful_logons"),
    ("new_filename_count", "unique_filename_count"),
    ("unique_filename_count", "file_access_count"),
    ("file_delete_count", "file_access_count"),
    ("new_domain_count", "unique_domain_count"),
    ("unique_domain_count", "http_request_count"),
    ("file_sharing_visit_count", "http_request_count"),
    ("unique_remote_ip_count", "external_connection_count"),
)


@dataclass(frozen=True)
class DailyAssessment:
    agent_id: str
    hostname: str
    review_date: date
    status: str
    missing: tuple[str, ...]
    features: tuple[float, ...] | None

    @property
    def observation_complete(self) -> bool:
        return self.features is not None


def _verified(value: Any) -> bool:
    return value is True or value == 1


def assess_daily_rollup(row: Mapping[str, Any]) -> DailyAssessment:
    """Validate one cache row; incomplete rows have no numeric model vector."""
    agent_id = str(row.get("agent_id") or "").strip()
    hostname = str(row.get("hostname") or "").strip()
    review_date = row.get("review_date")
    if isinstance(review_date, str):
        review_date = date.fromisoformat(review_date)
    if not agent_id or not hostname or not isinstance(review_date, date):
        raise ValueError("agent_id, hostname and UTC review_date are required")

    missing = [name for name in RAW_FEATURES if row.get(name) is None]
    sensor_missing = row.get("missing_sensors_json") or []
    if isinstance(sensor_missing, str):
        sensor_missing = json.loads(sensor_missing)
    if not isinstance(sensor_missing, list):
        raise ValueError("missing_sensors_json must be a list")
    missing.extend(f"sensor:{name}" for name in sensor_missing)
    if row.get("journal_gap_detected"):
        missing.append("sensor:usn_journal_gap")
    required_flags = ("observation_complete", "feature_contract_verified",
                      "sensor_coverage_verified", "timezone_verified")
    missing.extend(name for name in required_flags if not _verified(row.get(name)))
    if row.get("feature_contract_version") != CONTRACT_VERSION:
        missing.append("feature_contract_version")
    if row.get("source_kind") not in ("observed_unlabeled", "observed_labeled"):
        missing.append("source_kind")
    if missing:
        return DailyAssessment(agent_id, hostname, review_date,
                               "abstain_missing_sensors", tuple(sorted(set(missing))), None)

    values: dict[str, float] = {}
    for name in RAW_FEATURES:
        try:
            value = float(row[name])
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"invalid {name}") from exc
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"nonfinite or negative {name}")
        values[name] = value
    for name in RATIOS:
        if values[name] > 1:
            raise ValueError(f"ratio exceeds 1: {name}")
    if values["weekend_activity"] not in (0, 1):
        raise ValueError("weekend_activity must be 0 or 1")
    if values["interactive_duration_seconds"] > 86400:
        raise ValueError("interactive duration exceeds one day")
    for child, total in SUBSETS:
        if values[child] > values[total] + 1e-7:
            raise ValueError(f"{child} exceeds {total}")
    return DailyAssessment(agent_id, hostname, review_date, "complete", (),
                           tuple(values[name] for name in RAW_FEATURES))


def consecutive_complete_days(rows: Iterable[DailyAssessment], as_of: date) -> dict[str, int]:
    """Count complete days ending at as_of, resetting across every missing day."""
    by_agent: dict[str, set[date]] = {}
    for row in rows:
        if row.observation_complete:
            by_agent.setdefault(row.agent_id, set()).add(row.review_date)
    result = {}
    for agent_id, days in by_agent.items():
        cursor = as_of
        count = 0
        while cursor in days:
            count += 1
            cursor -= timedelta(days=1)
        result[agent_id] = count
    return result
