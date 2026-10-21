"""Fail-closed feeder for attested UTC daily40 cache rows.

The raw collector-to-feature producer is deliberately separate: this reader does
not certify feature definitions or turn absent measurements into zeroes.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from server.risk.daily_adapter import RAW_FEATURES, DailyAssessment, assess_daily_rollup
from server.risk.ml_worker import ModelV3Worker


COLUMNS = (
    "agent_id", "hostname", "review_date", "observation_complete",
    "journal_gap_detected", "feature_contract_verified",
    "sensor_coverage_verified", "timezone_verified", "source_kind",
    "missing_sensors_json", "coverage_details_json", "feature_contract_version",
) + RAW_FEATURES


def load_assessments(clickhouse: Any, as_of: date) -> list[DailyAssessment]:
    """Read 22 completed UTC days and represent every absent host-day as incomplete."""
    if as_of >= datetime.now(timezone.utc).date():
        raise ValueError("Model V3 requires a completed UTC calendar day")
    client = getattr(clickhouse, "_client", clickhouse)
    if client is None:
        raise RuntimeError("ClickHouse daily40 cache unavailable")
    start = as_of - timedelta(days=21)
    result = client.query(
        f"SELECT {', '.join(COLUMNS)} FROM endpoint_daily_feature_rollups FINAL "
        "WHERE review_date >= {start:Date} AND review_date <= {end:Date} "
        "ORDER BY agent_id, review_date",
        parameters={"start": start, "end": as_of},
    )
    rows = [dict(zip(COLUMNS, values, strict=True)) for values in result.result_rows]
    assessments = [assess_daily_rollup(row) for row in rows]
    identities: dict[str, str] = {}
    seen: set[tuple[str, date]] = set()
    for row in assessments:
        key = (row.agent_id, row.review_date)
        if key in seen or not start <= row.review_date <= as_of:
            raise ValueError("Duplicate or out-of-window daily40 cache row")
        seen.add(key)
        identities[row.agent_id] = row.hostname
    for agent_id, hostname in identities.items():
        for offset in range(22):
            day = start + timedelta(days=offset)
            if (agent_id, day) not in seen:
                assessments.append(DailyAssessment(
                    agent_id, hostname, day, "abstain_missing_day",
                    ("missing_daily_rollup",), None,
                ))
    return sorted(assessments, key=lambda row: (row.agent_id, row.review_date))


def run_daily_model_pipeline(clickhouse: Any, repository: Any, redis_client: Any = None,
                             as_of: date | None = None, max_reviews: int = 20) -> dict[str, Any]:
    day = as_of or datetime.now(timezone.utc).date() - timedelta(days=1)
    assessments = load_assessments(clickhouse, day)
    if not assessments:
        return {"as_of": day.isoformat(), "status": "no_daily40_rows", "reviewed": 0}
    return ModelV3Worker(repository, redis_client).run_daily_batch(
        assessments, day, max_reviews=max_reviews,
    )
