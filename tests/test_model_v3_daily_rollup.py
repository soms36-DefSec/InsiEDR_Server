from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from server.risk.daily_rollup import COLUMNS, load_assessments


class FakeClient:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters):
        assert " FINAL " in sql
        assert parameters["end"] == date(2026, 10, 20)
        return SimpleNamespace(result_rows=self.rows)


def test_missing_days_abstain_and_unverified_source_never_scores():
    day = date(2026, 10, 20)
    row = dict.fromkeys(COLUMNS)
    row.update(agent_id="AGENT-test", hostname="test", review_date=day,
               source_kind="observed_unlabeled", observation_complete=1,
               feature_contract_verified=0, sensor_coverage_verified=1,
               timezone_verified=1, missing_sensors_json="[]")
    client = FakeClient([tuple(row[name] for name in COLUMNS)])
    assessments = load_assessments(client, day)
    assert len(assessments) == 22
    assert all(not item.observation_complete for item in assessments)
    assert assessments[0].review_date == day - timedelta(days=21)
    assert "feature_contract_verified" in assessments[-1].missing


def test_current_utc_day_is_rejected():
    with pytest.raises(ValueError, match="completed UTC"):
        load_assessments(FakeClient([]), date.today() + timedelta(days=1))
