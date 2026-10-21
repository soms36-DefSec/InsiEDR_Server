from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest

from server.risk.daily40_source_inventory import inventory_daily40_sources


class FakeClient:
    def query(self, sql, parameters):
        assert "collector_results" in sql
        assert "< {end:DateTime64" in sql
        assert parameters["start"].tzinfo == timezone.utc
        stamp = datetime(2026, 10, 20, 1, tzinfo=timezone.utc)
        return SimpleNamespace(result_rows=[
            ("AGENT-test", "test", "usn-monitor", 3, stamp, stamp,
             ["journal_gap_detected", "daily_file_deletes_utc"], 0, 1, 0),
        ])


def test_inventory_never_attests_complete_daily40():
    rows = inventory_daily40_sources(FakeClient(), date(2026, 10, 20))
    assert rows[0]["collectors"]["usn-monitor"]["usn_gap_events"] == 1
    assert rows[0]["collectors"]["usn-monitor"]["usn_unverifiable_events"] == 0
    assert "daily_file_deletes_utc" in rows[0]["collectors"]["usn-monitor"]["latest_payload_keys"]
    assert rows[0]["observation_complete"] is False
    assert rows[0]["feature_contract_verified"] is False


def test_future_day_and_unknown_schema_are_rejected():
    with pytest.raises(ValueError, match="completed UTC"):
        inventory_daily40_sources(FakeClient(), date(2999, 1, 1))
    with pytest.raises(ValueError, match="schema_version"):
        inventory_daily40_sources(FakeClient(), date(2026, 10, 20), 3)
