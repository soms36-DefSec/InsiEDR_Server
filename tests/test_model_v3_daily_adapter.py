from datetime import date

import pytest

from server.risk.daily_adapter import (
    CONTRACT_VERSION, RAW_FEATURES, assess_daily_rollup, consecutive_complete_days,
)


def _row():
    row = {name: 0.0 for name in RAW_FEATURES}
    row.update(agent_id="AGENT-A", hostname="A", review_date="2026-10-20",
               source_kind="observed_unlabeled", observation_complete=1,
               feature_contract_verified=1, sensor_coverage_verified=1,
               timezone_verified=1, feature_contract_version=CONTRACT_VERSION,
               missing_sensors_json=[])
    return row


def test_missing_feature_abstains_without_zero_filling():
    row = _row()
    row["file_delete_count"] = None
    assessed = assess_daily_rollup(row)
    assert assessed.status == "abstain_missing_sensors"
    assert assessed.features is None
    assert "file_delete_count" in assessed.missing


def test_invalid_subset_is_rejected():
    row = _row()
    row["file_delete_count"] = 2
    row["file_access_count"] = 1
    with pytest.raises(ValueError, match="file_delete_count exceeds file_access_count"):
        assess_daily_rollup(row)


def test_journal_gap_abstains_and_breaks_history():
    complete = assess_daily_rollup(_row())
    gapped_row = _row()
    gapped_row["review_date"] = "2026-10-19"
    gapped_row["journal_gap_detected"] = True
    gapped = assess_daily_rollup(gapped_row)
    assert not gapped.observation_complete
    assert consecutive_complete_days([complete, gapped], date(2026, 10, 20)) == {"AGENT-A": 1}
