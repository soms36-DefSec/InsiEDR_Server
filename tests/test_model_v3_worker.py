import csv
from datetime import date, timedelta
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from server.risk.daily_adapter import RAW_FEATURES, DailyAssessment
from server.risk.ml_worker import ModelV3Worker


CLASSES = (
    "BENIGN", "CLOUD_EXFILTRATION_PRECURSOR", "CREDENTIAL_DUMP",
    "DATA_HOARDING", "IT_SABOTAGE", "USB_EXFILTRATION_PRECURSOR",
    "HONEYTOKEN_TRIP", "KILL_CHAIN_APT",
)


class Repository:
    def __init__(self):
        self.scores = []
        self.queue = None

    def save_endpoint_score(self, row):
        self.scores.append(row)

    def save_review_queue(self, as_of, items):
        self.queue = (as_of, items)


class Redis:
    def __init__(self):
        self.data = {}

    def hset(self, key, mapping):
        self.data[key] = mapping

    def expire(self, key, seconds):
        assert seconds == 172800


def test_worker_uses_agent_identity_and_persists_only_verified_outputs(monkeypatch):
    first = date(2026, 10, 1)
    assessments = [DailyAssessment("AGENT-01", "DISPLAY-HOST", first + timedelta(days=i),
                                   "complete", (), tuple(0.0 for _ in RAW_FEATURES))
                   for i in range(22)]

    def fake_run(command, **_kwargs):
        metadata = Path(command[command.index("--metadata") + 1])
        with metadata.open(newline="", encoding="utf-8") as handle:
            assert {r["hostname"] for r in csv.DictReader(handle)} == {"AGENT-01"}
        output = Path(command[command.index("--output") + 1])
        output.mkdir()
        with (output / "daily_predictions.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["hostname", "date", "if_risk",
                "threat_probability", "fused_risk", "forecasted_risk", "drift_error",
                "predicted_scenario", *("prob_" + name for name in CLASSES)])
            writer.writeheader()
            for i in range(22):
                writer.writerow({"hostname": "AGENT-01", "date": (first + timedelta(days=i)).isoformat(),
                    "if_risk": .3, "threat_probability": .8, "fused_risk": .6,
                    "forecasted_risk": "" if i < 7 else .5,
                    "drift_error": "" if i < 7 else .2,
                    "predicted_scenario": "DATA_HOARDING",
                    **{"prob_" + name: (.8 if name == "DATA_HOARDING" else .2 / 7)
                       for name in CLASSES}})
        with (output / "review_queue.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["hostname", "review_route", "pair_threat", "evidence_dates"])
            writer.writeheader()
            writer.writerow({"hostname": "AGENT-01", "review_route": "supervised_persistence",
                             "pair_threat": .7, "evidence_dates": "[]"})
        with (output / "host_rankings.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["hostname", "pair_threat"])
            writer.writeheader()
            writer.writerow({"hostname": "AGENT-01", "pair_threat": .7})
        (output / "summary.json").write_text(json.dumps({"as_of": "2026-10-22",
            "source_admission": "observed_contract_attested_not_independently_validated",
            "model_name": "Model V3", "classes": CLASSES, "reviewed": 1}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("server.risk.ml_worker.subprocess.run", fake_run)
    repo, redis = Repository(), Redis()
    result = ModelV3Worker(repo, redis, Path(sys.executable)).run_daily_batch(
        assessments, "2026-10-22")
    assert result["reviewed"] == 1
    assert len(repo.scores) == 22
    assert repo.queue[1][0]["agent_id"] == "AGENT-01"
    assert repo.queue[1][0]["hostname"] == "DISPLAY-HOST"
    assert "insiedr:ml:endpoint:AGENT-01" in redis.data
