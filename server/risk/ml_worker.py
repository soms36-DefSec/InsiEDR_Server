"""Isolated Model V3 batch runner. Call from a scheduled worker, never an API route."""
from __future__ import annotations

import csv
from datetime import date
import json
import logging
import math
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Iterable

from server.risk.daily_adapter import (
    CONTRACT_VERSION, RAW_FEATURES, DailyAssessment, consecutive_complete_days,
)

logger = logging.getLogger("insiedr.risk.ml_worker")
ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "model"


def _number(value: str | None, name: str, *, optional: bool = False) -> float | None:
    if value is None or value.strip().lower() in ("", "nan"):
        if optional:
            return None
        raise ValueError(f"Model V3 omitted {name}")
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise ValueError(f"Model V3 returned invalid {name}")
    return number


def _csv_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(f"Model V3 output missing: {path.name}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


class ModelV3Worker:
    def __init__(self, repository: Any, redis_client: Any = None,
                 python_bin: Path | None = None) -> None:
        self.repo = repository
        self.redis = redis_client
        self.python_bin = Path(python_bin) if python_bin else (
            MODEL / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        )

    def run_daily_batch(self, assessments: Iterable[DailyAssessment], as_of_date: date | str,
                        max_reviews: int = 20) -> dict[str, Any]:
        as_of = date.fromisoformat(as_of_date) if isinstance(as_of_date, str) else as_of_date
        if not 1 <= max_reviews <= 20:
            raise ValueError("Review budget must be between 1 and 20")
        rows = list(assessments)
        keys = [(r.agent_id, r.review_date) for r in rows]
        if len(keys) != len(set(keys)) or any(r.review_date > as_of for r in rows):
            raise ValueError("Duplicate or future endpoint daily rows")
        complete = sorted((r for r in rows if r.observation_complete),
                          key=lambda r: (r.agent_id, r.review_date))
        for row in rows:
            if not row.observation_complete:
                self.repo.save_endpoint_score(dict(agent_id=row.agent_id, hostname=row.hostname,
                    review_date=row.review_date, source_kind="observed_unlabeled",
                    observation_complete=False, selection_status=row.status,
                    missing_sensors=list(row.missing), feature_contract_version=CONTRACT_VERSION))
        if not complete:
            return dict(as_of=as_of.isoformat(), status="all_abstained", reviewed=0)
        if not self.python_bin.is_file():
            raise FileNotFoundError(f"Isolated Model V3 interpreter missing: {self.python_bin}")
        complete_keys = {(r.agent_id, r.review_date): r for r in complete}
        history = consecutive_complete_days(rows, as_of)
        with tempfile.TemporaryDirectory(prefix="insiedr_v3_") as temp:
            work = Path(temp)
            features_path = work / "X.csv"
            metadata_path = work / "metadata.csv"
            output = work / "output"
            with features_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(RAW_FEATURES)
                for row in complete:
                    if row.features is None or len(row.features) != len(RAW_FEATURES):
                        raise ValueError("Invalid daily40 vector")
                    writer.writerow(row.features)
            with metadata_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(("hostname", "date", "observation_complete", "source_kind",
                                 "feature_contract_version", "feature_contract_verified",
                                 "sensor_coverage_verified", "timezone_verified"))
                for row in complete:
                    # The frozen model groups by hostname; stable agent_id is its opaque key.
                    writer.writerow((row.agent_id, row.review_date.isoformat(), 1,
                                     "observed_unlabeled", CONTRACT_VERSION, 1, 1, 1))
            env = os.environ.copy()
            env.update(OMP_NUM_THREADS="2", MKL_NUM_THREADS="2", OPENBLAS_NUM_THREADS="2")
            result = subprocess.run([
                str(self.python_bin), str(MODEL / "predict.py"),
                "--features", str(features_path), "--metadata", str(metadata_path),
                "--output", str(output), "--as-of", as_of.isoformat(),
                "--max-reviews", str(max_reviews),
            ], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300, check=False)
            if result.returncode:
                raise RuntimeError(f"Model V3 exited {result.returncode}: {result.stderr[-1000:]}")
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            if summary.get("as_of") != as_of.isoformat() or summary.get("source_admission") != "observed_contract_attested_not_independently_validated":
                raise ValueError("Model V3 returned unexpected date or source admission")
            model_version = str(summary.get("model_name") or "Model V3")
            predictions: dict[tuple[str, date], dict[str, Any]] = {}
            for raw in _csv_rows(output / "daily_predictions.csv"):
                key = (raw["hostname"], date.fromisoformat(raw["date"]))
                source = complete_keys.get(key)
                if source is None or key in predictions:
                    raise ValueError("Unexpected or duplicate Model V3 prediction identity")
                probs = {name[5:]: _number(value, name) for name, value in raw.items()
                         if name.startswith("prob_")}
                if set(probs) != set(summary["classes"]):
                    raise ValueError("Model V3 scenario probability schema mismatch")
                prediction = dict(agent_id=source.agent_id, hostname=source.hostname,
                    review_date=source.review_date, source_kind="observed_unlabeled",
                    observation_complete=True, selection_status="complete" if raw.get("drift_error", "").lower() not in ("", "nan") else "temporal_warmup",
                    feature_contract_version=CONTRACT_VERSION, model_version=model_version,
                    threat_probability=_number(raw.get("threat_probability"), "threat_probability"),
                    if_risk=_number(raw.get("if_risk"), "if_risk"),
                    fused_risk=_number(raw.get("fused_risk"), "fused_risk"),
                    forecasted_risk=_number(raw.get("forecasted_risk"), "forecasted_risk", optional=True),
                    drift_error=_number(raw.get("drift_error"), "drift_error", optional=True),
                    predicted_scenario=raw["predicted_scenario"], scenario_probabilities=probs)
                predictions[key] = prediction
            if set(predictions) != set(complete_keys):
                raise ValueError("Model V3 did not return every admitted daily row")
            rankings = {}
            for raw in _csv_rows(output / "host_rankings.csv"):
                agent_id = raw["hostname"]
                if agent_id in rankings or not any(key[0] == agent_id for key in complete_keys):
                    raise ValueError("Unexpected or duplicate Model V3 host ranking")
                rankings[agent_id] = _number(raw.get("pair_threat"), "pair_threat", optional=True)
                if (agent_id, as_of) in predictions:
                    predictions[(agent_id, as_of)]["pair_threat_score"] = rankings[agent_id]
            queue = []
            for raw in _csv_rows(output / "review_queue.csv"):
                agent_id = raw["hostname"]
                source = complete_keys.get((agent_id, as_of))
                prediction = predictions.get((agent_id, as_of))
                if source is None or prediction is None or history.get(agent_id, 0) < 22:
                    raise ValueError("Model V3 queued an ineligible endpoint")
                if raw.get("review_route") != "supervised_persistence":
                    raise ValueError("Unconfigured Model V3 review route")
                pair = _number(raw.get("pair_threat"), "pair_threat")
                if rankings.get(agent_id) is None or abs(pair - rankings[agent_id]) > 1e-6:
                    raise ValueError("Review queue and host ranking disagree")
                queue.append(dict(agent_id=agent_id, hostname=source.hostname,
                    pair_threat_score=pair,
                    primary_hypothesis=prediction["predicted_scenario"],
                    scenario_probabilities=prediction["scenario_probabilities"],
                    evidence_dates=json.loads(raw["evidence_dates"]),
                    model_version=model_version))
            if len(queue) != summary.get("reviewed") or len(queue) > max_reviews:
                raise ValueError("Model V3 review queue count mismatch")
            for prediction in predictions.values():
                self.repo.save_endpoint_score(prediction)
            self.repo.save_review_queue(as_of, queue)
            if self.redis is not None:
                for (agent_id, day), prediction in predictions.items():
                    if (day != as_of or history.get(agent_id, 0) < 22 or
                            prediction["drift_error"] is None or
                            prediction.get("pair_threat_score") is None):
                        continue
                    key = f"insiedr:ml:endpoint:{agent_id}"
                    try:
                        self.redis.hset(key, mapping={
                            "threat_probability": str(prediction["threat_probability"]),
                            "fused_risk": str(prediction["fused_risk"]),
                            "drift_error": str(prediction["drift_error"]),
                            "pair_threat": str(prediction["pair_threat_score"]),
                            "predicted_scenario": prediction["predicted_scenario"],
                            "scenario_probabilities_json": json.dumps(prediction["scenario_probabilities"]),
                            "as_of": as_of.isoformat(), "model_version": model_version,
                            "history_days": str(history[agent_id]),
                        })
                        self.redis.expire(key, 172800)
                    except Exception:
                        logger.exception("Could not refresh Model V3 cache for %s", agent_id)
            return summary
