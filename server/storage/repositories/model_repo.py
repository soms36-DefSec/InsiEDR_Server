"""PostgreSQL persistence for host-scoped Model V3 shadow assessments."""
from __future__ import annotations

from datetime import date
import json
from typing import Any, Mapping


TRIAGE_STATUSES = frozenset({
    "needs_investigation", "benign_context", "confirmed_incident",
    "acknowledged_suppressed",
})


class ModelReviewRepository:
    def __init__(self, storage: Any) -> None:
        self.storage = getattr(storage, "pg", storage)
        if not callable(getattr(self.storage, "connection", None)):
            raise TypeError("ModelReviewRepository requires PostgreSQL storage")

    def save_endpoint_score(self, row: Mapping[str, Any]) -> None:
        complete = bool(row["observation_complete"])
        scored = row.get("threat_probability") is not None
        if scored and not complete:
            raise ValueError("Incomplete observations cannot be scored")
        params = (
            row["agent_id"], row["hostname"], row["review_date"],
            row.get("source_kind", "observed_unlabeled"), complete,
            row["selection_status"], json.dumps(row.get("missing_sensors", [])),
            json.dumps(row.get("coverage_details", {})), row.get("feature_contract_version"),
            row.get("model_version"), row.get("threat_probability"), row.get("if_risk"),
            row.get("fused_risk"), row.get("forecasted_risk"), row.get("drift_error"),
            row.get("pair_threat_score"), row.get("predicted_scenario"),
            json.dumps(row["scenario_probabilities"]) if row.get("scenario_probabilities") is not None else None,
            json.dumps(row["behavior_heads"]) if row.get("behavior_heads") is not None else None,
            scored,
        )
        with self.storage.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO endpoint_daily_model_scores (
                        agent_id, hostname, review_date, source_kind, observation_complete,
                        selection_status, missing_sensors_json, coverage_details_json,
                        feature_contract_version, model_version, threat_probability, if_risk,
                        fused_risk, forecasted_risk, drift_error, pair_threat_score,
                        predicted_scenario, scenario_probabilities_json, behavior_heads_json, scored_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb,
                        CASE WHEN %s THEN NOW() ELSE NULL END
                    ) ON CONFLICT (agent_id, review_date) DO UPDATE SET
                        hostname=EXCLUDED.hostname, source_kind=EXCLUDED.source_kind,
                        observation_complete=EXCLUDED.observation_complete,
                        selection_status=EXCLUDED.selection_status,
                        missing_sensors_json=EXCLUDED.missing_sensors_json,
                        coverage_details_json=EXCLUDED.coverage_details_json,
                        feature_contract_version=EXCLUDED.feature_contract_version,
                        model_version=EXCLUDED.model_version,
                        threat_probability=EXCLUDED.threat_probability,
                        if_risk=EXCLUDED.if_risk, fused_risk=EXCLUDED.fused_risk,
                        forecasted_risk=EXCLUDED.forecasted_risk,
                        drift_error=EXCLUDED.drift_error,
                        pair_threat_score=EXCLUDED.pair_threat_score,
                        predicted_scenario=EXCLUDED.predicted_scenario,
                        scenario_probabilities_json=EXCLUDED.scenario_probabilities_json,
                        behavior_heads_json=EXCLUDED.behavior_heads_json,
                        scored_at=EXCLUDED.scored_at, updated_at=NOW()
                """, params)
            conn.commit()

    def save_review_queue(self, as_of: date, items: list[Mapping[str, Any]]) -> None:
        """Replace one date atomically; retain feedback for the same endpoint."""
        if len(items) > 20:
            raise ValueError("Model V3 review budget exceeds 20")
        with self.storage.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT agent_id, analyst_status, analyst_note, reviewed_by, reviewed_at "
                            "FROM model_v3_review_queue WHERE as_of_date=%s FOR UPDATE", (as_of,))
                previous = {row[0]: row[1:] for row in cur.fetchall()}
                cur.execute("DELETE FROM model_v3_review_queue WHERE as_of_date=%s", (as_of,))
                for rank, item in enumerate(items, 1):
                    feedback = previous.get(item["agent_id"],
                                            ("needs_investigation", None, None, None))
                    cur.execute("""
                        INSERT INTO model_v3_review_queue (
                            as_of_date, rank, agent_id, hostname, pair_threat_score,
                            primary_hypothesis, scenario_probabilities_json, evidence_dates_json,
                            selection_status, analyst_status, analyst_note, reviewed_by,
                            reviewed_at, model_version
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s,%s,%s,%s,%s,%s)
                    """, (as_of, rank, item["agent_id"], item["hostname"],
                          item["pair_threat_score"], item["primary_hypothesis"],
                          json.dumps(item["scenario_probabilities"]),
                          json.dumps(item["evidence_dates"]), "review_candidate",
                          *feedback, item["model_version"]))
            conn.commit()

    def get_latest_review_queue(self, as_of: date | None = None) -> list[dict[str, Any]]:
        with self.storage.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT as_of_date, rank, agent_id, hostname, pair_threat_score,
                           primary_hypothesis, scenario_probabilities_json, evidence_dates_json,
                           selection_status, analyst_status, analyst_note, reviewed_by, reviewed_at
                    FROM model_v3_review_queue
                    WHERE as_of_date=COALESCE(%s, (SELECT MAX(as_of_date) FROM model_v3_review_queue))
                    ORDER BY rank
                """, (as_of,))
                rows = cur.fetchall()
        return [dict(as_of_date=r[0].isoformat(), rank=r[1], agent_id=r[2], hostname=r[3],
                     pair_threat_score=r[4], primary_hypothesis=r[5],
                     scenario_probabilities=r[6], evidence_dates=r[7],
                     selection_status=r[8], analyst_status=r[9], analyst_note=r[10],
                     reviewed_by=r[11], reviewed_at=r[12].isoformat() if r[12] else None)
                for r in rows]

    def update_queue_triage(self, as_of: date, agent_id: str, analyst_status: str,
                            analyst_note: str | None, actor: str) -> bool:
        if analyst_status not in TRIAGE_STATUSES:
            raise ValueError("Unknown analyst status")
        with self.storage.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT analyst_status FROM model_v3_review_queue "
                            "WHERE as_of_date=%s AND agent_id=%s FOR UPDATE", (as_of, agent_id))
                prior = cur.fetchone()
                if prior is None:
                    return False
                cur.execute("""
                    UPDATE model_v3_review_queue SET analyst_status=%s, analyst_note=%s,
                        reviewed_by=%s, reviewed_at=NOW()
                    WHERE as_of_date=%s AND agent_id=%s
                """, (analyst_status, analyst_note, actor, as_of, agent_id))
                updated = cur.rowcount > 0
                cur.execute("""
                    INSERT INTO model_v3_review_feedback_audit (
                        as_of_date, agent_id, previous_status, new_status, analyst_note, reviewed_by
                    ) VALUES (%s,%s,%s,%s,%s,%s)
                """, (as_of, agent_id, prior[0], analyst_status, analyst_note, actor))
            conn.commit()
        return updated

    def get_endpoint_trajectory(self, agent_id: str, limit: int = 30) -> list[dict[str, Any]]:
        with self.storage.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT review_date, threat_probability, if_risk, fused_risk,
                           forecasted_risk, drift_error, pair_threat_score,
                           predicted_scenario, observation_complete, selection_status,
                           missing_sensors_json
                    FROM endpoint_daily_model_scores WHERE agent_id=%s
                    ORDER BY review_date DESC LIMIT %s
                """, (agent_id, limit))
                rows = cur.fetchall()
        return [dict(review_date=r[0].isoformat(), threat_probability=r[1], if_risk=r[2],
                     fused_risk=r[3], forecasted_risk=r[4], drift_error=r[5],
                     pair_threat_score=r[6], predicted_scenario=r[7],
                     observation_complete=r[8], selection_status=r[9],
                     missing_sensors=r[10]) for r in rows]
