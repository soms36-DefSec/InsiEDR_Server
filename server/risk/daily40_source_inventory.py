"""Read-only UTC collector coverage evidence for designing the daily40 producer.

Presence and event counts are evidence, never a daily40 quality attestation.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any


def inventory_daily40_sources(client: Any, target_date: date,
                              collector_schema_version: int = 1) -> list[dict[str, Any]]:
    if target_date >= datetime.now(timezone.utc).date():
        raise ValueError("Source inventory requires a completed UTC day")
    if collector_schema_version not in (1, 2):
        raise ValueError("collector_schema_version must be 1 or 2")
    table = "collector_results" if collector_schema_version == 1 else "collector_events_v2 FINAL"
    start = datetime.combine(target_date, time.min, timezone.utc)
    end = start + timedelta(days=1)
    result = client.query(f"""
        SELECT agent_id, argMax(hostname, collector_collected_at) AS hostname,
               collector, uniqExact(id) AS events,
               min(collector_collected_at) AS first_seen,
               max(collector_collected_at) AS last_seen,
               argMax(JSONExtractKeys(payload_json), collector_collected_at) AS latest_payload_keys,
               uniqExactIf(id, status != 'success') AS failed_events,
               uniqExactIf(id, collector = 'usn-monitor' AND
                           JSONExtractBool(payload_json, 'journal_gap_detected')) AS usn_gap_events,
               uniqExactIf(id, collector = 'usn-monitor' AND
                           (NOT JSONHas(payload_json, 'journal_gap_detected') OR
                            NOT JSONHas(payload_json, 'daily_file_deletes_utc'))) AS usn_unverifiable_events
        FROM {table}
        WHERE collector_collected_at >= {{start:DateTime64(3, 'UTC')}}
          AND collector_collected_at < {{end:DateTime64(3, 'UTC')}}
          AND agent_id != ''
        GROUP BY agent_id, collector
        ORDER BY agent_id, collector
    """, parameters={"start": start, "end": end})
    by_agent: dict[str, dict[str, Any]] = {}
    for agent_id, hostname, collector, events, first, last, keys, failed, usn_gaps, usn_unknown in result.result_rows:
        agent = by_agent.setdefault(str(agent_id), {
            "agent_id": str(agent_id), "hostname": str(hostname),
            "review_date": target_date.isoformat(), "collectors": {},
            "observation_complete": False, "feature_contract_verified": False,
        })
        agent["collectors"][str(collector)] = {
            "unique_events": int(events), "first_seen": first.isoformat(),
            "last_seen": last.isoformat(), "failed_events": int(failed),
            "usn_gap_events": int(usn_gaps),
            "usn_unverifiable_events": int(usn_unknown),
            "latest_payload_keys": sorted(map(str, keys)),
        }
    return list(by_agent.values())
