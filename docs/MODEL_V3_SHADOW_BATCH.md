# Model V3 shadow batch

Run `python scripts/run_daily_model_pipeline.py` once per day at **01:00 UTC**
from the server repository with the normal PostgreSQL, ClickHouse, and Redis
environment settings. The command defaults to the previous completed UTC day;
`--as-of YYYY-MM-DD` supports an explicit replay. Keep one scheduler owner to
avoid overlapping runs. For a Linux deployment, the scheduler entry is:

```cron
0 1 * * * cd /path/to/InsiEDR_Server && /path/to/server-python scripts/run_daily_model_pipeline.py
```

The job reads the latest 22 days from ClickHouse
`endpoint_daily_feature_rollups`, validates every row through the daily adapter,
and passes valid vectors to the isolated `model/.venv` interpreter. It writes
host scores and the top 20 review candidates to PostgreSQL. Redis priors stay
shadow only while `INSIEDR_ENABLE_MODEL_PIPELINE` is false (the default).
The dashboard plugin reads `/api/v1/detection/ml/review-queue`; analyst feedback
requires an operator key with the `analyst` permission.

**Deployment gate:** The raw collector-to-40-feature producer and its source
coverage attestations must be verified before populating the ClickHouse cache.
This entrypoint does not infer missing features or set verification flags. An
absent host-day, missing sensor, journal gap, invalid feature contract, or
unverified UTC boundary causes abstention. A complete 22-day sequence is
required for review eligibility. The isolated `model/.venv` must be installed
from the model's locked dependencies before the first admitted batch. Do not
load example fixture endpoints into production databases.

## Runtime prerequisite

Use Python **3.12** to create `model/.venv`, then install
`model/requirements.txt` in that environment. Check the deployment with
`python scripts/check_model_v3_prerequisites.py`. The check verifies both frozen
joblib hashes, the isolated interpreter version, and all pinned package versions.
The batch does not attempt to install or upgrade packages while running.

## Daily40 producer prerequisite

The proposed single-query example using `telemetry_events` cannot be deployed
as written. That table stores `collector_name`, `timestamp`, and
`raw_payload_json`; it has no `successful_logons`, `bytes_sent`, or
`journal_gap_detected` columns. The daily cache has a `version` column, not a
`created_at` column. Its verification flags must be derived from actual sensor
coverage and UTC window evidence. In particular, a USN collector appearing once
does not prove coverage of every fixed NTFS volume for the whole day.

Several agent `daily_*` values are rolling 24-hour snapshots, while other
values are cumulative counters or sampled gauges. Summing snapshots would
overcount, and recording `1` for `observation_complete` without verifying every
required feature would permit a false baseline. Keep feature values nullable
and all quality flags false until each source mapping, counter reset rule,
deduplication key, and coverage interval has been checked against its collector.
The current server code only *reads* attested daily40 rows; it does not produce
or attest them.
See [the source audit](MODEL_V3_DAILY40_SOURCE_AUDIT.md) for collector-level
gaps found in the checked-in Rust agent and the supplied older Python capture.

Run `scripts/inventory_model_v3_sources.py --as-of YYYY-MM-DD` with the server
Python environment (which has `clickhouse-connect`) to inspect
the actual v1 `collector_results` stream for a completed UTC day. Use
`--collector-schema-version 2` for `collector_events_v2`. This read-only report
shows each host's collector names, first/last observation, failed observations,
and explicit USN gap reports. It intentionally leaves
`observation_complete` and `feature_contract_verified` false. Presence alone
cannot prove uninterrupted 24-hour coverage, and the inventory never inserts
daily40 rows.

The USN collector emits `daily_file_deletes_utc` as deltas grouped by the
native deletion record's UTC date. It is not a monotonic cumulative counter;
aggregate only disjoint collector intervals after checking journal continuity
on every fixed NTFS volume. The source query must use `[00:00 UTC, next
00:00 UTC)` to include fractional seconds in the final second of the day.
