# Telemetry performance audit — 2026-10-19

## Scope and result

This is a source and deployment configuration audit of the 12-core, 12 GB RAM, mechanical-HDD profile. The local Docker Linux engine was unavailable during the audit, and no live PostgreSQL or ClickHouse service was reachable. Database sizes, dead tuples, active parts, merge rate, disk IOPS, and API latency therefore remain unmeasured; no live workload or database change was performed.

The Compose profile already sets PostgreSQL 16 checkpoint timeout to 15 minutes, completion target to 0.9, max WAL size to 4 GB, and plaintext payload persistence to false by default. It bounds ClickHouse memory and query concurrency, uses ZSTD(1) for large JSON strings, uses LowCardinality for repeated labels, and enables 5-second application batch flushes. The application uses a leased, byte-bounded, adaptive outbox reconciler (128–1024 records by default); it synchronously confirms each ClickHouse batch before completing the PostgreSQL outbox claim.

For the HDD profile, the Compose ClickHouse batch row target is now 15,000 (was 5,000). To ensure both row and byte flush thresholds are reachable without premature eviction into the DLQ, the configuration defines explicit batch flush triggers and per-table queued data ceilings: `INSIEDR_CH_BATCH_MAX_ROWS=15000` (batch row trigger), `INSIEDR_CH_BATCH_MAX_BUFFER_ROWS=30000` (buffer row ceiling), `INSIEDR_CH_BATCH_MAX_BYTES=8388608` (8 MiB batch byte trigger), and `INSIEDR_CH_BATCH_MAX_BUFFER_BYTES=16777216` (16 MiB buffer byte ceiling). Both Compose and `.env.example` align on these thresholds alongside the 5-second flush interval. The capacity script now reports the synthetic collector-observation rate alongside acknowledged payload rate so the results are easier to compare with ingest targets. This rate is an estimate based on collector observations in the submitted template; confirm persisted row counts in ClickHouse.

## Findings and tuning limits

- `server/storage/clickhouse_schema.sql` already declares repeated labels as `LowCardinality(String)` and compresses JSON columns with ZSTD(1). It does not define specialized timestamp/numeric codecs. UUID and agent identifiers are stored as strings in some tables. Apply codecs only after measuring representative data and validating actual ClickHouse 24.3 DDL behavior; codec changes to an existing MergeTree table require a planned migration or table rebuild.
- `telemetry_events` is ordered by `(agent_id, collector_name, timestamp, event_id)`. This favors agent-scoped access. The proposed collector-first key would help collector-only scans but may hurt agent queries. Do not change the key until query logs or a workload replay establish the dominant filters and a migration plan covers existing data.
- Dashboard rollups are optional and currently summarize collector observations in `collector_results` / `collector_events_v2`, using exact distinct UUID states. The histogram also has a raw `telemetry_events` path. Confirm the API’s expected count semantics before enabling rollups or redirecting the histogram; these sources can represent different event counts.
- The PostgreSQL plaintext setting strips raw payload content before outbox persistence when disabled. The encrypted envelope metadata and scalar routing fields still have storage cost. PostgreSQL `JSONB` is not stored in the same compact form as ClickHouse columnar data, so verify the live schema and row sizes rather than assuming only scalar columns remain.
- The 4 GB WAL target is intentionally below the requested 8 GB suggestion for this host profile. A larger target may reduce checkpoint frequency but can increase retained WAL and recovery time. Change it only after collecting checkpoint and WAL statistics under the target workload. Keep `synchronous_commit` at its durable default for the transactional outbox: disabling it could acknowledge telemetry whose outbox transaction is lost on a host crash.
- The 8 MiB reconciler byte ceiling and adaptive 128–1024 claim size bound in-flight work. Raising claims to 1,000–5,000 records without observing mean record size, ClickHouse insert time, and outbox age risks increasing memory and lease time. Tune from measurements; byte limits should remain in force.
- A 15,000 row batch is a ceiling, not a guarantee that every insert reaches 15,000 rows. Flushes also occur upon reaching the 8 MiB `batch_bytes` threshold or the 5-second interval timer. Theoretical reductions in part creation rates (e.g. from ~24 to ~8 parts per minute) assume batches fill purely to the row limit; under live traffic, per-table buffers, payload size variance, and timer-driven flushes will dictate part creation and must be verified against `system.part_log`.
- `ClickHouseBatcher` explicitly triggers flushes on either row count (`len(buffer) >= batch_size`) or estimated byte volume (`table_bytes >= batch_bytes`), draining into ClickHouse without touching the DLQ under normal in-capacity operation. However, the separate buffer ceilings (`max_buffer_rows=30000`, `max_buffer_bytes=16777216`) are per-table bounds on estimated serialized payload volume, not hard process-memory fences: they do not account for CPython dictionary/object overhead or records held in-flight during active flushes, so they bound queued payload volume rather than guaranteeing immunity from OOM. If an incoming batch exceeds the remaining headroom under these ceilings before the asynchronous worker drains, `add_many()` intentionally evicts the oldest queued slice to the DLQ as a shed-to-disk backpressure mechanism during high bursts or downstream ClickHouse stalls.

## Read-only PostgreSQL baseline

Run these queries against the test or target database using a read-only monitoring role. They inspect the requested core relations and autovacuum state.

```sql
SELECT c.relname AS table_name,
       pg_size_pretty(pg_relation_size(c.oid)) AS heap,
       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes,
       pg_size_pretty(CASE WHEN c.reltoastrelid = 0 THEN 0
                           ELSE pg_total_relation_size(c.reltoastrelid) END) AS toast,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname IN ('collector_results', 'raw_payloads', 'clickhouse_outbox')
ORDER BY c.relname;

SELECT relname, n_live_tup, n_dead_tup,
       round(100.0 * n_dead_tup / greatest(n_live_tup + n_dead_tup, 1), 2) AS dead_pct,
       last_autovacuum, autovacuum_count, last_autoanalyze, autoanalyze_count
FROM pg_stat_user_tables
WHERE relname IN ('collector_results', 'raw_payloads', 'clickhouse_outbox')
ORDER BY relname;

SELECT name, setting, unit FROM pg_settings
WHERE name IN ('checkpoint_timeout', 'checkpoint_completion_target', 'max_wal_size',
               'synchronous_commit', 'wal_sync_method');
```

Take two snapshots of `pg_stat_wal` and `pg_stat_bgwriter` around the workload to measure WAL bytes, WAL sync count/time, checkpoint count/time, and buffers written. PostgreSQL 16 exposes checkpoint fields in `pg_stat_bgwriter`; retain timestamped snapshots so deltas can be calculated.

## Read-only ClickHouse baseline

Run against the configured analytics database. Compare two snapshots at least ten minutes apart for merge velocity; `system.merges` is only a point-in-time view.

```sql
SELECT table, count() AS active_parts, sum(rows) AS rows,
       sum(data_compressed_bytes) AS compressed_bytes,
       sum(data_uncompressed_bytes) AS uncompressed_bytes,
       round(sum(data_uncompressed_bytes) / greatest(sum(data_compressed_bytes), 1), 2) AS compression_ratio
FROM system.parts
WHERE active AND database = 'insiedr_analytics'
GROUP BY table
ORDER BY compressed_bytes DESC;

SELECT database, table, elapsed, progress, num_parts, source_part_names,
       memory_usage, total_size_bytes_compressed
FROM system.merges
WHERE database = 'insiedr_analytics'
ORDER BY elapsed DESC;

SELECT event_type, count() AS operations, sum(rows) AS rows,
       sum(size_in_bytes) AS output_bytes, sum(duration_ms) AS duration_ms
FROM system.part_log
WHERE event_time >= now() - INTERVAL 10 MINUTE
  AND database = 'insiedr_analytics'
  AND event_type IN ('NewPart', 'MergeParts')
GROUP BY event_type;
```

Compute ClickHouse bytes per telemetry record as `sum(data_compressed_bytes) / sum(rows)` for `telemetry_events` (and report both raw and merged-part snapshots). Compression and part counts vary with the data, merges, and retention age.

## Target-host workload procedure

Use an isolated test deployment on the same HDD class and resource limits. Do not point the synthetic generator at production: each request writes telemetry and registers synthetic agent IDs. Supply a dedicated test agent token and key through the `INSIEDR_LOADTEST_AGENT_TOKEN` and `INSIEDR_LOADTEST_AES_KEY` environment variables on the test host. The script defaults to a random `loadtest-` identity prefix.

For the requested ten-minute baseline, start disk sampling and the generator together on the Linux target:

```sh
iostat -xz 1 > /tmp/insiedr-iostat-20261019.log
```

```sh
python scripts/validate_ingest_capacity.py \
  --url https://TEST-HOST/api/logs \
  --agents 200 --duration 600 --concurrency 32 --interval 10 \
  --output reports/capacity-baseline-20261019.json
```

The script records client attempt P50/P95/P99 and acknowledged payload/estimated collector-observation rates. Correlate the same time window with `iostat` (`await`, `aqu-sz`, `%util`), PostgreSQL WAL/checkpoint deltas, ClickHouse part/merge snapshots, active outbox depth/age, and API 5xx counts. Stop `iostat` after the run.

The separate acceptance target of 2,000 events/second for 30 minutes needs a representative telemetry template and calibrated request interval/concurrency. Confirm the actual number of ClickHouse telemetry rows persisted per request and report observed rows/second from ClickHouse; the client estimate alone does not prove the criterion. Verify explorer page latency and 24-hour histogram latency against a populated 5M+ row test dataset. Retain the generated report and database snapshots with the deployment hardware details.

## Acceptance status

| Criterion | Status |
| --- | --- |
| PostgreSQL physical size, indexes, TOAST, dead tuples, autovacuum | Not measured: database service unavailable |
| ClickHouse compression, active parts, merge rate | Not measured: database service unavailable |
| 200-agent ten-minute stress run and disk IOPS | Not run: Docker Linux engine unavailable; no explicit test endpoint/credentials available |
| 2,000 events/s for 30 minutes | Not verified on target hardware |
| ≤80 compressed bytes per record | Not measured on representative telemetry |
| Explorer <20 ms and 24-hour histogram <100 ms | Not measured on populated target-sized data |
| Full test suite | Not completed: the run stalled at `tests/test_collector_export.py::test_get_export_collectors`; it was interrupted after 30 seconds with no test result |

The listed latency and throughput goals are hardware acceptance targets. They cannot be inferred from static configuration or a different local disk.

## Validation performed locally

- `docker compose config --quiet` passed.
- `git diff --check` passed.
- Relevant tests passed: `tests/test_clickhouse_storage.py`, `tests/test_clickhouse_telemetry_queries.py`, and `tests/test_replication_reliability.py` (**26 passed**).
- `pytest tests/` did not complete. With pytest temporary files directed to `.pytest_cache`, it stalled during `tests/test_collector_export.py::test_get_export_collectors`; the process was interrupted. This occurs outside the modified storage/configuration paths and needs separate investigation before declaring the full suite clean.
- Live database diagnostics and synthetic load tests were not run because Docker’s Linux engine is unavailable and no explicit test deployment credentials/endpoint were supplied.
