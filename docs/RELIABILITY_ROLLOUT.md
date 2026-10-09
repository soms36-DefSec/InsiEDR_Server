# Replication and maintenance rollout

Implemented 9 October 2026. These changes are source changes, not a deployment or
a capacity certification. PostgreSQL remains authoritative for acknowledged
telemetry. Keep `INSIEDR_TELEMETRY_READ_BACKEND=postgres` for this rollout.

## Delivery guarantees and limits

The telemetry repository now writes only through PostgreSQL and its transactional
outbox. The reconciler atomically claims rows with an expiring token, renews the
lease, synchronously inserts isolated batches and completes only rows still owned
by that token. PostgreSQL transactions do not remain open during ClickHouse I/O.
Missing PostgreSQL migrations prevent startup, and missing outbox tables prevent
new telemetry acknowledgements. A stopped worker's claims become eligible again
after lease expiry. Failures remain pending with exponential backoff and jitter.

Outbox claims start at 128 envelopes, grow to 1024 under successful catch-up, and
are limited to 8 MiB of serialized JSON, except that one oversized envelope may
be claimed to avoid starving the queue. ClickHouse inserts have independent row
and byte ceilings. A single generated row over the byte ceiling fails visibly and
remains pending; raise the ceiling only within a measured memory budget.
Python object overhead exceeds serialized sizes.

Delivery is **at least once**, not exactly once. An insert may commit before its
response is lost, or a lease may expire during an insert. Timestamps derived from
the durable outbox record and row identities are stable on replay. Identical
blocks use content-based insert tokens; schema initialization configures a
10,000-block nonreplicated deduplication window. That window is bounded and does
not cover arbitrary regrouping or arbitrarily long outages. Legacy query-side
deduplication remains necessary on schema version 1. The optional version 2
collector schema uses `ReplacingMergeTree(version)` with `(event time, id)`
as its stable sorting key and reads with `FINAL`. It stores username and
received time on each observation, eliminating the wide DISTINCT and raw-payload
aggregation/join from the version 2 explorer. `FINAL` still has a cost that must
be measured; it is not a promise of constant memory or latency. Historical duplicates are not
automatically deleted. This rollout does not promise sub-50 ms queries.

Privacy-stripped outbox records are deliberately excluded from ClickHouse replay.
Removing the old direct telemetry write closes its bypass of that policy. Review
the configured plaintext policy before expecting telemetry to appear in CH.
Detection-result writes still use their existing PG + asynchronous CH path; the
new synchronous outbox guarantee applies to telemetry replication, not all model
outputs. PostgreSQL retains those authoritative results.

The asynchronous batcher serializes drains and remembers prior delivery errors.
Its DLQ publishes flushed/fsynced files and preserves corrupt files for repair.
This does not establish a cross-process filesystem quota. The existing DLQ must
still be monitored and replayed deliberately; no unreplicated files are deleted
to free space.

## Before starting the updated services

1. Back up PostgreSQL, record the running image revision, and preserve the existing
   ClickHouse/DLQ volumes. Store backups on a different disk or host. Do not test
   restoration over the application database.
2. Stop the old backend workers before starting updated workers. Mixed old/new
   reconcilers are unsafe because old workers do not respect claim tokens.
3. Apply the normal PostgreSQL migrations, including `014_outbox_leases_pg.sql`.
   Its indexes can take time on an existing large outbox. Schedule a maintenance
   window and inspect migration logs; do not bypass a failed migration.
4. For large unpartitioned tables, run `scripts/sql/retention_indexes.sql` with
   an autocommit PostgreSQL client before enabling scheduled retention. Concurrent
   index builds must run outside a transaction. Check `pg_index.indisvalid` after
   interruption. Index creation adds I/O and is not run by the retention worker.
5. Verify retention settings. Defaults remain 30 days for payload-related data
   and 90 days for normalized features. Compose now enables maintenance after
   startup; set `INSIEDR_MAINTENANCE_ENABLED=false` while preparing indexes or
   reviewing policy. No cleanup has been executed by this coding change.

## Maintenance and monitoring

Maintenance runs hourly after a 60-second initial delay. A PostgreSQL advisory
lock and persisted last-run time prevent concurrent workers from duplicating a
run. Deletes commit in 5,000-row batches, with a 120-second run budget and short
pauses. Fully expired partitions are dropped using catalog bounds, including
historical `old_data` partitions. Row cleanup also covers DEFAULT partitions and
partially expired weeks. Partition DDL takes locks; lock waits and statements are
bounded. The worker prepares the current week and four future weeks.

When DEFAULT contains rows for a new week's range, at most 5,000 rows are moved
and attached in one atomic transaction. A larger conflict is **deferred and
reported**, so rows are never partly moved out of the readable partition tree.
For a larger existing backlog, run the standalone maintenance command with a
reviewed larger `--batch-size` in a controlled window, or perform a separately
planned online migration. No zero-downtime claim is made for large partition repair.
Legacy standalone `*_archive` tables are preserved for explicit backup review;
they are not ordinary attached partitions and must be included in disk accounting.

Completed outbox rows are purged in bounded batches after 24 hours by default.
Pending and processing rows are never purged. Configure the reconciler window
with `INSIEDR_OUTBOX_RETENTION_HOURS`; maintenance uses the same value.

An internal monitor samples once a minute and logs changes to operational alerts.
`GET /api/operations/health` (or `/api/v1/operations/health`) requires
`operator:read` when authentication is enforced and returns cached snapshots,
with HTTP 503 for actionable degradation. It reports outbox depth/age, worker
status, persisted maintenance results and local DLQ disk usage. Samples are
per-worker; poll all replicas or collect each replica's logs. A 200 on the ordinary
readiness route still only means the authoritative database is reachable.

Default warning thresholds: outbox age 300 seconds, local filesystem usage 75%,
critical at 80%, any pending DLQ files, stopped workers, overdue/failed/deferred
maintenance. Wire the endpoint/logs to the deployment's alert receiver; this
change does not configure email or paging. The disk metric covers the DLQ
filesystem, **not remote/separate PostgreSQL or ClickHouse volumes**. Monitor
those volumes, database I/O latency, WAL growth, CH parts/merges, Redis rejected
writes, RSS/OOM events and free space on the deployment host.

## Verification

Run the normal server test suite. To exercise actual PostgreSQL behavior, set
`INSIEDR_TEST_POSTGRES_DSN` to a disposable TEST database and run
`python -m pytest tests/test_replication_postgres_live.py -q`.
The tests create a unique schema and remove only that schema. They verify
concurrent claims, recovery after expiry, stale-token rejection, retry delays,
bounded purge, atomic default-partition relocation and partition-safe retention.
Skipped integration tests do not validate those SQL paths.

For a real encrypted HTTP load test, provision a separate test deployment with
the target host's resource limits. Set `INSIEDR_LOADTEST_AES_KEY` to the base64
test AES key and `INSIEDR_LOADTEST_AGENT_TOKEN` to its shared test agent token.
Then run, for example:

```text
python scripts/validate_ingest_capacity.py --url https://TEST-HOST/api/logs --agents 200 --duration 1800 --interval 10 --output reports/capacity-steady.json
python scripts/validate_ingest_capacity.py --url https://TEST-HOST/api/logs --agents 200 --duration 300 --interval 10 --concurrency 200 --burst --output reports/capacity-burst.json
```

Use `--template` with representative sanitized collector payloads; the default
small synthetic payload is a smoke test, not a capacity model. The harness creates
new payload IDs and retries the exact envelope. It does not delete test data or
automatically interrupt services. Burst mode aligns initial sends; it does not
simulate a day's accumulated spool. Run an extended soak with representative
offline-backlog replay, analyst queries, retention and backup I/O. Record p95/p99
ingest latency, valid ACK counts, oldest outbox age, drain time and bytes/day.
Interrupt only the test ClickHouse service/backend to validate recovery, verify
logical row counts after replay, and confirm no ACKed telemetry is missing in PG.

Before production rollout, restore a PostgreSQL custom-format `pg_dump` backup
using `pg_restore --exit-on-error` into a fresh test database, restore the matching
crypto/configuration separately, apply migrations and verify representative
payload IDs, agent/task ownership and replay. Use the deployment's supported CH
backup/restore procedure into a separate test database and verify schema and row
counts. Measure and record recovery time and the oldest recoverable backup.
No successful restore or 200-endpoint capacity result is claimed until performed.

## Rollback

Stop updated workers first. Preserve pending/processing outbox rows and all DLQ
files. Extra lease columns can remain in PostgreSQL. Do not simply roll back to
the old reconciler against rows in `processing`: with all workers stopped, review
and reset those claims to `pending` before an old version can see them. A rollback
restores the old replication weaknesses, so prefer rolling forward after repair.
Keep completed-row retention and backups long enough for the rollout's review.

## Optional ClickHouse collector schema v2

Schema initialization creates `collector_events_v2` alongside existing tables;
no historical table is renamed or dropped. The older
`telemetry_clickhouse_v2_proposal.sql` is a staging design with a different table
name and example retention; do not apply it for this rollout. The implemented v2
schema keeps the existing 90-day collector TTL.

1. Keep `INSIEDR_CH_COLLECTOR_SCHEMA_VERSION=1` while preparing migration.
   Back up the database and budget disk for both copies plus merge headroom.
2. Stop legacy writers for the final backfill/catch-up. Run
   `python scripts/backfill_clickhouse_collectors_v2.py --from-date YYYY-MM-DD --until-date YYYY-MM-DD --apply`
   against the configured test database first. The end date is exclusive. This
   command uses 15-minute time slices and 1,000-row pages, rejects conflicting
   identities using content hashes, copies available raw metadata, and compares
   logical counts for each slice. It can be restarted without logically
   duplicating identities when queried with FINAL. It does not switch readers.
3. Inspect `rows_missing_username_history`. Expired raw payloads cannot supply
   historical usernames: the script explicitly stores an empty username and uses
   event time as the received-time fallback. Resolve that limitation before
   switching if complete username history is required. Compare representative
   payloads and metadata as well as counts. The script's source queries retain
   the configured memory/time limits and may need smaller deployment-specific
   ranges on an already overloaded database.
4. After validation, set `INSIEDR_CH_COLLECTOR_SCHEMA_VERSION=2` for every backend
   and restart together. The collector writer, explorer, counts and export
   readers switch together. Existing legacy explorer cursors are rejected; begin
   a new page. PostgreSQL remains the default authoritative explorer backend
   unless `INSIEDR_TELEMETRY_READ_BACKEND=clickhouse` is explicitly selected.
5. Keep legacy tables until migration and rollback requirements have been met.
   After v2 begins receiving new data, switching to v1 alone loses visibility of
   that new data; reconcile/backfill it before rolling back readers. Do not drop
   retained evidence to recover disk space without a separate retention decision.

Source references: [ClickHouse retry deduplication](https://clickhouse.com/docs/guides/developer/deduplicating-inserts-on-retries),
[ReplacingMergeTree](https://clickhouse.com/docs/engines/table-engines/mergetree-family/replacingmergetree),
[PostgreSQL partition maintenance](https://www.postgresql.org/docs/16/ddl-partitioning.html).
