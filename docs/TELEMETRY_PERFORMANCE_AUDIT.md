# Telemetry audit and implemented improvements

Audited 8 October 2026 against the working server and Rust agent repositories.
Target: 12 cores, 12 GB physical RAM, one 512 GB mechanical HDD. Findings are
from source inspection and functional tests, not a production disk trace.

## Recommendation and scope

Keep PostgreSQL authoritative for acknowledged telemetry during this release.
Use the implemented count-free cursor explorer immediately after normal release
validation. Keep `INSIEDR_TELEMETRY_READ_BACKEND=postgres` (the default).

For sustained, large analytical workloads, the target architecture is PostgreSQL
for fleet/auth/config and ClickHouse for telemetry, with a durable ingestion
journal. This is an architectural recommendation, not an achieved migration or
a guarantee of 5,000 events/s. Removing the PostgreSQL telemetry copy requires
changing detection/export/retry consumers and proving durable replay first.
For a modest fleet that fits a short retention window, PostgreSQL alone is the
simpler alternative; the repository already contains native weekly partitioning.

Neither topology guarantees sub-100 ms queries or 5,000 events/s on an unspecified
HDD. Row size, events per envelope, features per collector, cache hit rate,
concurrent analysts, fsync latency and actual retained volume decide capacity.
“ClickHouse is 10–50x faster” is not supported by measurements here.

## Findings from the current code

| Finding | Evidence | Consequence |
| --- | --- | --- |
| Explorer reads PostgreSQL | `HybridStorage.get_telemetry_page` previously delegated directly to PG | Deliberate live-data consistency; CH connectivity alone is not sufficient to switch safely |
| Every page counted its full filtered set | `telemetry_queries.py` | Additional scan even when the visible page is small |
| Payload substring search | `CAST(cr.payload_json AS TEXT)` with a leading wildcard | Reads/parses wide JSON; the existing JSONB path GIN index cannot serve this predicate |
| Deep OFFSET pages | Ordered query discards earlier rows | Work increases with page depth; concurrent inserts shift page boundaries |
| Enrichment is already page-bounded | Risk window query filters page payload IDs | The pasted claim of an unbounded risk window is outdated |
| Refresh rate depends on SSE events as well as polling | 50 ms coalescing and 3/30-second interval | Connected clients could still query roughly 20 times/s under sustained events |
| SSE only carries invalidations | `dispatch_telemetry_event` publishes a payload ID | It does not contain full rows, filters, ordering or durable replay needed for correct append-only UI deltas |
| Durable ingest writes more than the pasted description | PG writes envelope, collectors, normalized features and outbox | JSON duplication, WAL and indexes amplify HDD writes; transaction boundaries protect agent ACKs |
| Two CH admission paths | Direct repository write plus reconciler replay | Deterministic UUIDs do not deduplicate plain MergeTree rows |
| Raw replay timestamps change | CH writer sets `received_at` to current time; raw table key includes it | ReplacingMergeTree does not collapse rows with different full sorting keys |
| Username is not on CH collector rows | Username must come from raw payloads | Raw TTL is 30 days versus collector TTL 90 days; old collector usernames can disappear |
| Reconciler forces flushes | Each batch is flushed before outbox completion | A 5-second batch timer alone does not ensure large inserts; two workers may also replay pending rows concurrently |
| Durability gaps in batch/DLQ claims | Background flush errors are not latched for later barriers; DLQ publication does not fsync | “Guaranteed zero data loss” comments are not proven. A shared buffer barrier is insufficient to prove per-outbox-record delivery |
| Retention already exists but needs operations work | Migration 004 partitions PG; `scripts/retention_cleanup.py` drops weekly partitions | Archives/default partitions and unscheduled cleanup still consume disk; partition drops do acquire locks |
| Rust spool is already durable | `src/bin/insiedr-service.rs:drain_spool` and `src/spool/sqlite_spool.rs` | Peeks ten envelopes, sends individually, retains them until matching durable ACK; not an HTTP bulk API |

The PostgreSQL live read remains the correctness default because these CH
replication issues are independent of query speed. Plaintext-disabled outbox
entries cannot reconstruct their original telemetry: the reconciler deliberately
skips them. The direct CH path may still contain analytics payloads under that
policy. Do not enable CH reads until privacy expectations and completeness are
verified for the deployment.

## Implemented changes

* PostgreSQL and optional CH telemetry readers support filter-bound, backend-bound
  opaque cursors. Ordering is time plus ID; PG preserves legacy NULLS LAST and
  fallback display timestamps. A `limit + 1` read supplies `has_more` and
  `next_cursor`. Cursor plus nonzero offset is rejected.
* `include_total=false` avoids COUNT entirely and returns `total: null`.
  The default remains exact totals and offset support for legacy API callers.
  No whole-table estimate is mislabeled as an exact filtered count.
* `search_scope=metadata` searches hostname, username and collector without JSON
  casting. The explorer uses this mode; “Include payload (slower)” preserves
  forensic full-payload search. Metadata substring search is still not a promise
  of indexed access. Selective optional indexes are supplied separately.
* The explorer uses Next/Prev/First cursor navigation and freezes the time-window
  lower bound across the cursor chain. It no longer invents total page counts or
  offers a Last-page jump that requires a full count.
* SSE invalidations are coalesced to a two-second window. Older pages and open
  inspectors pause automatic refresh. Hidden tabs skip requests; becoming visible
  schedules refresh. Connected mode has no periodic poll; disconnected mode has
  a 30-second recovery poll. Reconnection schedules a refresh. Requests remain
  abortable and stale responses cannot overwrite a newer filter selection.
* `INSIEDR_TELEMETRY_READ_BACKEND=clickhouse` explicitly selects analytics reads.
  Its compatibility query deduplicates replayed identical collector rows before
  pagination/count, aggregates raw metadata to one row per payload and uses
  page-bounded enrichment. Empty pages stay empty; outages return retryable 503
  rather than silently switching a cursor chain to another database.
* Disconnected CH inserts now raise instead of returning success without writing.

The CH compatibility query still joins raw metadata and deduplicates potentially
large sets. It is not the optimized v2 physical layout and must be benchmarked
before enabling. Old rows beyond raw metadata TTL have unavailable usernames.
Non-ASCII case matching can differ between PostgreSQL collation and CH Unicode
functions. Cursors preserve traversal under newer inserts, not a database snapshot:
late events and retention can still change results. Changing filters or backend
requires restarting at page one.

No new client cache library was needed for this change. Retaining the displayed
page, coalescing invalidations and pausing background reads removes the primary
request storm. A bounded, per-filter cache can be added later if navigation
measurements justify it; never share cached results across operator identities.

## Architecture comparison

Budgets below are proposals in GiB, not measured resident set sizes.

| Topology | Advantages | Costs / limitations | HDD impact | Database/service RAM |
| --- | --- | --- | --- | --- |
| Current durable hybrid, optimized reads | Small rollout; existing retry and detector contracts retained | Two telemetry copies, outbox, replay duplicates, three persistence engines | Highest write amplification; correctness default during transition | PG 2 + CH 3.5 + Redis 1.5 |
| True hybrid target | Columnar compression and scans; separate OLTP workload | Needs durable journal, idempotent consumers, denormalization and migration of PG telemetry consumers | Fewer duplicate payload writes, but CH merges and journal persistence still share disk | PG 2 + CH 3.5 + Redis 1.5 |
| PostgreSQL native partitions | One query/transaction engine; existing migration path; simple consistency | JSON/index storage and VACUUM cost; aggregation competes with ingestion | One main WAL/data engine; GIN still adds writes | PG 6 + Redis 0.75 |
| PostgreSQL + TimescaleDB | Chunk lifecycle and columnar/compression options | Extension/version/license evaluation; cannot simply wrap the existing partitioned tables; migration and compression jobs required | Compression rewrites consume temporary space and I/O | PG 6 + Redis 0.75 |

Timescale retention drops chunks through scheduled jobs; validate job execution
and compressed-chunk query behavior rather than treating a policy declaration as
proof that space was reclaimed. [Retention policy documentation](https://docs.timescale.com/use-timescale/latest/data-retention/create-a-retention-policy/),
[compression documentation](https://docs.timescale.com/use-timescale/latest/compression/about-compression/).

## Explicit memory budget

The current Compose allocation matches the separate deployment audit created in
this workspace. It is a useful hybrid starting point; this change does not alter it.

| Component | Hybrid MiB | PG consolidation MiB |
| --- | ---: | ---: |
| PostgreSQL | 2048 | 6144 |
| ClickHouse | 3584 | 0 |
| Redis | 1536 | 768 |
| Backend, all workers combined | 1792 | 1792 |
| Nginx | 256 | 256 |
| Containers total | 9216 | 8960 |
| OS/page cache/headroom on decimal 12 GB host | about 2228 | about 2484 |

Redis's 1536 MiB hybrid allowance includes AOF/fork/buffer headroom above the
512 MiB dataset ceiling. For consolidation, reduce its dataset ceiling to 256 MiB
and measure queue backlog before adopting the smaller process budget. Never use
an evicting cache policy for durable queue data. On a 12 GiB host there is more
headroom; do not mistake `effective_cache_size` for allocated PG RAM.

Hybrid PG starting settings: 512 MB shared buffers, 4 MB work_mem, 128 MB
maintenance_work_mem, 40 connections and two app workers with pool max 12 each.
Consolidation proposal: shared_buffers 1536 MB, effective_cache_size 4 GB,
work_mem 4 MB, maintenance_work_mem 256 MB, max_connections 40. Keep fsync and
synchronous_commit enabled. Work memory multiplies by operations and sessions.
CH: retain the existing 3.5 GiB container, 2.5 GiB tracked server budget, 512 MiB
per-query limit and conservative concurrency; avoid additional memory buffers
without accounting for them. The full backend/detector RSS still needs measuring.

## Schema and query rollout

`scripts/sql/telemetry_search_indexes.sql` provides optional pg_trgm indexes for
lowercased metadata and a latest-risk lookup index. Migration 013 already adds
the `(collector_collected_at DESC NULLS LAST, id DESC)` page-order index.
The optional script is maintenance-window SQL, not an automatically applied
migration. Parent tables may be partitioned; online builds require per-leaf
concurrent indexes plus attachment. The cross-table OR search can still defeat
selective index access. Use EXPLAIN before buying that write cost.

GIN on `payload_json jsonb_path_ops` supports structured containment, not arbitrary
text-cast substring search. Add explicit predicates such as
`payload_json @> '{"process_name":"example.exe"}'::jsonb` only when collector
schemas guarantee that path. Normalize arrays/events at ingest before claiming
one top-level process_name represents every event. BRIN is a small alternative
for physically time-correlated scans, not a substitute for an ordered keyset
index or a string-search index. [PostgreSQL index types](https://www.postgresql.org/docs/16/indexes-types.html),
[pg_trgm LIKE support](https://www.postgresql.org/docs/16/pgtrgm.html).

`scripts/sql/telemetry_clickhouse_v2_proposal.sql` is a staging design, deliberately
not wired into the writer. It denormalizes username/received_at, uses stable
time-plus-ID ordering, daily partitions and optional equality bloom filters.
ReplacingMergeTree needs FINAL or explicit dedup until merges complete; IDs,
event timestamps and partition assignment must stay stable on replay. Benchmark
every skip index; it can cost more than the granules it avoids. The current
case-insensitive substring predicate does not automatically benefit from those
bloom filters. [ClickHouse skip-index guidance](https://github.com/ClickHouse/clickhouse-docs/blob/main/docs/guides/best-practices/skipping-indexes.md).

Backfill in time slices, verify unique event counts and representative filtered
pages, dual-compare reads, then move the writer and reader together. Keep rollback
copies only within the storage budget. Do not overwrite the existing schema or
shorten evidence retention as a side effect of a query optimization.

## Ingestion design and batching

Current ACK boundary: authenticated/decrypted envelope -> PG transaction -> ACK;
the agent removes its spool entry only after that ACK. Retain this boundary now.
An in-memory queue or Redis AOF everysec cannot silently replace it while claiming
the same durability. ClickHouse `async_insert=1, wait_for_async_insert=0` confirms
buffer admission, can hide later errors, and weakens backpressure. With native
async inserts use `wait_for_async_insert=1`; storage/power-failure durability still
depends on the server and filesystem contract. [ClickHouse async insert behavior](https://clickhouse.com/blog/asynchronous-data-inserts-in-clickhouse).

Proposed true-hybrid sequence:

1. Authenticate and enforce compressed AND decompressed byte limits. Validate
   IDs and envelope hashes before admission. Preserve the existing retry identity.
2. Append the accepted encrypted batch and replay metadata to a bounded sequential
   journal; fsync a group of requests together. Acknowledge only durable offsets.
   If encryption keys/authorization cannot reconstruct normalized data, the
   journal must retain enough permitted material for replay.
3. One logical consumer claims journal offsets, transforms records and sends
   5,000–20,000 rows or 4–8 MiB batches, whichever comes first, with a 1–5 second
   latency cap. Tune from part creation and disk throughput, not row count alone.
4. Commit the consumer watermark only after every required table confirms its
   write. Make retries idempotent; partial multi-table commits must be replayable.
5. Pause admission with retryable 503/backoff before journal/disk limits. The
   existing agent spool retains unacknowledged envelopes. A dead-letter record
   needs reason, original ID, schema version and replay ownership; failed records
   remain in the journal until repaired or explicitly disposed of by policy.

Use one durable replication path to avoid today's direct-write/outbox duplication.
Do not remove the outbox until its replacement passes kill/restart and disk-full
tests. A near-term group-commit writer could batch several envelopes in one PG
transaction and resolve each request only after commit, preserving the current
contract without a new Redis queue. It needs refactoring the PG transaction owner;
simply moving `store_raw_payload` into a background task is unsafe.

Redis Streams provide consumer groups/reclaiming; Redis Lists need explicit
processing/ack/recovery bookkeeping. Both still consume HDD persistence bandwidth
and memory. Existing Redis also handles task queues; isolate capacity, use
noeviction, and do not ACK agents merely because XADD succeeds under everysec AOF.

Rust-side batching should preserve each payload ID/hash and return individual
durable results. It requires a versioned bulk protocol; the current route expects
one encrypted envelope. Compress before AES-GCM, record codec/version as
authenticated metadata, cap decompressed size/ratio, and retain the exact bytes
for retries. Compressing ciphertext gives little useful reduction. This protocol
change was designed here but not applied to the agent.

On shutdown: stop admission, drain pending durable commits, flush consumers within
the termination deadline, then leave remaining journal work for replay. A graceful
shutdown hook does not protect against power loss or SIGKILL. Current DLQ storage
also needs byte quota, fsync/rename durability, and record-specific delivery
tracking before it can replace the outbox.

## Retention and 512 GB disk capacity

Reserve at least 128 GB (25%) for free space, merges and recovery. One proposed
budget is 40 GB OS/images/logs, 30 GB WAL/AOF/journal, 200 GB collector/envelope
data, 60 GB features, 30 GB risk/models, leaving 24 GB additional slack. Backups
must use another device. Encryption often prevents raw-envelope compression.

Measure total physical bytes per accepted event across all representations.
At 5,000 events/s there are 432 million events/day. Even **250 physical bytes per
event** is 108 GB/day; a 200 GB telemetry allocation retains under 1.86 days, before
TTL delay or duplicate copies. At 1 KB/event it is 432 GB/day. Consequently the
existing CH TTLs (30/90/90/180/180/365 days) cannot be endorsed at that sustained rate.

Calculate `retention_days <= table_budget_bytes / measured_daily_growth_bytes`
with safety margin for merges and late arrivals. Example staging targets are
raw envelopes 1 day, collector rows 2 days, features 2 days, models 7 days,
risks/anomalies 30 days, conditional on measured per-table budgets. The v2 proposal
shows the 2-day collector TTL; it is not a change to current evidence policy.

Example commands to review for a NEW, capacity-tested deployment (not executed):

```sql
ALTER TABLE insiedr_analytics.raw_payloads MODIFY TTL received_at + INTERVAL 1 DAY DELETE;
ALTER TABLE insiedr_analytics.normalized_features MODIFY TTL feature_timestamp + INTERVAL 2 DAY DELETE;
ALTER TABLE insiedr_analytics.model_outputs MODIFY TTL created_at + INTERVAL 7 DAY DELETE;
ALTER TABLE insiedr_analytics.risk_events MODIFY TTL created_at + INTERVAL 30 DAY DELETE;
ALTER TABLE insiedr_analytics.anomalies MODIFY TTL created_at + INTERVAL 30 DAY DELETE;
```

Do not apply the short raw TTL with the legacy CH username join: migrate the
denormalized reader first. Changing TTL may trigger expensive work and delete
evidence. Retention is asynchronous, not a space quota; monitor free disk at
70/80/85% occupancy, outbox age/bytes, DLQ bytes, CH active parts and TTL lag.
Stop accepting new writes before space is exhausted; retain agent retries.
Avoid routine OPTIMIZE FINAL and simultaneous AOF rewrites/backfills/large merges.

For PG consolidation, schedule partition creation/retention and verify actual
partition bounds. Daily partitions better support a 1–2 day retention than the
current weekly layout. Account separately for `*_archive`, old/default partitions,
unpartitioned features and pending outbox entries. Do not blindly run the existing
cleanup script against a changed topology. Completed outbox purge is distinct
from pending delivery retention. Disabling CH alone currently still creates
outbox records; consolidation must stop that producer after routing all consumers.

## Validation and remaining deployment gates

Verified locally: 59 targeted Python tests, two real headless Edge browser tests,
and TypeScript/Vite production build. Tests cover literal search, filters, null
timestamps, tie ordering, insert-during-pagination, malformed/filter-mismatched
cursors, no-count SQL, analytics parameter binding/routing, unavailable writes,
SSE bursts, stable older pages, stale-response cancellation and retry behavior.
The viewport test retained 19 DOM rows for a synthetic 50,000-row dataset.

Python FastAPI tests needed execution outside the Windows sandbox because its
socket-pair initialization hung. Edge tests likewise required unsandboxed browser
startup. The Docker Linux engine is not running; no real PG/CH integration or HDD
throughput benchmark was performed. CH query tests use mocked client responses;
validate SQL syntax and plans on the deployed 24.3 version before opt-in.

Before a production CH cutover or durability redesign, benchmark representative
1/10/50-million row data sets with all-collector and selective searches, cold and
warm caches, 1/5/20 analysts, and sustained 5,000 events/s plus bursts. Record
HTTP p50/p95/p99, EXPLAIN buffers/rows, CH read_rows/read_bytes, RSS, disk await,
fsync latency, active parts, merge debt and replication age. Include disk-full,
network failure, process kill during flush and restart/replay tests. No measured
sub-second database latency or 5,000 events/s claim is made by this audit.

No live schema changes, retention deletions, deployment or agent protocol changes
were performed. Existing deployment edits in the shared working tree were
preserved. The optional schema files are reviewable proposals, not applied indexes.
