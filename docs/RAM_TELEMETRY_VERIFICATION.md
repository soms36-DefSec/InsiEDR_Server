# Server telemetry implementation review — 2026-10-20

## Status: PARTIAL PASS — production validation pending

The server-only implementation is available behind the disabled-by-default RAM
telemetry profile. No agent changes were made. Existing unrelated local edits
were retained.

## Implemented corrections

- Encrypted, fsync-backed bounded ingestion journal; acknowledgements follow
  durable commit. Retry identities and accepted projections survive restart.
- Bounded RAM cache, eviction-aware coverage checks, replay/resync notifications,
  stable snapshot cursors and memory-weighted admission. Slow Redis is separated
  from acknowledgement processing.
- Batched canonical ClickHouse writes and verified daily PostgreSQL archives.
  Source deletion requires completed verification; no independent TTL races.
- Pressure-based query, ingestion and archive limits, deployment memory budgets,
  offline migration, retry tombstones and verified rollback export.
- Credential scrubbing for collector errors and redacted replication repair.
- Lazy feature derivation and bounded metadata queries avoid unnecessary body
  and feature materialization.

## Verification performed

Final full regression run: **379 passed, 8 skipped, 1 warning** in 40.40 seconds.
The eight skipped tests require `INSIEDR_TEST_POSTGRES_DSN`; they were not run.
The warning is the existing Starlette/httpx TestClient deprecation.

Tests include actual encrypted SQLite journal files, abrupt subprocess exit,
HTTP acknowledgement/retry checks, fault injection, Redis Lua execution through
fakeredis, archive corruption/recovery and migration/rollback SQL models. The
models do not verify PostgreSQL or ClickHouse engine behavior.

Python compilation, migration CLI help, Compose configuration validation and
`git diff --check` passed. The optional deployment was not enabled.

## Unresolved release gates

The Docker daemon was unavailable. Real PostgreSQL/ClickHouse integration,
production-version Redis behavior, database crash recovery, full cutover and
rollback exercises, and target-machine sustained load/browser latency have not
been verified. Do not treat the latency targets or retention capacity as measured
results. Production approval requires these checks and measured disk throughput,
event sizes and arrival rates. See RAM_FIRST_SERVER_ARCHITECTURE.md for commands,
capacity calculations, operational constraints and deployment gates.
