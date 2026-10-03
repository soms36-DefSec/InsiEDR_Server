# InsiEDR Server pipeline audit and phased implementation plan

Date: 2026-10-03
Scope: Execute the pipeline-audit template in INSIEDR_SERVER_AI_SPEC.md against ingestion, fleet commands, hybrid persistence, batching, background queues, and application lifespan. This is a source review plus two isolated reproductions, not a production penetration test or load benchmark.

## Executive evaluation

The server has useful separation between FastAPI routes, hybrid storage, domain repositories, and crypto plugins. PostgreSQL is the durable ingestion authority: TelemetryRepository.store_payload commits there before optional ClickHouse replication. Preserve that acknowledgement guarantee. Synchronous database calls currently execute inside asynchronous request handlers. Fleet command endpoints lack application-level authentication and authorization. Queue recovery and ClickHouse replay also contain concrete data-delivery defects.

The guide is not an accurate implementation map: responses.py formats JSON; commands live in agents.py and agent_tasks, while task_queue.py runs webhook jobs. app.state.ml_executor is None, with no eight-worker executor constructed. PostgreSQL uses a synchronous psycopg2 ThreadedConnectionPool rather than asyncpg. Do not introduce ML work or replace durable ingestion routing merely to match stale documentation.

Six-perspective assessment: architecture is partially aligned; repository separation exists but handlers retain orchestration; security is deficient on fleet routes; concurrency and recovery need repair; plugins and additive migrations provide useful extension points; typing, request models, response models, and consistent errors remain incomplete.

## Findings matrix

References are repository-relative and refer to the reviewed working tree. P1 means high priority, P2 medium priority. Deployment reachability affects security exposure.

| Priority | Location | Class | Evidence and impact |
|---|---|---|---|
| P1 | server/api/agents.py:211, :299, :348, :385; server/app.py:177 | Missing command authorization | Action handlers depend only on storage; no principal or admin check is installed by the app. A caller that reaches these routes can enqueue isolation, termination, locking, or rollback. There is no actor-attributed immutable command audit in the reviewed path. |
| P1 | server/api/agents.py:53, :142 | Unauthenticated agent control plane | Heartbeats and task results trust body agent IDs. A caller can impersonate an endpoint, retrieve and consume pending commands, or submit results without identity binding. |
| P1 | server/api/ingest.py:285; server/api/agents.py:91; server/storage/postgres_storage.py:157 | Event-loop blocking | Async handlers invoke synchronous database operations directly. Slow queries block other requests on the same loop, including otherwise independent fleet and ingestion traffic. Crypto processing at ingest.py:243 is synchronous too; its CPU cost was not benchmarked. |
| P1 | server/storage/clickhouse_batcher.py:109 | Unbounded buffer | add_many extends lists without a row or byte ceiling; batch_size only wakes the consumer. During slow inserts or retries, producers continue growing memory. |
| P1 | server/storage/clickhouse_batcher.py:223 | Broken DLQ routing | Filename split selects parts[1], so raw_payloads becomes raw and collector_results becomes collector. Real replay targets the wrong table and generally fails. |
| P1 | server/task_queue.py:282, :291, :310, :321 | Non-atomic task transitions | BLPOP removes a job before HSET records it as running; fail deletes its running record before ZADD stores its retry. A crash or Redis error between operations loses the job. The stale reaper cannot recover an absent record. |
| P1 | server/api/agents.py:100; server/storage/repositories/fleet_repo.py:207, :240 | Delivery acknowledgement gap | Heartbeat reads pending commands and marks them dispatched before the HTTP response reaches the agent. A lost response strands dispatched commands; concurrent reads can return the same task before either update. |
| P2 | server/task_queue.py:424; server/app.py:133; server/storage/clickhouse_batcher.py:90 | Shutdown race | TaskWorker.stop only sets an event before app closes storage. Batcher.stop continues after a timed join even if the worker is still inserting, then reports clean shutdown. Background work can outlive its storage client. |
| P2 | server/api/agents.py:233 | Wrong isolation allowlist address | Missing server_ip defaults to request.client.host, the operator or proxy address rather than necessarily the agent-reachable server address. Isolation can sever the endpoint control channel. |
| P2 | server/api/responses.py:55; server/api/logs.py:53 | Error contract mismatch | api_error lacks the guide's top-level type/title/status/detail fields, and several handlers return their own JSON errors. Central handlers do not normalize those direct responses. |

## Root causes and recommendations

1. Authentication exists conditionally inside encrypted ingestion, not as shared route dependencies. Add separate operator and agent principal dependencies, fail closed for command operations, bind agent identity to credentials, and cover every /api and /api/v1 alias. Pair command insertion with actor-attributed audit persistence. Do not treat encryption alone as sender authorization.
2. The storage interface is synchronous while route functions are async. Offload cohesive synchronous persistence operations to a bounded worker facility; keep SSE dispatch on its owning event loop. Verify pool sizing, overload behavior, SQLite test connection affinity, and request cancellation before changing execution context.
3. During a ClickHouse outage a worker removes a snapshot and retries it while producers append to a fresh unbounded buffer. Add row and byte budgets, bounded batches, and durable overflow/reconciliation. PostgreSQL still retains acknowledged raw telemetry, so this is not evidence that every affected payload is lost; analytics can lag or be incomplete. DLQ write errors are currently logged and swallowed after snapshots are cleared.
4. DLQ filenames mix table metadata with underscore delimiters. Parse the fixed trailing timestamp/process suffix or introduce versioned metadata with legacy-file support. Replay must assert the exact destination table. Use exclusive file claiming to prevent append/replay races and only delete after verified insertion.
5. Redis needs atomic pending-to-running and running-to-retry transitions, plus ownership fencing for stale claims. PostgreSQL queue claims also have no stale-running recovery method. Keep retry limits and idempotency explicit so crash recovery does not create unbounded duplicate side effects.
6. Fleet command delivery needs a lease and explicit acknowledgement, with agent-side task-ID deduplication. Fetching and marking rows in separate transactions is insufficient. Roll this out compatibly with the agent protocol.
7. Shutdown must stop admission, finish or durably preserve in-flight work, join workers, and only then close clients. Surface timeout/failure instead of claiming successful drainage.

SQL review note: searched interpolation sites include internally assembled query fragments, table names, and parameterized values. An f-string alone is not proof of SQL injection; no confirmed request-driven injection is asserted by this audit. The PostgreSQL pooled connection path does roll back exceptions and return open connections. A complete query-by-query audit remains outside these confirmed findings.

## Validation performed

- Attempted: python -m pytest tests/test_tier3_fleet_control.py tests/test_hybrid_storage.py tests/test_clickhouse_storage.py -q
- Repeated using .venv/Scripts/python.exe. Both interpreters reported No module named pytest. No suite pass is claimed and no dependencies were installed.
- Isolated standard-library reproduction: replayed a temporary dlq_raw_payloads_123_456.jsonl through a recording callback. Expected raw_payloads; observed raw.
- Isolated buffer reproduction: batch_size=2 accepted 10,000 rows with no worker running and retained all 10,000. This demonstrates absence of an admission cap; it does not measure production memory growth.
- Existing tests/test_clickhouse_storage.py replay test records rows but ignores the destination-table argument, explaining why this defect is not detected by that assertion.
- No live database, endpoint, or remote command was exercised.

## Phased implementation plan

### Phase 1: Local storage and lifecycle corrections (no schema change)

Fix DLQ table recovery and legacy-file handling; add exact-table regression assertions. Introduce bounded buffer configuration and an explicit overflow policy backed by durable recovery. Make worker shutdown waitable and close storage only after workers finish or report a controlled failure. Preserve PostgreSQL-before-202 semantics.

Acceptance: underscore table names replay correctly; failed replay retains files; disk failure is observable; buffers remain within budgets during a blocked insert; shutdown cannot close clients under active workers.

### Phase 2: Identity, authorization, and audit

Introduce typed operator and endpoint principals in shared dependencies and apply them consistently to both route families. Use the deployed identity provider or explicit credential configuration rather than inventing a default shared administrator secret. Persist an audit event atomically with each authorized command, recording actor, endpoint, command, parameters or redacted digest, time, and task ID. Restrict audit mutation through a separate database owner/runtime-role privilege model.

Schema strategy: add a new audit table in 011_command_audit.sql after the credential/principal contract is selected; retain existing agent_tasks columns and historical records. This report does not provide executable SQL because principal identifiers, database roles, and retention policy are not established. Do not describe a mutable task status row as an immutable audit trail.

Acceptance: unauthenticated requests and wrong roles fail before storage writes; mismatched endpoint IDs fail; authorized commands and audit records commit together; secret fields never appear in audit data.

### Phase 3: Queue and delivery recovery

Make Redis transitions atomic, introduce ownership fencing, and add PostgreSQL stale-claim recovery. Implement fleet delivery leases with an additive migration after 011, retaining old columns and negotiating acknowledgement support with agents. Define retry exhaustion and idempotent execution behavior before enabling redelivery.

Acceptance: crash injection at each transition leaves a recoverable task; stale owners cannot complete newer claims; lost heartbeat responses trigger safe redelivery; concurrent heartbeats cannot independently claim the same lease.

### Phase 4: Async execution and API contracts

Move synchronous storage work off the event loop with bounded admission. Add request/response models and one error-formatting path with compatibility fields. Correct the specification's architecture map and remove unsupported executor/RVFL pipeline claims.

Acceptance: 100 concurrent mocked ingestion requests with delayed persistence allow a loop ticker and unrelated requests to progress; no 202 precedes durable commit; AES-GCM/HPKE failures are sanitized; existing aliases and legacy client fields remain supported; OpenAPI matches runtime responses.

## File modification table

| Files | Operation | Purpose |
|---|---|---|
| server/storage/clickhouse_batcher.py; server/config.py | Modify | Correct replay routing, bound buffers, define overload behavior |
| server/task_queue.py; server/app.py | Modify | Atomic recovery, waitable workers, ordered shutdown |
| server/api/deps.py; server/api/agents.py | Modify | Operator/agent authorization, typed inputs, safe server address selection |
| server/storage/repositories/fleet_repo.py; server/storage/hybrid_storage.py | Modify | Atomic command/audit persistence and delivery leases |
| server/storage/migrations/011_command_audit.sql | Create in Phase 2 | Add audit storage after identity contract is established |
| Subsequent additive delivery-lease migration | Create in Phase 3 | Add claim ownership and acknowledgement metadata |
| server/api/ingest.py; server/api/logs.py; server/api/errors.py; server/api/responses.py | Modify | Async-safe persistence and consistent errors |
| tests/test_clickhouse_storage.py; tests/test_tier3_fleet_control.py; new queue/lifespan regression tests | Modify/Create | Cover failure boundaries and authorization |
| docs/INSIEDR_SERVER_AI_SPEC.md | Modify after implementation | Align guide with actual supported architecture |

## Rollback and release gates

Keep each phase independently releasable. Record the deployed image digest and configuration before rollout. For storage/async regressions, stop admission, drain or durably retain outstanding work, then redeploy the preceding compatible image. Preserve PostgreSQL telemetry and DLQ files. For queue format changes, support both formats before rollout and drain new-format work before reverting consumers. Additive audit/lease tables and columns should remain in place on application rollback; no destructive down-migration is needed or recommended. Do not roll back to unauthenticated externally reachable command routes: disable command admission if the identity rollout fails. Database migration SQL, credential integration, and real PostgreSQL/Redis container validation remain implementation prerequisites, not completed work.
