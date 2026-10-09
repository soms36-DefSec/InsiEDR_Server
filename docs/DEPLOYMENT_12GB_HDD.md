# Deployment audit: 12 cores, 12 GB RAM, 512 GB HDD

Update 9 October 2026: [Reliability rollout](RELIABILITY_ROLLOUT.md) supersedes the outbox, batching, maintenance scheduling and monitoring descriptions below. This document retains the original resource-budget audit.

Audited 2026-10-08. The checked-in Compose file is a conservative starting point for a single Linux host, not a measured capacity guarantee. No deployment or data cleanup was performed.

## Resource allocation budget matrix

| Service | CPU limit | Memory limit | Memory reservation | Rationale |
| --- | ---: | ---: | ---: | --- |
| PostgreSQL 16 | 2 | 2048 MiB | 1024 MiB | 512 MiB shared buffers, 40 connections, small query work areas |
| Redis 7 | 1 | 1536 MiB | 512 MiB | 512 MiB dataset limit; headroom for allocator, buffers and AOF fork/rewrite |
| ClickHouse 24.3 | 4 | 3584 MiB | 1536 MiB | 2.5 GiB tracked server allocation budget plus RSS/cache headroom |
| Backend | 3 | 1792 MiB | 768 MiB | Two Uvicorn workers; 12 PostgreSQL connections per worker |
| Nginx | 0.5 | 256 MiB | 64 MiB | Two workers, 1024 connections each; proxy sockets also count |
| **Containers total** | **10.5** | **9216 MiB (9 GiB)** | **3904 MiB** | Hard limits below physical RAM |

A decimal 12 GB host provides about 11.18 GiB, leaving approximately 2.18 GiB outside container limits. A 12 GiB host leaves 3 GiB. Verify actual `MemTotal` on the target. CPU limits are quotas, not dedicated cores. Reservations are soft memory targets; they do not reserve host RAM. The backend tmpfs and PostgreSQL shared memory are charged within their respective container budgets.

Compose has matching service-level and `deploy.resources` CPU, memory and PID limits. Equal `memswap_limit` and `mem_limit` disables container swap on a host that supports swap accounting, preventing HDD swap thrashing. Do not disable the OOM killer. A process can still be killed at its container limit, and unrelated host workloads can consume the remaining RAM. Do not build images concurrently with production load on this host. [Docker resource semantics](https://docs.docker.com/reference/compose-file/services/)

## Bottlenecks and risk analysis

1. **Connection multiplication and configuration precedence — fixed.** The original four API workers could request 128 PostgreSQL connections, exceeding the normal server default of 100. Compose now budgets 24 application connections against a server limit of 40. It explicitly sets the `INSIEDR_*` connection variables; previously `.env` localhost values took precedence over Compose's unprefixed values. Stop the old backend before reducing the database connection limit; a rolling overlap is outside this budget.
2. **ClickHouse memory was only a query setting — fixed at both levels.** The old bare `CLICKHOUSE_MAX_MEMORY` variable was not read by `ServerConfig.clickhouse_max_memory`. The new configuration sets an application query limit and server/profile limits, with an independent cgroup cap. Four concurrent queries and two query threads are the starting point; CPU quota does not cap the number of threads in every internal pool.
3. **Frequent Redis persistence and narrow memory headroom — reduced.** Redis is a task queue, not merely a disposable cache. Keep `noeviction`: reaching maxmemory rejects writes instead of evicting tasks. Capacity rejection still needs monitoring; it is not a delivery guarantee. AOF remains enabled, using `everysec`; scheduled RDB snapshots are disabled. AOF rewrites still fork and perform disk I/O. The 512 MiB dataset ceiling leaves much more headroom than 1 GiB inside a 1.2 GiB container. `everysec` can lose roughly a second of recent writes on a crash; storage stalls can extend the exposure. [Redis persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/), [memory excluded from eviction accounting](https://redis.io/docs/latest/develop/reference/eviction/)
4. **Small ClickHouse parts — partly mitigated, still a capacity risk.** The application batch target is 5000 rows with an 8 MiB serialized buffer bound per table and a 5-second timer. Actual Python objects use more memory than serialized bytes. `server/app.py` still constructs a reconciler with a 1-second poll and a 100-record batch; `reconcile_once()` explicitly flushes before acknowledging its outbox records. Consequently, the 5-second setting is not a minimum insert interval. This needs workload-specific reconciler/backpressure work if active parts or replication lag grow. Do not bypass durable acknowledgements with `wait_for_async_insert=0`. No server async-insert buffer is added in this profile.
5. **Disk growth — only logs are bounded by these changes.** Docker logs rotate at 20 MiB × 3 per service (about 300 MiB across five services). ClickHouse file logs have their own rotation. Query and part system logs get 7-day TTLs; high-frequency diagnostic log tables are disabled, reducing diagnostic history. Existing system log tables, including tables renamed by an upgrade, must be inspected separately. Neither disabling log writers nor editing configuration guarantees removal of historical log data.
6. **DLQ, database retention and pending outbox remain operational risks.** DLQ files have no byte quota or expiry. ClickHouse application tables retain data for 30–365 days depending on the table; TTL cleanup occurs through merges and is not a disk quota. The PostgreSQL retention script exists but Compose does not schedule it. Pending outbox entries may grow during an outage. Do not delete unreplicated records or unreplayed DLQ files just to recover space.
7. **Production security remains incomplete.** Backend runs as UID/GID 10001, with a read-only root filesystem, all capabilities dropped, a bounded temporary directory and Compose init. All services use `no-new-privileges`; database images retain their initialization entrypoints, and the Nginx master still starts as root. Only Nginx publishes a host port; databases use an internal network. Port 80 remains HTTP: provide TLS termination before internet exposure, configure forwarded-header trust and application HTTPS enforcement. Example credentials and crypto keys must be replaced. Missing database passwords now fail Compose interpolation, but example values are not automatically rejected.

## Concrete configuration fixes

- `Dockerfile`: frontend and Python dependency build stages; compiler/dev headers absent from runtime; no unused Gunicorn installation; explicit application copies; freshly built dashboard assets; UID 10001; two API workers; Python standard-library readiness probe. Compose provides PID 1 signal/reaping via `init: true`; use `docker run --init` outside Compose. Optional model artifacts outside `server/` and `shared/` require explicit read-only mounts. Existing broad Python dependency ranges still need a separately tested lockfile; image tags also remain floating. No major-version database upgrade is bundled with resource tuning.
- `docker-compose.yml`: resource limits/reservations, per-worker pool bounds, authenticated probes, 3–4 minute startup grace, 90–120 second shutdown grace, required credentials and network separation. Health status does not make Docker restart an unhealthy-but-running container, and dependency conditions only gate startup.
- `deploy/clickhouse/low-memory.xml`: server allocation budget, smaller caches and background pools, log rotation and system-log policy. MergeTree free-slot thresholds are reduced with the merge pool; leaving their large defaults can prevent startup on ClickHouse 24.3. [Version-matched server configuration](https://github.com/ClickHouse/ClickHouse/blob/v24.3.18.7-lts/programs/server/config.xml), [MergeTree thresholds](https://github.com/ClickHouse/ClickHouse/blob/v24.3.18.7-lts/src/Storages/MergeTree/MergeTreeSettings.h)
- `deploy/clickhouse/query-limits.xml`: two threads/query, one insert thread, 512 MiB/query and 1.5 GiB/user. Large queries fail instead of spilling sorts/aggregations onto the shared HDD. Limits are defaults for the default profile, not a security boundary against an administrator changing settings. Expect to tune or simplify analytical queries that now hit these limits.
- `nginx/nginx.conf`: two workers; bounded keepalive; correct conditional WebSocket upgrade header; no temporary files for large upstream responses. Slow export clients can hold backend connections longer. Request-body buffering can still use the HDD. [Nginx response buffering](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_max_temp_file_size)

PostgreSQL uses `shared_buffers=512MB`, `work_mem=4MB`, `maintenance_work_mem=128MB`, `autovacuum_work_mem=64MB`, `effective_cache_size=1536MB`, and `max_connections=40`. Work memory is per operation, not per connection; a 1 GiB shared buffer plus 16 MiB work areas would be too aggressive for this 2 GiB container. Effective cache size is a planner estimate, not allocated memory. Query parallelism is disabled for this shared HDD. [PostgreSQL 16 memory settings](https://www.postgresql.org/docs/16/runtime-config-resource.html)

Checkpoints are spread over 90% of a 15-minute interval, with a 4 GiB WAL target and 1 GiB minimum. Keep `fsync`, `full_page_writes` and `synchronous_commit` enabled. `wal_writer_delay=200ms` retains the default and does not remove synchronous commit flushes. `commit_delay=0` avoids adding latency without group-commit measurements. `max_wal_size` is a soft checkpoint target, not a hard cap; replication slots, archiving failures and load can increase it. Longer checkpoints can lengthen crash recovery. [PostgreSQL 16 WAL configuration](https://www.postgresql.org/docs/16/runtime-config-wal.html)

## Storage operations and rollout

Maintain at least 20% free space (roughly 100 GB on the nominal disk) for WAL, merges, AOF rewrites and recovery. Alert at 75% usage and escalate at 80%; these are proposed operating thresholds, not configured monitoring. Measure daily database growth and derive retention from the available space, rather than assuming a 512 GB disk supports a particular endpoint count.

Before rollout, back up PostgreSQL, ClickHouse and Redis and test restoration. Use unique URL-safe database/Redis credentials, for example random hexadecimal strings: Compose inserts them directly into connection URLs, so reserved URL characters require a separately constructed, percent-encoded DSN. Retain current passwords for existing volumes until performing a deliberate database-side password rotation; changing environment values alone does not rotate an initialized PostgreSQL account. Keep `CLICKHOUSE_DB=insiedr_analytics` because the bootstrap SQL currently hardcodes that name.

Prepare the existing DLQ bind mount for the non-root backend on the Linux deployment host, from the verified repository directory, during the maintenance window:

```sh
mkdir -p ./data/dlq
sudo chown -R 10001:10001 ./data/dlq
sudo chmod 0700 ./data/dlq
```

This intentionally keeps the old DLQ location. Compose refuses to auto-create it with root ownership; the directory is absent in this local checkout and must be prepared on the deployment host. Review its size and replay status before rollout. For a hard disk bound, provision a dedicated filesystem or project quota for this directory (for example 10 GiB after measuring outage volume), alert well before exhaustion, and test full-disk behavior. A quota limits disk usage; it does not guarantee record delivery. No host quota or automatic deletion job has been installed.

Schedule `scripts/retention_cleanup.py` off-peak only after checking the actual schema, backup and retention requirements. It drops weekly partitions and deletes child rows; review orphan/default partitions and use chunked cleanup if a large backlog would exceed the 15-second application statement timeout. Avoid `VACUUM FULL`, forced full-partition ClickHouse merges, backups and Redis rewrites overlapping at peak ingest. Replay and verify DLQ records before removing them. Keep backups off this HDD.

Validation commands for the Linux target, after stopping the old backend during the maintenance window:

```sh
docker compose config --quiet
docker compose build backend
docker compose up -d db redis clickhouse
docker compose up -d backend nginx
docker compose exec nginx nginx -t
docker compose ps
docker stats --no-stream
```

Inspect effective PostgreSQL settings with `SHOW`, ClickHouse settings/system tables and Redis `INFO memory` / `INFO persistence`; confirm cgroup memory limits and authenticated probes. Exercise a cold start with populated volumes, sustained ingest plus dashboard exports, AOF rewrite, restart recovery, dependency outage and DLQ replay. Monitor OOM events, RSS, query memory-limit failures, Redis rejected writes, disk latency/IO wait, active parts, outbox age/depth and free space. If steady load overwhelms this disk or ClickHouse repeatedly rejects normal queries, reduce workload/retention or move storage to SSD/separate hosts; spare CPU cannot compensate for insufficient RAM or random I/O.

## Validation performed here

- Docker Compose configuration validation passed with the installed CLI.
- Both ClickHouse XML files parsed successfully; memory total is 9216 MiB.
- Version-specific ClickHouse pool thresholds and profile placement checked against upstream 24.3 source.
- `git diff --check` passed.
- Container builds, database startup, Nginx runtime validation and load/recovery tests were not run: the local Docker Linux engine is unavailable. This profile needs those checks on the Linux target before production use.
