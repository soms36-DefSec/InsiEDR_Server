# InsiEDR-Server: Specific AI Engineering & Prompt Guidebook
> **Codebase**: `d:\Projects\AISH\InsiEDR_Server`  
> **Tech Stack**: Python 3.13, FastAPI, PostgreSQL (asyncpg/psycopg), ClickHouse (ClickHouseBatcher), React + Vite (`dashboard/dist`), Nginx  
> **Core Subsystems**: ASGI Lifespan (`server/app.py`), Ingestion Gateway (`/api/logs`), RVFL Anomaly Engine (`server/baseline/engine.py`), Hybrid Storage (`server/storage/`), Task Queue (`server/task_queue.py`)

---

## 1. Concrete Architecture & Subsystem Map

Any AI agent operating on `InsiEDR_Server` must understand the exact file layout, data pipelines, and database layers:

```
server/
├── app.py                      # FastAPI App Factory & Lifespan (Startup/Shutdown, 8x ML workers pool)
├── config.py                   # Centralized configuration & environment loader (.env)
├── plugin_registry.py          # Dynamic plugin & detector registry
├── task_queue.py               # Durable background task queue for remote agent actions
├── api/                        # REST & Streaming Endpoints
│   ├── ingest.py               # Ingestion gateway (/api/logs) for encrypted telemetry
│   ├── agents.py               # Fleet management, agent registration, heartbeats & status
│   ├── events.py               # Server-Sent Events (SSE) streaming (/api/stream/threats, /api/stream/agents)
│   ├── responses.py            # Agent action dispatch (Isolate, Terminate, Lock, Rollback)
│   ├── keys.py                 # HPKE & AES-GCM cryptographic key distribution
│   ├── stats.py                # Telemetry aggregations & fleet statistics
│   ├── export.py               # Streaming CSV / NDJSON telemetry exports
│   ├── health.py               # Health check & readiness probes
│   ├── errors.py               # RFC 7807 Problem Details error formatting
│   └── deps.py, cache.py, docs.py, logs.py
├── crypto/                     # Cryptographic Decryption Plugins
│   ├── hpke_plugin.py          # Hybrid Public Key Encryption (X25519) decryption
│   ├── aesgcm_plugin.py        # AES-256-GCM symmetric decryption
│   ├── fernet_plugin.py        # Fernet compatibility layer
│   └── plaintext_plugin.py     # Development / debug bypass
├── baseline/                   # Threat Detection & ML Engine
│   └── engine.py               # Random Vector Functional Link (RVFL) neural network for user anomaly & risk scoring
├── storage/                    # Hybrid Data Persistence Layer
│   ├── hybrid_storage.py       # Orchestrator routing to Postgres and/or ClickHouse
│   ├── postgres_storage.py     # PostgreSQL client with connection pooling & transaction management
│   ├── clickhouse_storage.py   # ClickHouse client for high-scale analytical queries
│   ├── clickhouse_batcher.py   # Asynchronous batch accumulator for ClickHouse inserts
│   ├── migration_runner.py     # Automated SQL migration runner
│   ├── migrations/             # 10 Sequential SQL Schema Migrations:
│   │   ├── 001_initial_schema.sql
│   │   ├── 004_table_partitioning.sql
│   │   ├── 006_user_daily_rvfl_risk.sql
│   │   ├── 007_task_queue.sql
│   │   ├── 008_performance_indexes.sql
│   │   └── 010_default_partitions.sql
│   └── repositories/
│       ├── fleet_repo.py       # Agent records, health status, metadata queries
│       ├── telemetry_repo.py   # Telemetry event retrieval & time-series lookups
│       └── threat_repo.py      # Alerts, anomaly incidents, MITRE ATT&CK tags
└── utils/
    └── webhook.py              # Outbound alerting webhooks (Slack, Teams, SIEM)
```

---

## 2. The 6 Engineering Perspectives (Specific to FastAPI & Hybrid Storage)

Every AI agent reviewing or modifying this codebase must adhere strictly to these rules:

### 1. Architecture
- **Dual-Tier Ingestion Routing**: Ingestion via `/api/logs` decrypts payloads via `crypto/` plugins, then routes raw high-volume events to `ClickHouseBatcher` while maintaining relational fleet state and alerts in `PostgresStorage`.
- **Non-Blocking Async IO**: The FastAPI event loop must NEVER be blocked by CPU-intensive ML tasks. Heavy operations (e.g. RVFL training or inference in `server/baseline/engine.py`) must be offloaded to the 8x `ThreadPoolExecutor` initialized in `server/app.py`.

### 2. Design
- **Repository Pattern**: Keep business logic out of API route handlers. All database interactions must pass through `fleet_repo.py`, `telemetry_repo.py`, or `threat_repo.py`.
- **RFC 7807 Error Handling**: Any raised exception must be caught and transformed into RFC 7807 JSON schema (`{"type": "...", "title": "...", "status": ..., "detail": "..."}`) via `server/api/errors.py`.

### 3. Security
- **Encrypted Payload Decryption**: Agent telemetry arriving at `/api/logs` is encrypted with HPKE (`crypto/hpke_plugin.py`) or AES-256-GCM. Unauthenticated or invalid payloads must be rejected with 401/403 before parsing.
- **SQL Injection Prevention**: All SQL queries in `postgres_storage.py` and `clickhouse_storage.py` must use parameterized queries. Dynamic string formatting (`f"SELECT ... {param}"`) is strictly prohibited.
- **Remediation Action Authorization**: Commands issued via `server/api/responses.py` (Isolate host, terminate process) require valid administrative credentials and must generate an immutable audit log entry in the task queue.

### 4. Reliability & Concurrency
- **ClickHouse Batching & Backpressure**: `ClickHouseBatcher` must accumulate events up to batch size or flush interval. If ClickHouse is temporarily unavailable, events must be buffered in memory up to a bounded limit without crashing the server.
- **Postgres Connection Pools**: Ensure connections borrowed from `asyncpg`/`psycopg` pools are released cleanly using `async with` context managers. Avoid long-running transactions.
- **Graceful Lifespan Shutdown**: `server/app.py` must cleanly cancel background worker tasks, flush remaining ClickHouse batches, and drain the thread pool on SIGTERM.

### 5. Adaptability
- **Dynamic Plugin & Detector Architecture**: Detectors and crypto plugins register via `server/plugin_registry.py` at runtime. Adding new detection heuristics must not require changing core ingestion routes.
- **Zero-Downtime Migrations**: All database schema updates must follow the migration pattern in `server/storage/migrations/` (additive migrations, partition management, backward-compatible default values).

### 6. Developer-Friendly Code
- **Type Annotations**: Full Python 3.13 type annotations (`typing`, `pydantic` models).
- **Auto-Documented APIs**: All route handlers must declare Pydantic response models so OpenAPI documentation (`/api/docs`) stays accurate.
- **Reproducible Tests**: Integration tests in `tests/` must mock database and ClickHouse connections unless running under Docker test containers.

---

## 3. Specific Server Master Prompts (Ready to Copy)

### Server Prompt 1: Codebase Analysis & Pipeline Audit
```markdown
### TASK: INSIEDR-SERVER PIPELINE AUDIT & PERFORMANCE ANALYSIS

#### AGENT CONTEXT:
You are a Principal Backend Engineer & Security Architect auditing `InsiEDR_Server` (Python 3.13, FastAPI, Postgres asyncpg, ClickHouse, RVFL engine).

#### SCOPE:
- Target File / Subsystem: {{INSERT_FILE_E_G_server_storage_clickhouse_batcher_py}}
- Issue / Goal: {{INSERT_ISSUE_OR_PERFORMANCE_GOAL}}

#### AUDIT CHECKLIST:
1. **Async & Concurrency Health**:
   - Are any synchronous blocking calls (e.g., `requests.get`, `time.sleep`, heavy NumPy/SciPy math) executing inside async FastAPI routes?
   - Is work properly delegated to the thread pool executor in `server/app.py`?
2. **Database & Storage Integrity**:
   - Does `hybrid_storage.py` properly route between ClickHouse and Postgres?
   - Are transactions rolled back on error in `postgres_storage.py`?
   - Are SQL queries fully parameterized?
3. **Decryption & Payload Security**:
   - Does `/api/logs` handle malformed HPKE/AES-GCM ciphertexts gracefully without revealing server stack traces?
   - Is RBAC verified before remote actions are queued in `server/task_queue.py`?
4. **Memory & Batching Limits**:
   - Does the batcher buffer unbounded amounts of memory during ClickHouse latency spikes?

#### REQUIRED DELIVERABLE:
1. **Executive Evaluation**: Summary of subsystem architecture and adherence to the 6 Pillars.
2. **Vulnerability & Bottleneck Matrix**: Severity, File:Line, Bug Class, and Impact.
3. **Root Cause Breakdown**: Exact trace of the flaw under high load.
4. **Targeted Architectural Recommendations**: Concrete next steps before drafting the plan.
```

---

### Server Prompt 2: API & Integration Test Suite Generation
```markdown
### TASK: INSIEDR-SERVER TEST SUITE GENERATION

#### AGENT CONTEXT:
You are a Senior Backend SDET writing automated tests for `InsiEDR_Server` using PyTest and FastAPI TestClient.

#### SCOPE:
- Target Endpoint / Service: {{INSERT_ENDPOINT_E_G_api_ingest_py}}
- Related Files: {{INSERT_RELATED_FILES}}

#### TEST COVERAGE REQUIREMENTS:
1. **Decryption & Ingestion Tests**:
   - Test ingestion with valid AES-256-GCM and HPKE encrypted payloads.
   - Test rejected requests: expired tokens, invalid ciphertexts, tampered HMAC.
2. **Hybrid Storage Mocking**:
   - Mock `PostgresStorage` and `ClickHouseBatcher` to run tests hermetically without external database servers.
3. **Task Queue & Responses**:
   - Test queuing of isolation and termination commands in `server/task_queue.py`.
   - Verify RFC 7807 error responses for invalid agent IDs or unauthorized roles.
4. **Concurrency & Load Mock**:
   - Simulate 100 concurrent POST requests to `/api/logs` to verify async stability.

#### REQUIRED DELIVERABLE:
1. **Test Strategy Summary**: Table mapping test cases to risks.
2. **Production-Ready PyTest Code**: Complete test files with fixtures in `tests/`.
3. **Execution Command**: Exact command (e.g. `pytest tests/test_ingest.py -v`).
```

---

### Server Prompt 3: Specific Implementation Plan Generator
```markdown
### TASK: INSIEDR-SERVER PHASED IMPLEMENTATION PLAN

#### AGENT CONTEXT:
You are the Technical Lead for `InsiEDR_Server`. Create a detailed implementation plan for the requested feature or bug fix before changing any code.

#### SCOPE:
- Feature / Bug: {{INSERT_ISSUE_OR_FEATURE}}
- Analysis Summary: {{INSERT_ANALYSIS_SUMMARY}}

#### REQUIRED PLAN SECTIONS:
1. **Impacted Subsystems**: Identify exact files in `server/api/`, `server/storage/`, `server/crypto/`, `server/baseline/`, or `server/storage/migrations/`.
2. **Database Migration Strategy**:
   - If schema changes are needed, write the exact SQL migration script for `server/storage/migrations/011_*.sql`.
   - Ensure backward compatibility with existing agent payloads.
3. **Phased Roadmap**:
   - Phase 1: Migration script & Repository updates (`repositories/`).
   - Phase 2: Service / Storage layer logic (`storage/`, `baseline/`, `crypto/`).
   - Phase 3: FastAPI route & RFC 7807 error wiring (`api/`).
   - Phase 4: Integration testing & OpenAPI doc verification.
4. **Rollback Plan**: Exact procedure to roll back code and down-migrate the database.
5. **File Modification Table**: File paths, operations (Create/Modify), and descriptions.
```

---

### Server Prompt 4: Surgical Bug Fix & Implementation
```markdown
### TASK: INSIEDR-SERVER SURGICAL CODE IMPLEMENTATION

#### AGENT CONTEXT:
You are an expert Python 3.13 / FastAPI developer implementing an approved plan for `InsiEDR_Server`.

#### INPUT:
- Approved Plan: {{INSERT_APPROVED_PLAN}}
- Target Component: {{INSERT_TARGET_FILE_OR_MODULE}}

#### IMPLEMENTATION RULES:
1. Maintain strict type hints (`from __future__ import annotations`, Pydantic models).
2. Never block the async event loop; use `asyncio.to_thread` or the server's thread pool for synchronous calls.
3. Ensure all SQL queries are strictly parameterized.
4. Always wrap external calls with proper RFC 7807 error responses.
5. Provide complete, contiguous code blocks ready to be inserted.
```
