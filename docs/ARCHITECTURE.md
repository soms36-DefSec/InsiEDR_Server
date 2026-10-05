# InsiEDR Server: System Architecture & Data Flow

This document provides a technical deep-dive into the internal architecture, ingestion pipeline, detection engine handoffs, and storage strategies of the **InsiEDR Central Server**.

---

## 1. High-Level Architectural Diagram

```
                             [ Windows Endpoints ]
                   (InsiEDR-Agent: 30+ Telemetry Collectors)
                                       │
                      POST /api/logs   │ AES-256-GCM / HPKE Encrypted
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         InsiEDR FastAPI ASGI Server                         │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        1. Ingestion Layer                             │  │
│  │  • Payload Authentication & Replay Protection                         │  │
│  │  • Cryptographic Plugin Engine (AES-256-GCM / HPKE / Fernet)          │  │
│  │  • Schema Normalization & Validation (Pydantic v2)                    │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                   2. Multi-Stage Detection Pipeline                   │  │
│  │                                                                       │  │
│  │   ┌─────────────────────────────┐     ┌────────────────────────────┐  │  │
│  │   │  Deterministic Heuristics   │     │  Unsupervised Isolation    │  │  │
│  │   │  • CERT Behavioral Rules    │     │  Forest (Domain Anomaly)   │  │  │
│  │   │  • Honeytoken/Decoy Alert   │     │  • Overall & Sub-Domain    │  │  │
│  │   └──────────────┬──────────────┘     └─────────────┬──────────────┘  │  │
│  │                  │                                  │                 │  │
│  │                  ▼                                  ▼                 │  │
│  │   ┌─────────────────────────────┐     ┌────────────────────────────┐  │  │
│  │   │  Supervised XGBoost         │     │  Temporal Sequence         │  │  │
│  │   │  Classifier                 │     │  Modeler (RedRVFL / LSTM)  │  │  │
│  │   │  • Scenario Attribution     │     │  • Historical Trajectory   │  │  │
│  │   └──────────────┬──────────────┘     └─────────────┬──────────────┘  │  │
│  │                  └────────────────┬─────────────────┘                 │  │
│  │                                   ▼                                   │  │
│  │                     Risk Aggregator & Corroborator                    │  │
│  │                     • Composite Score: 0 - 100                        │  │
│  │                     • Threat Severity (LOW -> CRITICAL)               │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                   ┌──────────────────┴──────────────────┐                   │
│                   ▼                                     ▼                   │
│  ┌─────────────────────────────────┐   ┌─────────────────────────────────┐  │
│  │      3. Dual-Storage Engine     │   │     4. Event Broadcaster        │  │
│  │  • PostgreSQL: Entities, alerts,│   │  • Server-Sent Events (SSE)     │  │
│  │    baselines, task queues       │   │  • /api/stream/threats          │  │
│  │  • ClickHouse: High-volume raw  │   │  • /api/stream/agents           │  │
│  │    telemetry & columnar events  │   │  • Real-time SOC updates        │  │
│  └─────────────────────────────────┘   └────────────────┬────────────────┘  │
└─────────────────────────────────────────────────────────┼───────────────────┘
                                                          │
                                                          ▼
                                ┌───────────────────────────────────┐
                                │   Analyst Dashboard (React 19)    │
                                │   Fleet KPIs, Matrix, Forensics   │
                                └───────────────────────────────────┘
```

---

## 2. Telemetry Ingestion & Cryptographic Decryption

When telemetry arrives at `POST /api/logs`:
1. **Header Verification**: Validates the `X-InsiEDR-Agent-Id`, `X-InsiEDR-Payload-Id`, and signature headers.
2. **Replay Protection**: The payload ID is tracked against recent memory caches and PostgreSQL `telemetry_payloads` to prevent replay attacks.
3. **Pluggable Decryption Engine (`server/crypto/`)**:
   - `AESGCMCryptoPlugin`: Default symmetric cipher using 256-bit keys and 12-byte initialization vectors (IVs).
   - `HPKECryptoPlugin`: RFC 9180 Hybrid Public Key Encryption for asymmetric forward-secrecy deployments.
   - `FernetCryptoPlugin`: Backward compatibility mode.
4. **Queue Spooling & Task Queue**: Payloads can be evaluated synchronously or offloaded to an asynchronous durable worker thread pool (8x ML background workers) via `server/task_queue.py`.

---

## 3. The 4-Tier Detection Pipeline (`ModelBridge`)

Decrypted telemetry is extracted into a normalized feature vector across four domains:
* **Logon Activity**: Logon frequency, after-hours ratio, distinct machine counts.
* **File Activity**: Total reads, modifications, daily unique filenames, Honeytoken trips.
* **Device Activity**: USB insertions, unapproved hardware connects.
* **HTTP / Network**: Upload volumes, external domains, file-sharing domain visits.

### Layer 1: Deterministic Heuristics (`heuristics/`)
* Evaluates non-negotiable behavioral boundaries based on the CERT Insider Threat dataset.
* Immediately generates a deterministic severity level (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* Example: Any interaction with a known decoy file immediately trips a `CRITICAL` severity rating with 100% confidence.

### Layer 2: Domain Isolation Forest (`model/`)
* Unsupervised outlier scoring (`domain_isolation_forest.pkl`).
* Evaluates domain-specific distributions (File, Logon, Device, HTTP) against learned baseline parameters.
* Identifies "unknown unknowns" that violate statistical normality without tripping a hardcoded rule.

### Layer 3: Supervised XGBoost Classifier (`model/`)
* Multiclass gradient-boosted decision tree (`scenario_xgb.pkl`).
* Classifies feature combinations into specific insider threat scenario classes (e.g., Scenario 1: IT sabotage, Scenario 2: Intellectual property theft, Scenario 3: Bulk data exfiltration).

### Layer 4: RedRVFL Temporal Sequence Modeler (`model/`)
* Random Vector Functional Link (RedRVFL) network with RandomLSTM recurrent units (`rvfl_model.pkl`).
* Evaluates rolling sequences of historical user days.
* Computes temporal behavioral velocity: identifies whether activity is accelerating toward exfiltration or decaying back to normal.

---

## 4. Storage Architecture: Authoritative PostgreSQL + ClickHouse Outbox Replication

The server enforces an authoritative primary-source architecture balancing ACID persistence with high-throughput columnar analytics:

### 1. PostgreSQL (Authoritative Source of Truth)
* Durable transactional persistence commits BEFORE returning HTTP `202 Accepted` on telemetry ingestion.
* Strict transactional boundaries: `raw_payloads`, `collector_results`, `risk_events`, and `normalized_features` are committed together.
* Schema migrations serialized with PostgreSQL advisory locks (`pg_advisory_lock`):
  * `001_initial_schema.sql` — Core telemetry, agents, alerts.
  * `004_table_partitioning.sql` — Daily and monthly partition tables for scalable log management.
  * `005_normalized_features_payload_idx.sql` — Feature indexes.
  * `006_user_daily_rvfl_risk.sql` — Historical temporal score caching.
  * `007_task_queue.sql` — Durable job worker queue.
  * `008_performance_indexes.sql` — B-Tree and BRIN indexes for high-speed queries.
  * `011_command_audit.sql` — `command_audit_log`, `agent_tasks` delivery lease columns, and `clickhouse_outbox`.

### 2. Transactional Outbox & ClickHouse Replication
* ClickHouse in-memory buffer admission is **never** treated as durable persistence.
* During telemetry persistence, outbox entries are atomically enqueued into the PostgreSQL `clickhouse_outbox` table within the **exact same database transaction** as `raw_payloads` and `collector_results` before `conn.commit()`.
* A background `ReplicationReconciler` (`server/storage/reconciler.py`) periodically drains the outbox and replays records to ClickHouse with exponential backoff and retry tracking.
* The reconciler guarantees durability by requiring a confirmed ClickHouse flush (`flush_all` / `flush`) before marking outbox records `completed` in PostgreSQL; on flush failure, records remain `pending` for safe retry.
* ClickHouse Batcher (`server/storage/clickhouse_batcher.py`) enforces strict capacity bounds (`max_buffer_rows`, `max_buffer_bytes`) item-by-item, spilling any excess or oversized batches directly to the durable Dead-Letter Queue (DLQ) file store.
* DLQ table routing parses full table names (`raw_payloads`, `collector_results`) with atomic `.tmp` publication and `.replaying` exclusive claim locks.

### 3. Concurrency, Queue Safety, & Event Loop Health
* **Atomic Redis State Transitions**: Job claiming uses `BRPOPLPUSH` into an in-flight processing list (`insiedr:tasks:processing`), and job failure/rescheduling uses atomic Redis multi/exec pipelines (`HDEL + ZADD`), eliminating task-loss windows. The background reaper sweeps orphaned jobs from both running and in-flight processing structures.
* **Bounded Thread Offloading**: All blocking synchronous I/O operations (PostgreSQL database queries, ClickHouse queries, OpenPyXL spreadsheet generation) are offloaded to worker threads via `anyio.to_thread.run_sync`, keeping the FastAPI asynchronous event loop completely unblocked and responsive under heavy concurrent loads (verified at 236+ RPS).

---

## 5. Security, Fleet Control & Zero Trust

* **Operator RBAC**: Operator actions require verified bearer tokens with granular roles (`operator:containment` for isolation/unisolation, `operator:remediation` for process termination/lock/rollback, `operator:read` for telemetry queries and exports, `admin` for test broadcasts).
* **Command Audit Trail**: Every fleet containment or remediation action is written atomically to `command_audit_log` with actor identity, role, target agent, command parameters, and client IP.
* **Agent Credential Binding**: Agent requests (`/agent/heartbeat`, `/agent/task-result`, `/agent/task-ack`) verify credentials bound to the claimed `agent_id`, preventing cross-agent identity spoofing.
* **SQL Task Ownership**: Result ingestion enforces `WHERE task_id = %s AND agent_id = %s` and legal state machine transitions; terminal states cannot be rewritten or reopened.
* **Command Delivery Leases**: Remote tasks use recoverable command leases (`lease_expires_at`, `dispatch_count`) and an explicit acknowledgement protocol (`POST /api/agent/task-ack`).
* **RFC 7807 Problem Details**: Uniform error responses formatted per RFC 7807 (`type`, `title`, `status`, `detail`, `instance`) while retaining legacy keys for backwards compatibility.
* **Kubernetes Probes**: Ultra-lightweight `/api/health/live` (liveness) and `/api/health/ready` (readiness).
* **Cryptographic Protocol**: The HPKE adapter implements a custom hybrid public-key encryption scheme based on X25519 ECDH, HKDF-SHA256, and AES-256-GCM inspired by RFC 9180 (Mode 0: Base). Public-key encryption alone is not treated as sender authentication; agent token binding is required.
* **Secret Redaction**: URLs in logs and configuration strip credentials (`user:password` -> `user:***@host`).

---

## 6. Real-Time Streaming & Dashboard Interface

* **Server-Sent Events (SSE)**: The frontend connects to `/api/v1/stream/threats` and `/api/v1/stream/agents` for low-latency reactive updates protected by operator authorization.
* **React 19 Single-Page Application**: The production build (`frontend/dist/`) is served directly by the FastAPI backend at `/dashboard/`.
* **API Documentation**: Interactive OpenAPI 3.0 documentation is auto-generated and served at `/docs` (Swagger UI) and `/redoc` (ReDoc).
