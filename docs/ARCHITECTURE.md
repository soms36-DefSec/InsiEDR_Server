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

## 3. The Multi-Stage Detection Pipeline & ML Integration Boundary

Decrypted telemetry is extracted into a normalized feature vector across core behavioral domains (Logon, File, Device, HTTP/Network, Process, Memory).

### Core Deterministic Server Pipeline (Active, Standalone)

The server evaluates risk deterministically on ingestion without requiring active ML inference services:

1. **Heuristics Detection Engine (`heuristics/`)**:
   - **CERT Behavioral Rules**: Evaluates non-negotiable insider threat indicators mapped to canonical CERT scenarios (S1 IT Sabotage, S2 IP Theft, S3 Exfiltration, S4 Cloud Exfiltration, etc.).
   - **Direct Threat Detectors**: Real-time evaluation of endpoint sensor findings:
     - `S1_CRED_DUMP` (CRITICAL, score 100): Suspected LSASS credential dumping.
     - `S1_INJECTION` (HIGH, score 85): In-memory unbacked executable code regions or threats.
     - `NETWORK_TUNNELING` (HIGH, score 80): Reverse shell/tunneling process count or DNS tunneling.
     - `HONEYTOKEN` (CRITICAL, score 100): Direct tripwire interaction with canary/decoy assets.
     - `S1` (HIGH, score 85): Persistence modifications correlated with after-hours logon or authentication bursts.
   - **Correlation Clusters & Superposition**: Groups related rules into non-linear clusters to prevent artificial score stacking, applying sub-linear decay on secondary signals and cross-domain superposition.

2. **Authentication Burst Detector (`server/risk/signals.py`)**:
   - Evaluates host-scoped short-window (5-minute) successful-logon velocity, failure ratios, workstation breadth, and off-hours activity.
   - Emits factual burst categories. Current aggregate event-log telemetry does not support account-specific brute-force or password-spray attribution.

3. **User-Profile Baseline & Z-Score Engine (`server/baseline/engine.py`, `server/risk/signals.py`)**:
   - EMA baselines are keyed by the root payload username, representing the active primary session; this is not kernel-enforced SID attribution, and flattened host activity may still affect counters.
   - Enforces dual variance floors (`_std_floor`) to prevent division by zero or false positive explosions during periods of low activity.
   - **Anti-Poisoning Gate**: Observations are only admitted to update the baseline when the evaluated risk is below threshold (`Risk < 40`), preventing adversaries from slowly training the baseline to accept malicious behaviors.
   - Applies hourly observation throttling to prevent high-frequency telemetry bursts from biasing the profile.

4. **Risk Aggregator & Corroborator (`server/risk/aggregator.py`)**:
   - Fuses heuristics, authentication bursts, and baseline deviations into a calibrated composite score (0–100) and severity rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### Identity-Scoped Telemetry Roadmap

The current extractor matches user-keyed collector maps by the root payload username. It does not create independent identities for Windows SIDs or processes. Before introducing per-user or per-process baselines and z-scores, evolve the telemetry contract and storage model together:

1. **Declare scope on every metric group:** use an explicit scope such as `host`, `user_session`, or `process`. Do not infer user scope from a collector's presence in a payload that has a root username.
2. **Attach stable identity fields appropriate to that scope:** include `tenant_id` and `agent_id`; add `user_sid` for user-scoped events and `process_guid` (plus its owning `user_sid` where available) for process-scoped events. Keep `username` as display metadata, not as the identity key.
3. **Partition extraction and baseline state:** preserve scope and identity during feature extraction, and use typed composite keys such as `(tenant_id, agent_id, user_sid)` or `(tenant_id, agent_id, user_sid, process_guid)`. Keep host-scoped features on a host key and prevent implicit fallback from process/user data to root-session features.
4. **Migrate and validate before enabling:** retain existing username-keyed baselines as legacy active-session baselines, add the new scoped baselines separately, and only train or score a new scope when its identity is present and validated. Add schema-versioned fixtures and cross-scope isolation checks before rollout.

Until this contract and migration exist, describe current user baselines as active-session-associated host telemetry, not as isolated per-user or per-process behavior.

### External Machine Learning Integration Boundary

Advanced statistical and deep learning models operate as an external model training & inference tier:
* **Dataset Export Handlers**: The server provides high-throughput streaming exports (`/api/v1/export/training-dataset.csv`, `.xlsx`, `.ndjson`) to feed offline ML training workflows.
* **External Model Pipeline (Optional Integration)**:
  - **Domain Isolation Forest**: Unsupervised domain anomaly detection across feature distributions.
  - **Supervised XGBoost Classifier**: Multiclass classification into CERT insider threat scenarios.
  - **RedRVFL Temporal Modeler**: Random Vector Functional Link network with RandomLSTM units modeling multi-day velocity trajectories.
* When ML inference workers are active, their scores integrate into `RiskAggregator` via the pluggable detector contract. If ML workers are offline or disabled (`INSIEDR_ENABLE_MODEL_PIPELINE=false`), the server operates at full capability using deterministic heuristics, auth burst detection, and baseline z-scores.

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
