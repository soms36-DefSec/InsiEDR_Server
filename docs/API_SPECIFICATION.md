# InsiEDR Server: API Specification

The InsiEDR Central Server provides a RESTful and Server-Sent Events (SSE) interface for agent ingestion, forensic queries, threat feeds, and analyst dashboard interactions.

---

## 1. Authentication & Security Headers

Agent telemetry is sent as `application/json` to `POST /api/logs` (the
`/api/v1/logs` alias is also available). The agent supplies these headers:

* `X-AGENT-ID`: endpoint identity bound to its credential when agent
  authentication is enforced.
* `X-PAYLOAD-ID`: payload UUID used for idempotent retry and acknowledgement.
* `X-CRYPTO-SCHEME`: `aes-256-gcm`, `hpke`, or a configured legacy scheme.
* `X-PROTOCOL-VERSION`: currently `2.0`.
* `X-KEY-ID`: required for AES-GCM and HPKE envelopes.
* `X-Agent-Token` or `Authorization: Bearer ...`: agent credential. Production
  deployments require credentials and bind them to an agent ID through
  `INSIEDR_AGENT_TOKENS` or the configured bearer-token mode.

The encrypted envelope repeats the protocol version, scheme, payload ID and
key ID; the server rejects header/envelope mismatches. Payload identity is
also checked after decryption. Encryption by itself is not sender
authentication.

Operator APIs use `X-Operator-Key`, `Authorization: Bearer ...`, or `X-API-Key`
with configured operator credentials and roles. Sensitive reads require
`operator:read`; containment and remediation use their respective roles.

**Error format:** API exceptions use the RFC 7807-style JSON envelope:
  ```json
  {
    "type": "https://insiedr.local/errors/invalid-payload",
    "title": "Invalid Payload",
    "status": 400,
    "detail": "Failed to decrypt payload using configured AES key.",
    "instance": "/api/logs"
  }
  ```

---

## 2. Ingestion Endpoint

### `POST /api/logs`
Primary telemetry ingestion endpoint for remote agents.

* **Request format:** encrypted JSON envelope. The exact fields depend on the
  selected crypto scheme:
  ```json
  {
    "protocol_version": "2.0",
    "scheme": "aes-256-gcm",
    "key_id": "agent-key-2026-01",
    "payload_id": "a548e6c7-31ef-42d8-9189-72c0ecdbb912",
    "created_at": "2026-10-25T10:00:00Z",
    "nonce": "base64_encoded_nonce...",
    "ciphertext": "base64_encoded_ciphertext_and_auth_tag..."
  }
  ```
* **Durable acknowledgement:** the server responds only after PostgreSQL commits
  the payload and its ClickHouse outbox entry. The Rust agent accepts only HTTP
  `202` with a matching payload ID and `status: "accepted"`; it keeps the
  envelope in its local durable spool on other responses or transport failures.
  ```json
  {
    "ok": true,
    "payload_id": "a548e6c7-31ef-42d8-9189-72c0ecdbb912",
    "status": "accepted"
  }
  ```

Validation, authentication, decryption and storage failures are not accepted;
the agent retains and retries the same payload ID. Duplicate payload IDs with
the same content are acknowledged idempotently, while conflicting identities
or content are rejected.

---

## 3. Telemetry and Fleet APIs

Sensitive analyst routes require operator authentication and the `operator:read`
role. The principal collection endpoints are:

| Endpoint | Purpose | Bounds / pagination |
|---|---|---|
| `GET /api/logs` | Legacy raw-payload listing | `limit` 1–1000; offset pagination |
| `GET /api/telemetry` | Collector observations with optional risk/feature enrichment | `limit` 1–1000; offset or cursor, not both; optional total count |
| `GET /api/telemetry/explorer` | Lightweight event rows for the explorer | `limit` 1–1000; seek cursor |
| `GET /api/telemetry/events/{event_id}` | On-demand event detail | One event |
| `GET /api/telemetry/histogram` | Server-side event counts by time bucket | Predefined range/interval or explicit custom dates |
| `GET /api/collector-states/{agent_id}` | Latest collector observations with freshness | Per-agent state set |
| `GET /api/agents` | Fleet listing | `limit` 1–500; offset |
| `GET /api/agents/{agent_id}` | One agent record | Single record |
| `GET /api/stats`, `GET /api/dashboard-summary` | Dashboard aggregates and snapshot data | Snapshot-cached responses |
| `GET /api/risk-events` | Risk event history | `limit` 1–500; offset |
| `GET /api/user-analysis/{username}` | Collector, risk-score and prediction view | One user; risk history is bounded |

Most routes also have `/api/v1/...` aliases. The active router source is the
reference for query filters and response fields. Pagination pages continue on
the configured telemetry read source; ClickHouse lag is not silently filled
with PostgreSQL rows.

## 4. Agent Fleet Control

Agent-to-server endpoints include `POST /api/agent/heartbeat`,
`POST /api/agent/task-result`, and `POST /api/agent/task-ack`. They authenticate
the agent and bind requests to its configured identity. Operator task and
containment routes include:

* `GET /api/agents/{agent_id}/tasks`
* `POST /api/agents/{agent_id}/isolate` and `/unisolate`
* `POST /api/agents/{agent_id}/terminate`, `/lock`, and `/rollback`
* `GET /api/agents/tamper-alerts`

These require the appropriate operator read, containment, or remediation role.

## 5. Streaming and Exports

Authenticated SSE endpoints are `/api/v1/stream/telemetry`,
`/api/v1/stream/dashboard`, `/api/v1/stream/threats`, and
`/api/v1/stream/agents`. They emit notifications; REST queries are the recovery
path for missed updates.

CSV, NDJSON and XLSX export routes are under `/api/v1/export/`: logs, threats,
training datasets, normalized features, keystrokes, and collector datasets.
Log and threat stream exports cap each request at 200,000 rows; collector
dataset exports cap at the configured `INSIEDR_MAX_EXPORT_RECORDS`. Training
XLSX is built as a workbook and has higher memory cost than streaming CSV/JSONL.

## 6. Health, Operations, and Discovery

* `GET /api/health/live` is a lightweight liveness check.
* `GET /api/health/ready` checks whether required storage is ready.
* `GET /api/health` and `GET /api/operations/health` report operational state.
* `POST /api/operations/pause-ingestion` and `/resume-ingestion` control the
  operator ingestion switch.
* `GET /api/queue/metrics` reports queue metrics.
* `GET /api/crypto/public-keys` publishes configured encryption key metadata.
* OpenAPI and rendered docs are served at `/openapi.json`, `/docs`, and `/redoc`.

Model review routes are under `/api/v1/detection/ml/` and require analyst or
operator roles. Staging scenario-replay routes are conditional on deployment
configuration and are not part of the normal production API surface.
