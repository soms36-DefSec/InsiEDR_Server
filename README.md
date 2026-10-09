# InsiEDR Server: Central Intelligence & Threat Analytics Engine

For the current replication guarantees, scheduled retention, monitoring, and rollout gates, see [Reliability rollout](docs/RELIABILITY_ROLLOUT.md). Capacity on the target HDD requires measured validation.

[![Backend](https://img.shields.io/badge/Backend-FastAPI%20ASGI-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Frontend-React%2019%20%2B%20TypeScript%20%2B%20Vite-61DAFB.svg?style=flat&logo=react)](https://react.dev)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=python)](https://www.python.org)
[![Database](https://img.shields.io/badge/Storage-PostgreSQL%2016%20%2B%20ClickHouse-336791.svg?style=flat&logo=postgresql)](https://www.postgresql.org)
[![Cache](https://img.shields.io/badge/Cache-Redis%207-DC382D.svg?style=flat&logo=redis)](https://redis.io)
[![Encryption](https://img.shields.io/badge/Telemetry-AES--256--GCM%20%2F%20HPKE-critical.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Docker](https://img.shields.io/badge/Deploy-Docker%20Compose-2496ED.svg?style=flat&logo=docker)](https://www.docker.com)
[![Agent](https://img.shields.io/badge/Agent-InsiEDR_Agent-blue.svg)](https://github.com/soms36-DefSec/InsiEDR_agent)

**InsiEDR Server** is the central backend, analytics engine, and Security Operations Center (SOC) console for the **InsiEDR** platform. Engineered specifically to tackle **malicious insider threats, lateral movement, unauthorized data staging, and exfiltration**, InsiEDR blends deterministic rule heuristics with a multi-layered machine learning pipeline.

> 💡 **Looking for the endpoint sensor?** Check out the [InsiEDR Windows Agent](https://github.com/soms36-DefSec/InsiEDR_agent) for the 30+ telemetry collectors and client-side encryption modules.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Windows Endpoints                               │
│            (InsiEDR-Agent: 30+ Telemetry Collectors)                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTPS / AES-256-GCM Encrypted JSON
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      InsiEDR Central Server                            │
│                      (FastAPI / Uvicorn ASGI)                          │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      1. Ingestion Layer                        │   │
│   │   • Decryption (AES-256-GCM / HPKE)                            │   │
│   │   • Replay Protection & Payload Validation                     │   │
│   │   • Durable Task Worker Queue (8x Background Workers)          │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│                                   ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │             2. Multi-Layered Intelligence Pipeline             │   │
│   │                                                                │   │
│   │  [Heuristics Engine]       [Isolation Forest]                  │   │
│   │  Deterministic CERT Rules  Domain Outlier Scoring (0-100)      │   │
│   │             │                             │                    │   │
│   │             ▼                             ▼                    │   │
│   │  [XGBoost Classifier]      [RedRVFL Sequence Modeler]          │   │
│   │  Scenario Attribution      Temporal Behavioral Progression     │   │
│   │             │                             │                    │   │
│   │             └──────────────┬──────────────┘                    │   │
│   │                            ▼                                   │   │
│   │             [Composite Risk Aggregator]                        │   │
│   │             Normalized Threat Score (0 - 100) & Severity       │   │
│   └────────────────────────────┬───────────────────────────────────┘   │
│                                │                                       │
│                ┌───────────────┴───────────────┐                       │
│                ▼                               ▼                       │
│   ┌─────────────────────────┐     ┌─────────────────────────┐          │
│   │   Dual-Storage Engine   │     │  Reactive Stream Engine │          │
│   │ • PostgreSQL (Entities, │     │ • Server-Sent Events    │          │
│   │   Baselines, Queues)    │     │ • /api/v1/stream/sse    │          │
│   │ • ClickHouse (Analytics)│     │ • Real-time Threat Push │          │
│   └─────────────────────────┘     └────────────┬────────────┘          │
└────────────────────────────────────────────────┼───────────────────────┘
                                                 │
                                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   SOC Analyst Dashboard (React 19)                     │
│    • Fleet KPIs  • Temporal Risk Graphs  • High-FPS Virtualized Logs   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 The 4-Tier Hybrid Detection Pipeline

When encrypted telemetry is ingested, it is evaluated across four distinct analytical layers:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. Deterministic Heuristics Engine                                                          │
│    • Flags non-negotiable threat indicators (Honeytoken trips, after-hours logon spikes,     │
│      multi-PC lateral movement, abnormal mass file access, and USB exfiltration).            │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. Unsupervised Anomaly Detector (Isolation Forest)                                         │
│    • Isolates statistical outliers without requiring prior attack labels.                    │
│    • Outputs localized domain scores for Logon, File, Device, and HTTP vectors (0–100).      │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. Supervised Scenario Classifier (XGBoost)                                                  │
│    • Maps multi-domain feature vectors into explicit threat scenarios derived from the CERT  │
│      Insider Threat specification (IT Sabotage, IP Theft, Data Exfiltration).               │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ 4. Temporal Sequence Modeler (RedRVFL / RandomLSTM)                                          │
│    • Models behavioral progression over rolling multi-day time windows.                     │
│    • Distinguishes transient isolated spikes from persistent, coordinated exfiltration.      │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

For detailed mathematical formulas and threshold specs, see the [Detection Pipeline Guide](docs/DETECTION_PIPELINE.md).

---

## 🖥️ SOC Analyst Dashboard (Frontend)

The frontend is a dark-themed, high-performance Single-Page Application (SPA) built with **React 19, TypeScript, and Vite**, served directly by the FastAPI backend at `/dashboard/`:

* **Executive Fleet KPI Grid**: Real-time breakdown of online/offline endpoints, active threat counts, and fleet risk severity distributions.
* **Reactive Threat Feed**: Live chronological threat notifications pushed in real time via Server-Sent Events (SSE).
* **Domain Risk Breakdown**: Multi-vector radar and timeline charts dissecting risk across Logon, File, Device, and HTTP channels.
* **Forensic Drill-Down Drawer**: Deep-dive investigation view displaying user session history, baseline deviations, and decay indicators.
* **Virtualized High-FPS Log Viewport**: Capable of scrolling through 100,000+ raw events at 60 FPS.
* **Interactive API Documentation**: Embedded Swagger UI at `/docs` and ReDoc at `/redoc`.

For frontend architecture and custom UI plugin development, see [frontend/README.md](frontend/README.md).

---

## 🔌 Extensibility & Plugin Architecture

InsiEDR features dynamic plugin systems for both the backend and frontend:

### Backend Threat Detector Plugins (`server/detectors/`)
Subclass `Detector` to add custom analytical rules or external intelligence feeds:
```python
from server.detectors.base import Detector
from server.detectors.registry import register_detector

@register_detector
class CloudStorageExfiltrationDetector(Detector):
    @property
    def name(self) -> str:
        return "cloud_storage_exfiltration"

    def detect(self, payload_id, agent_id, username, features, baseline, storage=None):
        http_bytes = features.get("http_bytes_uploaded", 0)
        if http_bytes > 500_000_000:  # 500MB
            return self.format_result(
                detector_name=self.name,
                score=85.0,
                is_anomaly=True,
                reason="Mass outbound cloud storage transfer detected."
            )
        return self.format_result(detector_name=self.name, score=0.0, is_anomaly=False)
```

### Frontend UI Plugins (`frontend/src/plugins/`)
Create custom visualizations, analyst playbooks, or SIEM connectors in React using `PluginProps` and `registerPlugin()`.

---

## 🚀 Deployment Guide

### Option A: Docker Compose

The repository provides a turnkey multi-container deployment including PostgreSQL 16, Redis 7, ClickHouse 24.3, one FastAPI backend container with two Uvicorn workers, and an Nginx reverse proxy:

```bash
# 1. Clone the repository
git clone https://github.com/soms36-DefSec/InsiEDR_Server.git
cd InsiEDR_Server

# 2. Configure environment settings
cp .env.example .env

# 3. Launch the full cluster
docker compose up -d --build

# 4. Check cluster health
docker compose ps
```

The services will be accessible at:
* **Analyst Dashboard**: `http://localhost/dashboard/`
* **API Documentation**: `http://localhost/docs`
* **Telemetry Ingestion**: `http://localhost/api/logs`

---

### Option B: Local Bare-Metal Setup (Conda / venv)

#### 1. Python Environment Setup
```bash
# Using Conda
conda create -n insiedr python=3.11 -y
conda activate insiedr

# OR using standard venv
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# Install core dependencies
pip install -r requirements.txt
pip install psycopg2-binary gunicorn
```

#### 2. PostgreSQL Database Setup
```sql
CREATE USER insiedr WITH PASSWORD 'insiedr_pass';
CREATE DATABASE insiedr_db OWNER insiedr;
```

#### 3. Frontend Build (Optional if modifying UI)
```bash
cd frontend
npm install
npm run build
cd ..
```

#### 4. Configure Environment Variables
```bash
export INSIEDR_DATABASE_DSN="postgresql://insiedr:insiedr_pass@localhost:5432/insiedr_db"
export INSIEDR_SECRET_KEY="generate-a-secure-random-string"
export INSIEDR_AES_KEY="YOUR_BASE64_ENCODED_32_BYTE_AES_KEY"
export PYTHONPATH="."
```

#### 5. Launch the Server
Database schema migrations run automatically on the first boot:
```bash
uvicorn server.app:app --host 0.0.0.0 --port 5000 --workers 4
```

---

## ⚙️ Configuration Reference

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `INSIEDR_DATABASE_DSN` | *(Required)* | PostgreSQL connection string (`postgresql://user:pass@host:5432/db`). |
| `INSIEDR_AES_KEY` | *(Required)* | 32-byte key for decrypting agent telemetry payloads. |
| `INSIEDR_SECRET_KEY` | *(Required)* | Secret key used for signing session tokens and internal payloads. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis instance for pub/sub event caching and session management. |
| `CLICKHOUSE_ENABLED` | `false` | Enable high-throughput columnar storage for raw event telemetry. |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse host address. |
| `ENABLE_MODEL_PIPELINE` | `true` | Enable ML model inference (Isolation Forest, XGBoost, RedRVFL). |
| `PORT` | `5000` | Port for the ASGI server. |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## 📡 REST & Streaming API Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/logs` | Ingests encrypted telemetry envelopes from remote agents. |
| `GET` | `/api/v1/stream/sse` | Real-time Server-Sent Events stream for SOC dashboard. |
| `GET` | `/api/threats` | Paginated query endpoint for filtered threat events. |
| `GET` | `/api/anomalies` | Query detected statistical baseline anomalies. |
| `GET` | `/api/agents` | Status and health tracking of registered endpoints. |
| `GET` | `/api/baseline` | Statistical user baseline profiles. |
| `GET` | `/api/export/logs` | Streaming export of telemetry in CSV or NDJSON format. |
| `GET` | `/api/health` | Comprehensive health check across database, ML, and cache. |
| `GET` | `/docs` | Interactive Swagger UI API documentation. |

For complete request/response schemas, see the [API Specification](docs/API_SPECIFICATION.md).

---

## 🧪 Testing

Execute test suites for detection plugins, cryptographic adapters, storage layers, and FastAPI routes:
```bash
pytest tests/ -v
```

---

## 📚 Technical Documentation

* [System Architecture & Data Flow](docs/ARCHITECTURE.md)
* [API Specification & Protocols](docs/API_SPECIFICATION.md)
* [Detection Pipeline & Scoring Mathematics](docs/DETECTION_PIPELINE.md)
* [Frontend Developer & Plugin Guide](frontend/README.md)
* [Deterministic Heuristics Engine](heuristics/README_heuristics.md)

---

## 🔗 Related Repositories

* **[InsiEDR Windows Agent](https://github.com/soms36-DefSec/InsiEDR_agent)** — The endpoint telemetry sensor, collector plugins, and client-side encryption framework.
