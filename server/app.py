"""
server/app.py
-------------
Main Application Factory & ASGI Lifespan Manager for InsiEDR Server.

Architecture & Responsibilities:
- ASGI Lifespan:
  * Startup: initializes plugin registry, detector/feature registries, PostgreSQL storage,
    automatic schema migrations, worker thread pools (8x ML workers), and durable background task workers.
  * Shutdown: cleanly terminates background task queue workers and drains thread pools.
- Middleware Order:
  * CORS (permissive cross-origin headers for frontend SPA)
  * RFC 7807 Error Handlers (centralized JSON error formatting)
- Routing:
  * Ingestion: /api/logs (AES-256-GCM encrypted agent telemetry)
  * Real-Time Streaming: /api/stream/threats, /api/stream/agents (SSE)
  * Threat Intelligence: /api/anomalies, /api/threats, /api/risk-events, /api/baseline
  * Export: /api/export/logs, /api/export/threats (chunked streaming CSV / NDJSON)
  * Dashboard: /dashboard/ (React + Vite single-page application)
"""
from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

def load_env():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    parts = line.strip().split("=", 1)
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip()
                        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                            val = val[1:-1]
                        if key not in os.environ:
                            os.environ[key] = val

load_env()

from server.config import config
from server.api.agents import router as agents_bp
from server.api.health import router as health_bp
from server.api.logs import router as logs_bp
from server.api.stats import router as stats_bp
from server.api.events import router as events_bp
from server.api.export import router as export_bp
from server.api.docs import router as docs_bp
from server.api.keys import router as keys_bp
from server.api.errors import register_error_handlers
from server.plugin_registry import registry
from server.storage.postgres_storage import PostgresStorage
from server.storage.clickhouse_storage import ClickHouseStorage
from server.storage.hybrid_storage import HybridStorage
from server.dashboard import router as dashboard_bp


class DummyAppContext:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def create_app(*, storage=None, apply_migrations: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup phase
        registry.initialize()
        from server.api.events import broadcaster
        broadcaster.start()
        nonlocal storage
        if storage is None and config.database_dsn:
            try:
                pg_storage = PostgresStorage(config.database_dsn)
                ch_storage = None
                if config.clickhouse_enabled:
                    try:
                        ch_storage = ClickHouseStorage(
                            host=config.clickhouse_host,
                            port=config.clickhouse_port,
                            username=config.clickhouse_user,
                            password=config.clickhouse_password,
                            database=config.clickhouse_db,
                            secure=config.clickhouse_secure,
                            ca_cert=config.clickhouse_ca_cert,
                            query_timeout=config.clickhouse_query_timeout,
                            max_memory_usage=config.clickhouse_max_memory,
                            dlq_enabled=config.dlq_enabled,
                            dlq_dir=config.dlq_dir,
                            batch_size=config.ch_batch_max_rows,
                            flush_interval=config.ch_batch_flush_interval,
                            max_buffer_bytes=config.ch_batch_max_bytes,
                        )
                    except Exception as ch_err:
                        logging.getLogger("insiedr.app").warning("ClickHouse storage init failed, operating with PG fallback: %s", ch_err)
                storage = HybridStorage(postgres_storage=pg_storage, clickhouse_storage=ch_storage,
                                        telemetry_read_backend=config.telemetry_read_backend)
            except Exception as e:
                logging.getLogger("insiedr.app").warning("Failed to initialize database storage: %s", e)

        if storage is not None:
            app.state.storage = storage
            app.extensions["insiedr_storage"] = storage
            ensure_migrations = getattr(storage, "ensure_migrations", None)
            if apply_migrations and callable(ensure_migrations):
                try:
                    ensure_migrations()
                except Exception as e:
                    logging.getLogger("insiedr.app").warning("Migration warning: %s", e)


        # Task queue worker
        if storage is not None:
            try:
                from server.task_queue import start_worker
                worker = start_worker(storage, app)
                app.state.task_queue_worker = worker
                app.extensions["task_queue_worker"] = worker
                from server.utils.webhook import set_task_queue
                set_task_queue(getattr(app.state, "task_queue", None))
            except Exception as exc:
                logging.getLogger("insiedr.app").warning(
                    "Could not start TaskWorker (falling back to in-memory executor): %s", exc
                )

        # Replication Reconciler worker (PostgreSQL Outbox -> ClickHouse)
        if storage is not None and getattr(storage, "ch", None) is not None:
            try:
                from server.storage.reconciler import ReplicationReconciler
                reconciler = ReplicationReconciler(
                    postgres_storage=getattr(storage, "pg", storage),
                    clickhouse_storage=getattr(storage, "ch", None),
                    poll_interval=1.0,
                    batch_size=100,
                )
                reconciler.start()
                app.state.reconciler = reconciler
                app.extensions["reconciler"] = reconciler
                logging.getLogger("insiedr.app").info("ReplicationReconciler worker started successfully")
            except Exception as exc:
                logging.getLogger("insiedr.app").warning("Could not start ReplicationReconciler: %s", exc)

        yield

        # Shutdown phase
        app.state.shutting_down = True
        if hasattr(app.state, "reconciler") and app.state.reconciler:
            try:
                app.state.reconciler.stop(timeout=5.0)
            except Exception as exc:
                logging.getLogger("insiedr.app").warning("ReplicationReconciler stop notice: %s", exc)

        if hasattr(app.state, "task_queue_worker") and app.state.task_queue_worker:
            try:
                app.state.task_queue_worker.stop(timeout=5.0)
            except Exception as exc:
                logging.getLogger("insiedr.app").warning("TaskWorker stop notice: %s", exc)

        try:
            from server.api.events import broadcaster
            broadcaster.stop()
        except Exception:
            pass

        if hasattr(app.state, "storage") and app.state.storage and hasattr(app.state.storage, "close"):
            try:
                app.state.storage.close()
            except Exception as exc:
                logging.getLogger("insiedr.app").warning("Storage close notice: %s", exc)

    app = FastAPI(
        title="InsiEDR Telemetry & Dataset Collection Server",
        description="REST API for endpoint telemetry ingestion, persistent storage, and training dataset export.",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Attach storage eagerly if provided (e.g. mock in tests)
    app.state.storage = storage
    app.state.task_queue = None
    app.state.ml_executor = None

    # Backward compatibility shims for legacy scripts
    app.app_context = lambda: DummyAppContext()
    app.extensions = {
        "insiedr_storage": storage,
        "task_queue": None,
        "ml_executor": None,
    }

    # Cross-Origin Resource Sharing (CORS) support
    cors_origins = config.cors_origins
    allow_creds = cors_origins != ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=allow_creds,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register centralized RFC 7807 JSON error handlers
    register_error_handlers(app)

    # Register API routers (REST, SSE, Export, Docs, Dashboard)
    app.include_router(agents_bp)
    app.include_router(logs_bp)
    app.include_router(health_bp)
    app.include_router(stats_bp)
    app.include_router(events_bp)
    app.include_router(export_bp)
    app.include_router(docs_bp)
    app.include_router(keys_bp)
    app.include_router(dashboard_bp)

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/dashboard/")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=5000, reload=True)

