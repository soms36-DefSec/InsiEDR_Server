# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 – Frontend build (Node 20 LTS)
# Compiles the React + TypeScript dashboard into server/dashboard/dist/
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /build/frontend

# Install deps first (leverages layer cache when package.json is unchanged)
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --prefer-offline

# Copy the rest of the frontend source
COPY frontend/ ./

# Build into /build/server/dashboard/dist (vite.config.ts outDir)
RUN npm run build

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 – Python dependency build (compilers stay out of the runtime)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.10-slim AS python-builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt requirements-postgres.txt ./
RUN pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt -r requirements-postgres.txt

FROM python:3.10-slim AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app"

# Only runtime libraries; healthchecks use Python's standard library.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files first to leverage Docker cache
COPY requirements.txt requirements-postgres.txt ./

# Copy pre-compiled wheels from builder and install
COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt -r requirements-postgres.txt \
    && rm -rf /wheels

# Copy runtime source without local configuration or development artifacts.
COPY server/ ./server/
COPY shared/ ./shared/
COPY scripts/ ./scripts/

# Add freshly compiled frontend assets; local dist is excluded by .dockerignore.
COPY --from=frontend-builder /build/server/dashboard/dist/ ./server/dashboard/dist/

RUN groupadd --gid 10001 insiedr \
    && useradd --uid 10001 --gid insiedr --no-create-home insiedr \
    && mkdir -p /app/data/dlq \
    && chown -R insiedr:insiedr /app/data
USER 10001:10001

# Expose the port the app runs on
EXPOSE 5000

# Container Healthcheck (allowing sufficient time for DB migrations on cold start)
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health/ready', timeout=8)"

# Run the app with uvicorn ASGI server
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "2", "--timeout-graceful-shutdown", "60"]
