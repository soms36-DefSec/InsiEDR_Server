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
# Stage 2 – Python runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.10-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app"

# Install system dependencies (libpq-dev for postgres, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files first to leverage Docker cache
COPY requirements.txt requirements-postgres.txt ./

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt gunicorn

# Copy the full application source
COPY . .

# Overwrite the dist folder with the freshly compiled frontend assets
# (replaces any stale or missing pre-built files from the COPY above)
COPY --from=frontend-builder /build/server/dashboard/dist/ ./server/dashboard/dist/

# Expose the port the app runs on
EXPOSE 5000

# Container Healthcheck (allowing sufficient time for DB migrations on cold start)
HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the app with uvicorn ASGI server
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4"]
