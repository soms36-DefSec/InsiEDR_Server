FROM python:3.10-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app"

# Install system dependencies (libpq-dev for postgres, libgomp1 for XGBoost/ML OpenMP, curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files first to leverage Docker cache
COPY requirements.txt requirements-postgres.txt ./

# Install python dependencies and gunicorn
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt gunicorn

# Copy the rest of the application
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Container Healthcheck (allowing sufficient time for DB migrations on cold start)
HEALTHCHECK --interval=15s --timeout=10s --start-period=45s --retries=5 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the app with uvicorn ASGI server
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4"]

