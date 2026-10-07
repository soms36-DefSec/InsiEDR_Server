"""
server/api/errors.py
--------------------
Centralized exception handling and RFC 7807-compliant error formatters for FastAPI.
Ensures zero HTML error leakages on API calls.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from server.api.responses import api_error
from psycopg2.pool import PoolError
from psycopg2.errors import QueryCanceled, LockNotAvailable

logger = logging.getLogger("insiedr.api.errors")


class APIException(Exception):
    """Base exception for all domain-level API errors."""
    status_code: int = 400
    code: str = "API_ERROR"

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        code: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code
        self.details = details


class NotFoundError(APIException):
    status_code = 404
    code = "NOT_FOUND"


class ValidationError(APIException):
    status_code = 422
    code = "VALIDATION_ERROR"


class AuthenticationError(APIException):
    status_code = 401
    code = "UNAUTHORIZED"


class ForbiddenError(APIException):
    status_code = 403
    code = "FORBIDDEN"


class ServiceUnavailableError(APIException):
    status_code = 503
    code = "SERVICE_UNAVAILABLE"


def register_error_handlers(app: Any) -> None:
    """Register uniform JSON error handlers on the FastAPI application."""

    @app.exception_handler(PoolError)
    @app.exception_handler(QueryCanceled)
    @app.exception_handler(LockNotAvailable)
    async def handle_database_capacity(request: Request, exc: Exception):
        response = api_error(code="DATABASE_BUSY", message="Database busy; retry shortly", status_code=503)
        response.headers["Retry-After"] = "2"
        return response

    @app.exception_handler(APIException)
    async def handle_api_exception(request: Request, exc: APIException):
        return api_error(
            code=exc.code,
            message=exc.message,
            details=exc.details,
            status_code=exc.status_code,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException):
        code_name = f"HTTP_{exc.status_code}"
        if exc.status_code == 404:
            code_name = "NOT_FOUND"
        elif exc.status_code == 400:
            code_name = "BAD_REQUEST"
        elif exc.status_code == 403:
            code_name = "FORBIDDEN"
        elif exc.status_code == 401:
            code_name = "UNAUTHORIZED"
        return api_error(
            code=code_name,
            message=str(exc.detail) if hasattr(exc, "detail") else str(exc),
            details=None,
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_exception(request: Request, exc: RequestValidationError):
        return api_error(
            code="VALIDATION_ERROR",
            message="Request validation failed",
            details=exc.errors(),
            status_code=422,
        )

    @app.exception_handler(Exception)
    async def handle_unhandled_exception(request: Request, exc: Exception):
        incident_id = uuid.uuid4().hex[:12]
        path_str = getattr(request.url, "path", "unknown") if hasattr(request, "url") else "unknown"
        logger.error(f"[Incident {incident_id}] Unhandled server exception on {path_str}: {exc}", exc_info=True)
        return api_error(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected server error occurred. Reference incident ID.",
            details={"incident_id": incident_id},
            status_code=500,
        )

