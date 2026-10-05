"""
server/api/responses.py
-----------------------
Standardized JSON response envelopes for InsiEDR FastAPI.
Ensures uniform response structures while preserving legacy 'ok': True/False keys
for existing frontend and telemetry clients.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping
from fastapi.responses import JSONResponse


def api_success(
    data: Any = None,
    meta: Mapping[str, Any] | None = None,
    status_code: int = 200,
    **legacy_kwargs: Any,
) -> JSONResponse:
    """
    Produce a consistent success response:
    {
        "ok": true,
        "success": true,
        "data": <data>,
        "meta": <meta>,
        "timestamp": "<iso8601>",
        ...<legacy_kwargs>
    }
    """
    payload: dict[str, Any] = {
        "ok": True,
        "success": True,
        "data": data,
        "meta": meta or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Merge any legacy top-level keys (e.g., "agents", "logs", "anomalies") for backward compatibility
    for key, value in legacy_kwargs.items():
        if key not in payload or payload[key] is None:
            payload[key] = value

    return JSONResponse(content=payload, status_code=status_code)


STATUS_TITLES: dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


def api_error(
    code: str,
    message: str,
    details: Any = None,
    status_code: int = 400,
    instance: str | None = None,
    **legacy_kwargs: Any,
) -> JSONResponse:
    """
    Produce an RFC 7807 / RFC 9457 Problem Details compliant error response while
    preserving legacy backward-compatible keys ('ok': False, 'message', etc.):
    {
        "type": "urn:insiedr:error:<code>",
        "title": "<title>",
        "status": <status_code>,
        "detail": "<message>",
        "instance": "<instance>",
        "ok": false,
        "success": false,
        "error": {
            "code": code,
            "message": message,
            "details": details,
        },
        "message": message,
        "timestamp": "<iso8601>"
    }
    """
    import uuid

    title = STATUS_TITLES.get(status_code, "API Error")
    payload: dict[str, Any] = {
        # RFC 7807 / RFC 9457 Problem Details
        "type": f"urn:insiedr:error:{code.lower().replace('_', '-')}",
        "title": title,
        "status": status_code,
        "detail": message,
        "instance": instance or f"urn:uuid:{uuid.uuid4()}",
        # Legacy Compatibility
        "ok": False,
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "details": details,
        },
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # Backward compatibility: if legacy string error explicitly requested
    if "error_str" in legacy_kwargs:
        payload["error_str"] = legacy_kwargs.pop("error_str")

    for key, value in legacy_kwargs.items():
        if key not in payload:
            payload[key] = value

    return JSONResponse(
        content=payload,
        status_code=status_code,
        media_type="application/problem+json",
    )

