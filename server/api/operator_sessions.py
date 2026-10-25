"""Short lived, HttpOnly browser sessions for operator dashboard access."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from server.config import config

COOKIE_NAME = "insiedr_operator_session"
SESSION_SECONDS = 8 * 60 * 60


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _signing_key() -> bytes:
    credentials = sorted(config.operator_roles)
    material = "\0".join(credentials).encode("utf-8")
    return hashlib.sha256(b"insiedr-operator-session-v1\0" + material).digest()


def issue_session(token: str, *, now: int | None = None) -> tuple[str, int]:
    expires_at = (int(time.time()) if now is None else now) + SESSION_SECONDS
    payload = _b64(json.dumps({
        "sub": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "exp": expires_at,
    }, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.new(_signing_key(), payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}", expires_at


def resolve_session(value: str | None, *, now: int | None = None) -> tuple[str, int] | None:
    if not value or "." not in value:
        return None
    payload, supplied_signature = value.rsplit(".", 1)
    expected_signature = _b64(hmac.new(_signing_key(), payload.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(supplied_signature, expected_signature):
        return None
    try:
        claims: dict[str, Any] = json.loads(_unb64(payload))
        fingerprint = claims["sub"]
        expires_at = int(claims["exp"])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None
    if expires_at <= (int(time.time()) if now is None else now):
        return None
    for token in config.operator_roles:
        if hmac.compare_digest(hashlib.sha256(token.encode("utf-8")).hexdigest(), str(fingerprint)):
            return token, expires_at
    return None
