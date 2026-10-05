"""
server/storage/interceptors.py
------------------------------
Pluggable Telemetry Interceptor Pipeline for InsiEDR.

Architecture & Team Guide:
==========================
This module provides a modular interceptor pipeline that runs on decrypted
telemetry payloads BEFORE they are committed to persistent storage.

Team members can plug in custom enrichers, data sanitizers, PII scrubbers,
or threat intelligence tags without altering core database ingestion logic.

Security & Privacy Hardening:
-----------------------------
Includes multi-layered credential and PII scrubbing:
  1. Key-name sanitization: Redacts values under sensitive dictionary keys.
  2. In-string value sanitization: Regex scanning for credentials embedded
     in command-lines, URLs, Bearer tokens, private keys, and cloud API keys.
"""
from __future__ import annotations

import dataclasses
import logging
import re
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("insiedr.storage.interceptors")


@dataclasses.dataclass
class TelemetryContext:
    """Encapsulates the telemetry payload and envelope in transit."""
    envelope: Dict[str, Any]
    decrypted_payload: Dict[str, Any]
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    is_dropped: bool = False
    drop_reason: Optional[str] = None


TelemetryInterceptorFn = Callable[[TelemetryContext], TelemetryContext]


class InterceptorPipeline:
    """Manages ordered execution of telemetry interceptors."""

    def __init__(self) -> None:
        self._interceptors: List[tuple[int, str, TelemetryInterceptorFn, bool]] = []

    def register(
        self,
        fn: TelemetryInterceptorFn,
        name: str | None = None,
        order: int = 50,
        required: bool = False,
    ) -> TelemetryInterceptorFn:
        """Register an interceptor with execution priority and required failure policy."""
        interceptor_name = name or getattr(fn, "__name__", str(fn))
        self._interceptors.append((order, interceptor_name, fn, required))
        self._interceptors.sort(key=lambda item: item[0])
        logger.debug("Registered telemetry interceptor: '%s' (order=%d, required=%s)",
                     interceptor_name, order, required)
        return fn

    def process(self, envelope: Dict[str, Any], decrypted_payload: Dict[str, Any]) -> TelemetryContext:
        """Execute all registered interceptors sequentially with fail-closed policy for required filters."""
        ctx = TelemetryContext(envelope=envelope, decrypted_payload=decrypted_payload)
        for order, name, fn, required in self._interceptors:
            if ctx.is_dropped:
                logger.info("Telemetry payload '%s' was dropped by interceptor '%s': %s",
                            decrypted_payload.get("payload_id"), name, ctx.drop_reason)
                break
            try:
                ctx = fn(ctx)
            except Exception as exc:
                logger.error("Error executing telemetry interceptor '%s': %s", name, exc, exc_info=True)
                if required:
                    # Required security interceptor must fail closed to prevent unsanitized persistence
                    ctx.is_dropped = True
                    ctx.drop_reason = f"Required security interceptor '{name}' failed: {exc}"
                    raise RuntimeError(f"Required telemetry interceptor '{name}' failed: {exc}") from exc
        return ctx


# Global interceptor pipeline singleton
interceptor_pipeline = InterceptorPipeline()


def register_telemetry_interceptor(order: int = 50, name: str | None = None, required: bool = False):
    """Decorator to register a custom telemetry interceptor."""
    def decorator(fn: TelemetryInterceptorFn) -> TelemetryInterceptorFn:
        return interceptor_pipeline.register(fn, name=name, order=order, required=required)
    return decorator


# ==============================================================================
# Built-In Security & Privacy Interceptors
# ==============================================================================

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api_?key|auth_token|access_token|private_key|client_secret)",
    re.IGNORECASE,
)

# In-string regex patterns to scrub credentials from command lines, URLs, and text fields
_URL_CREDENTIAL_PATTERN = re.compile(r"://([^:\s]+):([^@\s]+)@")
_USER_PASS_FLAG_PATTERN = re.compile(r"(?i)(-u\s+|--user\s+)([^:\s]+):([^\s&\"']+)")
_CLI_PASSWORD_PATTERN = re.compile(
    r"(?i)(--?(?:password|token|secret|key|api[_-]?key|passwd)[=\s]+)([^\s&\"']+)"
)
_BEARER_TOKEN_PATTERN = re.compile(
    r"(?i)(bearer\s+)([A-Za-z0-9_\-\.]{15,})"
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN[ A-Z0-9_-]+KEY-----[\s\S]*?-----END[ A-Z0-9_-]+KEY-----"
)
_AWS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")


def sanitize_string_value(text: str) -> str:
    """Scan and scrub sensitive credentials embedded in free-form text strings."""
    if not isinstance(text, str) or len(text) < 4:
        return text

    # Redact URL credentials: http://user:pass@host -> http://user:[REDACTED]@host
    text = _URL_CREDENTIAL_PATTERN.sub(r"://\1:[REDACTED]@", text)

    # Redact curl/cli user credentials: -u user:password -> -u user:[REDACTED]
    text = _USER_PASS_FLAG_PATTERN.sub(r"\1\2:[REDACTED]", text)

    # Redact CLI flags: --password=secret123 -> --password=[REDACTED]
    text = _CLI_PASSWORD_PATTERN.sub(r"\1[REDACTED]", text)

    # Redact Authorization: Bearer <token>
    text = _BEARER_TOKEN_PATTERN.sub(r"\1[REDACTED]", text)

    # Redact Embedded Private Keys
    text = _PRIVATE_KEY_PATTERN.sub(r"[REDACTED_PRIVATE_KEY]", text)

    # Redact AWS Access Key IDs
    text = _AWS_KEY_PATTERN.sub(r"[REDACTED_AKIA_KEY]", text)

    return text


@register_telemetry_interceptor(order=10, name="pii_and_secret_scrubber", required=True)
def pii_and_secret_scrubber(ctx: TelemetryContext) -> TelemetryContext:
    """
    Enterprise Security Interceptor:
    Redacts accidental credentials, passwords, tokens, and secrets from both
    dictionary keys AND embedded string values (e.g. process command-lines, URLs)
    before persistent storage in ClickHouse or PostgreSQL.
    """
    def _scrub_object(obj: Any) -> Any:
        if isinstance(obj, dict):
            scrubbed = {}
            for k, v in obj.items():
                if _SENSITIVE_KEY_PATTERN.search(str(k)):
                    scrubbed[k] = "[REDACTED]"
                else:
                    scrubbed[k] = _scrub_object(v)
            return scrubbed
        elif isinstance(obj, list):
            return [_scrub_object(item) for item in obj]
        elif isinstance(obj, str):
            return sanitize_string_value(obj)
        return obj

    collectors = ctx.decrypted_payload.get("collectors")
    if isinstance(collectors, list):
        for col in collectors:
            if isinstance(col, dict) and "payload" in col:
                col["payload"] = _scrub_object(col["payload"])

    return ctx
