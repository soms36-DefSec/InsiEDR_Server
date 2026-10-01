from __future__ import annotations

import hashlib
import json
import inspect
from datetime import datetime, timezone, timedelta
from typing import Any

from shared.protocol import (
    HEADER_CRYPTO_SCHEME,
    HEADER_PROTOCOL_VERSION,
    HEADER_AGENT_ID,
    HEADER_PAYLOAD_ID,
    HEADER_KEY_ID,
    INGEST_CONTENT_TYPE,
    PROTOCOL_VERSION,
    TELEMETRY_SCHEMA,
    CRYPTO_SCHEME_AESGCM,
    CRYPTO_SCHEME_FERNET,
    CRYPTO_SCHEME_HPKE,
    parse_json_bytes,
    validate_telemetry_payload,
)

from server.config import config
from server.plugin_registry import registry


class IngestError(Exception):
    status_code = 400

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code


class ValidationError(IngestError):
    status_code = 422


class StorageUnavailableError(IngestError):
    status_code = 503


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hash_text(value: str | None) -> str | None:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value is not None else None


def _parse_iso(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise IngestError(f"missing or invalid timestamp: {field_name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IngestError(f"invalid timestamp: {field_name}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_age(value: Any, field_name: str) -> None:
    parsed = _parse_iso(value, field_name)
    now = datetime.now(timezone.utc)
    window = timedelta(hours=config.replay_window_hours)
    if parsed < now - window:
        raise IngestError(f"{field_name} is outside replay window")
    if parsed > now + timedelta(minutes=5):
        raise IngestError(f"{field_name} is in the future")


def validate_envelope_shape(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise IngestError("request body must be a JSON object")
    required = ["protocol_version", "scheme", "payload_id", "created_at"]
    for k in required:
        if k not in body:
            raise IngestError(f"missing envelope field: {k}")
    scheme = body.get("scheme")
    if scheme == CRYPTO_SCHEME_AESGCM:
        for k in ("key_id", "nonce", "ciphertext"):
            if not body.get(k):
                raise IngestError(f"missing envelope field: {k}")
    elif scheme == CRYPTO_SCHEME_HPKE:
        for k in ("key_id", "encapped_key", "nonce", "ciphertext"):
            if not body.get(k):
                raise IngestError(f"missing envelope field: {k}")
    elif scheme == CRYPTO_SCHEME_FERNET:
        if not body.get("token"):
            raise IngestError("missing envelope field: token")
    elif scheme == "plaintext":
        if not (body.get("ciphertext") or body.get("payload")):
            raise IngestError("missing envelope field: ciphertext")
    return body


def validate_collector_results(payload: dict[str, Any]) -> None:
    collectors = payload.get("collectors")
    if not isinstance(collectors, list):
        raise ValidationError("collectors must be a list")
    success_count = 0
    failed_count = 0
    for index, collector in enumerate(collectors):
        if not isinstance(collector, dict):
            raise ValidationError(f"collector[{index}] must be an object")
        for field in ("collector", "collected_at", "hostname", "status"):
            if not isinstance(collector.get(field), str) or not collector.get(field):
                raise ValidationError(f"collector[{index}].{field} is missing or invalid")
        status = collector.get("status")
        if status not in ("success", "failed", "critical", "unsupported"):
            raise ValidationError(f"collector[{index}].status is invalid")
        if status == "success":
            success_count += 1
            if "payload" not in collector:
                raise ValidationError(f"collector[{index}].payload is required for success")
        elif status == "failed":
            failed_count += 1
            error = collector.get("error")
            if not isinstance(error, dict):
                raise ValidationError(f"collector[{index}].error is required for failure")
        elif status == "critical":
            failed_count += 1  # count as failure for summary
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise ValidationError("summary is required")
    expected = {
        "collector_count": len(collectors),
        "success_count": success_count,
        "failed_count": failed_count,
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            raise ValidationError(f"summary.{key} mismatch")


def _check_duplicate_policy(storage, envelope: dict[str, Any], payload: dict[str, Any]) -> bool:
    get_payload = getattr(storage, "get_payload", None)
    if not callable(get_payload):
        return False
    existing = get_payload(str(payload.get("payload_id")))
    if not existing:
        return False
    existing_envelope = existing.get("encrypted_envelope_json") or {}
    if isinstance(existing_envelope, str):
        try:
            existing_envelope = json.loads(existing_envelope)
        except json.JSONDecodeError:
            existing_envelope = {}
    # The persisted plaintext hash may describe the privacy-scrubbed payload.
    # An exact, already authenticated encrypted envelope is the original retry;
    # it must not be rejected because storage redacted a credential.
    if existing_envelope and _hash_json(existing_envelope) == _hash_json(envelope):
        return True
    existing_cipher_hash = existing.get("ciphertext_hash") or _hash_text(existing_envelope.get("ciphertext"))
    existing_decrypted_hash = existing.get("decrypted_payload_hash")
    new_cipher_hash = _hash_text(envelope.get("ciphertext"))
    new_decrypted_hash = _hash_json(payload)
    if existing_cipher_hash and existing_cipher_hash != new_cipher_hash:
        raise IngestError("duplicate payload_id with different ciphertext")
    if existing_decrypted_hash and existing_decrypted_hash != new_decrypted_hash:
        raise IngestError("duplicate payload_id with different decrypted payload")
    return True


async def process_encrypted_request(req) -> tuple[int, dict[str, Any]]:
    # 1. Transport Security (HTTPS) Enforcement
    is_secure = getattr(req, "is_secure", False)
    if not is_secure and hasattr(req, "url"):
        is_secure = (req.url.scheme == "https")
    if config.require_https and not is_secure:
        raise IngestError("HTTPS is required for telemetry ingestion", status_code=403)

    # 2. Bearer Token / Auth Validation
    expected_token = config.agent_bearer_token
    if expected_token:
        import hmac
        auth_header = req.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise IngestError("invalid or missing Bearer token", status_code=403)
        provided_token = auth_header.split(" ", 1)[1]
        if not hmac.compare_digest(provided_token.encode("utf-8"), expected_token.encode("utf-8")):
            raise IngestError("invalid or missing Bearer token", status_code=403)

    # Basic header validation
    content_type = getattr(req, "content_type", req.headers.get("content-type", ""))
    if not (content_type or "").startswith(INGEST_CONTENT_TYPE):
        raise IngestError("invalid content type")
    headers = req.headers
    scheme = headers.get(HEADER_CRYPTO_SCHEME)
    proto = headers.get(HEADER_PROTOCOL_VERSION)
    agent_id = headers.get(HEADER_AGENT_ID)
    payload_id = headers.get(HEADER_PAYLOAD_ID)
    if not scheme or not proto or not agent_id or not payload_id:
        raise IngestError("missing required headers")
    if proto != PROTOCOL_VERSION:
        raise IngestError("protocol version mismatch")

    try:
        if hasattr(req, "json") and callable(req.json):
            if inspect.iscoroutinefunction(req.json):
                body = await req.json()
            else:
                body = req.json()
        elif hasattr(req, "get_json") and callable(req.get_json):
            body = req.get_json(force=True)
        elif hasattr(req, "body") and callable(req.body):
            raw_bytes = await req.body()
            body = json.loads(raw_bytes.decode("utf-8"))
        else:
            raise IngestError("unable to parse request JSON body")
    except Exception as exc:
        raise IngestError("invalid JSON body") from exc

    envelope = validate_envelope_shape(body)
    _validate_age(envelope.get("created_at"), "envelope.created_at")

    # header/envelope consistency
    if envelope.get("scheme") != scheme:
        raise IngestError("scheme header mismatch")
    if envelope.get("protocol_version") != proto:
        raise IngestError("envelope protocol mismatch")
    if envelope.get("payload_id") != payload_id:
        raise IngestError("payload_id mismatch")
    if scheme in (CRYPTO_SCHEME_AESGCM, CRYPTO_SCHEME_HPKE):
        key_id = headers.get(HEADER_KEY_ID)
        if not key_id:
            raise IngestError("missing required header: X-KEY-ID")
        if envelope.get("key_id") != key_id:
            raise IngestError("key_id mismatch")

    # select crypto plugin
    plugin = registry.get(scheme)
    if not plugin:
        raise IngestError("unsupported crypto scheme")

    # attempt decrypt
    try:
        plaintext_bytes = plugin.decrypt(envelope)
    except Exception as exc:
        raise IngestError("decryption failed") from exc

    try:
        payload = parse_json_bytes(plaintext_bytes)
    except Exception as exc:
        raise IngestError("decrypted payload JSON invalid") from exc

    # validate decrypted telemetry
    try:
        validate_telemetry_payload(payload)
        validate_collector_results(payload)
    except IngestError:
        raise
    except Exception as exc:
        raise ValidationError(f"telemetry validation failed: {exc}") from exc

    # additional consistency checks
    if payload.get("payload_id") != payload_id:
        raise IngestError("decrypted payload_id mismatch")
    if payload.get("agent_id") != agent_id:
        raise IngestError("decrypted agent_id mismatch")
    if payload.get("schema") != TELEMETRY_SCHEMA:
        raise ValidationError("telemetry schema mismatch")
    _validate_age(payload.get("collected_at"), "payload.collected_at")

    # Resolve storage and task queue from app.state (FastAPI) or app.extensions (legacy)
    app = getattr(req, "app", None)
    storage = getattr(app.state, "storage", None) if app and hasattr(app, "state") else None
    task_queue = getattr(app.state, "task_queue", None) if app and hasattr(app, "state") else None
    ml_executor = getattr(app.state, "ml_executor", None) if app and hasattr(app, "state") else None

    if storage is None and app and hasattr(app, "extensions"):
        storage = app.extensions.get("insiedr_storage")
        task_queue = app.extensions.get("task_queue")
        ml_executor = app.extensions.get("ml_executor")

    if storage is None:
        raise StorageUnavailableError("storage is not configured")

    try:
        if _check_duplicate_policy(storage, envelope, payload):
            return 202, {"ok": True, "payload_id": payload_id, "status": "accepted"}
        storage.store_raw_payload(envelope, payload)

        # Dispatch real-time agent status update to SSE stream
        try:
            from server.api.events import dispatch_agent_event
            dispatch_agent_event({
                "agent_id": payload.get("agent_id"),
                "hostname": payload.get("hostname"),
                "username": payload.get("username"),
                "status": "active",
                "collected_at": payload.get("collected_at"),
            })
        except Exception:
            pass


    except Exception as exc:
        import traceback
        traceback.print_exc()
        if isinstance(exc, IngestError):
            raise
        raise StorageUnavailableError("storage persistence failed") from exc

    return 202, {"ok": True, "payload_id": payload_id, "status": "accepted"}
