from __future__ import annotations

from typing import Mapping

from shared.protocol import PROTOCOL_VERSION


class PlaintextPlugin:
    scheme = "plaintext"

    def validate_envelope(self, envelope: Mapping[str, object]) -> None:
        """Validate required fields for plaintext envelope."""
        if not (envelope.get("ciphertext") or envelope.get("payload")):
            raise ValueError("missing envelope field: ciphertext")

    def decrypt(self, envelope: Mapping[str, object]) -> bytes:
        # For testing only: assume envelope['ciphertext'] is actually plaintext bytes encoded as utf-8
        try:
            if envelope.get("protocol_version") != PROTOCOL_VERSION:
                raise ValueError("protocol version mismatch")
            payload = envelope.get("ciphertext") or envelope.get("payload")
            if isinstance(payload, str):
                return payload.encode("utf-8")
            raise ValueError("plaintext plugin expects string payload")
        except KeyError as exc:
            raise ValueError("missing field") from exc
