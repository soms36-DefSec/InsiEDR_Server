from __future__ import annotations

from typing import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.crypto_utils import b64decode, normalize_aes_key
from shared.protocol import CRYPTO_SCHEME_AESGCM


AES_GCM_AAD = b"insiedr.agent.telemetry.v2"


class AESGCMPluginError(ValueError):
    pass


class AESGCMPlugin:
    scheme = CRYPTO_SCHEME_AESGCM

    def __init__(self, key: bytes | str) -> None:
        self.key = normalize_aes_key(key)
        self._aesgcm = AESGCM(self.key)

    def validate_envelope(self, envelope: Mapping[str, object]) -> None:
        """Validate required cipher-specific fields for AES-256-GCM."""
        for field in ("key_id", "nonce", "ciphertext"):
            if not envelope.get(field):
                raise AESGCMPluginError(f"missing envelope field: {field}")

    def decrypt(self, envelope: Mapping[str, object]) -> bytes:
        if envelope.get("scheme") != self.scheme:
            raise AESGCMPluginError("wrong scheme")
        try:
            nonce = b64decode(str(envelope["nonce"]))
            ciphertext = b64decode(str(envelope["ciphertext"]))
            return self._aesgcm.decrypt(nonce, ciphertext, AES_GCM_AAD)
        except KeyError as exc:
            raise AESGCMPluginError(f"missing field: {exc}") from exc
        except Exception as exc:
            raise AESGCMPluginError("decryption failed") from exc
