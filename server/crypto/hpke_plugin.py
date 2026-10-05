from __future__ import annotations

import logging
from typing import Mapping, Union

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shared.crypto_utils import (
    b64decode,
    load_x25519_private_key,
    load_x25519_public_key,
    derive_hpke_shared_key,
)
from shared.protocol import CRYPTO_SCHEME_HPKE

log = logging.getLogger("insiedr.crypto.hpke")

HPKE_AAD = b"insiedr.hpke.telemetry.v2"


class HPKEPluginError(ValueError):
    """Base exception for HPKE plugin failures."""
    pass


class UnknownKeyIdError(HPKEPluginError):
    """Raised when an incoming envelope references an unknown key ID."""
    pass


class InvalidEncappedKeyError(HPKEPluginError):
    """Raised when the peer's ephemeral public key is malformed or invalid."""
    pass


class HPKEDecryptionError(HPKEPluginError):
    """Raised when authenticated decryption or AEAD tag verification fails."""
    pass


class HPKEPlugin:
    scheme = CRYPTO_SCHEME_HPKE

    def __init__(
        self,
        keys: Union[x25519.X25519PrivateKey, bytes, str, Mapping[str, Union[x25519.X25519PrivateKey, bytes, str]]],
        default_key_id: str = "default",
    ) -> None:
        self._keys: dict[str, x25519.X25519PrivateKey] = {}
        self._public_keys_bytes: dict[str, bytes] = {}
        self._default_key_id = default_key_id

        if isinstance(keys, Mapping):
            for kid, key_mat in keys.items():
                priv = load_x25519_private_key(key_mat)
                self._keys[str(kid)] = priv
                self._public_keys_bytes[str(kid)] = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            priv = load_x25519_private_key(keys)
            self._keys[default_key_id] = priv
            self._public_keys_bytes[default_key_id] = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        if not self._keys:
            raise HPKEPluginError("at least one X25519 private key is required for HPKEPlugin")

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def get_public_key_bytes(self, key_id: str | None = None) -> bytes | None:
        if key_id and key_id in self._public_keys_bytes:
            return self._public_keys_bytes[key_id]
        if len(self._keys) == 1:
            return next(iter(self._public_keys_bytes.values()))
        return self._public_keys_bytes.get(self._default_key_id)

    def validate_envelope(self, envelope: Mapping[str, object]) -> None:
        """Validate required cipher-specific fields for HPKE / Hybrid X25519-AESGCM."""
        for field in ("key_id", "encapped_key", "nonce", "ciphertext"):
            if not envelope.get(field):
                raise HPKEPluginError(f"missing envelope field: {field}")

    def decrypt(self, envelope: Mapping[str, object]) -> bytes:
        if envelope.get("scheme") != self.scheme:
            raise HPKEPluginError(f"wrong scheme: expected '{self.scheme}', got '{envelope.get('scheme')}'")

        try:
            key_id = str(envelope.get("key_id", ""))
            encapped_key_b64 = str(envelope["encapped_key"])
            nonce_b64 = str(envelope["nonce"])
            ciphertext_b64 = str(envelope["ciphertext"])
        except KeyError as exc:
            raise HPKEPluginError(f"missing field: {exc}") from exc

        # 1. Resolve private key
        priv_key = self._keys.get(key_id)
        if priv_key is None:
            if len(self._keys) == 1 and (not key_id or key_id == "default"):
                key_id = next(iter(self._keys.keys()))
                priv_key = self._keys[key_id]
            else:
                raise UnknownKeyIdError(f"server does not have private key for key_id: '{key_id}'")

        # 2. Parse peer ephemeral public key
        try:
            peer_pub_bytes = b64decode(encapped_key_b64)
            peer_pub_key = load_x25519_public_key(peer_pub_bytes)
        except Exception as exc:
            raise InvalidEncappedKeyError(f"invalid ephemeral public key in envelope: {exc}") from exc

        # 3. Decode nonce and ciphertext
        try:
            nonce = b64decode(nonce_b64)
            ciphertext = b64decode(ciphertext_b64)
        except Exception as exc:
            raise HPKEPluginError(f"failed to base64 decode nonce or ciphertext: {exc}") from exc

        # 4. Perform ECDH & HKDF key derivation
        try:
            shared_secret = priv_key.exchange(peer_pub_key)
            server_pub_bytes = self._public_keys_bytes[key_id]
            derived_key = derive_hpke_shared_key(
                shared_secret=shared_secret,
                sender_pub=peer_pub_bytes,
                receiver_pub=server_pub_bytes,
                key_id=key_id,
            )
        except Exception as exc:
            raise HPKEPluginError(f"ECDH/KDF derivation failed: {exc}") from exc

        # 5. Authenticated Decryption via AES-256-GCM
        try:
            aesgcm = AESGCM(derived_key)
            return aesgcm.decrypt(nonce, ciphertext, HPKE_AAD)
        except Exception as exc:
            raise HPKEDecryptionError(f"HPKE AEAD decryption or authentication tag verification failed: {exc}") from exc
