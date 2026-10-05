from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


AES_GCM_KEY_BYTES = 32


class CryptoConfigError(ValueError):
    """Raised when configured cryptographic material is missing or invalid."""


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    try:
        data_str = data.strip()
        padding = "=" * (-len(data_str) % 4)
        return base64.urlsafe_b64decode((data_str + padding).encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise CryptoConfigError("value is not valid URL-safe base64") from exc


def _decode_candidate(value: str) -> bytes:
    stripped = value.strip()
    if not stripped:
        raise CryptoConfigError("encryption key is empty")

    try:
        raw = base64.urlsafe_b64decode(stripped.encode("ascii"))
        if len(raw) == AES_GCM_KEY_BYTES:
            return raw
    except (binascii.Error, UnicodeEncodeError):
        pass

    try:
        raw = bytes.fromhex(stripped)
        if len(raw) == AES_GCM_KEY_BYTES:
            return raw
    except ValueError:
        pass

    raw = stripped.encode("utf-8")
    if len(raw) == AES_GCM_KEY_BYTES:
        return raw

    raise CryptoConfigError("AES-GCM key must decode to exactly 32 bytes")


def normalize_aes_key(key_material: bytes | str) -> bytes:
    if isinstance(key_material, bytes):
        if len(key_material) == AES_GCM_KEY_BYTES:
            return key_material
        try:
            return _decode_candidate(key_material.decode("ascii"))
        except UnicodeDecodeError as exc:
            raise CryptoConfigError("AES-GCM key bytes must be raw 32 bytes or ASCII encoded") from exc
    return _decode_candidate(key_material)


def load_aes_key(*, env_value: Optional[str] = None, key_path: Optional[str] = None) -> bytes:
    if env_value:
        return normalize_aes_key(env_value)
    if key_path:
        path = Path(key_path).expanduser()
        if not path.is_file():
            raise CryptoConfigError(f"AES key file does not exist: {path}")
        return normalize_aes_key(path.read_bytes().strip())
    raise CryptoConfigError("AES key is required; set INSIEDR_AES_KEY/AES_KEY or INSIEDR_AES_KEY_PATH/AES_KEY_PATH")


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:12]


def sign_hmac_sha256(secret: bytes, payload: bytes) -> str:
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_hmac_sha256(secret: bytes, payload: bytes, signature: str) -> bool:
    expected = sign_hmac_sha256(secret, payload)
    return hmac.compare_digest(expected, signature)


import re
from urllib.parse import urlsplit, urlunsplit


def redact_url_credentials(url: str | None) -> str:
    """Safely redact credentials (user:password) from database and Redis connection URLs."""
    if not url:
        return "<unset>"
    try:
        parsed = urlsplit(url)
        if not parsed.netloc:
            # Fallback regex if scheme/netloc parsing failed
            return re.sub(r"://([^:@\s]+)?(:[^@\s]+)?@", r"://***:***@", url)
        
        # Check if username or password is embedded
        if parsed.password or parsed.username:
            user = parsed.username or ""
            # Redact password completely, mask username
            netloc_parts = parsed.netloc.split("@")
            host_port = netloc_parts[-1]
            masked_userinfo = f"{user}:***" if user else ":***"
            new_netloc = f"{masked_userinfo}@{host_port}"
            return urlunsplit((parsed.scheme, new_netloc, parsed.path, parsed.query, parsed.fragment))
        return url
    except Exception:
        return re.sub(r"://([^:@\s]+)?(:[^@\s]+)?@", r"://***:***@", url)


def redact_dsn_credentials(dsn: str | None) -> str:
    """Redact credentials from both URL-format and libpq keyword-format DSNs.

    URL format:  ``postgresql://user:password@host/db``
    Keyword format: ``host=db user=insiedr password=secret dbname=insiedr_db``
    """
    if not dsn:
        return "<unset>"
    stripped = dsn.strip()
    # Detect keyword format: does not contain "://" but contains "password=" or "passfile="
    if "://" not in stripped and ("password=" in stripped or "passfile=" in stripped):
        # Redact the value of password= and passfile= keyword arguments
        redacted = re.sub(
            r"(password|passfile)\s*=\s*(\S+)",
            r"\1=***",
            stripped,
            flags=re.IGNORECASE,
        )
        return redacted
    return redact_url_credentials(stripped)


def redact_secret(value: str | None, full: bool = True) -> str:
    """Redact confidential API keys, passwords, and private key strings."""
    if not value:
        return "<unset>"
    if full or len(value) <= 8:
        return "<redacted>"
    return f"{value[:3]}...[REDACTED]...{value[-3:]}"



X25519_KEY_BYTES = 32
HPKE_KDF_SALT = b"insiedr.hpke.v1.kem.salt"
HPKE_KDF_INFO_PREFIX = b"insiedr.hpke.v1.aes256gcm"


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Generates a new X25519 private/public keypair as raw 32-byte tuples."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes


def _decode_asym_candidate(value: str | bytes, expected_len: int = 32) -> bytes:
    if isinstance(value, bytes):
        if len(value) == expected_len:
            return value
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise CryptoConfigError(f"key material must be raw {expected_len} bytes or valid text/PEM") from exc

    stripped = value.strip()
    if not stripped:
        raise CryptoConfigError("cryptographic key is empty")

    raw_candidate = stripped.encode("ascii", errors="ignore")
    if len(raw_candidate) == expected_len and not stripped.startswith("-----"):
        return raw_candidate

    try:
        raw = base64.urlsafe_b64decode(stripped.encode("ascii"))
        if len(raw) == expected_len:
            return raw
    except (binascii.Error, UnicodeEncodeError):
        pass

    try:
        raw = base64.b64decode(stripped.encode("ascii"))
        if len(raw) == expected_len:
            return raw
    except (binascii.Error, UnicodeEncodeError):
        pass

    try:
        raw = bytes.fromhex(stripped)
        if len(raw) == expected_len:
            return raw
    except ValueError:
        pass

    raise CryptoConfigError(f"unable to decode {expected_len}-byte raw key material")


def load_x25519_public_key(key_material: bytes | str) -> x25519.X25519PublicKey:
    """Loads an X25519 public key from raw 32 bytes, base64, hex, or PEM format."""
    if isinstance(key_material, x25519.X25519PublicKey):
        return key_material

    str_val = key_material.decode("utf-8", errors="ignore") if isinstance(key_material, bytes) else key_material
    if "-----BEGIN PUBLIC KEY-----" in str_val:
        try:
            pem_bytes = str_val.encode("utf-8") if isinstance(str_val, str) else key_material
            key = load_pem_public_key(pem_bytes)
            if not isinstance(key, x25519.X25519PublicKey):
                raise CryptoConfigError("PEM key is not an X25519 public key")
            return key
        except Exception as exc:
            raise CryptoConfigError(f"failed to load X25519 public key from PEM: {exc}") from exc

    raw_bytes = _decode_asym_candidate(key_material, expected_len=X25519_KEY_BYTES)
    try:
        return x25519.X25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as exc:
        raise CryptoConfigError(f"invalid X25519 public key bytes: {exc}") from exc


def load_x25519_private_key(key_material: bytes | str) -> x25519.X25519PrivateKey:
    """Loads an X25519 private key from raw 32 bytes, base64, hex, or PEM format."""
    if isinstance(key_material, x25519.X25519PrivateKey):
        return key_material

    str_val = key_material.decode("utf-8", errors="ignore") if isinstance(key_material, bytes) else key_material
    if "-----BEGIN PRIVATE KEY-----" in str_val or "-----BEGIN OPENSSH PRIVATE KEY-----" in str_val:
        try:
            pem_bytes = str_val.encode("utf-8") if isinstance(str_val, str) else key_material
            key = load_pem_private_key(pem_bytes, password=None)
            if not isinstance(key, x25519.X25519PrivateKey):
                raise CryptoConfigError("PEM key is not an X25519 private key")
            return key
        except Exception as exc:
            raise CryptoConfigError(f"failed to load X25519 private key from PEM: {exc}") from exc

    raw_bytes = _decode_asym_candidate(key_material, expected_len=X25519_KEY_BYTES)
    try:
        return x25519.X25519PrivateKey.from_private_bytes(raw_bytes)
    except Exception as exc:
        raise CryptoConfigError(f"invalid X25519 private key bytes: {exc}") from exc


def export_x25519_public_key(key: x25519.X25519PublicKey | bytes | str, as_pem: bool = False) -> str:
    """Exports an X25519 public key as URL-safe base64 string or SubjectPublicKeyInfo PEM."""
    if not isinstance(key, x25519.X25519PublicKey):
        key = load_x25519_public_key(key)
    if as_pem:
        return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64encode(raw)


def export_x25519_private_key(key: x25519.X25519PrivateKey | bytes | str, as_pem: bool = False) -> str:
    """Exports an X25519 private key as URL-safe base64 string or PKCS#8 PEM."""
    if not isinstance(key, x25519.X25519PrivateKey):
        key = load_x25519_private_key(key)
    if as_pem:
        return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return b64encode(raw)


def derive_hpke_shared_key(
    shared_secret: bytes,
    sender_pub: bytes,
    receiver_pub: bytes,
    key_id: str = "",
    length: int = 32,
) -> bytes:
    """Derives a symmetric key from ECDH shared secret using HKDF-SHA256 (RFC 5869)."""
    info = HPKE_KDF_INFO_PREFIX + sender_pub + receiver_pub + key_id.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=HPKE_KDF_SALT,
        info=info,
    )
    return hkdf.derive(shared_secret)


def public_key_fingerprint(pub_bytes: bytes) -> str:
    """Returns a short SHA-256 fingerprint for public key identification."""
    return f"sha256:{hashlib.sha256(pub_bytes).hexdigest()[:16]}"

