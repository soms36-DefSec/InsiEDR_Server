"""
tests/test_hpke.py
------------------
Comprehensive test suite for InsiEDR Hybrid Public-Key Encryption (HPKE).
Verifies RFC 9180 aligned X25519 ECDH + HKDF-SHA256 + AES-256-GCM encryption,
multi-key rotation, tamper resistance, and FastAPI endpoint ingestion.
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from shared.crypto_utils import (
    generate_x25519_keypair,
    load_x25519_private_key,
    load_x25519_public_key,
    export_x25519_private_key,
    export_x25519_public_key,
    public_key_fingerprint,
    b64decode,
    b64encode,
)
from shared.protocol import (
    CRYPTO_SCHEME_HPKE,
    PROTOCOL_VERSION,
    TELEMETRY_SCHEMA,
    encrypted_payload_headers,
)
from server.crypto.hpke_plugin import (
    HPKEPlugin,
    HPKEPluginError,
    HPKEDecryptionError,
    InvalidEncappedKeyError,
    UnknownKeyIdError,
)
from server.plugin_registry import registry
from server.app import create_app

# Agent crypto import
import sys
from pathlib import Path
agent_repo = Path("d:/Projects/AISH/InsiEDR-agent")
if str(agent_repo) not in sys.path:
    sys.path.insert(0, str(agent_repo))

from agent.crypto.hpke import HPKECrypto
from agent.queue.local_queue import LocalEncryptedQueue


def _sample_telemetry(payload_id: str, agent_id: str = "test-agent-01") -> dict:
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema": TELEMETRY_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "payload_id": payload_id,
        "agent_id": agent_id,
        "collected_at": now_str,
        "hostname": "DESKTOP-SECURE",
        "username": "secops",
        "collectors": [
            {
                "collector": "file-monitor",
                "collected_at": now_str,
                "hostname": "DESKTOP-SECURE",
                "status": "success",
                "payload": {"events_count": 12},
            }
        ],
        "summary": {
            "collector_count": 1,
            "success_count": 1,
            "failed_count": 0,
        },
    }


# ==============================================================================
# 1. Key Generation, Serialization, and Fingerprint Tests
# ==============================================================================

def test_x25519_keypair_lifecycle():
    raw_priv, raw_pub = generate_x25519_keypair()
    assert len(raw_priv) == 32
    assert len(raw_pub) == 32

    # Load objects
    priv_obj = load_x25519_private_key(raw_priv)
    pub_obj = load_x25519_public_key(raw_pub)

    # Base64 export & re-import
    b64_priv = export_x25519_private_key(priv_obj, as_pem=False)
    b64_pub = export_x25519_public_key(pub_obj, as_pem=False)
    reloaded_priv = load_x25519_private_key(b64_priv)
    reloaded_pub = load_x25519_public_key(b64_pub)
    assert reloaded_priv is not None
    assert reloaded_pub is not None

    # PEM export & re-import
    pem_priv = export_x25519_private_key(priv_obj, as_pem=True)
    pem_pub = export_x25519_public_key(pub_obj, as_pem=True)
    assert "-----BEGIN PRIVATE KEY-----" in pem_priv
    assert "-----BEGIN PUBLIC KEY-----" in pem_pub

    reloaded_pem_priv = load_x25519_private_key(pem_priv)
    reloaded_pem_pub = load_x25519_public_key(pem_pub)
    assert reloaded_pem_priv is not None
    assert reloaded_pem_pub is not None

    # Fingerprint format
    fp = public_key_fingerprint(raw_pub)
    assert fp.startswith("sha256:")
    assert len(fp) == 23  # sha256: + 16 chars


# ==============================================================================
# 2. HPKE End-to-End Encryption / Decryption Symmetry
# ==============================================================================

def test_hpke_encrypt_decrypt_symmetry():
    # 1. Setup server keys
    raw_priv, raw_pub = generate_x25519_keypair()
    server_key_id = "srv-x25519-v1"
    server_plugin = HPKEPlugin({server_key_id: raw_priv}, default_key_id=server_key_id)

    # 2. Agent encrypts telemetry using ONLY server public key
    agent_crypto = HPKECrypto(server_public_key=raw_pub, key_id=server_key_id)
    payload_id = str(uuid.uuid4())
    telemetry = _sample_telemetry(payload_id)

    envelope = agent_crypto.encrypt_payload(telemetry)
    assert envelope["scheme"] == CRYPTO_SCHEME_HPKE
    assert envelope["key_id"] == server_key_id
    assert envelope["protocol_version"] == PROTOCOL_VERSION
    assert "encapped_key" in envelope
    assert "nonce" in envelope
    assert "ciphertext" in envelope

    # 3. Server decapsulates & decrypts
    decrypted_bytes = server_plugin.decrypt(envelope)
    decrypted_json = json.loads(decrypted_bytes.decode("utf-8"))

    assert decrypted_json["payload_id"] == payload_id
    assert decrypted_json["agent_id"] == "test-agent-01"
    assert decrypted_json["summary"]["success_count"] == 1


# ==============================================================================
# 3. Tamper Resistance and AEAD Tag Verification
# ==============================================================================

def test_hpke_ciphertext_tamper_fails():
    raw_priv, raw_pub = generate_x25519_keypair()
    server_plugin = HPKEPlugin(raw_priv, default_key_id="k1")
    agent_crypto = HPKECrypto(raw_pub, key_id="k1")

    envelope = agent_crypto.encrypt_payload(_sample_telemetry(str(uuid.uuid4())))

    # Corrupt ciphertext
    ct_bytes = bytearray(b64decode(envelope["ciphertext"]))
    ct_bytes[0] ^= 0xFF  # flip bit
    tampered_envelope = dict(envelope)
    tampered_envelope["ciphertext"] = b64encode(bytes(ct_bytes))

    with pytest.raises(HPKEDecryptionError):
        server_plugin.decrypt(tampered_envelope)


def test_hpke_nonce_tamper_fails():
    raw_priv, raw_pub = generate_x25519_keypair()
    server_plugin = HPKEPlugin(raw_priv, default_key_id="k1")
    agent_crypto = HPKECrypto(raw_pub, key_id="k1")

    envelope = agent_crypto.encrypt_payload(_sample_telemetry(str(uuid.uuid4())))

    # Corrupt nonce
    nonce_bytes = bytearray(b64decode(envelope["nonce"]))
    nonce_bytes[0] ^= 0xAA
    tampered_envelope = dict(envelope)
    tampered_envelope["nonce"] = b64encode(bytes(nonce_bytes))

    with pytest.raises(HPKEDecryptionError):
        server_plugin.decrypt(tampered_envelope)


def test_hpke_corrupt_encapped_key_fails():
    raw_priv, raw_pub = generate_x25519_keypair()
    server_plugin = HPKEPlugin(raw_priv, default_key_id="k1")
    agent_crypto = HPKECrypto(raw_pub, key_id="k1")

    envelope = agent_crypto.encrypt_payload(_sample_telemetry(str(uuid.uuid4())))

    # Malformed encapped_key (wrong length)
    tampered_envelope = dict(envelope)
    tampered_envelope["encapped_key"] = b64encode(b"short_key")

    with pytest.raises(InvalidEncappedKeyError):
        server_plugin.decrypt(tampered_envelope)


# ==============================================================================
# 4. Multi-Key Rotation Tests
# ==============================================================================

def test_hpke_multi_key_rotation():
    priv1, pub1 = generate_x25519_keypair()
    priv2, pub2 = generate_x25519_keypair()

    # Server supports BOTH key1 and key2 simultaneously
    server_plugin = HPKEPlugin({
        "srv-2026-v1": priv1,
        "srv-2026-v2": priv2,
    })

    agent1 = HPKECrypto(pub1, key_id="srv-2026-v1")
    agent2 = HPKECrypto(pub2, key_id="srv-2026-v2")

    env1 = agent1.encrypt_payload(_sample_telemetry("p-01"))
    env2 = agent2.encrypt_payload(_sample_telemetry("p-02"))

    # Both decrypt successfully with matching key
    res1 = json.loads(server_plugin.decrypt(env1).decode("utf-8"))
    res2 = json.loads(server_plugin.decrypt(env2).decode("utf-8"))
    assert res1["payload_id"] == "p-01"
    assert res2["payload_id"] == "p-02"

    # Unknown key ID raises UnknownKeyIdError
    agent_rogue = HPKECrypto(pub1, key_id="srv-nonexistent-v99")
    env_rogue = agent_rogue.encrypt_payload(_sample_telemetry("p-rogue"))
    with pytest.raises(UnknownKeyIdError):
        server_plugin.decrypt(env_rogue)


# ==============================================================================
# 5. Local Queue Validation with HPKE Envelopes
# ==============================================================================

def test_agent_queue_hpke_support(tmp_path):
    _, pub = generate_x25519_keypair()
    agent_crypto = HPKECrypto(pub, key_id="test-key")
    payload = _sample_telemetry("p-queued-01")
    envelope = agent_crypto.encrypt_payload(payload)

    queue = LocalEncryptedQueue(tmp_path / "agent_queue")
    item_path = queue.enqueue(envelope, {"X-Crypto-Scheme": "hpke"})
    assert item_path.is_file()

    items = list(queue.iter_items())
    assert len(items) == 1
    assert items[0].body["envelope"]["scheme"] == "hpke"
    assert items[0].body["envelope"]["payload_id"] == "p-queued-01"

    # Corrupt envelope validation test
    invalid_env = dict(envelope)
    del invalid_env["encapped_key"]
    with pytest.raises(ValueError, match="HPKE encrypted envelope is missing encapped_key"):
        queue.enqueue(invalid_env)


# ==============================================================================
# 6. FastAPI Server Integration Test (HPKE Ingestion)
# ==============================================================================

def test_fastapi_hpke_telemetry_ingestion():
    from unittest.mock import patch
    from tests.test_fastapi_server import MockStorage

    raw_priv, raw_pub = generate_x25519_keypair()
    key_id = "test-fastapi-hpke-key"

    # Register HPKE plugin in server registry
    hpke_plugin = HPKEPlugin({key_id: raw_priv}, default_key_id=key_id)
    registry._plugins[CRYPTO_SCHEME_HPKE] = hpke_plugin

    mock_storage = MockStorage()
    stored_payloads = []
    mock_storage.store_raw_payload = lambda env, payload: stored_payloads.append((env, payload))
    mock_storage.get_payload = lambda pid: None

    app = create_app(storage=mock_storage, apply_migrations=False)
    client = TestClient(app)

    # 1. Verify Public Key Discovery Endpoint
    resp_keys = client.get("/api/v1/crypto/public-keys")
    assert resp_keys.status_code == 200
    keys_data = resp_keys.json()
    assert keys_data["ok"] is True

    # 2. Ingest HPKE Telemetry to /api/logs
    payload_id = str(uuid.uuid4())
    telemetry = _sample_telemetry(payload_id, agent_id="agent-hpke-prod")

    agent_crypto = HPKECrypto(raw_pub, key_id=key_id)
    envelope = agent_crypto.encrypt_payload(telemetry)
    headers = encrypted_payload_headers(envelope, agent_id="agent-hpke-prod", payload_id=payload_id)

    resp = client.post("/api/logs", content=json.dumps(envelope), headers=headers)
    assert resp.status_code == 202
    res_body = resp.json()
    assert res_body["ok"] is True
    assert res_body["payload_id"] == payload_id
    assert res_body["status"] == "accepted"

    # Verify storage was called with decrypted payload
    assert len(stored_payloads) == 1
    stored_env, stored_payload = stored_payloads[0]
    assert stored_env["scheme"] == "hpke"
    assert stored_payload["payload_id"] == payload_id
    assert stored_payload["agent_id"] == "agent-hpke-prod"
