import json
import base64
import os
import pytest
from unittest.mock import MagicMock

from server.config import config
from server.api.export import (
    _resolve_decrypted_payload,
    _extract_parameters,
    _stream_json_training_dataset,
    _stream_csv_training_dataset,
)
from server.plugin_registry import registry
from server.crypto.aesgcm_plugin import AESGCMPlugin
from shared.crypto_utils import b64encode
from shared.protocol import CRYPTO_SCHEME_AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TEST_AES_KEY = b"12345678901234567890123456789012"


@pytest.fixture(autouse=True)
def setup_crypto(monkeypatch):
    b64_key = base64.b64encode(TEST_AES_KEY).decode("utf-8")
    monkeypatch.setenv("INSIEDR_AES_KEY", b64_key)
    registry.register(AESGCMPlugin(TEST_AES_KEY))


def test_resolve_decrypted_payload_plaintext_dict():
    sample_payload = {"agent_id": "AGENT-TEST", "collectors": []}
    row = {"payload": sample_payload}
    assert _resolve_decrypted_payload(row) == sample_payload


def test_resolve_decrypted_payload_payload_json():
    sample_payload = {"agent_id": "AGENT-TEST", "collectors": []}
    row = {"payload_json": json.dumps(sample_payload)}
    assert _resolve_decrypted_payload(row) == sample_payload


def test_resolve_decrypted_payload_from_encrypted_envelope():
    aesgcm = AESGCM(TEST_AES_KEY)
    
    inner_payload = {
        "agent_id": "AGENT-TEST-01",
        "hostname": "DATASL-173",
        "username": "DSL-173",
        "collectors": [
            {
                "collector": "process-watcher",
                "status": "success",
                "payload": {"process_count": 142, "admin_process_count": 5}
            },
            {
                "collector": "dns-monitor",
                "status": "success",
                "payload": {"total_queries_captured": 120}
            }
        ]
    }
    
    plaintext = json.dumps(inner_payload).encode("utf-8")
    nonce = os.urandom(12)
    aad = b"insiedr.agent.telemetry.v2"
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    envelope = {
        "scheme": CRYPTO_SCHEME_AESGCM,
        "key_id": "default",
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
    }
    
    row = {
        "payload_id": "payload-123",
        "crypto_scheme": "aes-256-gcm",
        "encrypted_envelope_json": json.dumps(envelope),
    }
    
    # Decrypt via _resolve_decrypted_payload
    resolved = _resolve_decrypted_payload(row)
    assert resolved is not None
    assert resolved["agent_id"] == "AGENT-TEST-01"
    assert resolved["hostname"] == "DATASL-173"
    assert len(resolved["collectors"]) == 2


def test_extract_parameters_from_decrypted_envelope():
    aesgcm = AESGCM(TEST_AES_KEY)
    
    inner_payload = {
        "agent_id": "AGENT-TEST",
        "collectors": [
            {
                "collector": "process-watcher",
                "status": "success",
                "payload": {"process_count": 99, "tunneling_process_count": 2}
            }
        ]
    }
    plaintext = json.dumps(inner_payload).encode("utf-8")
    nonce = os.urandom(12)
    aad = b"insiedr.agent.telemetry.v2"
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    row = {
        "payload_id": "p-1",
        "crypto_scheme": "aes-256-gcm",
        "encrypted_envelope_json": {
            "scheme": CRYPTO_SCHEME_AESGCM,
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
        }
    }
    
    features = _extract_parameters(None, row)
    assert features["process_count"] == 99
    assert features["tunneling_process_count"] == 2


def test_stream_json_contains_decrypted_raw_logs():
    aesgcm = AESGCM(TEST_AES_KEY)
    
    inner_payload = {
        "agent_id": "AGENT-TEST",
        "collectors": [
            {
                "collector": "dns-monitor",
                "status": "success",
                "payload": {"total_queries_captured": 75}
            }
        ]
    }
    plaintext = json.dumps(inner_payload).encode("utf-8")
    nonce = os.urandom(12)
    aad = b"insiedr.agent.telemetry.v2"
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    row = {
        "username": "alice",
        "agent_id": "AGENT-TEST",
        "hostname": "HOST-01",
        "payload_id": "p-test-01",
        "received_at": "2026-10-06T12:00:00Z",
        "crypto_scheme": "aes-256-gcm",
        "encrypted_envelope_json": {
            "scheme": CRYPTO_SCHEME_AESGCM,
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
        }
    }
    
    mock_storage = MagicMock()
    mock_storage.list_logs.return_value = [row]
    
    gen = _stream_json_training_dataset(mock_storage, filters={}, limit=10)
    lines = list(gen)
    assert len(lines) == 1
    
    record = json.loads(lines[0])
    assert record["user"] == "alice"
    assert record["agent_id"] == "AGENT-TEST"
    assert record["raw_logs"] is not None
    assert record["raw_logs"]["agent_id"] == "AGENT-TEST"
    assert record["parameters"]["total_queries_captured"] == 75


def test_stream_csv_contains_decrypted_raw_logs():
    aesgcm = AESGCM(TEST_AES_KEY)
    
    inner_payload = {
        "agent_id": "AGENT-TEST",
        "collectors": [
            {
                "collector": "logon",
                "status": "success",
                "payload": {"failed_logons": 1}
            }
        ]
    }
    plaintext = json.dumps(inner_payload).encode("utf-8")
    nonce = os.urandom(12)
    aad = b"insiedr.agent.telemetry.v2"
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    
    row = {
        "username": "bob",
        "agent_id": "AGENT-TEST",
        "hostname": "HOST-02",
        "payload_id": "p-test-02",
        "received_at": "2026-10-06T12:00:00Z",
        "crypto_scheme": "aes-256-gcm",
        "encrypted_envelope_json": {
            "scheme": CRYPTO_SCHEME_AESGCM,
            "nonce": b64encode(nonce),
            "ciphertext": b64encode(ciphertext),
        }
    }
    
    mock_storage = MagicMock()
    mock_storage.list_logs.return_value = [row]
    
    gen = _stream_csv_training_dataset(mock_storage, filters={}, limit=10)
    csv_output = "".join(list(gen))
    
    import csv
    import io
    reader = csv.reader(io.StringIO(csv_output))
    rows = list(reader)
    # Row 0 is header, Row 1 is data
    assert len(rows) == 2
    header = rows[0]
    data = rows[1]
    
    assert header[0] == "user"
    assert data[0] == "bob"
    
    raw_logs_col = data[3]
    parsed_raw_logs = json.loads(raw_logs_col)
    assert parsed_raw_logs["agent_id"] == "AGENT-TEST"
    assert len(parsed_raw_logs["collectors"]) == 1
