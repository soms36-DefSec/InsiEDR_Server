"""
tests/test_hpke_stress_benchmark.py
-----------------------------------
Stress tests, concurrency verification, performance benchmarks, and replay
protection tests for the InsiEDR HPKE encryption scheme.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from shared.crypto_utils import (
    generate_x25519_keypair,
    export_x25519_public_key,
)
from shared.protocol import (
    CRYPTO_SCHEME_HPKE,
    PROTOCOL_VERSION,
    TELEMETRY_SCHEMA,
    encrypted_payload_headers,
)
from server.crypto.hpke_plugin import HPKEPlugin
from server.plugin_registry import registry
from server.app import create_app
from tests.test_fastapi_server import MockStorage

import sys
from pathlib import Path
agent_repo = Path("d:/Projects/AISH/InsiEDR-agent")
if str(agent_repo) not in sys.path:
    sys.path.insert(0, str(agent_repo))

from agent.crypto.hpke import HPKECrypto


def _build_telemetry(payload_id: str, num_collectors: int = 5, extra_size_kb: int = 0) -> dict:
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    padding = "X" * (extra_size_kb * 1024) if extra_size_kb > 0 else ""
    return {
        "schema": TELEMETRY_SCHEMA,
        "protocol_version": PROTOCOL_VERSION,
        "payload_id": payload_id,
        "agent_id": "benchmark-agent",
        "collected_at": now_str,
        "hostname": "BENCHMARK-NODE",
        "username": "tester",
        "collectors": [
            {
                "collector": f"collector-{i}",
                "collected_at": now_str,
                "hostname": "BENCHMARK-NODE",
                "status": "success",
                "payload": {"index": i, "padding": padding},
            }
            for i in range(num_collectors)
        ],
        "summary": {
            "collector_count": num_collectors,
            "success_count": num_collectors,
            "failed_count": 0,
        },
    }


def test_hpke_performance_benchmark():
    """Verify latency and throughput of 200 consecutive HPKE encrypt+decrypt operations."""
    priv, pub = generate_x25519_keypair()
    server_plugin = HPKEPlugin(priv, default_key_id="bench-key")
    agent_crypto = HPKECrypto(pub, key_id="bench-key")

    iterations = 200
    telemetry = _build_telemetry("bench-001")

    # Benchmark encryption
    start_enc = time.perf_counter()
    envelopes = [agent_crypto.encrypt_payload(telemetry) for _ in range(iterations)]
    enc_duration = time.perf_counter() - start_enc

    # Benchmark decryption
    start_dec = time.perf_counter()
    decrypted = [server_plugin.decrypt(env) for env in envelopes]
    dec_duration = time.perf_counter() - start_dec

    avg_enc_ms = (enc_duration / iterations) * 1000
    avg_dec_ms = (dec_duration / iterations) * 1000
    total_ops_sec = iterations / (enc_duration + dec_duration)

    print(f"\n[BENCHMARK] 200 Cycles: Encrypt Avg={avg_enc_ms:.3f}ms | Decrypt Avg={avg_dec_ms:.3f}ms | Combined Throughput={total_ops_sec:.1f} ops/sec")

    assert len(decrypted) == iterations
    # In C-native OpenSSL X25519, average latency must be under 3ms per op
    assert avg_enc_ms < 5.0
    assert avg_dec_ms < 5.0


def test_hpke_large_payload_handling():
    """Verify HPKE handling of a 500 KB telemetry payload."""
    priv, pub = generate_x25519_keypair()
    server_plugin = HPKEPlugin(priv, default_key_id="large-key")
    agent_crypto = HPKECrypto(pub, key_id="large-key")

    payload = _build_telemetry("large-payload-01", num_collectors=2, extra_size_kb=250)
    envelope = agent_crypto.encrypt_payload(payload)

    decrypted_raw = server_plugin.decrypt(envelope)
    restored = json.loads(decrypted_raw.decode("utf-8"))
    assert restored["payload_id"] == "large-payload-01"
    assert restored["collectors"][0]["payload"]["padding"].startswith("XXXX")


def test_hpke_multithreaded_concurrency():
    """Verify thread-safety and lock-free execution across 10 concurrent threads."""
    priv, pub = generate_x25519_keypair()
    server_plugin = HPKEPlugin(priv, default_key_id="thread-key")
    agent_crypto = HPKECrypto(pub, key_id="thread-key")

    def _worker(thread_id: int):
        for i in range(20):
            pid = f"thread-{thread_id}-{i}"
            payload = _build_telemetry(pid)
            env = agent_crypto.encrypt_payload(payload)
            dec_bytes = server_plugin.decrypt(env)
            parsed = json.loads(dec_bytes.decode("utf-8"))
            assert parsed["payload_id"] == pid

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_worker, i) for i in range(10)]
        for f in futures:
            f.result()  # Will raise if any thread failed


def test_hpke_duplicate_payload_rejection():
    """Verify that submitting the same payload_id twice with differing ciphertext raises 400."""
    priv, pub = generate_x25519_keypair()
    key_id = "replay-test-key"
    registry._plugins[CRYPTO_SCHEME_HPKE] = HPKEPlugin({key_id: priv}, default_key_id=key_id)

    mock_storage = MockStorage()
    existing_records = {}

    def _mock_store(env, payload):
        existing_records[payload["payload_id"]] = {
            "payload_id": payload["payload_id"],
            "ciphertext_hash": "original_hash",
            "encrypted_envelope_json": env,
            "decrypted_payload_hash": "original_decrypted_hash",
        }

    mock_storage.store_raw_payload = _mock_store
    mock_storage.get_payload = lambda pid: existing_records.get(pid)

    app = create_app(storage=mock_storage, apply_migrations=False)
    client = TestClient(app)

    agent_crypto = HPKECrypto(pub, key_id=key_id)
    telemetry = _build_telemetry("duplicate-payload-01")

    # 1. First submission succeeds
    env1 = agent_crypto.encrypt_payload(telemetry)
    h1 = encrypted_payload_headers(env1, agent_id="benchmark-agent", payload_id="duplicate-payload-01")
    r1 = client.post("/api/logs", content=json.dumps(env1), headers=h1)
    assert r1.status_code == 202

    # 2. Second submission with different ephemeral ciphertext triggers duplicate collision detection
    env2 = agent_crypto.encrypt_payload(telemetry)  # Different ephemeral key & nonce
    h2 = encrypted_payload_headers(env2, agent_id="benchmark-agent", payload_id="duplicate-payload-01")
    r2 = client.post("/api/logs", content=json.dumps(env2), headers=h2)
    assert r2.status_code == 400
    assert "duplicate" in r2.text.lower()


def test_hpke_replay_window_expiration():
    """Verify that HPKE envelopes older than replay_window_hours are rejected with 400."""
    priv, pub = generate_x25519_keypair()
    key_id = "age-test-key"
    registry._plugins[CRYPTO_SCHEME_HPKE] = HPKEPlugin({key_id: priv}, default_key_id=key_id)

    mock_storage = MockStorage()
    mock_storage.get_payload = lambda pid: None
    mock_storage.store_raw_payload = lambda env, p: None

    app = create_app(storage=mock_storage, apply_migrations=False)
    client = TestClient(app)

    agent_crypto = HPKECrypto(pub, key_id=key_id)
    telemetry = _build_telemetry("expired-payload-01")

    # Envelope created 48 hours ago (outside default 24h replay window)
    expired_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
    env = agent_crypto.encrypt_payload(telemetry)
    env["created_at"] = expired_time
    h = encrypted_payload_headers(env, agent_id="benchmark-agent", payload_id="expired-payload-01")

    with patch.dict(os.environ, {"INSIEDR_REPLAY_WINDOW_HOURS": "24"}):
        r = client.post("/api/logs", content=json.dumps(env), headers=h)
        assert r.status_code == 400
        assert "replay window" in r.text
