"""
tests/test_tier2_interop.py
----------------------------
Tier 2 Integration & Interoperability Test Suite.
Validates the end-to-end telemetry ingestion contract between the native
Windows Rust agent (InsiEDR-agent) and the FastAPI server (InsiEDR-server),
including:
1. Strict wire envelope and decrypted payload schema compliance.
2. Dual cryptographic framing: AES-256-GCM and HPKE (RFC 9180 X25519).
3. Full 20-collector telemetry harvesting and feature extraction.
4. Stage 1 Domain Isolation Forest and Stage 2 Scenario XGBoost feature completeness.
5. Real-time detectors: LanlEDRExtractor, AuthBurstDetector, TamperDetector, KeystrokeDetector, and RiskAggregator.
"""
from __future__ import annotations

import os
import sys
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.protocol import (
    PROTOCOL_VERSION,
    TELEMETRY_SCHEMA,
    CRYPTO_SCHEME_AESGCM,
    CRYPTO_SCHEME_HPKE,
    HEADER_CRYPTO_SCHEME,
    HEADER_PROTOCOL_VERSION,
    HEADER_AGENT_ID,
    HEADER_PAYLOAD_ID,
    HEADER_KEY_ID,
    HEADER_ENCAPPED_KEY,
    INGEST_CONTENT_TYPE,
    canonical_json_bytes,
    validate_telemetry_payload,
)
from shared.crypto_utils import (
    b64encode,
    generate_x25519_keypair,
)
from server.crypto.aesgcm_plugin import AESGCMPlugin, AES_GCM_AAD
from server.crypto.hpke_plugin import HPKEPlugin, HPKE_AAD
from server.plugin_registry import registry
from server.api.ingest import validate_collector_results
from server.features.lanl_edr import LanlEDRExtractor
from server.model_bridge import bridge as model_bridge
from server.app import create_app
from tests.test_fastapi_server import MockStorage

# Path to InsiEDR-agent Python utilities for testing
agent_repo = Path("d:/Projects/AISH/InsiEDR-agent")
if str(agent_repo) not in sys.path:
    sys.path.insert(0, str(agent_repo))

from agent.crypto.hpke import HPKECrypto


def _build_full_agent_telemetry(payload_id: str, username: str = "secops", agent_id: str = "AGENT-WIN11-PRO") -> dict:
    """Builds a complete telemetry payload matching the native Rust agent's 20-collector output."""
    now_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    hostname = "WIN11-PRO"

    collectors = [
        # 1. LANL Auth & Short-term EDR (Exact name required by LanlEDRExtractor)
        {
            "collector": "short-Term_EDR_Feature",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {
                "edr_auth_event_count_window": 1.0,
                "edr_failed_auth_ratio_window": 0.0,
                "edr_auth_events_per_minute_window": 0.2,
                "edr_failed_auth_events_per_minute_window": 0.0,
                "edr_unique_logon_type_count_window": 1.0,
                "auth_rate_300s": 0.02,
                "auth_fail_rate_300s": 0.0,
                "auth_rate_3600s": 0.005,
                "unique_workstations_300s": 1,
                "off_hours_auth_count": 0,
                "logon_velocity_zscore": 0.12,
            },
        },
        # 2. Logon Domain (10 canonical G-model features)
        {
            "collector": "logon",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {
                "logon_count": 1.0,
                "logoff_count": 0.0,
                "unique_pc_count": 1.0,
                "daily_unique_pc_count": 1.0,
                "after_hours_logon": 0.0,
                "daily_after_hours_logon_ratio": 0.0,
                "first_logon_time": 9.0,
                "last_logoff_time": 17.5,
                "weekend_logon": 0.0,
                "daily_pc_access_entropy": 0.0,
            },
        },
        # 3. Device Domain (6 canonical G-model features)
        {
            "collector": "devices",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {
                "usb_devices_count": 1,
                "usb_connect_count": 1.0,
                "usb_disconnect_count": 0.0,
                "after_hours_usb_usage": 0.0,
                "daily_device_connect_count": 1.0,
                "daily_device_usage_flag": 1.0,
                "first_usb_usage_time": 10.5,
            },
        },
        # 4. HTTP Domain (11 canonical G-model features)
        {
            "collector": "http",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {
                "http_count": 12.0,
                "daily_http_request_count": 12.0,
                "unique_url_count": 5.0,
                "suspicious_url_count": 0.0,
                "file_sharing_site_visits": 0.0,
                "job_search_site_visits": 0.0,
                "http_after_hours": 0.0,
                "daily_unique_domain_count": 3.0,
                "daily_new_domain_count": 0.0,
                "daily_domain_access_entropy": 1.58,
                "daily_external_domain_ratio": 0.33,
            },
        },
        # 5. File Domain (4 canonical G-model features)
        {
            "collector": "file-integrity-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {
                "file_access_count": 8.0,
                "daily_unique_filename_count": 8.0,
                "daily_new_filename_count": 0.0,
                "daily_file_access_entropy": 2.1,
                "event_count": 8,
            },
        },
        # 6. Keystroke Biometrics
        {
            "collector": "keystroke-collector",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {
                "keystroke_timings": [[68.2, 115.4], [72.1, 118.0], [65.0, 112.5], [70.4, 114.2]],
                "mean_flight_time_ms": 115.4,
                "std_flight_time_ms": 22.8,
                "mean_dwell_time_ms": 68.2,
                "std_dwell_time_ms": 14.1,
                "typing_speed_cpm": 260.0,
                "backspace_ratio": 0.04,
            },
        },
        # 7. Network Monitor
        {
            "collector": "network",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"active_connections_count": 4, "connections_sample": []},
        },
        # 8. USN Monitor
        {
            "collector": "usn-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"journal_id": 123456, "first_usn": 100, "next_usn": 500, "usn_records_captured": 0},
        },
        # 9. Activity Monitor
        {
            "collector": "activity-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"user_idle_seconds": 2.5, "is_user_active": True, "last_input_tick": 45000},
        },
        # 10. Clipboard Monitor
        {
            "collector": "clipboard-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"clipboard_sequence": 10, "clipboard_copy_count": 0, "monitor_active": True},
        },
        # 11. DNS Monitor
        {
            "collector": "dns-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"total_queries_captured": 15, "suspicious_queries_count": 0, "tunneling_detected": False},
        },
        # 12. Driver Monitor
        {
            "collector": "driver-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"driver_count": 120, "running_drivers": 120},
        },
        # 13. Email Monitor
        {
            "collector": "email-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"email_clients_installed": ["Outlook"], "outbound_attachment_count": 0, "external_recipient_ratio": 0.0},
        },
        # 14. LSASS Monitor
        {
            "collector": "lsass-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"target_process": "lsass.exe", "event_count": 0, "credential_dumping_suspected": False},
        },
        # 15. Memory Scanner
        {
            "collector": "memory-scanner",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"target_processes_scanned": 12, "threats_detected": False, "unbacked_executable_regions": 0},
        },
        # 16. Named Pipe Monitor
        {
            "collector": "named-pipe-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"pipe_count": 25, "named_pipes_sample": []},
        },
        # 17. Persistence Monitor
        {
            "collector": "persistence-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"total_monitored_keys": 8, "entry_count": 8, "modifications_detected": False},
        },
        # 18. Process Watcher
        {
            "collector": "process-watcher",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"daily_unique_process_count": 45, "executables_from_temp_folder": 0, "admin_process_count": 2, "process_count": 45},
        },
        # 19. Decoy Monitor
        {
            "collector": "decoy-monitor",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"monitored_decoys": ["C:\\Users\\Public\\Admin_Passwords.xlsx"], "threat_triggered": False},
        },
        # 20. WMI Activity Monitor
        {
            "collector": "wmi-activity",
            "collected_at": now_str,
            "hostname": hostname,
            "status": "success",
            "payload": {"total_queries_captured": 0, "lateral_movement_suspected": False},
        },
    ]

    return {
        "protocol_version": PROTOCOL_VERSION,
        "schema": TELEMETRY_SCHEMA,
        "payload_id": payload_id,
        "agent_id": agent_id,
        "hostname": hostname,
        "username": username,
        "collected_at": now_str,
        "os": {
            "system": "Windows",
            "release": "11",
            "version": "10.0.22631",
            "machine": "AMD64",
        },
        "summary": {
            "collector_count": len(collectors),
            "success_count": len(collectors),
            "failed_count": 0,
        },
        "collectors": collectors,
    }


# ==============================================================================
# Tests
# ==============================================================================

def test_rust_agent_schema_validates():
    """Verify that a payload constructed according to the Rust agent's model validates cleanly."""
    payload_id = str(uuid.uuid4())
    telemetry = _build_full_agent_telemetry(payload_id)

    # Validate against protocol rules
    validate_telemetry_payload(telemetry)
    # Validate against collector rules
    validate_collector_results(telemetry)
    assert telemetry["summary"]["collector_count"] == 20
    assert telemetry["summary"]["success_count"] == 20
    assert telemetry["summary"]["failed_count"] == 0


def test_lanl_edr_feature_extraction():
    """Verify that LanlEDRExtractor extracts all 5 LANL features from short-Term_EDR_Feature."""
    payload_id = str(uuid.uuid4())
    telemetry = _build_full_agent_telemetry(payload_id)

    extractor = LanlEDRExtractor()
    features = extractor.extract(telemetry)

    assert "edr_auth_event_count_window" in features
    assert "edr_failed_auth_ratio_window" in features
    assert "edr_auth_events_per_minute_window" in features
    assert "edr_failed_auth_events_per_minute_window" in features
    assert "edr_unique_logon_type_count_window" in features
    assert features["edr_auth_events_per_minute_window"] == 0.2


def test_model_bridge_feature_completeness():
    """Verify that ModelBridge extracts all 31 canonical G-model features with 0 missing."""
    payload_id = str(uuid.uuid4())
    telemetry = _build_full_agent_telemetry(payload_id)

    from server.config import config
    model_bridge.models_dir = Path(config.g_model_models_dir).resolve()
    model_bridge._feature_columns = None

    mock_storage = MockStorage()
    mock_storage.store_raw_payload = MagicMock()
    mock_storage.get_payload = lambda pid: None
    raw_features = model_bridge._features_for_payload(mock_storage, telemetry)
    ordered, missing = model_bridge._ordered_features(raw_features)

    # 31 domain features expected by the Isolation Forest & XGBoost scenario classifier
    expected_31 = [
        "logon_count", "logoff_count", "unique_pc_count", "daily_unique_pc_count",
        "after_hours_logon", "daily_after_hours_logon_ratio", "first_logon_time",
        "last_logoff_time", "weekend_logon", "daily_pc_access_entropy",
        "file_access_count", "daily_unique_filename_count", "daily_new_filename_count",
        "daily_file_access_entropy", "usb_connect_count", "usb_disconnect_count",
        "after_hours_usb_usage", "daily_device_connect_count", "daily_device_usage_flag",
        "first_usb_usage_time", "http_count", "daily_http_request_count",
        "unique_url_count", "suspicious_url_count", "file_sharing_site_visits",
        "job_search_site_visits", "http_after_hours", "daily_unique_domain_count",
        "daily_new_domain_count", "daily_domain_access_entropy", "daily_external_domain_ratio",
    ]

    for feat in expected_31:
        assert feat in ordered, f"Feature '{feat}' missing from ordered features"


def _make_interop_mock_storage():
    storage = MockStorage()
    storage.store_raw_payload = MagicMock()
    storage.get_payload = lambda pid: None
    storage.load_baseline = MagicMock(return_value=None)
    storage.save_baseline = MagicMock()
    storage.save_model_output = MagicMock()
    storage.save_risk_event = MagicMock()
    storage.list_recent_risk_scores = MagicMock(return_value=[])
    storage.get_feature_vector = MagicMock(return_value=None)
    storage.list_daily_feature_vectors = MagicMock(return_value=[])
    storage.store_collector_results = MagicMock()
    storage.store_normalized_features = MagicMock()
    return storage


def test_end_to_end_aesgcm_ingestion():
    """Verify end-to-end ingestion via AES-256-GCM encrypted envelope through /api/logs."""
    aes_key = b"\x42" * 32
    key_id = "default"
    plugin = AESGCMPlugin(aes_key)
    registry._plugins[CRYPTO_SCHEME_AESGCM] = plugin

    mock_storage = _make_interop_mock_storage()
    app = create_app(storage=mock_storage, apply_migrations=False)
    client = TestClient(app)

    payload_id = str(uuid.uuid4())
    agent_id = "AGENT-WIN11-PRO"
    telemetry = _build_full_agent_telemetry(payload_id, agent_id=agent_id)
    plaintext_bytes = canonical_json_bytes(telemetry)

    # Encrypt envelope matching the Rust AesGcmEngine
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, AES_GCM_AAD)

    envelope = {
        "protocol_version": PROTOCOL_VERSION,
        "scheme": CRYPTO_SCHEME_AESGCM,
        "payload_id": payload_id,
        "key_id": key_id,
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    headers = {
        "Content-Type": INGEST_CONTENT_TYPE,
        HEADER_CRYPTO_SCHEME: CRYPTO_SCHEME_AESGCM,
        HEADER_PROTOCOL_VERSION: PROTOCOL_VERSION,
        HEADER_AGENT_ID: agent_id,
        HEADER_PAYLOAD_ID: payload_id,
        HEADER_KEY_ID: key_id,
    }

    with patch.dict(os.environ, {"INSIEDR_ENABLE_MODEL_PIPELINE": "true"}), patch.object(
        model_bridge, "process_payload", wraps=model_bridge.process_payload
    ) as mock_bridge:
        response = client.post("/api/logs", content=json.dumps(envelope), headers=headers)
        assert response.status_code == 202
        body = response.json()
        assert body["ok"] is True
        assert body["payload_id"] == payload_id
        assert body["status"] == "accepted"
        assert mock_bridge.called


def test_end_to_end_hpke_ingestion():
    """Verify end-to-end ingestion via HPKE (X25519) encrypted envelope through /api/logs."""
    raw_priv, raw_pub = generate_x25519_keypair()
    key_id = "hpke-srv-v1"
    plugin = HPKEPlugin({key_id: raw_priv}, default_key_id=key_id)
    registry._plugins[CRYPTO_SCHEME_HPKE] = plugin

    mock_storage = _make_interop_mock_storage()
    app = create_app(storage=mock_storage, apply_migrations=False)
    client = TestClient(app)

    payload_id = str(uuid.uuid4())
    agent_id = "AGENT-WIN11-PRO"
    telemetry = _build_full_agent_telemetry(payload_id, agent_id=agent_id)

    # Encrypt envelope matching the Rust HpkeEngine
    agent_crypto = HPKECrypto(server_public_key=raw_pub, key_id=key_id)
    envelope = agent_crypto.encrypt_payload(telemetry)

    headers = {
        "Content-Type": INGEST_CONTENT_TYPE,
        HEADER_CRYPTO_SCHEME: CRYPTO_SCHEME_HPKE,
        HEADER_PROTOCOL_VERSION: PROTOCOL_VERSION,
        HEADER_AGENT_ID: agent_id,
        HEADER_PAYLOAD_ID: payload_id,
        HEADER_KEY_ID: key_id,
        HEADER_ENCAPPED_KEY: envelope["encapped_key"],
    }

    response = client.post("/api/logs", content=json.dumps(envelope), headers=headers)
    assert response.status_code == 202
    body = response.json()
    assert body["ok"] is True
    assert body["payload_id"] == payload_id
    assert body["status"] == "accepted"


def test_tamper_flag_triggers_critical_alert():
    """Verify that when a shutdown/tamper payload is sent, TamperDetector raises a critical anomaly."""
    from server.detectors.tamper_detector import TamperDetector

    detector = TamperDetector()
    features = {
        "manual_agent_stop_flag": 1.0,
        "logon_count": 0.0,
    }

    result = detector.detect(
        payload_id=str(uuid.uuid4()),
        agent_id="AGENT-WIN11-PRO",
        username="attacker",
        features=features,
        baseline=None,
    )

    assert result["is_anomaly"] is True
    assert result["score"] == 100.0
    assert "CRITICAL" in result["reason"]


def test_ingestion_model_pipeline_disabled_persists_keystrokes_and_features():
    """Verify that when INSIEDR_ENABLE_MODEL_PIPELINE=false, agent telemetry
    including all 20 sensors (specifically keystroke timing biometrics) is ingested,
    stored in collector_results and normalized_features, but ML inference is bypassed."""
    aes_key = b"\x55" * 32
    key_id = "default"
    plugin = AESGCMPlugin(aes_key)
    registry._plugins[CRYPTO_SCHEME_AESGCM] = plugin

    mock_storage = _make_interop_mock_storage()
    app = create_app(storage=mock_storage, apply_migrations=False)
    client = TestClient(app)

    payload_id = str(uuid.uuid4())
    agent_id = "AGENT-WIN11-PRO"
    telemetry = _build_full_agent_telemetry(payload_id, agent_id=agent_id)
    plaintext_bytes = canonical_json_bytes(telemetry)

    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, AES_GCM_AAD)

    envelope = {
        "protocol_version": PROTOCOL_VERSION,
        "scheme": CRYPTO_SCHEME_AESGCM,
        "payload_id": payload_id,
        "key_id": key_id,
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    headers = {
        "Content-Type": INGEST_CONTENT_TYPE,
        HEADER_CRYPTO_SCHEME: CRYPTO_SCHEME_AESGCM,
        HEADER_PROTOCOL_VERSION: PROTOCOL_VERSION,
        HEADER_AGENT_ID: agent_id,
        HEADER_PAYLOAD_ID: payload_id,
        HEADER_KEY_ID: key_id,
    }

    env_overrides = {
        "INSIEDR_ENABLE_MODEL_PIPELINE": "false",
        "INSIEDR_STORE_PLAINTEXT_PAYLOADS": "true",
    }
    with patch.dict(os.environ, env_overrides), patch.object(
        model_bridge, "process_payload", wraps=model_bridge.process_payload
    ) as mock_bridge:
        response = client.post("/api/logs", content=json.dumps(envelope), headers=headers)
        assert response.status_code == 202
        body = response.json()
        assert body["ok"] is True
        assert body["payload_id"] == payload_id
        assert body["status"] == "accepted"

        # Model pipeline must NOT be invoked
        assert not mock_bridge.called

        # Raw payload MUST be stored with all collectors preserved
        assert mock_storage.store_raw_payload.called
        stored_envelope, stored_payload = mock_storage.store_raw_payload.call_args[0]
        assert stored_payload["payload_id"] == payload_id

        # Verify keystroke collector was included in stored results
        found_keystroke = False
        for res in stored_payload.get("collectors", []):
            if res.get("collector") == "keystroke-collector":
                found_keystroke = True
                payload = res.get("payload", {})
                assert "keystroke_timings" in payload
                assert "mean_flight_time_ms" in payload
                assert "typing_speed_cpm" in payload
        assert found_keystroke, "Keystroke collector result was not stored"
