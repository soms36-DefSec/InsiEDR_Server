"""
tests/test_detection_pipeline_toggle.py
---------------------------------------
Verifies that the entire detection pipeline can be turned OFF while telemetry log
collection, decryption, storage persistence, and export remain fully functional.
"""
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

import server.config as config_module
from server.config import config
from server.risk.pipeline import process_telemetry_risk
from server.app import create_app


@pytest.fixture
def clean_config():
    """Ensure config is restored after each test."""
    orig_det = config_module.ENABLE_DETECTION_PIPELINE
    orig_ing = config_module.ENABLE_LOG_INGESTION
    yield
    config_module.ENABLE_DETECTION_PIPELINE = orig_det
    config_module.ENABLE_LOG_INGESTION = orig_ing


def test_detection_pipeline_config_toggle(clean_config, monkeypatch):
    """Verify master config toggle, environment variable, and pause flag for detection pipeline."""
    # 1. Config constant toggle (when env var is not overriding)
    monkeypatch.delenv("INSIEDR_ENABLE_DETECTION_PIPELINE", raising=False)
    monkeypatch.delenv("INSIEDR_ENABLE_DETECTION", raising=False)

    config_module.ENABLE_DETECTION_PIPELINE = False
    assert config.enable_detection_pipeline is False

    config_module.ENABLE_DETECTION_PIPELINE = True
    assert config.enable_detection_pipeline is True

    # 2. Environment variable override
    monkeypatch.setenv("INSIEDR_ENABLE_DETECTION_PIPELINE", "false")
    assert config.enable_detection_pipeline is False

    monkeypatch.setenv("INSIEDR_ENABLE_DETECTION_PIPELINE", "true")
    assert config.enable_detection_pipeline is True

    # 3. Log ingestion remains independently active
    assert config.enable_log_ingestion is True


def test_process_telemetry_risk_bypassed_when_disabled(clean_config, monkeypatch):
    """Verify that process_telemetry_risk immediately exits with zero risk when disabled."""
    monkeypatch.setenv("INSIEDR_ENABLE_DETECTION_PIPELINE", "false")
    config_module.ENABLE_DETECTION_PIPELINE = False

    storage_mock = MagicMock()
    # A suspicious payload that would normally trigger heuristics
    payload = {
        "payload_id": "test-payload-123",
        "agent_id": "agent-01",
        "username": "attacker",
        "collected_at": "2026-10-27T10:00:00Z",
        "collectors": [
            {
                "collector": "memory",
                "status": "success",
                "payload": {
                    "credential_dumping_suspected": True,
                    "target_process": "lsass.exe",
                },
            }
        ],
    }

    result = process_telemetry_risk(storage_mock, payload)

    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "low"
    assert "disabled" in result["summary"].lower()

    # Verify no storage mutation or risk persistence occurred
    assert storage_mock.save_risk_event.call_count == 0
    assert storage_mock.load_baseline.call_count == 0
    assert storage_mock.save_baseline.call_count == 0


def test_health_check_reports_detection_disabled(clean_config, monkeypatch):
    """Verify that /api/health accurately reports detection pipeline state."""
    monkeypatch.setenv("INSIEDR_ENABLE_DETECTION_PIPELINE", "false")
    config_module.ENABLE_DETECTION_PIPELINE = False
    config_module.ENABLE_LOG_INGESTION = True

    mock_storage = MagicMock()
    mock_storage.ping.return_value = True
    mock_storage.telemetry_read_backend = "postgres"

    app = create_app(storage=mock_storage, apply_migrations=False)
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()

        assert data["ok"] is True
        assert data["telemetry_collection"] == "ok"
        assert data["log_ingestion_enabled"] is True
        assert data["detection_pipeline"] == "disabled"
        assert data["detection_pipeline_enabled"] is False
