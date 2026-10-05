"""
tests/test_telemetry_interceptors.py
------------------------------------
Unit tests for pluggable telemetry interceptor pipeline and enhanced PII/credential scrubber.
"""
from server.storage.interceptors import (
    InterceptorPipeline,
    TelemetryContext,
    pii_and_secret_scrubber,
    sanitize_string_value,
)


def test_interceptor_pipeline_ordering():
    pipeline = InterceptorPipeline()
    log = []

    def second_step(ctx: TelemetryContext) -> TelemetryContext:
        log.append("step_2")
        return ctx

    def first_step(ctx: TelemetryContext) -> TelemetryContext:
        log.append("step_1")
        return ctx

    pipeline.register(second_step, name="second", order=50)
    pipeline.register(first_step, name="first", order=10)

    res = pipeline.process(envelope={}, decrypted_payload={"payload_id": "test-1"})
    assert log == ["step_1", "step_2"]
    assert res.decrypted_payload["payload_id"] == "test-1"


def test_sanitize_string_value_credentials():
    # 1. URL credential scrubbing
    url_test = "git clone https://operator:super_secret_pass@github.com/org/repo.git"
    assert sanitize_string_value(url_test) == "git clone https://operator:[REDACTED]@github.com/org/repo.git"

    # 2. CLI password flag scrubbing
    cli_test = "mysql -u root --password=SuperSecretPassword123 database"
    assert sanitize_string_value(cli_test) == "mysql -u root --password=[REDACTED] database"

    # 3. Bearer token scrubbing
    bearer_test = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    assert sanitize_string_value(bearer_test) == "Authorization: Bearer [REDACTED]"

    # 4. Embedded AWS Access Key ID
    aws_test = "AccessKey: AKIAIOSFODNN7EXAMPLE"
    assert sanitize_string_value(aws_test) == "AccessKey: [REDACTED_AKIA_KEY]"


def test_pii_and_secret_scrubber():
    raw_payload = {
        "payload_id": "p-100",
        "agent_id": "a-100",
        "collectors": [
            {
                "collector": "cmd-monitor",
                "status": "success",
                "payload": {
                    "cmd": "curl -u admin:super_secret_password https://target.internal",
                    "cli_command": "deploy --api-key=AKIA1234567890EXAMPLE --password=mypassword",
                    "password": "super_secret_password",
                    "api_key": "AKIA1234567890EXAMPLE",
                    "auth_token": "Bearer eyJhbGciOi...",
                    "normal_field": "safe_value",
                },
            }
        ],
    }

    ctx = TelemetryContext(envelope={}, decrypted_payload=raw_payload)
    clean_ctx = pii_and_secret_scrubber(ctx)

    col_payload = clean_ctx.decrypted_payload["collectors"][0]["payload"]
    # Key-level redaction
    assert col_payload["password"] == "[REDACTED]"
    assert col_payload["api_key"] == "[REDACTED]"
    assert col_payload["auth_token"] == "[REDACTED]"
    assert col_payload["normal_field"] == "safe_value"

    # Value-level in-string redaction
    assert "[REDACTED]" in col_payload["cmd"]
    assert "super_secret_password" not in col_payload["cmd"]
    assert "--api-key=[REDACTED]" in col_payload["cli_command"]
    assert "--password=[REDACTED]" in col_payload["cli_command"]


def test_interceptor_failure_policies():
    """Verify that optional interceptors fail open while required interceptors fail closed."""
    import pytest

    pipeline = InterceptorPipeline()

    def optional_faulty(ctx: TelemetryContext) -> TelemetryContext:
        raise ValueError("Optional enrichment service timeout")

    def required_faulty(ctx: TelemetryContext) -> TelemetryContext:
        raise ValueError("Mandatory PII sanitization engine down")

    # 1. Optional interceptor fails open: error logged, processing continues
    pipeline.register(optional_faulty, name="optional_enricher", order=10, required=False)
    ctx1 = pipeline.process(envelope={}, decrypted_payload={"payload_id": "p1", "data": "raw"})
    assert ctx1.is_dropped is False
    assert ctx1.decrypted_payload["data"] == "raw"

    # 2. Required interceptor fails closed: raises RuntimeError and marks payload dropped
    pipeline.register(required_faulty, name="mandatory_sanitizer", order=20, required=True)
    with pytest.raises(RuntimeError, match="Required telemetry interceptor 'mandatory_sanitizer' failed"):
        pipeline.process(envelope={}, decrypted_payload={"payload_id": "p2", "data": "sensitive"})
