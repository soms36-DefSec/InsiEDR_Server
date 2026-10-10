"""
server/config.py
----------------
Centralized Configuration Provider for the InsiEDR Server.

Loads configuration from process environment variables and optional .env files.
Provides strong type coercion, fallback defaults, secret loading, and audit redactions.

Configuration Groups:
- Cryptography: AES-256-GCM (production), Fernet (legacy), Plaintext (testing only)
- Persistence & Database: PostgreSQL connection DSN, automated migrations
- Message Queue & PubSub: Redis URL (high-throughput buffer) or Postgres queue fallback
- Telemetry & Retentions: Baseline EMA windows, replay deduplication, payload TTL
- Machine Learning (G-Model): Artifact directories, active model versions, pipeline switches
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519

from shared.crypto_utils import (
    CryptoConfigError,
    load_aes_key,
    redact_secret,
    redact_url_credentials,
    redact_dsn_credentials,
    load_x25519_private_key,
    export_x25519_public_key,
    public_key_fingerprint,
)


class ServerConfig:
    @staticmethod
    def _env_bool(name: str, default: bool = False) -> bool:
        return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")

    @property
    def aes_key_env(self) -> str | None:
        return os.environ.get("INSIEDR_AES_KEY") or os.environ.get("AES_KEY")

    @property
    def aes_key_path(self) -> str | None:
        return os.environ.get("INSIEDR_AES_KEY_PATH") or os.environ.get("AES_KEY_PATH")

    @property
    def database_dsn(self) -> str | None:
        return os.environ.get("INSIEDR_DATABASE_DSN") or os.environ.get("DATABASE_DSN")

    @property
    def redis_url(self) -> str | None:
        """Redis URL used as the high-throughput ML inference queue buffer and shared API cache.
        Falls back to the PostgreSQL-backed queue and in-memory cache when not configured.
        """
        return os.environ.get("INSIEDR_REDIS_URL") or os.environ.get("REDIS_URL")

    @property
    def cors_origins(self) -> list[str]:
        raw = os.environ.get("INSIEDR_CORS_ORIGINS", "")
        if raw.strip():
            return [x.strip() for x in raw.split(",") if x.strip()]
        return ["*"]

    @property
    def server_ip(self) -> str:
        """Authoritative server IP or hostname that agents must retain egress to when isolated."""
        return os.environ.get("INSIEDR_SERVER_IP") or os.environ.get("SERVER_IP", "127.0.0.1")

    @property
    def operator_api_key(self) -> str | None:
        return os.environ.get("INSIEDR_OPERATOR_API_KEY") or os.environ.get("OPERATOR_API_KEY")

    @property
    def operator_roles(self) -> dict[str, set[str]]:
        """
        Parses INSIEDR_OPERATOR_ROLES string formatted as 'token:role1,role2;token2:role3'.
        Defaults primary operator_api_key to {'admin'}.
        """
        roles_map: dict[str, set[str]] = {}
        if self.operator_api_key:
            roles_map[self.operator_api_key] = {"admin"}
        raw = os.environ.get("INSIEDR_OPERATOR_ROLES", "")
        if raw.strip():
            for entry in raw.split(";"):
                if ":" in entry:
                    tok, rlist = entry.split(":", 1)
                    tok = tok.strip()
                    if tok:
                        roles = {r.strip() for r in rlist.split(",") if r.strip()}
                        roles_map[tok] = roles
        return roles_map

    @property
    def environment(self) -> str:
        """Process execution environment: 'development', 'staging', 'test', or 'production'."""
        return (
            os.environ.get("INSIEDR_ENVIRONMENT")
            or os.environ.get("ENVIRONMENT")
            or os.environ.get("ENV", "development")
        ).strip().lower()

    @property
    def is_production(self) -> bool:
        return self.environment in ("production", "prod", "live")

    @property
    def auth_enforced(self) -> bool:
        """
        Whether strict authentication is enforced.
        Always True in production to eliminate permissive bypasses (audit finding I01).
        In non-production, defaults to True if credentials are configured,
        or if explicitly set via INSIEDR_AUTH_ENFORCED.
        """
        if self.is_production:
            return True
        raw = os.environ.get("INSIEDR_AUTH_ENFORCED")
        if raw is not None:
            return raw.lower() in ("1", "true", "yes", "on")
        return bool(self.operator_api_key or self.agent_bearer_token or self.agent_tokens or self.operator_roles)

    def validate_production_readiness(self) -> None:
        """
        Hard fail-safe validation when running in production.
        Prevents starting with permissive auth, missing keys, or insecure defaults (audit finding I01).
        """
        if not self.is_production:
            return

        errors = []
        if not (self.operator_api_key or self.operator_roles):
            errors.append("INSIEDR_OPERATOR_API_KEY or INSIEDR_OPERATOR_ROLES must be set in production")
        if not (self.agent_bearer_token or self.agent_tokens):
            errors.append("INSIEDR_AGENT_BEARER_TOKEN or INSIEDR_AGENT_TOKENS must be set in production")
        if not self.secret_key:
            errors.append("INSIEDR_SECRET_KEY must be configured in production")

        if errors:
            raise RuntimeError(
                "Production readiness validation failed:\n - " + "\n - ".join(errors)
            )

    @property
    def max_request_bytes(self) -> int:
        raw = os.environ.get("INSIEDR_MAX_REQUEST_BYTES", "10485760")  # 10 MB default
        try:
            return int(raw)
        except ValueError:
            return 10485760

    @property
    def max_collectors_per_payload(self) -> int:
        raw = os.environ.get("INSIEDR_MAX_COLLECTORS", "100")
        try:
            return int(raw)
        except ValueError:
            return 100

    @property
    def clickhouse_host(self) -> str:
        return os.environ.get("INSIEDR_CLICKHOUSE_HOST") or os.environ.get("CLICKHOUSE_HOST", "localhost")

    @property
    def clickhouse_port(self) -> int:
        raw = os.environ.get("INSIEDR_CLICKHOUSE_PORT") or os.environ.get("CLICKHOUSE_PORT", "8123")
        try:
            return int(raw)
        except ValueError:
            return 8123

    @property
    def clickhouse_user(self) -> str:
        return os.environ.get("INSIEDR_CLICKHOUSE_USER") or os.environ.get("CLICKHOUSE_USER", "default")

    @property
    def clickhouse_password(self) -> str:
        return os.environ.get("INSIEDR_CLICKHOUSE_PASSWORD") or os.environ.get("CLICKHOUSE_PASSWORD", "")

    @property
    def clickhouse_db(self) -> str:
        return os.environ.get("INSIEDR_CLICKHOUSE_DB") or os.environ.get("CLICKHOUSE_DB", "insiedr_analytics")

    @property
    def clickhouse_enabled(self) -> bool:
        return self._env_bool("INSIEDR_CLICKHOUSE_ENABLED", True)

    @property
    def telemetry_read_backend(self) -> str:
        default_backend = "clickhouse" if self.clickhouse_enabled else "postgres"
        return os.environ.get('INSIEDR_TELEMETRY_READ_BACKEND', default_backend).strip().lower()

    @property
    def clickhouse_secure(self) -> bool:
        return self._env_bool("INSIEDR_CLICKHOUSE_SECURE", False)

    @property
    def clickhouse_ca_cert(self) -> str | None:
        return os.environ.get("INSIEDR_CLICKHOUSE_CA_CERT")

    @property
    def clickhouse_query_timeout(self) -> int:
        raw = os.environ.get("INSIEDR_CLICKHOUSE_QUERY_TIMEOUT", "30")
        try:
            return int(raw)
        except ValueError:
            return 30

    @property
    def clickhouse_max_memory(self) -> int:
        raw = os.environ.get("INSIEDR_CLICKHOUSE_MAX_MEMORY", "2000000000")
        try:
            return int(raw)
        except ValueError:
            return 2000000000

    @property
    def dlq_enabled(self) -> bool:
        return self._env_bool("INSIEDR_DLQ_ENABLED", True)

    @property
    def dlq_dir(self) -> str:
        return os.environ.get("INSIEDR_DLQ_DIR", "data/dlq")

    @property
    def ch_batch_max_rows(self) -> int:
        """Maximum rows held in the ClickHouse in-memory batch buffer."""
        try:
            return int(os.environ.get("INSIEDR_CH_BATCH_MAX_ROWS", "10000"))
        except ValueError:
            return 10000

    @property
    def ch_batch_max_bytes(self) -> int:
        """Maximum bytes held in the ClickHouse in-memory batch buffer (default 10 MB)."""
        try:
            return int(os.environ.get("INSIEDR_CH_BATCH_MAX_BYTES", str(10 * 1024 * 1024)))
        except ValueError:
            return 10 * 1024 * 1024

    @property
    def ch_batch_flush_interval(self) -> float:
        """Seconds between periodic ClickHouse batch flushes."""
        try:
            return float(os.environ.get("INSIEDR_CH_BATCH_FLUSH_INTERVAL", "2.0"))
        except ValueError:
            return 2.0

    @property
    def redis_ssl(self) -> bool:
        return self._env_bool("INSIEDR_REDIS_SSL", False)

    @property
    def migrations_auto(self) -> bool:
        return os.environ.get("INSIEDR_MIGRATIONS_AUTO", "true").lower() in ("1", "true", "yes")

    @property
    def secret_key(self) -> str | None:
        return os.environ.get("INSIEDR_SECRET_KEY") or os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or os.environ.get("INSIEDR_FLASK_SECRET_KEY")

    @property
    def flask_secret_key(self) -> str | None:
        """Backward compatibility alias for secret_key."""
        return self.secret_key

    @property
    def require_https(self) -> bool:
        return os.environ.get("INSIEDR_REQUIRE_HTTPS", "true").lower() in ("1", "true", "yes")

    @property
    def agent_bearer_token(self) -> str | None:
        return os.environ.get("INSIEDR_AGENT_BEARER_TOKEN")

    @property
    def agent_tokens(self) -> dict[str, str]:
        """
        Parses INSIEDR_AGENT_TOKENS string into a mapping of {token: agent_id}.
        Supports:
          - Semicolon-delimited: 'token1:agent-001;token2:agent-002' or 'agent-001:token1;agent-002:token2'
          - JSON dictionary: '{"agent-001": "token1"}' or '{"token1": "agent-001"}'
        """
        raw = os.environ.get("INSIEDR_AGENT_TOKENS", "").strip()
        if not raw:
            return {}
        if raw.startswith("{") and raw.endswith("}"):
            try:
                import json
                data = json.loads(raw)
                mapping: dict[str, str] = {}
                for k, v in data.items():
                    k_str = str(k).strip()
                    v_str = str(v).strip()
                    if k_str.startswith("agent-") or k_str.startswith("AGENT-"):
                        mapping[v_str] = k_str
                    else:
                        mapping[k_str] = v_str
                return mapping
            except Exception:
                pass
        mapping = {}
        for entry in raw.split(";"):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            part1, part2 = entry.split(":", 1)
            p1 = part1.strip()
            p2 = part2.strip()
            if not p1 or not p2:
                continue
            if p1.startswith("agent-") or p1.startswith("AGENT-"):
                mapping[p2] = p1
            elif p2.startswith("agent-") or p2.startswith("AGENT-"):
                mapping[p1] = p2
            else:
                mapping[p1] = p2
        return mapping

    @property
    def agent_tokens_configured(self) -> bool:
        """True if per-agent tokens are configured in the token registry."""
        return bool(self.agent_tokens)

    @property
    def active_model_version(self) -> str:
        """The currently active ML artifact schema version (e.g., 'v2')."""
        return os.environ.get("INSIEDR_ACTIVE_MODEL_VERSION", "v2")

    def load_aes_key(self) -> bytes:
        return load_aes_key(env_value=self.aes_key_env, key_path=self.aes_key_path)

    @property
    def replay_window_hours(self) -> int:
        raw = os.environ.get("INSIEDR_REPLAY_WINDOW_HOURS", "24")
        try:
            value = int(raw)
        except ValueError:
            value = 24
        return max(value, 1)

    @property
    def payload_retention_days(self) -> int:
        """Data Retention Policy (VERIFY_REQUIRED): Legal/Privacy must approve this default."""
        raw = os.environ.get("INSIEDR_PAYLOAD_RETENTION_DAYS", "30")
        try:
            value = int(raw)
        except ValueError:
            value = 30
        return max(value, 1)

    @property
    def feature_retention_days(self) -> int:
        """Data Retention Policy (VERIFY_REQUIRED): Legal/Privacy must approve this default."""
        raw = os.environ.get("INSIEDR_FEATURE_RETENTION_DAYS", "90")
        try:
            value = int(raw)
        except ValueError:
            value = 90
        return max(value, 1)

    @property
    def baseline_window_days(self) -> int:
        """Baseline Window Size for ML EMA decay calculations."""
        raw = os.environ.get("INSIEDR_BASELINE_WINDOW_DAYS", "14")
        try:
            value = int(raw)
        except ValueError:
            value = 14
        return max(value, 1)

    @property
    def zscore_calibration_threshold(self) -> float:
        """Dynamic calibration cutoff for Z-Score models."""
        raw = os.environ.get("INSIEDR_ZSCORE_CALIBRATION_THRESHOLD", "8.0")
        try:
            return float(raw)
        except ValueError:
            return 8.0

    @property
    def enable_fernet(self) -> bool:
        return self._env_bool("INSIEDR_ENABLE_FERNET", False)

    @property
    def enable_plaintext_crypto(self) -> bool:
        return self._env_bool("INSIEDR_ENABLE_PLAINTEXT_CRYPTO", False)

    @property
    def store_plaintext_payloads(self) -> bool:
        return self._env_bool("INSIEDR_STORE_PLAINTEXT_PAYLOADS", False)

    @property
    def enable_model_pipeline(self) -> bool:
        return self._env_bool("INSIEDR_ENABLE_MODEL_PIPELINE", False)

    @property
    def model_isolation_forest_path(self) -> str:
        return os.environ.get("INSIEDR_MODEL_IF_PATH", "v2_domain_isolation_forest.pkl")

    @property
    def model_scenario_xgb_path(self) -> str:
        return os.environ.get("INSIEDR_MODEL_XGB_PATH", "v2_scenario_xgb.pkl")

    @property
    def model_inference_dir(self) -> str:
        return os.environ.get("INSIEDR_MODEL_INFERENCE_DIR", ".")  # src/ and models/ live at repo root

    @property
    def g_model_models_dir(self) -> str:
        """
        Resolves to the G-model's artifact directory (latest_data/models/).
        All .pkl files are loaded from InsiEDR-G-model-latest-dataset IN-PLACE.
        Nothing is copied or moved.
        """
        base = self.model_inference_dir
        candidate = os.path.join(base, "latest_data", "models")
        if os.path.isdir(candidate):
            return candidate
        candidate2 = os.path.join(base, "model", "latest_data", "models")
        if os.path.isdir(candidate2):
            return candidate2
        # Fallback: if pointed at old-style layout where models/ sits at the root
        return os.path.join(base, "models")

    @property
    def fernet_key_env(self) -> str | None:
        return os.environ.get("INSIEDR_FERNET_KEY") or os.environ.get("FERNET_KEY")

    @property
    def fernet_key_path(self) -> str | None:
        return os.environ.get("INSIEDR_FERNET_KEY_PATH") or os.environ.get("FERNET_KEY_PATH")

    def load_fernet_key(self) -> bytes:
        # Fernet keys are URL-safe base64 bytes as returned by Fernet.generate_key()
        if self.fernet_key_env:
            val = self.fernet_key_env
            return val.encode("ascii") if isinstance(val, str) else val
        if self.fernet_key_path:
            path = self.fernet_key_path
            from pathlib import Path

            p = Path(path).expanduser()
            if not p.is_file():
                raise CryptoConfigError(f"Fernet key file does not exist: {p}")
    @property
    def hpke_private_key_env(self) -> str | None:
        return os.environ.get("INSIEDR_HPKE_PRIVATE_KEY") or os.environ.get("HPKE_PRIVATE_KEY")

    @property
    def hpke_private_key_path(self) -> str | None:
        return os.environ.get("INSIEDR_HPKE_PRIVATE_KEY_PATH") or os.environ.get("HPKE_PRIVATE_KEY_PATH")

    @property
    def hpke_key_id(self) -> str:
        return os.environ.get("INSIEDR_HPKE_KEY_ID") or os.environ.get("HPKE_KEY_ID", "default")

    @property
    def hpke_keys_dir(self) -> str | None:
        return os.environ.get("INSIEDR_HPKE_KEYS_DIR") or os.environ.get("HPKE_KEYS_DIR")

    def load_hpke_private_keys(self) -> dict[str, x25519.X25519PrivateKey]:
        """Loads all available HPKE private keys into a key_id -> X25519PrivateKey mapping."""
        keys: dict[str, x25519.X25519PrivateKey] = {}

        # 1. Primary key from env
        if self.hpke_private_key_env:
            try:
                keys[self.hpke_key_id] = load_x25519_private_key(self.hpke_private_key_env)
            except Exception as exc:
                raise CryptoConfigError(f"failed to load HPKE private key from environment: {exc}") from exc

        # 2. Primary key from file
        if self.hpke_private_key_path:
            path = Path(self.hpke_private_key_path).expanduser()
            if not path.is_file():
                raise CryptoConfigError(f"HPKE private key file does not exist: {path}")
            try:
                keys[self.hpke_key_id] = load_x25519_private_key(path.read_bytes())
            except Exception as exc:
                raise CryptoConfigError(f"failed to load HPKE private key from file {path}: {exc}") from exc

        # 3. Keys from directory (multi-key rotation support)
        if self.hpke_keys_dir:
            kdir = Path(self.hpke_keys_dir).expanduser()
            if kdir.is_dir():
                for ext in ("*.pem", "*.key"):
                    for key_file in kdir.glob(ext):
                        kid = key_file.stem
                        if kid not in keys:
                            try:
                                keys[kid] = load_x25519_private_key(key_file.read_bytes())
                            except Exception:
                                pass

        return keys

    def load_hpke_public_keys(self) -> list[dict[str, str]]:
        """Returns a list of public key metadata for discovery and client provisioning."""
        keys = self.load_hpke_private_keys()
        output = []
        for kid, priv in keys.items():
            pub = priv.public_key()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            raw_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            output.append({
                "key_id": kid,
                "scheme": "hpke",
                "algorithm": "DHKEM(X25519, HKDF-SHA256)",
                "public_key": export_x25519_public_key(pub),
                "public_key_pem": export_x25519_public_key(pub, as_pem=True),
                "fingerprint": public_key_fingerprint(raw_bytes),
                "is_primary": (kid == self.hpke_key_id),
            })
        return output

    def redact(self) -> dict[str, Optional[str]]:
        return {
            "aes_key": redact_secret(self.aes_key_env) if self.aes_key_env else None,
            "aes_key_path": self.aes_key_path,
            "hpke_private_key": redact_secret(self.hpke_private_key_env) if self.hpke_private_key_env else None,
            "hpke_private_key_path": self.hpke_private_key_path,
            "hpke_key_id": self.hpke_key_id,
            "fernet_key": redact_secret(self.fernet_key_env) if self.fernet_key_env else None,
            "fernet_key_path": self.fernet_key_path,
            "database_dsn": redact_dsn_credentials(self.database_dsn) if self.database_dsn else None,
            "redis_url": redact_url_credentials(self.redis_url) if self.redis_url else None,
            "clickhouse_password": "<redacted>" if self.clickhouse_password else None,
            "agent_bearer_token": "<redacted>" if self.agent_bearer_token else None,
            "replay_window_hours": str(self.replay_window_hours),
            "enable_fernet": str(self.enable_fernet),
            "enable_plaintext_crypto": str(self.enable_plaintext_crypto),
            "enable_model_pipeline": str(self.enable_model_pipeline),
            "model_inference_dir": self.model_inference_dir,
            "clickhouse_host": self.clickhouse_host,
            "clickhouse_port": str(self.clickhouse_port),
            "clickhouse_db": self.clickhouse_db,
            "clickhouse_enabled": str(self.clickhouse_enabled),
        }


config = ServerConfig()

