"""Runtime configuration. All secrets come from the environment; nothing is hard-coded for non-dev use."""

from __future__ import annotations

import functools
import hashlib
import hmac

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_PLACEHOLDER = "dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ASVAS_", env_file=".env", extra="ignore")

    env: str = Field(default="development", pattern="^(development|test|production)$")
    database_url: str = "postgresql+psycopg://asvas_app:asvas_app_dev@localhost:5432/asvas"
    migration_database_url: str = "postgresql+psycopg://asvas_owner:asvas_owner_dev@localhost:5432/asvas"
    redis_url: str = "redis://localhost:6379/0"
    redis_ca_file: str = ""  # CA bundle for rediss:// (dev CA from scripts/dev-certs.sh)
    opa_url: str = "http://127.0.0.1:8181"
    opa_timeout_seconds: float = 2.0
    opa_ca_file: str = ""  # CA bundle when ASVAS_OPA_URL is https:// (dev CA)
    # API gateway TLS (uvicorn). Required outside development.
    api_tls_cert: str = ""
    api_tls_key: str = ""

    jwt_secret: SecretStr = SecretStr(DEV_PLACEHOLDER)
    jwt_ttl_minutes: int = 60
    # Master key for HMAC signing of job envelopes and approval tokens (shared with execution plane).
    signing_key: SecretStr = SecretStr(DEV_PLACEHOLDER)

    # Model provider. "deterministic-test" is NOT an AI assessment and is labelled as such everywhere.
    model_provider: str = Field(default="deterministic-test", pattern="^(deterministic-test|anthropic)$")
    model_name: str = "claude-sonnet-4-5"
    anthropic_api_key: SecretStr | None = None
    anthropic_base_url: str = "https://api.anthropic.com"
    model_timeout_seconds: float = 10.0  # spec p.54: < 10 s
    # What to do when the live model fails: "none" = fail the planning round honestly (default);
    # "deterministic-test" = continue with the rule-based planner, recorded and shown as NOT AI.
    model_fallback: str = Field(default="none", pattern="^(none|deterministic-test)$")

    # Local test environments: loopback targets are refused unless explicitly enabled.
    allow_loopback_targets: bool = False
    # Ports of the platform itself; never valid targets even on loopback.
    protected_ports: list[int] = [5432, 6379, 8000, 8181, 5173, 7474, 7687, 6333, 7443]

    # Graph projection (Neo4j). Empty URI disables it; PostgreSQL stays the source of truth either way.
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("")

    # mTLS client material for the executors' gRPC ExecutorService (scripts/dev-certs.sh for development).
    executor_tls_ca: str = ""
    executor_tls_cert: str = ""
    executor_tls_key: str = ""

    # Key ring for envelope encryption at rest (local-file KMS stand-in; must be outside the repo, mode 0600).
    keyring_file: str = "../var/keys/keyring.json"

    rate_limit_per_minute: int = 100  # spec p.86
    approval_ttl_minutes: int = 15
    dispatch_grace_seconds: int = 20
    worker_stale_seconds: int = 15

    @model_validator(mode="after")
    def _refuse_dev_secrets_outside_dev(self) -> Settings:
        if self.env == "production":
            for name in ("jwt_secret", "signing_key"):
                if getattr(self, name).get_secret_value() == DEV_PLACEHOLDER:
                    raise ValueError(f"ASVAS_{name.upper()} must be set outside development")
                if len(getattr(self, name).get_secret_value()) < 32:
                    raise ValueError(f"ASVAS_{name.upper()} must be at least 32 characters")
            if self.allow_loopback_targets:
                raise ValueError("loopback targets cannot be enabled in production")
        return self

    def derived_key(self, purpose: str) -> bytes:
        return hmac.new(self.signing_key.get_secret_value().encode(), purpose.encode(), hashlib.sha256).digest()


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()
