"""
Configuration management for API-Hub-Pro (apihub-pro).
Supports PostgreSQL production settings, Redis distributed rate limiting & caching,
security policies, and Termux / local SQLite development profiles.
Never hardcodes production credentials; all sensitive values load from environment variables.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Dict


def _env_bool(key: str, default: bool = False) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_int(key: str, default: int) -> int:
    val = os.getenv(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


@dataclass
class Settings:
    app_name: str = field(default_factory=lambda: os.getenv("APIHUB_APP_NAME", "apihub-pro"))
    environment: str = field(default_factory=lambda: os.getenv("APIHUB_ENV", "development"))
    debug: bool = field(default_factory=lambda: _env_bool("APIHUB_DEBUG", False))
    host: str = field(default_factory=lambda: os.getenv("APIHUB_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("APIHUB_PORT", 8000))

    # Database / PostgreSQL production configuration
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./apihub_pro.db")
    )
    db_pool_size: int = field(default_factory=lambda: _env_int("DB_POOL_SIZE", 20))
    db_max_overflow: int = field(default_factory=lambda: _env_int("DB_MAX_OVERFLOW", 10))
    db_pool_timeout: int = field(default_factory=lambda: _env_int("DB_POOL_TIMEOUT", 30))
    db_pool_recycle: int = field(default_factory=lambda: _env_int("DB_POOL_RECYCLE", 1800))
    db_pool_pre_ping: bool = field(default_factory=lambda: _env_bool("DB_POOL_PRE_PING", True))
    db_ssl_mode: str = field(default_factory=lambda: os.getenv("DB_SSL_MODE", "prefer"))

    # Redis caching & distributed rate limiting configuration
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    redis_enabled: bool = field(default_factory=lambda: _env_bool("REDIS_ENABLED", True))
    redis_key_prefix: str = field(default_factory=lambda: os.getenv("REDIS_KEY_PREFIX", "apihub:"))
    cache_default_ttl_seconds: int = field(
        default_factory=lambda: _env_int("CACHE_DEFAULT_TTL_SECONDS", 60)
    )

    # Security & cryptographic secret management (stable workspace-derived dev fallback when env unset)
    secret_key: str = field(
        default_factory=lambda: os.getenv("APIHUB_SECRET_KEY")
        or hashlib.sha256(f"{os.path.abspath(os.getcwd())}:apihub-session-key".encode("utf-8")).hexdigest()
    )
    audit_hmac_secret: str = field(
        default_factory=lambda: os.getenv("APIHUB_AUDIT_HMAC_SECRET")
        or hashlib.sha256(f"{os.path.abspath(os.getcwd())}:apihub-audit-hmac".encode("utf-8")).hexdigest()
    )
    webhook_signing_secret: str = field(
        default_factory=lambda: os.getenv("APIHUB_WEBHOOK_SECRET")
        or hashlib.sha256(f"{os.path.abspath(os.getcwd())}:apihub-webhook-secret".encode("utf-8")).hexdigest()
    )

    # Request limits, timeouts & abuse prevention
    max_request_body_bytes: int = field(
        default_factory=lambda: _env_int("MAX_REQUEST_BODY_BYTES", 1024 * 1024)  # 1 MiB default
    )
    default_gateway_timeout_ms: int = field(
        default_factory=lambda: _env_int("DEFAULT_GATEWAY_TIMEOUT_MS", 5000)
    )
    max_gateway_timeout_ms: int = field(
        default_factory=lambda: _env_int("MAX_GATEWAY_TIMEOUT_MS", 30000)
    )

    # Login throttling, MFA & API key policies
    login_max_attempts: int = field(default_factory=lambda: _env_int("LOGIN_MAX_ATTEMPTS", 5))
    login_lockout_seconds: int = field(
        default_factory=lambda: _env_int("LOGIN_LOCKOUT_SECONDS", 300)
    )
    password_reset_ttl_seconds: int = field(
        default_factory=lambda: _env_int("PASSWORD_RESET_TTL_SECONDS", 900)
    )
    default_api_key_ttl_days: int = field(
        default_factory=lambda: _env_int("DEFAULT_API_KEY_TTL_DAYS", 90)
    )
    default_key_rotation_grace_seconds: int = field(
        default_factory=lambda: _env_int("DEFAULT_KEY_ROTATION_GRACE_SECONDS", 86400)
    )

    # Default rate limits (requests per minute)
    default_rpm_limit: int = field(default_factory=lambda: _env_int("DEFAULT_RPM_LIMIT", 60))

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith(("postgresql://", "postgresql+", "postgres://"))

    def get_sqlalchemy_engine_kwargs(self) -> Dict[str, object]:
        """Return production-grade SQLAlchemy engine kwargs for PostgreSQL or SQLite."""
        if self.is_postgres:
            return {
                "pool_size": self.db_pool_size,
                "max_overflow": self.db_max_overflow,
                "pool_timeout": self.db_pool_timeout,
                "pool_recycle": self.db_pool_recycle,
                "pool_pre_ping": self.db_pool_pre_ping,
                "connect_args": {"sslmode": self.db_ssl_mode},
            }
        return {"connect_args": {"check_same_thread": False}}


settings = Settings()
