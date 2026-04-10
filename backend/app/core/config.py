"""
AEGIS Configuration — centralized settings loaded from environment variables.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from .env file and environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────
    app_name: str = "AEGIS"
    app_env: str = "development"
    log_level: str = "INFO"
    api_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # ── PostgreSQL ───────────────────────────────────────
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "aegis"
    postgres_user: str = "aegis"
    postgres_password: str = "aegis"
    database_url: str = "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"

    # ── Redis ────────────────────────────────────────────
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_url: str = "redis://localhost:6379/0"

    # ── OpenSearch ───────────────────────────────────────
    opensearch_enabled: bool = True
    opensearch_host: str = "http://localhost:9200"
    opensearch_alert_index: str = "alerts-v1"

    # ── Mistral AI / LLM ─────────────────────────────────
    mistral_api_key: str = "replace_me"
    mistral_model: str = "mistral-large-latest"
    summary_generation_enabled: bool = True

    # ── Splunk Bridge ────────────────────────────────────
    splunk_host: str = ""
    splunk_user: str = "admin"
    splunk_pass: str = ""
    splunk_token: str = ""
    splunk_index: str = "cowrie"
    splunk_poll_interval: int = 30
    aegis_api_url: str = "http://localhost:8000"

    # ── Correlation ──────────────────────────────────────
    correlation_lookback_minutes: int = 30
    correlation_attach_threshold: int = 30

    # ── Summary ──────────────────────────────────────────
    summary_min_alert_count: int = 2
    summary_min_severity_score: int = 40

    # ── MemPalace ────────────────────────────────────────
    mempalace_enabled: bool = False
    mempalace_palace_path: str = "~/.aegis/mempalace/"
    mempalace_mcp_port: int = 6333
    mempalace_wake_up_wing: str = "wing_attackers"

    # ── PCAP Analysis ────────────────────────────────────
    pcap_upload_dir: str = "./pcap_uploads"

    @property
    def async_database_url(self) -> str:
        """Return async-compatible database URL."""
        return self.database_url.replace("postgresql://", "postgresql+asyncpg://").replace(
            "postgresql+psycopg://", "postgresql+asyncpg://"
        )

    @property
    def sync_database_url(self) -> str:
        """Return sync-compatible database URL for Alembic."""
        url = self.database_url
        if "+asyncpg" in url:
            url = url.replace("+asyncpg", "+psycopg")
        return url


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
