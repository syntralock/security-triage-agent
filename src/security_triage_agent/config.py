"""Typed, environment-based application configuration."""

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Validated settings loaded from `STA_`-prefixed environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="STA_",
        extra="ignore",
        case_sensitive=False,
    )

    environment: Environment = Environment.DEVELOPMENT
    service_name: str = Field(default="security-triage-agent", min_length=1, max_length=80)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    database_url: str = Field(default="sqlite:///security-triage-agent.db", min_length=1)
    fixture_path: str = Field(default="fixtures/v1", min_length=1)
    max_request_bytes: int = Field(default=65_536, ge=1_024, le=1_000_000)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return process settings, cached after the first validated load."""

    return Settings()
