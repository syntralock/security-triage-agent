"""Typed, environment-based application configuration."""

from enum import StrEnum
from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class ReasonerProvider(StrEnum):
    DEMO = "demo"
    OPENAI = "openai"


class Settings(BaseSettings):
    """Validated settings loaded from `STA_`-prefixed environment variables."""

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
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
    approval_lifetime_seconds: int = Field(default=900, ge=60, le=86_400)
    evaluation_path: str = Field(default="evaluations/v1/manifest.json", min_length=1)
    reasoner_provider: ReasonerProvider = ReasonerProvider.DEMO
    openai_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("OPENAI_API_KEY", "STA_OPENAI_API_KEY"),
        exclude=True,
    )
    openai_model: str = Field(default="gpt-5.6-luna", min_length=1, max_length=128)
    openai_request_timeout_seconds: float = Field(default=4.0, ge=1.0, le=5.0)
    openai_max_output_tokens: int = Field(default=1_500, ge=128, le=8_192)
    openai_prompt_version: Literal["openai-l1-v1"] = "openai-l1-v1"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return process settings, cached after the first validated load."""

    return Settings()
