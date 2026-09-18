"""Foundation configuration tests."""

import pytest
from pydantic import ValidationError

from security_triage_agent.config import Environment, ReasonerProvider, Settings


def test_settings_have_safe_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.environment is Environment.DEVELOPMENT
    assert settings.service_name == "security-triage-agent"
    assert settings.log_level == "INFO"
    assert settings.log_format == "json"


def test_settings_load_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STA_ENVIRONMENT", "test")
    monkeypatch.setenv("STA_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("STA_LOG_FORMAT", "console")

    settings = Settings(_env_file=None)

    assert settings.environment is Environment.TEST
    assert settings.log_level == "WARNING"
    assert settings.log_format == "console"


def test_openai_configuration_is_trusted_and_secret_is_excluded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STA_REASONER_PROVIDER", "openai")
    monkeypatch.setenv("STA_OPENAI_MODEL", "configured-model")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    settings = Settings(_env_file=None)
    assert settings.reasoner_provider is ReasonerProvider.OPENAI
    assert settings.openai_model == "configured-model"
    assert settings.openai_api_key is not None
    assert "synthetic-test-key" not in repr(settings)
    assert "synthetic-test-key" not in settings.model_dump_json()


@pytest.mark.parametrize(
    ("name", "value"),
    [("STA_ENVIRONMENT", "staging"), ("STA_LOG_LEVEL", "TRACE"), ("STA_LOG_FORMAT", "xml")],
)
def test_settings_reject_unknown_closed_values(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
