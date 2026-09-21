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
    assert settings.openai_request_timeout_seconds == 25.0
    assert settings.stale_execution_seconds == 900
    assert settings.stale_action_execution_seconds == 300


def test_production_runtime_profile_fails_closed() -> None:
    settings = Settings(environment=Environment.PRODUCTION, _env_file=None)

    with pytest.raises(RuntimeError, match="production identity provider"):
        settings.validate_runtime_profile()


def test_openai_timeout_has_a_hard_upper_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STA_OPENAI_REQUEST_TIMEOUT_SECONDS", "25.1")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


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


def test_openai_prompt_version_selection_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STA_OPENAI_PROMPT_VERSION", "openai-l1-v2")
    assert Settings(_env_file=None).openai_prompt_version == "openai-l1-v2"

    monkeypatch.setenv("STA_OPENAI_PROMPT_VERSION", "unreviewed-v3")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


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
