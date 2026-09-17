"""Structured logging and redaction tests."""

import io
import json
import logging

from security_triage_agent.config import Settings
from security_triage_agent.logging import REDACTED, configure_logging, log_event, redact


def test_redact_recurses_through_mappings_and_sequences() -> None:
    value = {
        "user": "synthetic-user",
        "password": "do-not-log",  # pragma: allowlist secret
        "nested": [{"api_key": "do-not-log"}, {"safe": "visible"}],  # pragma: allowlist secret
        "service_token": "do-not-log",  # pragma: allowlist secret
    }

    assert redact(value) == {
        "user": "synthetic-user",
        "password": REDACTED,
        "nested": [{"api_key": REDACTED}, {"safe": "visible"}],
        "service_token": REDACTED,
    }


def test_json_logging_is_structured_and_redacted() -> None:
    stream = io.StringIO()
    settings = Settings(log_format="json", _env_file=None)
    configure_logging(settings, stream)

    log_event(
        logging.getLogger("test.security"),
        logging.INFO,
        "configuration_checked",
        api_key="do-not-log",  # pragma: allowlist secret
        subject="synthetic-user",
    )

    payload = json.loads(stream.getvalue())
    assert payload["event"] == "configuration_checked"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "test.security"
    assert payload["context"] == {"api_key": REDACTED, "subject": "synthetic-user"}
    assert "do-not-log" not in stream.getvalue()


def test_json_logging_supports_plain_and_exception_events() -> None:
    stream = io.StringIO()
    settings = Settings(log_format="json", _env_file=None)
    configure_logging(settings, stream)
    logger = logging.getLogger("test.security")

    logger.info("plain_event")
    try:
        raise ValueError("synthetic failure")
    except ValueError:
        logger.exception("exception_event")

    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert "context" not in lines[0]
    assert lines[1]["event"] == "exception_event"
    assert "ValueError: synthetic failure" in lines[1]["exception"]


def test_console_logging_redacts_context() -> None:
    stream = io.StringIO()
    settings = Settings(log_format="console", _env_file=None)
    configure_logging(settings, stream)

    sensitive_value = "hidden"
    log_event(
        logging.getLogger("test.security"),
        logging.WARNING,
        "test_event",
        **{"token": sensitive_value},
    )

    assert "WARNING" in stream.getvalue()
    assert REDACTED in stream.getvalue()
    assert "hidden" not in stream.getvalue()


def test_console_logging_supports_event_without_context() -> None:
    stream = io.StringIO()
    settings = Settings(log_format="console", _env_file=None)
    configure_logging(settings, stream)

    logging.getLogger("test.security").info("plain_event")

    assert stream.getvalue().strip() == "INFO     test.security plain_event"
