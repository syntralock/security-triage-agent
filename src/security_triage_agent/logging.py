"""Structured logging with recursive sensitive-value redaction."""

import json
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final, TextIO

from security_triage_agent.config import Settings

REDACTED: Final = "[REDACTED]"
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "password",
        "refresh_token",
        "secret",
        "set-cookie",
        "token",
    }
)
_NORMALIZED_SENSITIVE_KEYS: Final = frozenset(key.replace("-", "_") for key in SENSITIVE_KEYS)


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in _NORMALIZED_SENSITIVE_KEYS or any(
        normalized.endswith(f"_{suffix}") for suffix in ("password", "secret", "token", "api_key")
    )


def redact(value: Any) -> Any:
    """Recursively redact values whose mapping keys indicate sensitive data."""

    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    """Render one JSON object per log event."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        context = getattr(record, "context", None)
        if context is not None:
            payload["context"] = redact(context)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(redact(payload), default=str, separators=(",", ":"), sort_keys=True)


class ConsoleFormatter(logging.Formatter):
    """Human-readable development formatter with redacted structured context."""

    def format(self, record: logging.LogRecord) -> str:
        base = f"{record.levelname:<8} {record.name} {record.getMessage()}"
        context = getattr(record, "context", None)
        if context is None:
            return base
        return f"{base} {json.dumps(redact(context), default=str, sort_keys=True)}"


def configure_logging(settings: Settings, stream: TextIO | None = None) -> None:
    """Configure the root logger once per call without retaining old handlers."""

    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter() if settings.log_format == "json" else ConsoleFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **context: Any,
) -> None:
    """Write a structured event through the standard logging package."""

    logger.log(level, event, extra={"context": context})
