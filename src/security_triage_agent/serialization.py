"""Explicit JSON serialization for immutable domain and reporting values."""

import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from pydantic import BaseModel


def to_jsonable(value: Any) -> Any:
    """Convert supported values without weakening immutable domain containers."""

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported JSON value type: {type(value).__name__}")


def safe_json_dumps(value: Any, *, indent: int | None = None) -> str:
    return json.dumps(to_jsonable(value), indent=indent, separators=None if indent else (",", ":"))
