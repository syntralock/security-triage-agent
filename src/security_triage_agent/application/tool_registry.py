"""Closed registry for explicitly trusted read-only evidence tools."""

from collections.abc import Iterable, Iterator, Mapping
from types import MappingProxyType
from typing import Any, cast

from pydantic import BaseModel

from security_triage_agent.application.ports.tools import EvidenceTool, ToolAccess, ToolMetadata


class ToolRegistrationError(ValueError):
    """Raised when trusted composition code attempts an invalid registration."""


APPROVED_EVIDENCE_TOOLS = frozenset(
    {
        "get_recent_signins",
        "get_user_risk",
        "get_device_context",
        "get_ip_reputation",
        "get_mfa_events",
        "find_related_alerts",
        "get_identity_context",
    }
)


class ToolRegistry(Mapping[str, EvidenceTool[Any, Any]]):
    """Immutable name-to-implementation map built only by trusted composition code."""

    def __init__(self, tools: Iterable[EvidenceTool[Any, Any]]) -> None:
        registered: dict[str, EvidenceTool[Any, Any]] = {}
        for tool in tools:
            metadata = tool.metadata
            if metadata.name not in APPROVED_EVIDENCE_TOOLS:
                raise ToolRegistrationError(f"tool {metadata.name!r} is not approved")
            if metadata.access is not ToolAccess.READ_ONLY:
                raise ToolRegistrationError(f"tool {metadata.name!r} is not read-only")
            if metadata.name in registered:
                raise ToolRegistrationError(f"duplicate tool registration: {metadata.name!r}")
            if metadata.timeout_ms <= 0:
                raise ToolRegistrationError(f"tool {metadata.name!r} has an invalid timeout")
            registered[metadata.name] = tool
        self._tools = MappingProxyType(registered)

    def __getitem__(self, name: str) -> EvidenceTool[Any, Any]:
        return self._tools[name]

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._tools))

    def __len__(self) -> int:
        return len(self._tools)

    @property
    def metadata(self) -> tuple[ToolMetadata[BaseModel, BaseModel], ...]:
        """Return deterministic immutable metadata without exposing implementations."""

        return tuple(
            cast(ToolMetadata[BaseModel, BaseModel], self._tools[name].metadata) for name in self
        )

    def lookup(self, name: str) -> EvidenceTool[Any, Any] | None:
        """Look up an explicitly registered implementation without dynamic resolution."""

        return self._tools.get(name)
