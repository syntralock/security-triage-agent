"""Capability-free reasoner and deterministic runtime ports."""

from datetime import datetime
from typing import Protocol

from security_triage_agent.application.orchestration_contracts import (
    ReasonerContext,
    ReasonerStep,
)


class AgentReasoner(Protocol):
    """Advisory component receiving data and returning one proposed next step."""

    def next_step(self, context: ReasonerContext) -> ReasonerStep: ...


class Clock(Protocol):
    def now(self) -> datetime: ...
    def monotonic_ms(self) -> int: ...


class IdentifierGenerator(Protocol):
    def next_id(self, purpose: str) -> str: ...
