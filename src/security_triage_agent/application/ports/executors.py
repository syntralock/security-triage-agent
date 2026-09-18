"""Port for capability-limited action execution adapters."""

from typing import Protocol

from pydantic import JsonValue

from security_triage_agent.domain._base import DomainModel
from security_triage_agent.domain.actions import ActionProposal


class ActionExecutionResult(DomainModel):
    mode: str
    outcome: str
    details: dict[str, JsonValue]


class ActionExecutor(Protocol):
    mode: str

    def execute(self, action: ActionProposal) -> ActionExecutionResult: ...
