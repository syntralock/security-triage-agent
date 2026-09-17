"""Triage execution lifecycle concepts and transition rules."""

from enum import StrEnum
from typing import Self

from security_triage_agent.domain._base import DomainModel, Identifier
from security_triage_agent.domain.errors import InvalidStateTransitionError


class TriageExecutionState(StrEnum):
    """States for one immutable-history triage execution."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


_TRIAGE_TRANSITIONS: dict[TriageExecutionState, frozenset[TriageExecutionState]] = {
    TriageExecutionState.PENDING: frozenset({TriageExecutionState.RUNNING}),
    TriageExecutionState.RUNNING: frozenset(
        {
            TriageExecutionState.COMPLETED,
            TriageExecutionState.FAILED,
            TriageExecutionState.NEEDS_REVIEW,
        }
    ),
    TriageExecutionState.COMPLETED: frozenset(),
    TriageExecutionState.FAILED: frozenset(),
    TriageExecutionState.NEEDS_REVIEW: frozenset(),
}


class TriageExecution(DomainModel):
    """Immutable triage execution state with explicit legal transitions."""

    execution_id: Identifier
    alert_id: Identifier
    state: TriageExecutionState = TriageExecutionState.PENDING

    def transition_to(self, target: TriageExecutionState) -> Self:
        if not isinstance(target, TriageExecutionState):
            raise TypeError("target must be a TriageExecutionState")
        if target not in _TRIAGE_TRANSITIONS[self.state]:
            raise InvalidStateTransitionError("triage execution", self.state, target)
        return self.model_copy(update={"state": target})
