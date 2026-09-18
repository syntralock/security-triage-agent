"""Typed data-only contracts for bounded reasoner orchestration."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field

from security_triage_agent.application.policy import CandidateAssessment, PolicyDecision
from security_triage_agent.domain._base import DomainModel, Identifier
from security_triage_agent.domain.alerts import SecurityAlert
from security_triage_agent.domain.evidence import EvidenceReference, ToolCallReference
from security_triage_agent.domain.triage import TriageResult


class ReasonerToolCall(DomainModel):
    step_type: Literal["TOOL_CALL"] = "TOOL_CALL"
    call_id: Identifier
    tool_name: Identifier
    arguments: dict[str, object]


class ReasonerCandidate(DomainModel):
    step_type: Literal["CANDIDATE"] = "CANDIDATE"
    candidate: CandidateAssessment


type ReasonerStep = Annotated[
    ReasonerToolCall | ReasonerCandidate,
    Field(discriminator="step_type"),
]


class AccumulatedEvidence(DomainModel):
    reference: EvidenceReference
    tool_call: ToolCallReference
    outcome: dict[str, object]


class ReasonerContext(DomainModel):
    alert: SecurityAlert
    evidence: tuple[AccumulatedEvidence, ...]
    iteration: int = Field(ge=1)
    remaining_iterations: int = Field(ge=0)
    remaining_total_tool_calls: int = Field(ge=0)


class OrchestrationReasonCode(StrEnum):
    COMPLETED = "COMPLETED"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    REASONER_FAILURE = "REASONER_FAILURE"
    INVALID_REASONER_OUTPUT = "INVALID_REASONER_OUTPUT"
    ITERATION_LIMIT = "ITERATION_LIMIT"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    TOOL_REQUEST_DENIED = "TOOL_REQUEST_DENIED"
    TOOL_FAILURE = "TOOL_FAILURE"
    CONTEXT_LIMIT = "CONTEXT_LIMIT"
    EVIDENCE_REFERENCE_VIOLATION = "EVIDENCE_REFERENCE_VIOLATION"
    POLICY_SAFE_REVIEW = "POLICY_SAFE_REVIEW"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"


class OrchestrationOutcome(DomainModel):
    execution_id: Identifier
    correlation_id: Identifier
    durable: bool
    reason_code: OrchestrationReasonCode
    result: TriageResult | None = None
    policy_decision: PolicyDecision | None = None


class OrchestrationLimits(DomainModel):
    max_iterations: int = Field(default=8, ge=1, le=100)
    deadline_ms: int = Field(default=5_000, ge=1, le=300_000)
    max_evidence_items: int = Field(default=16, ge=1, le=100)
    max_context_bytes: int = Field(default=131_072, ge=1_024, le=5_000_000)


class FixedClock:
    """Deterministic clock useful for offline adapters and tests."""

    def __init__(self, now: datetime, monotonic_values: tuple[int, ...] = (0,)) -> None:
        self._now = now
        self._values = iter(monotonic_values)
        self._last = monotonic_values[-1]

    def now(self) -> datetime:
        return self._now

    def monotonic_ms(self) -> int:
        self._last = next(self._values, self._last)
        return self._last


class SequenceIdentifierGenerator:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}

    def next_id(self, purpose: str) -> str:
        count = self._counts.get(purpose, 0) + 1
        self._counts[purpose] = count
        return f"{purpose}-{count:04d}"
