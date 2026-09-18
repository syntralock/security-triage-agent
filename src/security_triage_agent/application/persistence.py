"""Framework-independent persistence records used at repository boundaries."""

from enum import StrEnum

from pydantic import Field, JsonValue, model_validator

from security_triage_agent.domain._base import (
    DomainModel,
    Identifier,
    UtcDatetime,
    Version,
)
from security_triage_agent.domain.actions import ActionProposal, ActionState
from security_triage_agent.domain.states import TriageExecutionState


class TriageExecutionRecord(DomainModel):
    execution_id: Identifier
    alert_id: Identifier
    state: TriageExecutionState
    idempotency_key: Identifier
    created_at: UtcDatetime
    updated_at: UtcDatetime
    predecessor_execution_id: Identifier | None = None
    failure_category: Identifier | None = None


class ActionExecutionRecord(DomainModel):
    action_execution_id: Identifier
    action_id: Identifier
    state: ActionState
    started_at: UtcDatetime
    completed_at: UtcDatetime | None = None
    outcome: Identifier | None = None
    failure_category: Identifier | None = None
    mode: str = "SIMULATED"
    result: dict[str, JsonValue] | None = None


class PersistedAction(DomainModel):
    execution_id: Identifier
    policy_version: Version
    action: ActionProposal


class AuditOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILED = "FAILED"


class AuditEvent(DomainModel):
    event_id: Identifier
    event_type: Identifier
    occurred_at: UtcDatetime
    target_type: Identifier
    target_id: Identifier
    data: dict[str, JsonValue] = Field(default_factory=dict)
    schema_version: Version = "1.0"
    execution_id: Identifier | None = None
    correlation_id: Identifier | None = None
    actor_id: Identifier | None = None
    outcome: AuditOutcome | None = None
    failure_category: Identifier | None = None

    @model_validator(mode="after")
    def bound_payload(self) -> "AuditEvent":
        if len(self.model_dump_json()) > 16_384:
            raise ValueError("audit event exceeds size limit")
        return self
