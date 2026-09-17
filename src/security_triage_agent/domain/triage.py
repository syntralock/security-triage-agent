"""Triage assessment values and the final typed result contract."""

from enum import StrEnum

from pydantic import model_validator

from security_triage_agent.domain._base import (
    Confidence,
    DomainModel,
    Identifier,
    NonEmptyText,
    UtcDatetime,
)
from security_triage_agent.domain.actions import ActionProposal, ActionReference
from security_triage_agent.domain.evidence import EvidenceReference, ToolCallReference


class Disposition(StrEnum):
    """Closed set of supported triage outcomes."""

    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class Severity(StrEnum):
    """Closed severity scale used for source and assessed severity values."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TriageResult(DomainModel):
    """Policy-ready triage result containing traceable evidence and proposals."""

    alert_id: Identifier
    disposition: Disposition
    confidence: Confidence
    severity: Severity
    evidence: tuple[EvidenceReference, ...] = ()
    reasoning_summary: NonEmptyText
    recommended_actions: tuple[ActionProposal, ...] = ()
    actions_requiring_approval: tuple[ActionReference, ...] = ()
    escalation_required: bool
    escalation_reason: NonEmptyText | None = None
    tool_calls: tuple[ToolCallReference, ...] = ()
    timestamp: UtcDatetime

    @model_validator(mode="after")
    def validate_cross_references(self) -> "TriageResult":
        if self.escalation_required and self.escalation_reason is None:
            raise ValueError("escalation_reason is required when escalation_required is true")
        if not self.escalation_required and self.escalation_reason is not None:
            raise ValueError("escalation_reason must be absent when escalation_required is false")

        self._require_unique("evidence identifier", [item.evidence_id for item in self.evidence])
        self._require_unique(
            "tool call identifier", [item.invocation_id for item in self.tool_calls]
        )
        self._require_unique(
            "action identifier", [item.action_id for item in self.recommended_actions]
        )
        self._require_unique(
            "approval-required action identifier",
            [item.action_id for item in self.actions_requiring_approval],
        )

        tool_ids = {item.invocation_id for item in self.tool_calls}
        unresolved_tools = {
            item.tool_invocation_id
            for item in self.evidence
            if item.tool_invocation_id is not None and item.tool_invocation_id not in tool_ids
        }
        if unresolved_tools:
            raise ValueError("evidence references an unknown tool invocation")

        actions = {item.action_id: item for item in self.recommended_actions}
        for reference in self.actions_requiring_approval:
            action = actions.get(reference.action_id)
            if action is None or action.digest != reference.action_digest:
                raise ValueError("approval-required action must match a recommended action")
        return self

    @staticmethod
    def _require_unique(label: str, values: list[str]) -> None:
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {label}")
