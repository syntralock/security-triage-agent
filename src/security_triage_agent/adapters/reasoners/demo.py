"""Deterministic local demo reasoner; no model or network access."""

from decimal import Decimal

from security_triage_agent.application.orchestration_contracts import (
    ReasonerCandidate,
    ReasonerContext,
    ReasonerStep,
    ReasonerToolCall,
)
from security_triage_agent.application.policy import CandidateAssessment
from security_triage_agent.domain.actions import ActionProposal
from security_triage_agent.domain.entities import EntityType
from security_triage_agent.domain.triage import Disposition, Severity


class DemoReasoner:
    """Request user risk once, then return a conservative review candidate."""

    def next_step(self, context: ReasonerContext) -> ReasonerStep:
        user = next(
            (entity for entity in context.alert.entities if entity.entity_type is EntityType.USER),
            None,
        )
        if not context.evidence and user is not None and context.remaining_total_tool_calls > 0:
            return ReasonerToolCall(
                call_id=f"demo-risk-{context.alert.alert_id}",
                tool_name="get_user_risk",
                arguments={"user_id": str(user.identifier)},
            )
        actions: tuple[ActionProposal, ...] = ()
        if user is not None and context.alert.source_severity in {Severity.HIGH, Severity.CRITICAL}:
            actions = (
                ActionProposal(
                    action_id=f"demo-revoke-{context.alert.alert_id}",
                    catalog_action_id="revoke_sessions",
                    target=user,
                    parameters={},
                    rationale=(
                        "Synthetic high-severity demo alert warrants analyst review of session "
                        "revocation."
                    ),
                ),
            )
        return ReasonerCandidate(
            candidate=CandidateAssessment(
                disposition=Disposition.NEEDS_REVIEW,
                severity=context.alert.source_severity,
                confidence=Decimal("0.5"),
                evidence=tuple(item.reference for item in context.evidence),
                reasoning_summary=(
                    "Deterministic demo triage collected available synthetic evidence; "
                    "human review remains required."
                ),
                recommended_actions=actions,
                escalation_required=True,
                escalation_reason="Deterministic demo mode always requires analyst review.",
                tool_calls=tuple(item.tool_call for item in context.evidence),
            )
        )
