"""Versioned deterministic enforcement for untrusted candidate assessments."""

from collections.abc import Callable
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import ValidationError

from security_triage_agent.application.action_catalog import ActionCatalog
from security_triage_agent.domain._base import (
    Confidence,
    DomainModel,
    Identifier,
    NonEmptyText,
    UtcDatetime,
    Version,
)
from security_triage_agent.domain.actions import (
    ActionProposal,
    ActionRecommendation,
    ActionReference,
)
from security_triage_agent.domain.entities import EntityReference
from security_triage_agent.domain.evidence import EvidenceReference, ToolCallReference
from security_triage_agent.domain.triage import Disposition, Severity, TriageResult

POLICY_VERSION = "1.0.0"


class CandidateAssessment(DomainModel):
    """Untrusted advisory proposal with no approval or policy authority."""

    disposition: Disposition
    severity: Severity
    confidence: Confidence
    evidence: tuple[EvidenceReference, ...] = ()
    reasoning_summary: NonEmptyText
    recommended_actions: tuple[ActionRecommendation, ...] = ()
    escalation_required: bool = False
    escalation_reason: NonEmptyText | None = None
    tool_calls: tuple[ToolCallReference, ...] = ()


class PolicyReasonCode(StrEnum):
    ACCEPTED = "ACCEPTED"
    CANDIDATE_INVALID = "CANDIDATE_INVALID"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    INVALID_ACTION_PARAMETERS = "INVALID_ACTION_PARAMETERS"
    UNSUPPORTED_TARGET_TYPE = "UNSUPPORTED_TARGET_TYPE"
    ACTION_TARGET_OUT_OF_SCOPE = "ACTION_TARGET_OUT_OF_SCOPE"
    CANDIDATE_ESCALATION = "CANDIDATE_ESCALATION"


class RejectedAction(DomainModel):
    catalog_action_id: Identifier
    reason_code: PolicyReasonCode


class PolicyDecision(DomainModel):
    policy_version: Version
    result: TriageResult
    reason_codes: tuple[PolicyReasonCode, ...]
    accepted_action_ids: tuple[Identifier, ...]
    rejected_actions: tuple[RejectedAction, ...]


class AuthorizedActionScope(DomainModel):
    keys: frozenset[str]

    @classmethod
    def from_entities(cls, entities: tuple[EntityReference, ...]) -> "AuthorizedActionScope":
        return cls(keys=frozenset(entity.scope_key for entity in entities))


class DeterministicPolicy:
    """Pure rule evaluation; no tools, databases, models, or network access."""

    version = POLICY_VERSION

    def __init__(self, catalog: ActionCatalog, action_id_factory: Callable[[], str]) -> None:
        self._catalog = catalog
        self._action_id_factory = action_id_factory

    def evaluate(
        self,
        candidate: CandidateAssessment,
        *,
        alert_id: str,
        action_scope: AuthorizedActionScope,
        timestamp: datetime,
    ) -> PolicyDecision:
        reasons: list[PolicyReasonCode] = []
        accepted: list[ActionProposal] = []
        approvals: list[ActionReference] = []
        rejected: list[RejectedAction] = []

        if candidate.disposition is not Disposition.NEEDS_REVIEW and not candidate.evidence:
            reasons.append(PolicyReasonCode.INSUFFICIENT_EVIDENCE)

        for action in candidate.recommended_actions:
            definition = self._catalog.lookup(action.catalog_action_id)
            reason: PolicyReasonCode | None = None
            if definition is None:
                reason = PolicyReasonCode.UNKNOWN_ACTION
            elif action.target.entity_type not in definition.target_types:
                reason = PolicyReasonCode.UNSUPPORTED_TARGET_TYPE
            elif action.target.scope_key not in action_scope.keys:
                reason = PolicyReasonCode.ACTION_TARGET_OUT_OF_SCOPE
            else:
                try:
                    definition.parameters_model.model_validate(dict(action.parameters), strict=True)
                except ValidationError:
                    reason = PolicyReasonCode.INVALID_ACTION_PARAMETERS
            if reason is not None:
                reasons.append(reason)
                rejected.append(
                    RejectedAction(
                        catalog_action_id=action.catalog_action_id,
                        reason_code=reason,
                    )
                )
                continue
            canonical = action.canonicalize(self._action_id_factory())
            accepted.append(canonical)
            if definition is not None and definition.approval_required:
                approvals.append(ActionReference.from_proposal(canonical))

        if candidate.escalation_required:
            reasons.append(PolicyReasonCode.CANDIDATE_ESCALATION)
        forced_review = any(
            reason
            in {
                PolicyReasonCode.INSUFFICIENT_EVIDENCE,
                PolicyReasonCode.UNKNOWN_ACTION,
                PolicyReasonCode.INVALID_ACTION_PARAMETERS,
                PolicyReasonCode.UNSUPPORTED_TARGET_TYPE,
                PolicyReasonCode.ACTION_TARGET_OUT_OF_SCOPE,
            }
            for reason in reasons
        )
        escalation = candidate.escalation_required or forced_review
        final_disposition = Disposition.NEEDS_REVIEW if forced_review else candidate.disposition
        if forced_review:
            escalation_reason = "Deterministic policy requires human review: " + ", ".join(
                sorted(
                    {reason.value for reason in reasons if reason is not PolicyReasonCode.ACCEPTED}
                )
            )
        elif candidate.escalation_required:
            escalation_reason = candidate.escalation_reason or "Candidate requested human review."
        else:
            escalation_reason = None
        if not reasons:
            reasons.append(PolicyReasonCode.ACCEPTED)

        try:
            result = TriageResult(
                alert_id=alert_id,
                disposition=final_disposition,
                confidence=candidate.confidence,
                severity=candidate.severity,
                evidence=candidate.evidence,
                reasoning_summary=candidate.reasoning_summary,
                recommended_actions=tuple(accepted),
                actions_requiring_approval=tuple(approvals),
                escalation_required=escalation,
                escalation_reason=escalation_reason,
                tool_calls=candidate.tool_calls,
                timestamp=timestamp,
            )
        except ValidationError:
            return self._safe_review(alert_id, timestamp)
        return PolicyDecision(
            policy_version=self.version,
            result=result,
            reason_codes=tuple(dict.fromkeys(reasons)),
            accepted_action_ids=tuple(action.action_id for action in accepted),
            rejected_actions=tuple(rejected),
        )

    def evaluate_untrusted(
        self,
        payload: object,
        *,
        alert_id: str,
        action_scope: AuthorizedActionScope,
        timestamp: UtcDatetime,
    ) -> PolicyDecision:
        """Parse an untrusted boundary payload or produce a safe review result."""

        try:
            candidate = CandidateAssessment.model_validate(payload)
        except (ValidationError, TypeError, ValueError):
            return self._safe_review(alert_id, timestamp)
        return self.evaluate(
            candidate,
            alert_id=alert_id,
            action_scope=action_scope,
            timestamp=timestamp,
        )

    def _safe_review(self, alert_id: str, timestamp: datetime) -> PolicyDecision:
        result = TriageResult(
            alert_id=alert_id,
            disposition=Disposition.NEEDS_REVIEW,
            confidence=Decimal("0"),
            severity=Severity.INFORMATIONAL,
            reasoning_summary="Candidate assessment failed deterministic validation.",
            escalation_required=True,
            escalation_reason="Deterministic policy could not validate the candidate assessment.",
            timestamp=timestamp,
        )
        return PolicyDecision(
            policy_version=self.version,
            result=result,
            reason_codes=(PolicyReasonCode.CANDIDATE_INVALID,),
            accepted_action_ids=(),
            rejected_actions=(),
        )
