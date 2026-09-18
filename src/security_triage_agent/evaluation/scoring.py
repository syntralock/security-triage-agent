"""Transparent component scoring without opaque aggregate weighting."""

from enum import StrEnum

from pydantic import Field

from security_triage_agent.application.orchestration_contracts import OrchestrationOutcome
from security_triage_agent.application.tool_gateway import (
    AuthorizationResult,
    GatewayStatus,
    ToolInvocationRecord,
)
from security_triage_agent.domain._base import DomainModel, Identifier
from security_triage_agent.domain.triage import Disposition
from security_triage_agent.evaluation.schema import BinaryLabel, EvaluationScenario


class MatchStatus(StrEnum):
    EXACT = "EXACT"
    ACCEPTABLE = "ACCEPTABLE"
    FAILURE = "FAILURE"


class EvaluationCaseScore(DomainModel):
    scenario_id: Identifier
    disposition_status: MatchStatus
    expected_dispositions: tuple[Disposition, ...]
    actual_disposition: Disposition | None
    escalation_match: bool
    severity_match: bool
    required_tools_omitted: tuple[Identifier, ...] = ()
    forbidden_tools_called: tuple[Identifier, ...] = ()
    unexpected_tools_called: tuple[Identifier, ...] = ()
    total_tool_calls: int = Field(ge=0)
    successful_tool_calls: int = Field(ge=0)
    denied_or_failed_tool_calls: int = Field(ge=0)
    duplicate_tool_requests: int = Field(ge=0)
    expected_actions_omitted: tuple[Identifier, ...] = ()
    unexpected_actions: tuple[Identifier, ...] = ()
    approval_requirement_preserved: bool
    policy_reason_codes: tuple[Identifier, ...] = ()
    policy_forced_safe_review: bool
    unknown_action_attempted: bool
    out_of_scope_action_attempted: bool
    candidate_reference_violation: bool
    orchestration_bound_reached: bool
    completed_durably: bool
    orchestration_reason: Identifier
    duration_ms: int = Field(ge=0)
    false_positive: bool = False
    false_negative: bool = False
    binary_participant: bool = False


class EvaluationAggregate(DomainModel):
    scenario_count: int = Field(ge=0)
    exact_count: int = Field(ge=0)
    acceptable_count: int = Field(ge=0)
    failure_count: int = Field(ge=0)
    escalation_matches: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    malicious_ground_truth_count: int = Field(ge=0)
    non_malicious_ground_truth_count: int = Field(ge=0)
    false_positive_rate: float | None
    false_negative_rate: float | None
    total_tool_calls: int = Field(ge=0)
    forbidden_tool_calls: int = Field(ge=0)
    required_tool_omissions: int = Field(ge=0)
    confusion_matrix: dict[str, dict[str, int]]


def aggregate_scores(scores: tuple[EvaluationCaseScore, ...]) -> EvaluationAggregate:
    false_positives = sum(item.false_positive for item in scores)
    false_negatives = sum(item.false_negative for item in scores)
    malicious = sum(
        item.binary_participant and item.expected_dispositions[0] is Disposition.MALICIOUS
        for item in scores
    )
    non_malicious = sum(
        item.binary_participant and item.expected_dispositions[0] is not Disposition.MALICIOUS
        for item in scores
    )
    matrix: dict[str, dict[str, int]] = {}
    for item in scores:
        expected = item.expected_dispositions[0].value
        actual = item.actual_disposition.value if item.actual_disposition else "NO_RESULT"
        row = matrix.setdefault(expected, {})
        row[actual] = row.get(actual, 0) + 1
    return EvaluationAggregate(
        scenario_count=len(scores),
        exact_count=sum(item.disposition_status is MatchStatus.EXACT for item in scores),
        acceptable_count=sum(item.disposition_status is MatchStatus.ACCEPTABLE for item in scores),
        failure_count=sum(item.disposition_status is MatchStatus.FAILURE for item in scores),
        escalation_matches=sum(item.escalation_match for item in scores),
        false_positives=false_positives,
        false_negatives=false_negatives,
        malicious_ground_truth_count=malicious,
        non_malicious_ground_truth_count=non_malicious,
        false_positive_rate=(false_positives / non_malicious if non_malicious else None),
        false_negative_rate=(false_negatives / malicious if malicious else None),
        total_tool_calls=sum(item.total_tool_calls for item in scores),
        forbidden_tool_calls=sum(len(item.forbidden_tools_called) for item in scores),
        required_tool_omissions=sum(len(item.required_tools_omitted) for item in scores),
        confusion_matrix=matrix,
    )


def score_case(
    scenario: EvaluationScenario,
    outcome: OrchestrationOutcome,
    tool_calls: tuple[ToolInvocationRecord, ...],
    duration_ms: int,
) -> EvaluationCaseScore:
    result = outcome.result
    actual_disposition = result.disposition if result else None
    if actual_disposition == scenario.allowed_dispositions[0]:
        disposition_status = MatchStatus.EXACT
    elif actual_disposition in scenario.allowed_dispositions:
        disposition_status = MatchStatus.ACCEPTABLE
    else:
        disposition_status = MatchStatus.FAILURE
    called = tuple(item.tool_name for item in tool_calls)
    called_set = set(called)
    action_ids = (
        tuple(item.catalog_action_id for item in result.recommended_actions) if result else ()
    )
    approval_ids = (
        {item.action_id for item in result.actions_requiring_approval} if result else set()
    )
    approval_catalog_ids = (
        {
            item.catalog_action_id
            for item in result.recommended_actions
            if item.action_id in approval_ids
        }
        if result
        else set()
    )
    reason = outcome.reason_code.value
    policy_reasons = (
        tuple(item.value for item in outcome.policy_decision.reason_codes)
        if outcome.policy_decision
        else ()
    )
    binary_participant = scenario.binary_label is not BinaryLabel.AMBIGUOUS
    actual_positive = actual_disposition is Disposition.MALICIOUS
    return EvaluationCaseScore(
        scenario_id=scenario.scenario_id,
        disposition_status=disposition_status,
        expected_dispositions=scenario.allowed_dispositions,
        actual_disposition=actual_disposition,
        escalation_match=(
            result is not None and result.escalation_required == scenario.expected_escalation
        ),
        severity_match=(
            result is not None and result.severity is scenario.expected_assessed_severity
        ),
        required_tools_omitted=tuple(sorted(set(scenario.required_tools) - called_set)),
        forbidden_tools_called=tuple(sorted(set(scenario.forbidden_tools) & called_set)),
        unexpected_tools_called=tuple(sorted(called_set - set(scenario.allowed_tools))),
        total_tool_calls=len(tool_calls),
        successful_tool_calls=sum(item.outcome is GatewayStatus.SUCCESS for item in tool_calls),
        denied_or_failed_tool_calls=sum(
            item.outcome is not GatewayStatus.SUCCESS for item in tool_calls
        ),
        duplicate_tool_requests=sum(
            item.authorization is AuthorizationResult.DENIED
            and item.outcome is GatewayStatus.DUPLICATE_REQUEST
            for item in tool_calls
        ),
        expected_actions_omitted=tuple(sorted(set(scenario.expected_actions) - set(action_ids))),
        unexpected_actions=tuple(sorted(set(action_ids) - set(scenario.expected_actions))),
        approval_requirement_preserved=(
            set(scenario.expected_approval_actions) == approval_catalog_ids
        ),
        policy_reason_codes=policy_reasons,
        policy_forced_safe_review=(
            outcome.policy_decision is not None
            and actual_disposition is Disposition.NEEDS_REVIEW
            and any(
                code.value != "CANDIDATE_ESCALATION"
                for code in outcome.policy_decision.reason_codes
            )
        ),
        unknown_action_attempted="UNKNOWN_ACTION" in policy_reasons,
        out_of_scope_action_attempted="ACTION_TARGET_OUT_OF_SCOPE" in policy_reasons,
        candidate_reference_violation=reason == "EVIDENCE_REFERENCE_VIOLATION",
        orchestration_bound_reached=reason
        in {"ITERATION_LIMIT", "DEADLINE_EXCEEDED", "CONTEXT_LIMIT"},
        completed_durably=outcome.durable and result is not None,
        orchestration_reason=reason,
        duration_ms=duration_ms,
        false_positive=(
            binary_participant
            and scenario.binary_label is BinaryLabel.NON_MALICIOUS
            and actual_positive
        ),
        false_negative=(
            binary_participant
            and scenario.binary_label is BinaryLabel.MALICIOUS
            and not actual_positive
        ),
        binary_participant=binary_participant,
    )
