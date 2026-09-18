"""Transparent scoring and binary metric tests."""

from datetime import UTC, datetime
from decimal import Decimal

from security_triage_agent.application.orchestration_contracts import (
    OrchestrationOutcome,
    OrchestrationReasonCode,
)
from security_triage_agent.application.tool_gateway import (
    AuthorizationResult,
    GatewayStatus,
    ToolInvocationRecord,
)
from security_triage_agent.domain.triage import Disposition, Severity, TriageResult
from security_triage_agent.evaluation.schema import BinaryLabel, EvaluationScenario
from security_triage_agent.evaluation.scoring import MatchStatus, aggregate_scores, score_case

NOW = datetime(2026, 1, 15, 12, tzinfo=UTC)


def scenario(label: BinaryLabel, dispositions: tuple[Disposition, ...]) -> EvaluationScenario:
    return EvaluationScenario(
        scenario_id=f"scenario-{label.value.lower()}",
        scenario_version="1.0",
        description="Synthetic scoring case.",
        alert_id="alert-synthetic",
        allowed_dispositions=dispositions,
        expected_escalation=True,
        required_tools=("get_user_risk",),
        allowed_tools=("get_user_risk",),
        forbidden_tools=("find_related_alerts",),
        expected_actions=(),
        expected_approval_actions=(),
        binary_label=label,
        expected_assessed_severity=Severity.HIGH,
        ground_truth_rationale="Maintainer-only deterministic rationale.",
    )


def outcome(disposition: Disposition) -> OrchestrationOutcome:
    return OrchestrationOutcome(
        execution_id="execution-score",
        correlation_id="correlation-score",
        durable=True,
        reason_code=OrchestrationReasonCode.COMPLETED,
        result=TriageResult(
            alert_id="alert-synthetic",
            disposition=disposition,
            confidence=Decimal("1.0"),
            severity=Severity.HIGH,
            reasoning_summary="Synthetic summary.",
            escalation_required=True,
            escalation_reason="Synthetic escalation.",
            timestamp=NOW,
        ),
    )


def tool(
    name: str, status: GatewayStatus, authorization: AuthorizationResult
) -> ToolInvocationRecord:
    return ToolInvocationRecord(
        execution_id="execution-score",
        correlation_id="correlation-score",
        call_id=f"call-{name}-{status}",
        tool_name=name,
        sanitized_arguments={},
        authorization=authorization,
        outcome=status,
        started_at=NOW,
        completed_at=NOW,
        duration_ms=0,
        failure_category=status if status is not GatewayStatus.SUCCESS else None,
    )


def test_false_positive_false_negative_and_ambiguous_exclusion() -> None:
    false_positive = score_case(
        scenario(BinaryLabel.NON_MALICIOUS, (Disposition.BENIGN,)),
        outcome(Disposition.MALICIOUS),
        (),
        5,
    )
    false_negative = score_case(
        scenario(BinaryLabel.MALICIOUS, (Disposition.MALICIOUS,)),
        outcome(Disposition.NEEDS_REVIEW),
        (),
        5,
    )
    ambiguous = score_case(
        scenario(BinaryLabel.AMBIGUOUS, (Disposition.NEEDS_REVIEW,)),
        outcome(Disposition.MALICIOUS),
        (),
        5,
    )
    aggregate = aggregate_scores((false_positive, false_negative, ambiguous))
    assert aggregate.false_positives == 1
    assert aggregate.false_negatives == 1
    assert aggregate.false_positive_rate == 1.0
    assert aggregate.false_negative_rate == 1.0
    assert not ambiguous.binary_participant
    assert "NEEDS_REVIEW" in aggregate.confusion_matrix["MALICIOUS"]


def test_acceptable_and_tool_policy_failures_remain_independent() -> None:
    expected = scenario(BinaryLabel.AMBIGUOUS, (Disposition.SUSPICIOUS, Disposition.NEEDS_REVIEW))
    tools = (
        tool("get_user_risk", GatewayStatus.SUCCESS, AuthorizationResult.ALLOWED),
        tool("find_related_alerts", GatewayStatus.SUCCESS, AuthorizationResult.ALLOWED),
        tool("get_user_risk", GatewayStatus.DUPLICATE_REQUEST, AuthorizationResult.DENIED),
    )
    score = score_case(expected, outcome(Disposition.NEEDS_REVIEW), tools, 17)
    assert score.disposition_status is MatchStatus.ACCEPTABLE
    assert score.forbidden_tools_called == ("find_related_alerts",)
    assert score.unexpected_tools_called == ("find_related_alerts",)
    assert score.duplicate_tool_requests == 1
    assert score.denied_or_failed_tool_calls == 1
    assert score.duration_ms == 17


def test_zero_binary_denominators_return_none_rates() -> None:
    score = score_case(
        scenario(BinaryLabel.AMBIGUOUS, (Disposition.NEEDS_REVIEW,)),
        outcome(Disposition.NEEDS_REVIEW),
        (),
        0,
    )
    aggregate = aggregate_scores((score,))
    assert aggregate.false_positive_rate is None
    assert aggregate.false_negative_rate is None
