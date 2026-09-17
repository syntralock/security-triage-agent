"""Triage result, evidence provenance, enum, and confidence tests."""

from collections.abc import Callable
from datetime import datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from security_triage_agent.domain.actions import ActionProposal, ActionReference
from security_triage_agent.domain.evidence import EvidenceReference
from security_triage_agent.domain.triage import Disposition, Severity, TriageResult


@pytest.mark.parametrize("disposition", ["UNKNOWN", "benign", ""])
def test_unknown_disposition_is_rejected(
    triage_result_factory: Callable[..., TriageResult], disposition: str
) -> None:
    with pytest.raises(ValidationError):
        triage_result_factory(disposition=disposition)


@pytest.mark.parametrize("severity", ["SEVERE", "high", ""])
def test_unknown_severity_is_rejected(
    triage_result_factory: Callable[..., TriageResult], severity: str
) -> None:
    with pytest.raises(ValidationError):
        triage_result_factory(severity=severity)


@pytest.mark.parametrize("confidence", [Decimal("0.0"), Decimal("1.0")])
def test_confidence_inclusive_bounds_are_accepted(
    triage_result_factory: Callable[..., TriageResult], confidence: Decimal
) -> None:
    assert triage_result_factory(confidence=confidence).confidence == confidence


def test_confidence_preserves_precision(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    value = Decimal("0.873421")
    result = triage_result_factory(confidence=value)
    restored = TriageResult.model_validate_json(result.model_dump_json())

    assert result.confidence == value
    assert restored.confidence == value


@pytest.mark.parametrize("confidence", [Decimal("-0.000001"), Decimal("1.000001")])
def test_confidence_outside_bounds_is_rejected(
    triage_result_factory: Callable[..., TriageResult], confidence: Decimal
) -> None:
    with pytest.raises(ValidationError):
        triage_result_factory(confidence=confidence)


def test_naive_result_timestamp_is_rejected(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        triage_result_factory(timestamp=datetime(2026, 1, 15, 12, 0))


def test_escalation_reason_is_required_when_escalating(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    with pytest.raises(ValidationError, match="escalation_reason is required"):
        triage_result_factory(escalation_required=True, escalation_reason=None)


def test_escalation_reason_is_rejected_without_escalation(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    with pytest.raises(ValidationError, match="must be absent"):
        triage_result_factory(escalation_required=False, escalation_reason="Not consistent.")


def test_non_escalated_result_without_reason_is_valid(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    result = triage_result_factory(escalation_required=False, escalation_reason=None)

    assert result.escalation_reason is None


def test_evidence_tool_provenance_must_resolve(
    occurred_at: datetime,
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    evidence = EvidenceReference(
        evidence_id="evidence-002",
        source_type="device-context",
        source_reference="fixture-device-001",
        source_version="1.0",
        collected_at=occurred_at,
        summary="Synthetic device context.",
        tool_invocation_id="unknown-tool-call",
    )

    with pytest.raises(ValidationError, match="unknown tool invocation"):
        triage_result_factory(evidence=(evidence,))


def test_non_tool_evidence_has_complete_provenance(
    occurred_at: datetime,
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    evidence = EvidenceReference(
        evidence_id="evidence-source-alert",
        source_type="source-alert",
        source_reference="payload-001",
        source_version="2026-01",
        collected_at=occurred_at,
        summary="Evidence originates in the normalized source alert.",
    )

    result = triage_result_factory(evidence=(evidence,))

    assert result.evidence[0].tool_invocation_id is None


def test_approval_reference_must_match_recommended_action(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    unknown = ActionReference(action_id="unknown-action", action_digest=f"sha256:{'b' * 64}")

    with pytest.raises(ValidationError, match="must match a recommended action"):
        triage_result_factory(actions_requiring_approval=(unknown,))


def test_matching_approval_reference_is_accepted(
    action_factory: Callable[..., ActionProposal],
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    action = action_factory()
    result = triage_result_factory(
        recommended_actions=(action,),
        actions_requiring_approval=(ActionReference.from_proposal(action),),
    )

    assert result.actions_requiring_approval[0].action_digest == action.digest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence", None),
        ("tool_calls", None),
        ("recommended_actions", None),
        ("actions_requiring_approval", None),
    ],
)
def test_typed_collections_reject_null(
    triage_result_factory: Callable[..., TriageResult], field: str, value: None
) -> None:
    with pytest.raises(ValidationError):
        triage_result_factory(**{field: value})


def test_duplicate_references_are_rejected(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    result = triage_result_factory()

    with pytest.raises(ValidationError, match="duplicate evidence identifier"):
        triage_result_factory(evidence=(result.evidence[0], result.evidence[0]))


def test_triage_result_round_trip_is_deterministic(
    triage_result_factory: Callable[..., TriageResult],
) -> None:
    result = triage_result_factory(
        disposition=Disposition.MALICIOUS,
        severity=Severity.CRITICAL,
    )

    encoded = result.model_dump_json()
    restored = TriageResult.model_validate_json(encoded)

    assert restored == result
    assert restored.model_dump_json() == encoded
