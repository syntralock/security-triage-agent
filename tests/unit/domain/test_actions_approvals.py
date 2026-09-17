"""Action identity and approval contract tests."""

from collections.abc import Callable, MutableMapping
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from pydantic import JsonValue, ValidationError

from security_triage_agent.domain.actions import ActionProposal, ActionReference
from security_triage_agent.domain.approvals import ApprovalDecision, ApprovalRecord
from security_triage_agent.domain.entities import UserEntityReference


def test_action_digest_is_stable_for_equivalent_parameter_order(
    action_factory: Callable[..., ActionProposal],
) -> None:
    first = action_factory(parameters={"alpha": 1, "nested": {"x": True, "y": [1, 2]}})
    second = action_factory(parameters={"nested": {"y": [1, 2], "x": True}, "alpha": 1})

    assert first.digest == second.digest
    assert ActionReference.from_proposal(first).action_digest == first.digest


@pytest.mark.parametrize(
    "override",
    [
        {"catalog_action_id": "isolate-device"},
        {"target": UserEntityReference(identifier="user-002")},
        {"parameters": {"invalidate_sessions": False}},
    ],
)
def test_action_digest_changes_with_material_request_data(
    action_factory: Callable[..., ActionProposal], override: dict[str, object]
) -> None:
    assert action_factory().digest != action_factory(**override).digest


def test_non_material_rationale_does_not_change_action_digest(
    action_factory: Callable[..., ActionProposal],
) -> None:
    first = action_factory(rationale="First reviewer-facing rationale.")
    second = action_factory(rationale="Updated reviewer-facing rationale.")

    assert first.digest == second.digest


def test_action_parameters_are_deeply_immutable(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory(parameters={"nested": {"enabled": True}, "items": ["a"]})

    with pytest.raises(TypeError):
        action.parameters["new"] = True  # type: ignore[index]
    nested = cast(MutableMapping[str, JsonValue], action.parameters["nested"])
    with pytest.raises(TypeError):
        nested["enabled"] = False


def test_action_round_trip_preserves_digest(action_factory: Callable[..., ActionProposal]) -> None:
    action = action_factory()

    restored = ActionProposal.model_validate_json(action.model_dump_json())

    assert restored == action
    assert restored.digest == action.digest


def test_approval_record_binds_exact_action_and_normalizes_time(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    decided_at = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    approval = ApprovalRecord(
        approval_id="approval-001",
        action_id=action.action_id,
        action_digest=action.digest,
        reviewer_id="reviewer-001",
        decision=ApprovalDecision.APPROVED,
        decided_at=decided_at,
        reason="Synthetic reviewer approved the exact proposed action.",
        policy_version="1.0",
        expires_at=decided_at + timedelta(minutes=15),
    )

    assert approval.action_digest == action.digest
    assert approval.decided_at.tzinfo is UTC


def test_approval_record_rejects_non_future_expiry(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    decided_at = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)

    with pytest.raises(ValidationError, match="expires_at"):
        ApprovalRecord(
            approval_id="approval-001",
            action_id=action.action_id,
            action_digest=action.digest,
            reviewer_id="reviewer-001",
            decision=ApprovalDecision.APPROVED,
            decided_at=decided_at,
            reason="Synthetic reviewer approved the proposed action.",
            policy_version="1.0",
            expires_at=decided_at,
        )


def test_approved_decision_requires_expiry(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    decided_at = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)

    with pytest.raises(ValidationError, match="required for an approved decision"):
        ApprovalRecord(
            approval_id="approval-001",
            action_id=action.action_id,
            action_digest=action.digest,
            reviewer_id="reviewer-001",
            decision=ApprovalDecision.APPROVED,
            decided_at=decided_at,
            reason="Synthetic reviewer approved the proposed action.",
            policy_version="1.0",
        )


def test_rejected_decision_preserves_facts_without_expiry(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    decided_at = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    rejection = ApprovalRecord(
        approval_id="approval-001",
        action_id=action.action_id,
        action_digest=action.digest,
        reviewer_id="reviewer-001",
        decision=ApprovalDecision.REJECTED,
        decided_at=decided_at,
        reason="Synthetic reviewer rejected the exact proposed action.",
        policy_version="1.0",
    )

    assert rejection.expires_at is None
    assert rejection.action_digest == action.digest
    assert rejection.reviewer_id == "reviewer-001"


def test_rejected_decision_forbids_expiry(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    decided_at = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)

    with pytest.raises(ValidationError, match="absent for a rejected decision"):
        ApprovalRecord(
            approval_id="approval-001",
            action_id=action.action_id,
            action_digest=action.digest,
            reviewer_id="reviewer-001",
            decision=ApprovalDecision.REJECTED,
            decided_at=decided_at,
            reason="Synthetic reviewer rejected the proposed action.",
            policy_version="1.0",
            expires_at=decided_at + timedelta(minutes=15),
        )


def test_approval_record_rejects_invalid_digest(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    now = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)

    with pytest.raises(ValidationError, match="action_digest"):
        ApprovalRecord(
            approval_id="approval-001",
            action_id=action.action_id,
            action_digest="not-a-digest",
            reviewer_id="reviewer-001",
            decision=ApprovalDecision.APPROVED,
            decided_at=now,
            reason="Synthetic decision.",
            policy_version="1.0",
            expires_at=now + timedelta(minutes=1),
        )
