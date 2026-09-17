"""Deterministic lifecycle transition tests."""

from collections.abc import Callable
from typing import Any

import pytest

from security_triage_agent.domain.actions import ActionLifecycle, ActionProposal, ActionState
from security_triage_agent.domain.approvals import ApprovalLifecycle, ApprovalState
from security_triage_agent.domain.errors import InvalidStateTransitionError
from security_triage_agent.domain.states import TriageExecution, TriageExecutionState


@pytest.mark.parametrize(
    "terminal",
    [
        TriageExecutionState.COMPLETED,
        TriageExecutionState.FAILED,
        TriageExecutionState.NEEDS_REVIEW,
    ],
)
def test_valid_triage_execution_transitions(terminal: TriageExecutionState) -> None:
    pending = TriageExecution(execution_id="execution-001", alert_id="alert-001")

    running = pending.transition_to(TriageExecutionState.RUNNING)
    finished = running.transition_to(terminal)

    assert pending.state is TriageExecutionState.PENDING
    assert finished.state is terminal


def test_invalid_triage_execution_transition_is_rejected() -> None:
    execution = TriageExecution(execution_id="execution-001", alert_id="alert-001")

    with pytest.raises(InvalidStateTransitionError, match="PENDING -> COMPLETED"):
        execution.transition_to(TriageExecutionState.COMPLETED)


def test_untyped_transition_target_is_rejected() -> None:
    execution = TriageExecution(execution_id="execution-001", alert_id="alert-001")
    untrusted_target: Any = "RUNNING"

    with pytest.raises(TypeError, match="TriageExecutionState"):
        execution.transition_to(untrusted_target)


@pytest.mark.parametrize(
    "target",
    [ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.EXPIRED],
)
def test_valid_pending_approval_transitions(
    action_factory: Callable[..., ActionProposal], target: ApprovalState
) -> None:
    action = action_factory()
    pending = ApprovalLifecycle(
        approval_id="approval-001",
        action_id=action.action_id,
        action_digest=action.digest,
    )

    assert pending.transition_to(target).state is target


def test_approved_approval_can_expire(action_factory: Callable[..., ActionProposal]) -> None:
    action = action_factory()
    pending = ApprovalLifecycle(
        approval_id="approval-001",
        action_id=action.action_id,
        action_digest=action.digest,
    )

    expired = pending.transition_to(ApprovalState.APPROVED).transition_to(ApprovalState.EXPIRED)

    assert expired.state is ApprovalState.EXPIRED


def test_invalid_approval_transition_is_rejected(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    rejected = ApprovalLifecycle(
        approval_id="approval-001",
        action_id=action.action_id,
        action_digest=action.digest,
        state=ApprovalState.REJECTED,
    )

    with pytest.raises(InvalidStateTransitionError, match="REJECTED -> APPROVED"):
        rejected.transition_to(ApprovalState.APPROVED)


def test_untyped_approval_transition_target_is_rejected(
    action_factory: Callable[..., ActionProposal],
) -> None:
    action = action_factory()
    approval = ApprovalLifecycle(
        approval_id="approval-001",
        action_id=action.action_id,
        action_digest=action.digest,
    )
    untrusted_target: Any = "APPROVED"

    with pytest.raises(TypeError, match="ApprovalState"):
        approval.transition_to(untrusted_target)


def test_valid_action_workflow(action_factory: Callable[..., ActionProposal]) -> None:
    proposal = action_factory()
    lifecycle = ActionLifecycle(action_id=proposal.action_id)

    pending = lifecycle.transition_to(ActionState.PENDING_APPROVAL)
    approved = pending.transition_to(ActionState.APPROVED)
    executing = approved.transition_to(ActionState.EXECUTING)
    succeeded = executing.transition_to(ActionState.SUCCEEDED)

    assert succeeded.state is ActionState.SUCCEEDED


def test_invalid_action_transition_is_rejected(
    action_factory: Callable[..., ActionProposal],
) -> None:
    lifecycle = ActionLifecycle(action_id=action_factory().action_id)

    with pytest.raises(InvalidStateTransitionError, match="PROPOSED -> EXECUTING"):
        lifecycle.transition_to(ActionState.EXECUTING)


def test_untyped_action_transition_target_is_rejected(
    action_factory: Callable[..., ActionProposal],
) -> None:
    lifecycle = ActionLifecycle(action_id=action_factory().action_id)
    untrusted_target: Any = "PENDING_APPROVAL"

    with pytest.raises(TypeError, match="ActionState"):
        lifecycle.transition_to(untrusted_target)
