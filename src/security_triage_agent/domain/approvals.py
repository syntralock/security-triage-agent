"""Approval decision contracts and lifecycle rules without service behavior."""

from enum import StrEnum
from typing import Self

from pydantic import model_validator

from security_triage_agent.domain._base import (
    DomainModel,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    UtcDatetime,
    Version,
)
from security_triage_agent.domain.errors import InvalidStateTransitionError


class ApprovalDecision(StrEnum):
    """Human decisions that may be recorded for an action."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ApprovalRecord(DomainModel):
    """Immutable human decision bound to an exact action and policy version."""

    approval_id: Identifier
    action_id: Identifier
    action_digest: Sha256Digest
    reviewer_id: Identifier
    decision: ApprovalDecision
    decided_at: UtcDatetime
    reason: NonEmptyText
    policy_version: Version
    expires_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def validate_expiry(self) -> "ApprovalRecord":
        if self.decision is ApprovalDecision.APPROVED and self.expires_at is None:
            raise ValueError("expires_at is required for an approved decision")
        if self.decision is ApprovalDecision.REJECTED and self.expires_at is not None:
            raise ValueError("expires_at must be absent for a rejected decision")
        if self.expires_at is not None and self.expires_at <= self.decided_at:
            raise ValueError("expires_at must be later than decided_at")
        return self


class ApprovalState(StrEnum):
    """Lifecycle states for a future human approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


_APPROVAL_TRANSITIONS: dict[ApprovalState, frozenset[ApprovalState]] = {
    ApprovalState.PENDING: frozenset(
        {ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.EXPIRED}
    ),
    ApprovalState.APPROVED: frozenset({ApprovalState.EXPIRED}),
    ApprovalState.REJECTED: frozenset(),
    ApprovalState.EXPIRED: frozenset(),
}


class ApprovalLifecycle(DomainModel):
    """Immutable approval state with explicit legal transitions."""

    approval_id: Identifier
    action_id: Identifier
    action_digest: Sha256Digest
    state: ApprovalState = ApprovalState.PENDING

    def transition_to(self, target: ApprovalState) -> Self:
        if not isinstance(target, ApprovalState):
            raise TypeError("target must be an ApprovalState")
        if target not in _APPROVAL_TRANSITIONS[self.state]:
            raise InvalidStateTransitionError("approval", self.state, target)
        return self.model_copy(update={"state": target})
