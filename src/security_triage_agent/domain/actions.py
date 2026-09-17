"""Action proposals, deterministic identities, and lifecycle states."""

import hashlib
import json
from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Self

from pydantic import JsonValue, field_serializer, field_validator

from security_triage_agent.domain._base import (
    DomainModel,
    Identifier,
    NonEmptyText,
    Sha256Digest,
)
from security_triage_agent.domain.entities import EntityReference
from security_triage_agent.domain.errors import InvalidStateTransitionError


class ActionProposal(DomainModel):
    """Recommendation for a registered action, without execution authority."""

    action_id: Identifier
    catalog_action_id: Identifier
    target: EntityReference
    parameters: Mapping[str, JsonValue]
    rationale: NonEmptyText

    @field_validator("parameters", mode="after")
    @classmethod
    def freeze_parameters(cls, value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        """Deep-freeze action parameters so approved material cannot mutate in place."""

        return _freeze_mapping(value)

    @field_serializer("parameters")
    def serialize_parameters(self, value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        return _thaw_mapping(value)

    @property
    def digest(self) -> str:
        """Return a stable digest of approval-relevant action material."""

        material: dict[str, Any] = {
            "catalog_action_id": self.catalog_action_id,
            "target": self.target.model_dump(mode="json"),
            "parameters": _thaw_mapping(self.parameters),
        }
        canonical = json.dumps(
            material,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


class ActionReference(DomainModel):
    """Typed reference binding an action identifier to its exact digest."""

    action_id: Identifier
    action_digest: Sha256Digest

    @classmethod
    def from_proposal(cls, proposal: ActionProposal) -> "ActionReference":
        return cls(action_id=proposal.action_id, action_digest=proposal.digest)


class ActionState(StrEnum):
    """States for the future approval-gated action workflow."""

    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


_ACTION_TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    ActionState.PROPOSED: frozenset({ActionState.PENDING_APPROVAL}),
    ActionState.PENDING_APPROVAL: frozenset(
        {ActionState.APPROVED, ActionState.REJECTED, ActionState.EXPIRED}
    ),
    ActionState.APPROVED: frozenset({ActionState.EXECUTING, ActionState.EXPIRED}),
    ActionState.EXECUTING: frozenset({ActionState.SUCCEEDED, ActionState.FAILED}),
    ActionState.REJECTED: frozenset(),
    ActionState.EXPIRED: frozenset(),
    ActionState.SUCCEEDED: frozenset(),
    ActionState.FAILED: frozenset(),
}


class ActionLifecycle(DomainModel):
    """Immutable action state with deterministic transition validation."""

    action_id: Identifier
    state: ActionState = ActionState.PROPOSED

    def transition_to(self, target: ActionState) -> Self:
        if not isinstance(target, ActionState):
            raise TypeError("target must be an ActionState")
        if target not in _ACTION_TRANSITIONS[self.state]:
            raise InvalidStateTransitionError("action", self.state, target)
        return self.model_copy(update={"state": target})


def _freeze_json(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return _freeze_mapping(value)  # type: ignore[return-value]
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)  # type: ignore[return-value]
    return value


def _freeze_mapping(value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})


def _thaw_json(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return _thaw_mapping(value)
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _thaw_mapping(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    return {key: _thaw_json(item) for key, item in value.items()}
