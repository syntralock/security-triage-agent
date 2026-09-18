"""Immutable deterministic catalog for approval-gated response actions."""

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict

from security_triage_agent.domain._base import Identifier
from security_triage_agent.domain.entities import EntityType


class ActionRisk(StrEnum):
    HIGH_IMPACT = "HIGH_IMPACT"


class ExecutionSupport(StrEnum):
    SIMULATED_ONLY = "SIMULATED_ONLY"


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DeleteEmailParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    message_id: Identifier


class RemovePrivilegeParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
    privilege_id: Identifier


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_id: str
    version: str
    description: str
    target_types: frozenset[EntityType]
    risk: ActionRisk
    approval_required: bool
    execution_support: ExecutionSupport
    parameters_model: type[BaseModel]


class ActionCatalogError(ValueError):
    pass


class ActionCatalog(Mapping[str, ActionDefinition]):
    """Closed mapping assembled only from trusted application configuration."""

    def __init__(self, definitions: Iterable[ActionDefinition]) -> None:
        entries: dict[str, ActionDefinition] = {}
        for definition in definitions:
            if not definition.action_id or not definition.version:
                raise ActionCatalogError("action identity and version are required")
            if not definition.target_types:
                raise ActionCatalogError("action target types are required")
            if definition.risk is ActionRisk.HIGH_IMPACT and not definition.approval_required:
                raise ActionCatalogError("high-impact actions must require approval")
            if definition.action_id in entries:
                raise ActionCatalogError(f"duplicate action registration: {definition.action_id}")
            entries[definition.action_id] = definition
        self._entries = MappingProxyType(entries)

    def __getitem__(self, key: str) -> ActionDefinition:
        return self._entries[key]

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._entries))

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, action_id: str) -> ActionDefinition | None:
        return self._entries.get(action_id)


def initial_action_catalog() -> ActionCatalog:
    def high_impact(
        action_id: str,
        description: str,
        target_type: EntityType,
        parameters_model: type[BaseModel] = NoParameters,
    ) -> ActionDefinition:
        return ActionDefinition(
            action_id=action_id,
            version="1.0.0",
            description=description,
            target_types=frozenset({target_type}),
            risk=ActionRisk.HIGH_IMPACT,
            approval_required=True,
            execution_support=ExecutionSupport.SIMULATED_ONLY,
            parameters_model=parameters_model,
        )

    return ActionCatalog(
        (
            high_impact("disable_account", "Disable a user account.", EntityType.USER),
            high_impact("revoke_sessions", "Revoke active user sessions.", EntityType.USER),
            high_impact("reset_password", "Require a user password reset.", EntityType.USER),
            high_impact("isolate_device", "Isolate a managed device.", EntityType.DEVICE),
            high_impact(
                "delete_email",
                "Delete a specified email message for a scoped user.",
                EntityType.USER,
                DeleteEmailParameters,
            ),
            high_impact(
                "remove_privilege",
                "Remove a specified privilege from a scoped user.",
                EntityType.USER,
                RemovePrivilegeParameters,
            ),
        )
    )
