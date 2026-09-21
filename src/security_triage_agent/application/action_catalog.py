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
    objective: str = ""
    category: str = ""
    evidence_considerations: str = ""
    blast_radius: str = ""
    reversibility: str = ""
    excessive_when: str = ""
    reasonable_combinations: tuple[str, ...] = ()


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
        *,
        objective: str,
        category: str,
        evidence_considerations: str,
        blast_radius: str,
        reversibility: str,
        excessive_when: str,
        reasonable_combinations: tuple[str, ...] = (),
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
            objective=objective,
            category=category,
            evidence_considerations=evidence_considerations,
            blast_radius=blast_radius,
            reversibility=reversibility,
            excessive_when=excessive_when,
            reasonable_combinations=reasonable_combinations,
        )

    return ActionCatalog(
        (
            high_impact(
                "disable_account",
                "Disable a user account.",
                EntityType.USER,
                objective=(
                    "Prevent all account use when compromise or imminent reuse creates "
                    "intolerable risk."
                ),
                category="CONTAINMENT",
                evidence_considerations=(
                    "Established compromise or a trusted emergency playbook; consider business "
                    "and break-glass impact."
                ),
                blast_radius="Broad account and dependent-workload disruption.",
                reversibility="Generally reversible by an authorized identity administrator.",
                excessive_when=(
                    "Compromise remains uncorroborated and narrower controls meet the "
                    "containment objective."
                ),
                reasonable_combinations=("revoke_sessions", "reset_password", "remove_privilege"),
            ),
            high_impact(
                "revoke_sessions",
                "Revoke active user sessions.",
                EntityType.USER,
                objective="Terminate existing unauthorized or suspect session access.",
                category="CONTAINMENT",
                evidence_considerations="A suspect active session or stolen token may exist.",
                blast_radius="Forces reauthentication and may disrupt active work.",
                reversibility="Access can resume after successful authorized authentication.",
                excessive_when="No session or access concern is supported.",
                reasonable_combinations=("reset_password", "disable_account"),
            ),
            high_impact(
                "reset_password",
                "Require a user password reset.",
                EntityType.USER,
                objective="Replace a password credential suspected of exposure.",
                category="ERADICATION_RECOVERY",
                evidence_considerations=(
                    "Password compromise is supported or a trusted recovery playbook requires "
                    "rotation."
                ),
                blast_radius="Disrupts user and password-dependent services.",
                reversibility=(
                    "The user can recover through authorized identity proofing and reset."
                ),
                excessive_when="Evidence concerns only an unrelated endpoint or session token.",
                reasonable_combinations=("revoke_sessions", "disable_account"),
            ),
            high_impact(
                "isolate_device",
                "Isolate a managed device.",
                EntityType.DEVICE,
                objective="Stop a compromised endpoint from communicating or moving laterally.",
                category="CONTAINMENT",
                evidence_considerations=(
                    "Endpoint compromise or imminent endpoint-driven spread is supported."
                ),
                blast_radius="High endpoint and user operational disruption.",
                reversibility="An authorized endpoint operator can normally release isolation.",
                excessive_when=(
                    "The device is merely mentioned, unfamiliar, or noncompliant without "
                    "compromise evidence."
                ),
                reasonable_combinations=("revoke_sessions", "reset_password"),
            ),
            high_impact(
                "delete_email",
                "Delete a specified email message for a scoped user.",
                EntityType.USER,
                objective="Remove an exactly identified malicious message from a mailbox.",
                category="CONTAINMENT_ERADICATION",
                evidence_considerations=(
                    "The exact message is confirmed harmful and remains accessible."
                ),
                blast_radius="Removes content and may affect retention, legal, or user workflows.",
                reversibility="Recovery depends on mailbox retention and provider behavior.",
                excessive_when="No exact malicious message has been identified.",
                reasonable_combinations=("revoke_sessions", "reset_password"),
                parameters_model=DeleteEmailParameters,
            ),
            high_impact(
                "remove_privilege",
                "Remove a specified privilege from a scoped user.",
                EntityType.USER,
                objective="Remove an exactly identified unauthorized or compromised entitlement.",
                category="CONTAINMENT_RISK_REDUCTION",
                evidence_considerations=(
                    "The exact privilege is unauthorized, misused, or covered by a trusted "
                    "containment playbook."
                ),
                blast_radius=(
                    "May disrupt administration, separation of duties, or business processes."
                ),
                reversibility="An authorized entitlement administrator can normally restore it.",
                excessive_when=(
                    "The privilege is legitimate and no misuse or compromise is established."
                ),
                reasonable_combinations=("revoke_sessions", "disable_account"),
                parameters_model=RemovePrivilegeParameters,
            ),
        )
    )
