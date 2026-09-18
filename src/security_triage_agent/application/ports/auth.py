"""Replaceable principal and authorization boundary for transport adapters."""

from enum import StrEnum
from typing import Protocol

from security_triage_agent.domain._base import DomainModel, Identifier


class PrincipalRole(StrEnum):
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    REVIEWER = "REVIEWER"


class Principal(DomainModel):
    principal_id: Identifier
    role: PrincipalRole
    development_only: bool


class PrincipalProvider(Protocol):
    def current_principal(self) -> Principal | None: ...


class AuthorizationService:
    def __init__(
        self, authorized_reviewer_ids: frozenset[str] = frozenset({"development-reviewer"})
    ) -> None:
        self._authorized_reviewer_ids = authorized_reviewer_ids

    def may_view(self, principal: Principal) -> bool:
        return principal.role in {
            PrincipalRole.ANALYST,
            PrincipalRole.VIEWER,
            PrincipalRole.REVIEWER,
        }

    def may_ingest_or_triage(self, principal: Principal) -> bool:
        return principal.role in {PrincipalRole.ANALYST, PrincipalRole.REVIEWER}

    def may_review(self, principal: Principal) -> bool:
        return (
            principal.role is PrincipalRole.REVIEWER
            and principal.principal_id in self._authorized_reviewer_ids
        )

    def is_authorized_reviewer_id(self, reviewer_id: str) -> bool:
        return reviewer_id in self._authorized_reviewer_ids
