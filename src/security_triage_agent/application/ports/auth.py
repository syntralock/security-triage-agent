"""Replaceable principal and authorization boundary for transport adapters."""

from enum import StrEnum
from typing import Protocol

from security_triage_agent.domain._base import DomainModel, Identifier


class PrincipalRole(StrEnum):
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class Principal(DomainModel):
    principal_id: Identifier
    role: PrincipalRole
    development_only: bool


class PrincipalProvider(Protocol):
    def current_principal(self) -> Principal | None: ...


class AuthorizationService:
    def may_view(self, principal: Principal) -> bool:
        return principal.role in {PrincipalRole.ANALYST, PrincipalRole.VIEWER}

    def may_ingest_or_triage(self, principal: Principal) -> bool:
        return principal.role is PrincipalRole.ANALYST
