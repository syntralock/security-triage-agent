"""Production-shaped local clock, identifiers, and development principal."""

from datetime import UTC, datetime
from time import monotonic_ns
from uuid import uuid4

from security_triage_agent.application.ports.auth import Principal, PrincipalProvider, PrincipalRole


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ms(self) -> int:
        return monotonic_ns() // 1_000_000


class UuidIdentifierGenerator:
    def next_id(self, purpose: str) -> str:
        return f"{purpose}-{uuid4()}"


class DevelopmentPrincipalProvider(PrincipalProvider):
    """Explicit local-only identity; never reads identity claims from a request."""

    def current_principal(self) -> Principal:
        return Principal(
            principal_id="development-analyst",
            role=PrincipalRole.ANALYST,
            development_only=True,
        )
