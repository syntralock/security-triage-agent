"""Transactional normalized-alert ingestion service."""

from collections.abc import Callable
from dataclasses import dataclass

from security_triage_agent.application.persistence import AuditEvent, AuditOutcome
from security_triage_agent.application.ports.reasoner import Clock, IdentifierGenerator
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.domain.alerts import SecurityAlert


class AlertConflictError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IngestionResult:
    alert: SecurityAlert
    created: bool


class AlertIngestionService:
    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        clock: Clock,
        identifiers: IdentifierGenerator,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._identifiers = identifiers

    def ingest(
        self, alert: SecurityAlert, *, correlation_id: str, actor_id: str
    ) -> IngestionResult:
        with self._uow_factory() as uow:
            existing = uow.alerts.get(alert.alert_id)
            if existing is not None:
                if existing != alert:
                    raise AlertConflictError("alert identifier already exists with different data")
                return IngestionResult(alert=existing, created=False)
            uow.alerts.add(alert)
            uow.audit.append(
                AuditEvent(
                    event_id=self._identifiers.next_id("audit"),
                    event_type="alert.ingested",
                    occurred_at=self._clock.now(),
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    target_type="security_alert",
                    target_id=alert.alert_id,
                    data={"source": alert.source, "source_severity": alert.source_severity.value},
                    outcome=AuditOutcome.SUCCESS,
                )
            )
            uow.commit()
        return IngestionResult(alert=alert, created=True)
