"""SQLAlchemy Unit of Work and sanitized persistence failures."""

from types import TracebackType
from typing import Self

from sqlalchemy import Engine, event
from sqlalchemy import create_engine as sa_create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from security_triage_agent.adapters.persistence.repositories import (
    SqlAlchemyActionExecutionRepository,
    SqlAlchemyActionRepository,
    SqlAlchemyAlertRepository,
    SqlAlchemyApprovalRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyEvaluationRepository,
    SqlAlchemyExecutionRepository,
    SqlAlchemyToolInvocationRepository,
    SqlAlchemyTriageResultRepository,
)
from security_triage_agent.application.ports.repositories import (
    ActionExecutionRepository,
    ActionRepository,
    AlertRepository,
    ApprovalRepository,
    AuditRepository,
    EvaluationRepository,
    ExecutionRepository,
    ToolInvocationRepository,
    TriageResultRepository,
)


class PersistenceError(RuntimeError):
    """Sanitized application-boundary persistence failure."""


def create_engine(database_url: str) -> Engine:
    """Create a supported SQLAlchemy engine without exposing its URL in errors."""

    url = make_url(database_url)
    if url.get_backend_name() not in {"sqlite", "postgresql"}:
        raise PersistenceError("unsupported database backend")
    engine = sa_create_engine(url, future=True)
    if url.get_backend_name() == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def _enable_sqlite_foreign_keys(dbapi_connection: object, _record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class SqlAlchemyUnitOfWork:
    """Own one session/transaction; repositories never commit independently."""

    alerts: AlertRepository
    executions: ExecutionRepository
    tool_invocations: ToolInvocationRepository
    triage_results: TriageResultRepository
    actions: ActionRepository
    approvals: ApprovalRepository
    action_executions: ActionExecutionRepository
    audit: AuditRepository
    evaluations: EvaluationRepository

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self.session: Session | None = None

    def __enter__(self) -> Self:
        self.session = self._session_factory()
        self.alerts = SqlAlchemyAlertRepository(self.session)
        self.executions = SqlAlchemyExecutionRepository(self.session)
        self.tool_invocations = SqlAlchemyToolInvocationRepository(self.session)
        self.triage_results = SqlAlchemyTriageResultRepository(self.session)
        self.actions = SqlAlchemyActionRepository(self.session)
        self.approvals = SqlAlchemyApprovalRepository(self.session)
        self.action_executions = SqlAlchemyActionExecutionRepository(self.session)
        self.audit = SqlAlchemyAuditRepository(self.session)
        self.evaluations = SqlAlchemyEvaluationRepository(self.session)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.session is None:
            return
        if exc_type is not None:
            self.session.rollback()
        self.session.close()
        self.session = None

    def commit(self) -> None:
        if self.session is None:
            raise PersistenceError("unit of work is not active")
        try:
            self.session.commit()
        except SQLAlchemyError as error:
            self.session.rollback()
            raise PersistenceError("persistence transaction failed") from error

    def flush(self) -> None:
        """Order dependent writes without committing the enclosing transaction."""

        if self.session is None:
            raise PersistenceError("unit of work is not active")
        try:
            self.session.flush()
        except SQLAlchemyError as error:
            self.session.rollback()
            raise PersistenceError("persistence transaction failed") from error

    def rollback(self) -> None:
        if self.session is None:
            raise PersistenceError("unit of work is not active")
        self.session.rollback()
