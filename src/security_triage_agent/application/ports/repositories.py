"""Narrow framework-independent persistence ports."""

from types import TracebackType
from typing import Protocol, Self

from security_triage_agent.application.persistence import (
    ActionExecutionRecord,
    AuditEvent,
    TriageExecutionRecord,
)
from security_triage_agent.application.tool_gateway import ToolInvocationRecord
from security_triage_agent.domain.actions import ActionProposal
from security_triage_agent.domain.alerts import SecurityAlert
from security_triage_agent.domain.approvals import ApprovalRecord
from security_triage_agent.domain.triage import TriageResult


class AlertRepository(Protocol):
    def add(self, alert: SecurityAlert) -> None: ...
    def get(self, alert_id: str) -> SecurityAlert | None: ...


class ExecutionRepository(Protocol):
    def add(self, execution: TriageExecutionRecord) -> None: ...
    def get(self, execution_id: str) -> TriageExecutionRecord | None: ...


class ToolInvocationRepository(Protocol):
    def add(
        self, invocation: ToolInvocationRecord, result: dict[str, object] | None = None
    ) -> None: ...
    def list_for_execution(self, execution_id: str) -> tuple[ToolInvocationRecord, ...]: ...


class TriageResultRepository(Protocol):
    def add(self, result_id: str, execution_id: str, result: TriageResult) -> None: ...
    def get_for_execution(self, execution_id: str) -> TriageResult | None: ...


class ActionRepository(Protocol):
    def add(self, execution_id: str, action: ActionProposal) -> None: ...
    def get(self, action_id: str) -> ActionProposal | None: ...


class ApprovalRepository(Protocol):
    def add(self, approval: ApprovalRecord) -> None: ...
    def get(self, approval_id: str) -> ApprovalRecord | None: ...


class ActionExecutionRepository(Protocol):
    def add(self, execution: ActionExecutionRecord) -> None: ...
    def get(self, action_execution_id: str) -> ActionExecutionRecord | None: ...


class AuditRepository(Protocol):
    def append(self, event: AuditEvent) -> None: ...
    def list_for_target(self, target_type: str, target_id: str) -> tuple[AuditEvent, ...]: ...


class UnitOfWork(Protocol):
    alerts: AlertRepository
    executions: ExecutionRepository
    tool_invocations: ToolInvocationRepository
    triage_results: TriageResultRepository
    actions: ActionRepository
    approvals: ApprovalRepository
    action_executions: ActionExecutionRepository
    audit: AuditRepository

    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...
    def flush(self) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
