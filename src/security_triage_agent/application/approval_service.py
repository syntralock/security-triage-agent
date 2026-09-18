"""Human approval and independently revalidated simulated execution workflow."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from security_triage_agent.application.action_catalog import (
    ActionCatalog,
    ExecutionSupport,
)
from security_triage_agent.application.persistence import (
    ActionExecutionRecord,
    AuditEvent,
    AuditOutcome,
)
from security_triage_agent.application.ports.auth import AuthorizationService
from security_triage_agent.application.ports.executors import ActionExecutor
from security_triage_agent.application.ports.reasoner import Clock, IdentifierGenerator
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.domain.actions import ActionLifecycle, ActionReference, ActionState
from security_triage_agent.domain.approvals import (
    ApprovalDecision,
    ApprovalLifecycle,
    ApprovalRecord,
    ApprovalState,
)


class WorkflowErrorCode(StrEnum):
    ACTION_NOT_FOUND = "ACTION_NOT_FOUND"
    APPROVAL_NOT_REQUIRED = "APPROVAL_NOT_REQUIRED"
    DECISION_CONFLICT = "DECISION_CONFLICT"
    APPROVAL_MISSING = "APPROVAL_MISSING"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    STALE_APPROVAL = "STALE_APPROVAL"
    REVIEWER_INVALID = "REVIEWER_INVALID"
    EXECUTION_NOT_SUPPORTED = "EXECUTION_NOT_SUPPORTED"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
    EXECUTOR_FAILED = "EXECUTOR_FAILED"
    PERSISTENCE_FAILED = "PERSISTENCE_FAILED"


class WorkflowError(RuntimeError):
    def __init__(self, code: WorkflowErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    record: ActionExecutionRecord
    durable: bool


class ApprovalService:
    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        catalog: ActionCatalog,
        executor: ActionExecutor,
        authorization: AuthorizationService,
        clock: Clock,
        identifiers: IdentifierGenerator,
        approval_lifetime: timedelta,
    ) -> None:
        self._uow_factory = uow_factory
        self._catalog = catalog
        self._executor = executor
        self._authorization = authorization
        self._clock = clock
        self._ids = identifiers
        self._approval_lifetime = approval_lifetime

    def approve(self, action_id: str, reviewer_id: str, reason: str) -> ApprovalRecord:
        return self._decide(action_id, reviewer_id, reason, ApprovalDecision.APPROVED)

    def reject(self, action_id: str, reviewer_id: str, reason: str) -> ApprovalRecord:
        return self._decide(action_id, reviewer_id, reason, ApprovalDecision.REJECTED)

    def _decide(
        self, action_id: str, reviewer_id: str, reason: str, decision: ApprovalDecision
    ) -> ApprovalRecord:
        if not self._authorization.is_authorized_reviewer_id(reviewer_id):
            raise WorkflowError(WorkflowErrorCode.REVIEWER_INVALID)
        now = self._clock.now()
        with self._uow_factory() as uow:
            persisted = uow.actions.get_persisted(action_id)
            if persisted is None:
                raise WorkflowError(WorkflowErrorCode.ACTION_NOT_FOUND)
            result = uow.triage_results.get_for_execution(persisted.execution_id)
            reference = ActionReference.from_proposal(persisted.action)
            if result is None or reference not in result.actions_requiring_approval:
                raise WorkflowError(WorkflowErrorCode.APPROVAL_NOT_REQUIRED)
            existing = uow.approvals.get_for_action(action_id)
            if existing is not None:
                if (
                    existing.decision is decision
                    and existing.reviewer_id == reviewer_id
                    and existing.reason == reason
                ):
                    return existing
                raise WorkflowError(WorkflowErrorCode.DECISION_CONFLICT)
            ApprovalLifecycle(
                approval_id=self._ids.next_id("approval-lifecycle"),
                action_id=action_id,
                action_digest=persisted.action.digest,
            ).transition_to(
                ApprovalState.APPROVED
                if decision is ApprovalDecision.APPROVED
                else ApprovalState.REJECTED
            )
            approval = ApprovalRecord(
                approval_id=self._ids.next_id("approval"),
                action_id=action_id,
                action_digest=persisted.action.digest,
                reviewer_id=reviewer_id,
                decision=decision,
                decided_at=now,
                reason=reason,
                policy_version=persisted.policy_version,
                expires_at=(
                    now + self._approval_lifetime if decision is ApprovalDecision.APPROVED else None
                ),
            )
            uow.approvals.add(approval)
            uow.audit.append(
                self._audit(
                    f"action.{decision.value.lower()}",
                    action_id,
                    reviewer_id,
                    {
                        "approval_id": approval.approval_id,
                        "action_digest": approval.action_digest,
                        "policy_version": approval.policy_version,
                        "decision": approval.decision.value,
                    },
                    AuditOutcome.SUCCESS,
                )
            )
            uow.commit()
            return approval

    def execute(self, action_id: str, actor_id: str) -> ExecutionOutcome:
        if not self._authorization.is_authorized_reviewer_id(actor_id):
            raise WorkflowError(WorkflowErrorCode.REVIEWER_INVALID)
        now = self._clock.now()
        with self._uow_factory() as uow:
            persisted = uow.actions.get_persisted(action_id)
            if persisted is None:
                raise WorkflowError(WorkflowErrorCode.ACTION_NOT_FOUND)
            action = persisted.action
            result = uow.triage_results.get_for_execution(persisted.execution_id)
            approval = uow.approvals.get_for_action(action_id)
            existing = uow.action_executions.get_for_action(action_id)
            if existing is not None and existing.state is ActionState.SUCCEEDED:
                return ExecutionOutcome(existing, durable=True)
            code: WorkflowErrorCode | None = None
            definition = self._catalog.lookup(action.catalog_action_id)
            reference = ActionReference.from_proposal(action)
            if definition is None or result is None or action not in result.recommended_actions:
                code = WorkflowErrorCode.STALE_APPROVAL
            elif reference not in result.actions_requiring_approval:
                code = WorkflowErrorCode.APPROVAL_NOT_REQUIRED
            elif (
                definition.execution_support is not ExecutionSupport.SIMULATED_ONLY
                or self._executor.mode != "SIMULATED"
            ):
                code = WorkflowErrorCode.EXECUTION_NOT_SUPPORTED
            elif approval is None:
                code = WorkflowErrorCode.APPROVAL_MISSING
            elif approval.decision is ApprovalDecision.REJECTED:
                code = WorkflowErrorCode.APPROVAL_REJECTED
            elif approval.expires_at is None or approval.expires_at <= now:
                ApprovalLifecycle(
                    approval_id=approval.approval_id,
                    action_id=approval.action_id,
                    action_digest=approval.action_digest,
                    state=ApprovalState.APPROVED,
                ).transition_to(ApprovalState.EXPIRED)
                code = WorkflowErrorCode.APPROVAL_EXPIRED
            elif (
                approval.action_digest != action.digest
                or approval.policy_version != persisted.policy_version
            ):
                code = WorkflowErrorCode.STALE_APPROVAL
            elif not self._authorization.is_authorized_reviewer_id(approval.reviewer_id):
                code = WorkflowErrorCode.REVIEWER_INVALID
            if code is not None:
                uow.audit.append(
                    self._audit(
                        "action.execution_denied",
                        action_id,
                        actor_id,
                        {"reason_code": code.value, "action_digest": action.digest},
                        AuditOutcome.DENIED,
                    )
                )
                uow.commit()
                raise WorkflowError(code)
            executing_state = ActionLifecycle(
                action_id=action_id, state=ActionState.APPROVED
            ).transition_to(ActionState.EXECUTING)
            execution = ActionExecutionRecord(
                action_execution_id=self._ids.next_id("action-execution"),
                action_id=action_id,
                state=executing_state.state,
                started_at=now,
                mode="SIMULATED",
            )
            uow.action_executions.add(execution)
            uow.audit.append(
                self._audit(
                    "action.simulation_started",
                    action_id,
                    actor_id,
                    {"mode": "SIMULATED", "action_digest": action.digest},
                    AuditOutcome.SUCCESS,
                )
            )
            uow.commit()

        try:
            simulated = self._executor.execute(action)
        except Exception as error:
            self._finish_failed(execution, actor_id)
            raise WorkflowError(WorkflowErrorCode.EXECUTOR_FAILED) from error

        succeeded_state = ActionLifecycle(
            action_id=action_id, state=ActionState.EXECUTING
        ).transition_to(ActionState.SUCCEEDED)
        completed = execution.model_copy(
            update={
                "state": succeeded_state.state,
                "completed_at": self._clock.now(),
                "outcome": simulated.outcome,
                "mode": simulated.mode,
                "result": simulated.details,
            }
        )
        try:
            with self._uow_factory() as uow:
                uow.action_executions.replace(completed)
                uow.audit.append(
                    self._audit(
                        "action.simulation_succeeded",
                        action_id,
                        actor_id,
                        {"mode": simulated.mode, "outcome": simulated.outcome},
                        AuditOutcome.SUCCESS,
                    )
                )
                uow.commit()
        except Exception as error:
            raise WorkflowError(WorkflowErrorCode.PERSISTENCE_FAILED) from error
        return ExecutionOutcome(completed, durable=True)

    def _finish_failed(self, execution: ActionExecutionRecord, actor_id: str) -> None:
        failed_state = ActionLifecycle(
            action_id=execution.action_id, state=ActionState.EXECUTING
        ).transition_to(ActionState.FAILED)
        failed = execution.model_copy(
            update={
                "state": failed_state.state,
                "completed_at": self._clock.now(),
                "outcome": "SIMULATED_FAILURE",
                "failure_category": "SIMULATOR_FAILURE",
            }
        )
        with self._uow_factory() as uow:
            uow.action_executions.replace(failed)
            uow.audit.append(
                self._audit(
                    "action.simulation_failed",
                    execution.action_id,
                    actor_id,
                    {"mode": "SIMULATED", "failure_code": "SIMULATOR_FAILURE"},
                    AuditOutcome.FAILED,
                )
            )
            uow.commit()

    def _audit(
        self,
        event_type: str,
        action_id: str,
        actor_id: str,
        data: dict[str, str],
        outcome: AuditOutcome,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=self._ids.next_id("audit"),
            event_type=event_type,
            occurred_at=self._clock.now(),
            actor_id=actor_id,
            target_type="recommended_action",
            target_id=action_id,
            data=data,
            outcome=outcome,
        )
