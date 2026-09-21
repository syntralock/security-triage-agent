"""Explicit deterministic recovery for stale non-terminal records."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from security_triage_agent.application.persistence import AuditEvent, AuditOutcome
from security_triage_agent.application.ports.reasoner import Clock, IdentifierGenerator
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.domain.actions import ActionLifecycle, ActionState
from security_triage_agent.domain.states import TriageExecutionState

STALE_EXECUTION = "STALE_EXECUTION"
STALE_SIMULATED_ACTION = "STALE_SIMULATED_ACTION"


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    stale_executions_failed: int
    stale_actions_failed: int


class StaleStateRecoveryService:
    """Fail stale work closed; never infer success or rerun an action."""

    def __init__(
        self,
        *,
        uow_factory: Callable[[], UnitOfWork],
        clock: Clock,
        identifiers: IdentifierGenerator,
        execution_threshold: timedelta,
        action_threshold: timedelta,
    ) -> None:
        self._uow_factory = uow_factory
        self._clock = clock
        self._ids = identifiers
        self._execution_threshold = execution_threshold
        self._action_threshold = action_threshold

    def recover_all(self, *, operator_id: str, correlation_id: str) -> RecoveryReport:
        return RecoveryReport(
            stale_executions_failed=self.recover_stale_executions(
                operator_id=operator_id, correlation_id=correlation_id
            ),
            stale_actions_failed=self.recover_stale_actions(
                operator_id=operator_id, correlation_id=correlation_id
            ),
        )

    def recover_stale_executions(self, *, operator_id: str, correlation_id: str) -> int:
        now = self._clock.now()
        cutoff = now - self._execution_threshold
        recovered = 0
        with self._uow_factory() as uow:
            for execution in uow.executions.list_running_before(cutoff):
                failed = execution.model_copy(
                    update={
                        "state": TriageExecutionState.FAILED,
                        "updated_at": now,
                        "failure_category": STALE_EXECUTION,
                    }
                )
                uow.executions.replace(failed)
                uow.audit.append(
                    AuditEvent(
                        event_id=self._ids.next_id("audit"),
                        event_type="triage.stale_execution_recovered",
                        occurred_at=now,
                        execution_id=execution.execution_id,
                        correlation_id=correlation_id,
                        actor_id=operator_id,
                        target_type="triage_execution",
                        target_id=execution.execution_id,
                        data={"failure_category": STALE_EXECUTION},
                        outcome=AuditOutcome.FAILED,
                        failure_category=STALE_EXECUTION,
                    )
                )
                recovered += 1
            uow.commit()
        return recovered

    def recover_stale_actions(self, *, operator_id: str, correlation_id: str) -> int:
        now = self._clock.now()
        cutoff = now - self._action_threshold
        recovered = 0
        with self._uow_factory() as uow:
            for execution in uow.action_executions.list_executing_before(cutoff):
                failed_state = ActionLifecycle(
                    action_id=execution.action_id,
                    state=ActionState.EXECUTING,
                ).transition_to(ActionState.FAILED)
                failed = execution.model_copy(
                    update={
                        "state": failed_state.state,
                        "completed_at": now,
                        "outcome": "SIMULATED_RECOVERY_FAILURE",
                        "failure_category": STALE_SIMULATED_ACTION,
                    }
                )
                uow.action_executions.replace(failed)
                uow.audit.append(
                    AuditEvent(
                        event_id=self._ids.next_id("audit"),
                        event_type="action.stale_simulation_recovered",
                        occurred_at=now,
                        correlation_id=correlation_id,
                        actor_id=operator_id,
                        target_type="recommended_action",
                        target_id=execution.action_id,
                        data={
                            "action_execution_id": execution.action_execution_id,
                            "failure_category": STALE_SIMULATED_ACTION,
                            "mode": "SIMULATED",
                        },
                        outcome=AuditOutcome.FAILED,
                        failure_category=STALE_SIMULATED_ACTION,
                    )
                )
                recovered += 1
            uow.commit()
        return recovered
