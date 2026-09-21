"""Narrow SQLAlchemy repository implementations and explicit domain mappings."""

from datetime import datetime
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_triage_agent.adapters.persistence.models import (
    ActionExecutionRow,
    AlertRow,
    ApprovalDecisionRow,
    AuditEventRow,
    EvaluationCaseResultRow,
    EvaluationRunRow,
    RecommendedActionRow,
    ToolInvocationRow,
    TriageExecutionRow,
    TriageResultRow,
)
from security_triage_agent.application.persistence import (
    ActionExecutionRecord,
    AuditEvent,
    PersistedAction,
    TriageExecutionRecord,
)
from security_triage_agent.application.tool_gateway import ToolInvocationRecord
from security_triage_agent.domain.actions import ActionProposal, ActionState
from security_triage_agent.domain.alerts import SecurityAlert
from security_triage_agent.domain.approvals import ApprovalRecord
from security_triage_agent.domain.states import TriageExecutionState
from security_triage_agent.domain.triage import TriageResult
from security_triage_agent.evaluation.persistence import EvaluationCaseRecord, EvaluationRunRecord
from security_triage_agent.evaluation.scoring import EvaluationAggregate, EvaluationCaseScore


def _json(model: Any) -> dict[str, Any]:
    return cast(dict[str, Any], model.model_dump(mode="json"))


class SqlAlchemyAlertRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, alert: SecurityAlert) -> None:
        self._session.add(
            AlertRow(
                alert_id=alert.alert_id,
                source=alert.source,
                source_severity=alert.source_severity.value,
                occurred_at=alert.occurred_at.isoformat(),
                detected_at=alert.detected_at.isoformat(),
                payload_digest=alert.original_payload.payload_digest,
                domain_data=_json(alert),
            )
        )

    def get(self, alert_id: str) -> SecurityAlert | None:
        row = self._session.get(AlertRow, alert_id)
        return SecurityAlert.model_validate(row.domain_data) if row else None

    def list_recent(self, limit: int = 100) -> tuple[SecurityAlert, ...]:
        rows = self._session.scalars(
            select(AlertRow).order_by(AlertRow.detected_at.desc(), AlertRow.alert_id).limit(limit)
        )
        return tuple(SecurityAlert.model_validate(row.domain_data) for row in rows)


class SqlAlchemyExecutionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, execution: TriageExecutionRecord) -> None:
        self._session.add(
            TriageExecutionRow(
                execution_id=execution.execution_id,
                alert_id=execution.alert_id,
                state=execution.state.value,
                idempotency_key=execution.idempotency_key,
                created_at=execution.created_at.isoformat(),
                updated_at=execution.updated_at.isoformat(),
                predecessor_execution_id=execution.predecessor_execution_id,
                failure_category=execution.failure_category,
            )
        )

    def get(self, execution_id: str) -> TriageExecutionRecord | None:
        row = self._session.get(TriageExecutionRow, execution_id)
        if row is None:
            return None
        return TriageExecutionRecord.model_validate(
            {
                "execution_id": row.execution_id,
                "alert_id": row.alert_id,
                "state": row.state,
                "idempotency_key": row.idempotency_key,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "predecessor_execution_id": row.predecessor_execution_id,
                "failure_category": row.failure_category,
            }
        )

    def get_by_idempotency_key(self, key: str) -> TriageExecutionRecord | None:
        row = self._session.scalar(
            select(TriageExecutionRow).where(TriageExecutionRow.idempotency_key == key)
        )
        return self.get(row.execution_id) if row else None

    def replace(self, execution: TriageExecutionRecord) -> None:
        row = self._session.get(TriageExecutionRow, execution.execution_id)
        if row is None:
            raise ValueError("triage execution does not exist")
        row.state = execution.state.value
        row.updated_at = execution.updated_at.isoformat()
        row.failure_category = execution.failure_category

    def list_for_alert(self, alert_id: str) -> tuple[TriageExecutionRecord, ...]:
        rows = self._session.scalars(
            select(TriageExecutionRow)
            .where(TriageExecutionRow.alert_id == alert_id)
            .order_by(TriageExecutionRow.created_at.desc(), TriageExecutionRow.execution_id)
        )
        return tuple(
            TriageExecutionRecord.model_validate(
                {
                    "execution_id": row.execution_id,
                    "alert_id": row.alert_id,
                    "state": row.state,
                    "idempotency_key": row.idempotency_key,
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                    "predecessor_execution_id": row.predecessor_execution_id,
                    "failure_category": row.failure_category,
                }
            )
            for row in rows
        )

    def list_running_before(self, cutoff: datetime) -> tuple[TriageExecutionRecord, ...]:
        rows = self._session.scalars(
            select(TriageExecutionRow)
            .where(
                TriageExecutionRow.state == TriageExecutionState.RUNNING.value,
                TriageExecutionRow.updated_at < cutoff.isoformat(),
            )
            .order_by(TriageExecutionRow.updated_at, TriageExecutionRow.execution_id)
        )
        return tuple(record for row in rows if (record := self.get(row.execution_id)) is not None)


class SqlAlchemyToolInvocationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(
        self, invocation: ToolInvocationRecord, result: dict[str, object] | None = None
    ) -> None:
        self._session.add(
            ToolInvocationRow(
                invocation_id=invocation.call_id,
                execution_id=invocation.execution_id,
                correlation_id=invocation.correlation_id,
                tool_name=invocation.tool_name,
                arguments=invocation.sanitized_arguments,
                authorization=invocation.authorization.value,
                outcome=invocation.outcome.value,
                started_at=invocation.started_at.isoformat(),
                completed_at=invocation.completed_at.isoformat(),
                duration_ms=invocation.duration_ms,
                failure_category=(
                    invocation.failure_category.value if invocation.failure_category else None
                ),
                result=result,
            )
        )

    def list_for_execution(self, execution_id: str) -> tuple[ToolInvocationRecord, ...]:
        rows = self._session.scalars(
            select(ToolInvocationRow)
            .where(ToolInvocationRow.execution_id == execution_id)
            .order_by(ToolInvocationRow.started_at, ToolInvocationRow.invocation_id)
        )
        return tuple(
            ToolInvocationRecord.model_validate(
                {
                    "execution_id": row.execution_id,
                    "correlation_id": row.correlation_id,
                    "call_id": row.invocation_id,
                    "tool_name": row.tool_name,
                    "sanitized_arguments": row.arguments,
                    "authorization": row.authorization,
                    "outcome": row.outcome,
                    "started_at": row.started_at,
                    "completed_at": row.completed_at,
                    "duration_ms": row.duration_ms,
                    "failure_category": row.failure_category,
                }
            )
            for row in rows
        )


class SqlAlchemyTriageResultRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, result_id: str, execution_id: str, result: TriageResult) -> None:
        self._session.add(
            TriageResultRow(
                result_id=result_id,
                execution_id=execution_id,
                alert_id=result.alert_id,
                disposition=result.disposition.value,
                confidence=result.confidence,
                assessed_severity=result.severity.value,
                occurred_at=result.timestamp.isoformat(),
                domain_data=_json(result),
            )
        )

    def get_for_execution(self, execution_id: str) -> TriageResult | None:
        row = self._session.scalar(
            select(TriageResultRow).where(TriageResultRow.execution_id == execution_id)
        )
        return TriageResult.model_validate(row.domain_data) if row else None


class SqlAlchemyActionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, execution_id: str, action: ActionProposal, policy_version: str = "1.0.0") -> None:
        data = _json(action)
        self._session.add(
            RecommendedActionRow(
                action_id=action.action_id,
                execution_id=execution_id,
                catalog_action_id=action.catalog_action_id,
                target=data["target"],
                parameters=data["parameters"],
                action_digest=action.digest,
                policy_version=policy_version,
                rationale=action.rationale,
                domain_data=data,
            )
        )

    def get(self, action_id: str) -> ActionProposal | None:
        row = self._session.get(RecommendedActionRow, action_id)
        return ActionProposal.model_validate(row.domain_data) if row else None

    def get_persisted(self, action_id: str) -> PersistedAction | None:
        row = self._session.get(RecommendedActionRow, action_id)
        if row is None:
            return None
        return PersistedAction(
            execution_id=row.execution_id,
            policy_version=row.policy_version,
            action=ActionProposal.model_validate(row.domain_data),
        )


class SqlAlchemyApprovalRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, approval: ApprovalRecord) -> None:
        self._session.add(
            ApprovalDecisionRow(
                approval_id=approval.approval_id,
                action_id=approval.action_id,
                action_digest=approval.action_digest,
                reviewer_id=approval.reviewer_id,
                decision=approval.decision.value,
                decided_at=approval.decided_at.isoformat(),
                reason=approval.reason,
                policy_version=approval.policy_version,
                expires_at=approval.expires_at.isoformat() if approval.expires_at else None,
                domain_data=_json(approval),
            )
        )

    def get(self, approval_id: str) -> ApprovalRecord | None:
        row = self._session.get(ApprovalDecisionRow, approval_id)
        return ApprovalRecord.model_validate(row.domain_data) if row else None

    def get_for_action(self, action_id: str) -> ApprovalRecord | None:
        row = self._session.scalar(
            select(ApprovalDecisionRow).where(ApprovalDecisionRow.action_id == action_id)
        )
        return ApprovalRecord.model_validate(row.domain_data) if row else None


class SqlAlchemyActionExecutionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, execution: ActionExecutionRecord) -> None:
        self._session.add(
            ActionExecutionRow(
                action_execution_id=execution.action_execution_id,
                action_id=execution.action_id,
                state=execution.state.value,
                started_at=execution.started_at.isoformat(),
                completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
                outcome=execution.outcome,
                failure_category=execution.failure_category,
                mode=execution.mode,
                result=execution.result,
            )
        )

    def get(self, action_execution_id: str) -> ActionExecutionRecord | None:
        row = self._session.get(ActionExecutionRow, action_execution_id)
        if row is None:
            return None
        return ActionExecutionRecord.model_validate(
            {
                "action_execution_id": row.action_execution_id,
                "action_id": row.action_id,
                "state": row.state,
                "started_at": row.started_at,
                "completed_at": row.completed_at,
                "outcome": row.outcome,
                "failure_category": row.failure_category,
                "mode": row.mode,
                "result": row.result,
            }
        )

    def get_for_action(self, action_id: str) -> ActionExecutionRecord | None:
        row = self._session.scalar(
            select(ActionExecutionRow).where(ActionExecutionRow.action_id == action_id)
        )
        return self.get(row.action_execution_id) if row else None

    def replace(self, execution: ActionExecutionRecord) -> None:
        row = self._session.get(ActionExecutionRow, execution.action_execution_id)
        if row is None:
            raise ValueError("action execution does not exist")
        row.state = execution.state.value
        row.completed_at = execution.completed_at.isoformat() if execution.completed_at else None
        row.outcome = execution.outcome
        row.failure_category = execution.failure_category
        row.mode = execution.mode
        row.result = execution.result

    def list_executing_before(self, cutoff: datetime) -> tuple[ActionExecutionRecord, ...]:
        rows = self._session.scalars(
            select(ActionExecutionRow)
            .where(
                ActionExecutionRow.state == ActionState.EXECUTING.value,
                ActionExecutionRow.started_at < cutoff.isoformat(),
            )
            .order_by(ActionExecutionRow.started_at, ActionExecutionRow.action_execution_id)
        )
        return tuple(
            record for row in rows if (record := self.get(row.action_execution_id)) is not None
        )


class SqlAlchemyAuditRepository:
    """Append/list-only repository; historical events have no mutation API."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: AuditEvent) -> None:
        self._session.add(
            AuditEventRow(
                event_id=event.event_id,
                event_type=event.event_type,
                occurred_at=event.occurred_at.isoformat(),
                execution_id=event.execution_id,
                correlation_id=event.correlation_id,
                actor_id=event.actor_id,
                target_type=event.target_type,
                target_id=event.target_id,
                event_data=event.data,
                outcome=event.outcome.value if event.outcome else None,
                failure_category=event.failure_category,
                schema_version=event.schema_version,
            )
        )

    def list_for_target(self, target_type: str, target_id: str) -> tuple[AuditEvent, ...]:
        rows = self._session.scalars(
            select(AuditEventRow)
            .where(
                AuditEventRow.target_type == target_type,
                AuditEventRow.target_id == target_id,
            )
            .order_by(AuditEventRow.occurred_at, AuditEventRow.event_id)
        )
        return tuple(
            AuditEvent.model_validate(
                {
                    "event_id": row.event_id,
                    "event_type": row.event_type,
                    "occurred_at": row.occurred_at,
                    "execution_id": row.execution_id,
                    "correlation_id": row.correlation_id,
                    "actor_id": row.actor_id,
                    "target_type": row.target_type,
                    "target_id": row.target_id,
                    "data": row.event_data,
                    "outcome": row.outcome,
                    "failure_category": row.failure_category,
                    "schema_version": row.schema_version,
                }
            )
            for row in rows
        )


class SqlAlchemyEvaluationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_run(self, run: EvaluationRunRecord) -> None:
        self._session.add(
            EvaluationRunRow(
                run_id=run.run_id,
                suite_version=run.suite_version,
                schema_version=run.schema_version,
                fixture_version=run.fixture_version,
                policy_version=run.policy_version,
                reasoner_label=run.reasoner_label,
                reasoner_implementation=run.reasoner_implementation,
                provider=run.provider,
                model=run.model,
                prompt_version=run.prompt_version,
                application_version=run.application_version,
                started_at=run.started_at.isoformat(),
                completed_at=run.completed_at.isoformat(),
                aggregate_data=_json(run.aggregate),
            )
        )

    def add_case(self, case: EvaluationCaseRecord) -> None:
        self._session.add(
            EvaluationCaseResultRow(
                case_id=case.case_id,
                run_id=case.run_id,
                scenario_id=case.scenario_id,
                scenario_version=case.scenario_version,
                triage_execution_id=case.triage_execution_id,
                score_data=_json(case.score),
            )
        )

    def get_run(self, run_id: str) -> EvaluationRunRecord | None:
        row = self._session.get(EvaluationRunRow, run_id)
        if row is None:
            return None
        return EvaluationRunRecord(
            run_id=row.run_id,
            suite_version=row.suite_version,
            schema_version=row.schema_version,
            fixture_version=row.fixture_version,
            policy_version=row.policy_version,
            reasoner_label=row.reasoner_label,
            reasoner_implementation=row.reasoner_implementation,
            provider=row.provider,
            model=row.model,
            prompt_version=row.prompt_version,
            application_version=row.application_version,
            started_at=row.started_at,
            completed_at=row.completed_at,
            aggregate=EvaluationAggregate.model_validate(row.aggregate_data),
        )

    def list_cases(self, run_id: str) -> tuple[EvaluationCaseRecord, ...]:
        rows = self._session.scalars(
            select(EvaluationCaseResultRow)
            .where(EvaluationCaseResultRow.run_id == run_id)
            .order_by(EvaluationCaseResultRow.scenario_id)
        )
        return tuple(
            EvaluationCaseRecord(
                case_id=row.case_id,
                run_id=row.run_id,
                scenario_id=row.scenario_id,
                scenario_version=row.scenario_version,
                triage_execution_id=row.triage_execution_id,
                score=EvaluationCaseScore.model_validate(row.score_data),
            )
            for row in rows
        )
