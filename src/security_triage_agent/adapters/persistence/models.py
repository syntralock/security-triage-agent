"""SQLAlchemy mappings; domain packages remain ORM-independent."""

from decimal import Decimal
from typing import Any

from sqlalchemy import JSON, CheckConstraint, ForeignKey, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AlertRow(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(128))
    source_severity: Mapped[str] = mapped_column(String(32))
    occurred_at: Mapped[str] = mapped_column(String(40))
    detected_at: Mapped[str] = mapped_column(String(40))
    payload_digest: Mapped[str] = mapped_column(String(71), unique=True)
    domain_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class TriageExecutionRow(Base):
    __tablename__ = "triage_executions"
    execution_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"))
    state: Mapped[str] = mapped_column(String(32))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    predecessor_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("triage_executions.execution_id")
    )
    failure_category: Mapped[str | None] = mapped_column(String(128))


class ToolInvocationRow(Base):
    __tablename__ = "tool_invocations"
    invocation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    execution_id: Mapped[str] = mapped_column(ForeignKey("triage_executions.execution_id"))
    correlation_id: Mapped[str] = mapped_column(String(128))
    tool_name: Mapped[str] = mapped_column(String(128))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON)
    authorization: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[str] = mapped_column(String(40))
    completed_at: Mapped[str] = mapped_column(String(40))
    duration_ms: Mapped[int] = mapped_column()
    failure_category: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class TriageResultRow(Base):
    __tablename__ = "triage_results"
    result_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("triage_executions.execution_id"), unique=True
    )
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.alert_id"))
    disposition: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[Decimal] = mapped_column(Numeric(38, 18))
    assessed_severity: Mapped[str] = mapped_column(String(32))
    occurred_at: Mapped[str] = mapped_column(String(40))
    domain_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class RecommendedActionRow(Base):
    __tablename__ = "recommended_actions"
    action_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    execution_id: Mapped[str] = mapped_column(ForeignKey("triage_executions.execution_id"))
    catalog_action_id: Mapped[str] = mapped_column(String(128))
    target: Mapped[dict[str, Any]] = mapped_column(JSON)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON)
    action_digest: Mapped[str] = mapped_column(String(71))
    rationale: Mapped[str] = mapped_column(Text)
    domain_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class ApprovalDecisionRow(Base):
    __tablename__ = "approval_decisions"
    __table_args__ = (
        CheckConstraint(
            "(decision = 'APPROVED' AND expires_at IS NOT NULL) OR "
            "(decision = 'REJECTED' AND expires_at IS NULL)",
            name="ck_approval_expiry_semantics",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > decided_at",
            name="ck_approval_expiry_after_decision",
        ),
    )
    approval_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("recommended_actions.action_id"))
    action_digest: Mapped[str] = mapped_column(String(71))
    reviewer_id: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(16))
    decided_at: Mapped[str] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(Text)
    policy_version: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[str | None] = mapped_column(String(40))
    domain_data: Mapped[dict[str, Any]] = mapped_column(JSON)


class ActionExecutionRow(Base):
    __tablename__ = "action_executions"
    action_execution_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("recommended_actions.action_id"))
    state: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[str] = mapped_column(String(40))
    completed_at: Mapped[str | None] = mapped_column(String(40))
    outcome: Mapped[str | None] = mapped_column(String(128))
    failure_category: Mapped[str | None] = mapped_column(String(128))


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("event_id", name="uq_audit_event_id"),)
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(128))
    occurred_at: Mapped[str] = mapped_column(String(40))
    execution_id: Mapped[str | None] = mapped_column(String(128))
    correlation_id: Mapped[str | None] = mapped_column(String(128))
    actor_id: Mapped[str | None] = mapped_column(String(128))
    target_type: Mapped[str] = mapped_column(String(128))
    target_id: Mapped[str] = mapped_column(String(128))
    event_data: Mapped[dict[str, Any]] = mapped_column(JSON)
    outcome: Mapped[str | None] = mapped_column(String(32))
    failure_category: Mapped[str | None] = mapped_column(String(128))
    schema_version: Mapped[str] = mapped_column(String(64))
