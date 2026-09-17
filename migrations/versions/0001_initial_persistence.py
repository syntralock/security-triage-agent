"""Initial durable persistence and audit schema."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_persistence"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(128), primary_key=True),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("source_severity", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.Column("detected_at", sa.String(40), nullable=False),
        sa.Column("payload_digest", sa.String(71), nullable=False, unique=True),
        sa.Column("domain_data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "triage_executions",
        sa.Column("execution_id", sa.String(128), primary_key=True),
        sa.Column("alert_id", sa.String(128), sa.ForeignKey("alerts.alert_id"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.Column(
            "predecessor_execution_id",
            sa.String(128),
            sa.ForeignKey("triage_executions.execution_id"),
        ),
        sa.Column("failure_category", sa.String(128)),
    )
    op.create_table(
        "tool_invocations",
        sa.Column("invocation_id", sa.String(128), primary_key=True),
        sa.Column(
            "execution_id",
            sa.String(128),
            sa.ForeignKey("triage_executions.execution_id"),
            nullable=False,
        ),
        sa.Column("correlation_id", sa.String(128), nullable=False),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("arguments", sa.JSON(), nullable=False),
        sa.Column("authorization", sa.String(32), nullable=False),
        sa.Column("outcome", sa.String(64), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("failure_category", sa.String(64)),
        sa.Column("result", sa.JSON()),
    )
    op.create_table(
        "triage_results",
        sa.Column("result_id", sa.String(128), primary_key=True),
        sa.Column(
            "execution_id",
            sa.String(128),
            sa.ForeignKey("triage_executions.execution_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("alert_id", sa.String(128), sa.ForeignKey("alerts.alert_id"), nullable=False),
        sa.Column("disposition", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Numeric(38, 18), nullable=False),
        sa.Column("assessed_severity", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.Column("domain_data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "recommended_actions",
        sa.Column("action_id", sa.String(128), primary_key=True),
        sa.Column(
            "execution_id",
            sa.String(128),
            sa.ForeignKey("triage_executions.execution_id"),
            nullable=False,
        ),
        sa.Column("catalog_action_id", sa.String(128), nullable=False),
        sa.Column("target", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("action_digest", sa.String(71), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("domain_data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "approval_decisions",
        sa.Column("approval_id", sa.String(128), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(128),
            sa.ForeignKey("recommended_actions.action_id"),
            nullable=False,
        ),
        sa.Column("action_digest", sa.String(71), nullable=False),
        sa.Column("reviewer_id", sa.String(128), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("decided_at", sa.String(40), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.String(40)),
        sa.Column("domain_data", sa.JSON(), nullable=False),
        sa.CheckConstraint(
            "(decision = 'APPROVED' AND expires_at IS NOT NULL) OR "
            "(decision = 'REJECTED' AND expires_at IS NULL)",
            name="ck_approval_expiry_semantics",
        ),
        sa.CheckConstraint(
            "expires_at IS NULL OR expires_at > decided_at",
            name="ck_approval_expiry_after_decision",
        ),
    )
    op.create_table(
        "action_executions",
        sa.Column("action_execution_id", sa.String(128), primary_key=True),
        sa.Column(
            "action_id",
            sa.String(128),
            sa.ForeignKey("recommended_actions.action_id"),
            nullable=False,
        ),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("completed_at", sa.String(40)),
        sa.Column("outcome", sa.String(128)),
        sa.Column("failure_category", sa.String(128)),
    )
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(128), primary_key=True),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.String(40), nullable=False),
        sa.Column("execution_id", sa.String(128)),
        sa.Column("correlation_id", sa.String(128)),
        sa.Column("actor_id", sa.String(128)),
        sa.Column("target_type", sa.String(128), nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
        sa.Column("event_data", sa.JSON(), nullable=False),
        sa.Column("outcome", sa.String(32)),
        sa.Column("failure_category", sa.String(128)),
        sa.Column("schema_version", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "audit_events",
        "action_executions",
        "approval_decisions",
        "recommended_actions",
        "triage_results",
        "tool_invocations",
        "triage_executions",
        "alerts",
    ):
        op.drop_table(table)
