"""Bind actions to policy and persist unique simulated execution results."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_approval_execution_workflow"
down_revision: str | None = "0001_initial_persistence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "recommended_actions",
        sa.Column("policy_version", sa.String(64), nullable=False, server_default="1.0.0"),
    )
    op.create_index("uq_approval_action_id", "approval_decisions", ["action_id"], unique=True)
    op.add_column(
        "action_executions",
        sa.Column("mode", sa.String(32), nullable=False, server_default="SIMULATED"),
    )
    op.add_column("action_executions", sa.Column("result", sa.JSON()))
    op.create_index(
        "uq_action_execution_action_id", "action_executions", ["action_id"], unique=True
    )


def downgrade() -> None:
    op.drop_index("uq_action_execution_action_id", table_name="action_executions")
    op.drop_column("action_executions", "result")
    op.drop_column("action_executions", "mode")
    op.drop_index("uq_approval_action_id", table_name="approval_decisions")
    op.drop_column("recommended_actions", "policy_version")
