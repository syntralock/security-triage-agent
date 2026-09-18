"""Persist deterministic evaluation runs and case results."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_evaluation_results"
down_revision: str | None = "0002_approval_execution_workflow"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evaluation_runs",
        sa.Column("run_id", sa.String(128), primary_key=True),
        sa.Column("suite_version", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(64), nullable=False),
        sa.Column("fixture_version", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("reasoner_label", sa.String(128), nullable=False),
        sa.Column("application_version", sa.String(64), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.Column("aggregate_data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "evaluation_case_results",
        sa.Column("case_id", sa.String(128), primary_key=True),
        sa.Column(
            "run_id",
            sa.String(128),
            sa.ForeignKey("evaluation_runs.run_id"),
            nullable=False,
        ),
        sa.Column("scenario_id", sa.String(128), nullable=False),
        sa.Column("scenario_version", sa.String(64), nullable=False),
        sa.Column(
            "triage_execution_id",
            sa.String(128),
            sa.ForeignKey("triage_executions.execution_id"),
            nullable=False,
        ),
        sa.Column("score_data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("run_id", "scenario_id", name="uq_eval_run_scenario"),
    )


def downgrade() -> None:
    op.drop_table("evaluation_case_results")
    op.drop_table("evaluation_runs")
