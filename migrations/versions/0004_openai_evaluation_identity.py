"""Preserve external reasoner identity in evaluation runs."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_openai_evaluation_identity"
down_revision: str | None = "0003_evaluation_results"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "evaluation_runs",
        sa.Column(
            "reasoner_implementation",
            sa.String(128),
            nullable=False,
            server_default="DemoReasoner",
        ),
    )
    op.add_column(
        "evaluation_runs",
        sa.Column("provider", sa.String(128), nullable=False, server_default="offline"),
    )
    op.add_column(
        "evaluation_runs",
        sa.Column("model", sa.String(128), nullable=False, server_default="deterministic-demo-v1"),
    )
    op.add_column(
        "evaluation_runs",
        sa.Column("prompt_version", sa.String(64), nullable=False, server_default="demo-v1"),
    )


def downgrade() -> None:
    op.drop_column("evaluation_runs", "prompt_version")
    op.drop_column("evaluation_runs", "model")
    op.drop_column("evaluation_runs", "provider")
    op.drop_column("evaluation_runs", "reasoner_implementation")
