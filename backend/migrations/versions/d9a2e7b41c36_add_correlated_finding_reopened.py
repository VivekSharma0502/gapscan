"""record who reopened a combined finding and when

Revision ID: d9a2e7b41c36
Revises: c3f1d8a47e25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d9a2e7b41c36"
down_revision: str | None = "c3f1d8a47e25"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REOPENED_BY_FK = "fk_correlated_findings_reopened_by_profiles"


def upgrade() -> None:
    op.add_column(
        "correlated_findings", sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("correlated_findings", sa.Column("reopened_by", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        _REOPENED_BY_FK,
        "correlated_findings",
        "profiles",
        ["reopened_by"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(_REOPENED_BY_FK, "correlated_findings", type_="foreignkey")
    op.drop_column("correlated_findings", "reopened_by")
    op.drop_column("correlated_findings", "reopened_at")
