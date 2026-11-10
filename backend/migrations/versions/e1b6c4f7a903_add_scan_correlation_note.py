"""keep the explanation of a score that counted a leaked repo key

Revision ID: e1b6c4f7a903
Revises: d9a2e7b41c36
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "e1b6c4f7a903"
down_revision: str | None = "d9a2e7b41c36"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans", sa.Column("correlation_note", sqlmodel.sql.sqltypes.AutoString(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scans", "correlation_note")
