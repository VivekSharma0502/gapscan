"""add scan verification note

Revision ID: f2c9a1d7b350
Revises: e8b3f27a9c14
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "f2c9a1d7b350"
down_revision: str | None = "e8b3f27a9c14"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans", sa.Column("verification_note", sqlmodel.sql.sqltypes.AutoString(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("scans", "verification_note")
