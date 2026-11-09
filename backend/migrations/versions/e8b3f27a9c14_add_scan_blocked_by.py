"""add scan blocked_by

Revision ID: e8b3f27a9c14
Revises: d4a1c8e52b71
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e8b3f27a9c14"
down_revision: str | None = "d4a1c8e52b71"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "blocked_by",
            sa.Enum("vercel", "cloudflare", name="botprotection", native_enum=False, length=16),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "blocked_by")
