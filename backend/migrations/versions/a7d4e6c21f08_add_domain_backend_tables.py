"""add domain backend tables

Revision ID: a7d4e6c21f08
Revises: f2c9a1d7b350
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "a7d4e6c21f08"
down_revision: str | None = "f2c9a1d7b350"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_backend_tables",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("backend_id", sa.Uuid(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=63), nullable=False),
        sa.Column(
            "access",
            sa.Enum(
                "readable",
                "no_rows",
                "refused",
                "not_found",
                "unknown",
                name="tableaccess",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("meant_to_be_public_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["backend_id"], ["domain_backends.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("backend_id", "name", name="uq_domain_backend_tables_backend_name"),
    )


def downgrade() -> None:
    op.drop_table("domain_backend_tables")
