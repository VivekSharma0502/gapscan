"""add domain backends

Revision ID: d4a1c8e52b71
Revises: c7e2a9d14f60
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "d4a1c8e52b71"
down_revision: str | None = "c7e2a9d14f60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_backends",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "firebase_rtdb",
                "firebase_storage",
                "supabase",
                name="baaskind",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("identifier", sqlmodel.sql.sqltypes.AutoString(length=253), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain_id", "kind", "identifier", name="uq_domain_backends_domain_kind_identifier"
        ),
    )


def downgrade() -> None:
    op.drop_table("domain_backends")
