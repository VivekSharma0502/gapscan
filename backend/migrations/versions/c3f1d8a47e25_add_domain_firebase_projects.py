"""add firebase project ids seen on a domain

Revision ID: c3f1d8a47e25
Revises: b5e8f0a3c612
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "c3f1d8a47e25"
down_revision: str | None = "b5e8f0a3c612"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domain_firebase_projects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sqlmodel.sql.sqltypes.AutoString(length=63), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "domain_id", "project_id", name="uq_domain_firebase_projects_domain_project"
        ),
    )


def downgrade() -> None:
    op.drop_table("domain_firebase_projects")
