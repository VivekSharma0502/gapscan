"""add domains

Revision ID: 614a5c395273
Revises: 4774dc71d1ab
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "614a5c395273"
down_revision: str | None = "4774dc71d1ab"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "domains",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sqlmodel.sql.sqltypes.AutoString(length=253), nullable=False),
        sa.Column("verify_token", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_method", sqlmodel.sql.sqltypes.AutoString(length=8), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_id", "hostname", name="uq_domains_owner_hostname"),
    )
    op.create_foreign_key(
        "fk_scans_domain_id_domains", "scans", "domains", ["domain_id"], ["id"], ondelete="SET NULL"
    )

    # Security: same as the other tables. RLS with no policies keeps this table out of
    # Supabase's public REST API once app data moves there.
    op.execute("ALTER TABLE domains ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_constraint("fk_scans_domain_id_domains", "scans", type_="foreignkey")
    op.drop_table("domains")
