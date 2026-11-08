"""add profiles and scan claim redemption

Revision ID: 4774dc71d1ab
Revises: 7c2de08d8fab
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "4774dc71d1ab"
down_revision: str | None = "7c2de08d8fab"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "profiles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sqlmodel.sql.sqltypes.AutoString(length=320), nullable=True),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True),
        sa.Column("plan", sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("scan_claims", sa.Column("claimed_by", sa.Uuid(), nullable=True))
    op.add_column("scan_claims", sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key(
        "fk_scan_claims_claimed_by_profiles",
        "scan_claims",
        "profiles",
        ["claimed_by"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_scans_owner_id_profiles", "scans", "profiles", ["owner_id"], ["id"], ondelete="SET NULL"
    )

    # Security: same as the other tables. Profiles hold email addresses, and RLS with no
    # policies keeps them out of Supabase's public REST API once app data moves there.
    op.execute("ALTER TABLE profiles ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_constraint("fk_scans_owner_id_profiles", "scans", type_="foreignkey")
    op.drop_constraint("fk_scan_claims_claimed_by_profiles", "scan_claims", type_="foreignkey")
    op.drop_column("scan_claims", "claimed_at")
    op.drop_column("scan_claims", "claimed_by")
    op.drop_table("profiles")
