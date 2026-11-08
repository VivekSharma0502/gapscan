"""add dashboard indexes

Revision ID: b3d81f6a4c52
Revises: a1f4c7e29b30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "b3d81f6a4c52"
down_revision: str | None = "a1f4c7e29b30"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_scans_domain_id_created_at", "scans", ["domain_id", "created_at"])
    # Replaces the owner-only index: the new one serves those lookups too.
    op.create_index("ix_scans_owner_id_created_at", "scans", ["owner_id", "created_at"])
    op.drop_index("ix_scans_owner_id", table_name="scans")
    op.create_index("ix_scan_claims_claimed_by", "scan_claims", ["claimed_by"])


def downgrade() -> None:
    op.drop_index("ix_scan_claims_claimed_by", table_name="scan_claims")
    op.create_index("ix_scans_owner_id", "scans", ["owner_id"])
    op.drop_index("ix_scans_owner_id_created_at", table_name="scans")
    op.drop_index("ix_scans_domain_id_created_at", table_name="scans")
