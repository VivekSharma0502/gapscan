"""keep legacy verify names for existing domains

Revision ID: a1f4c7e29b30
Revises: 614a5c395273
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1f4c7e29b30"
down_revision: str | None = "614a5c395273"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "domains",
        sa.Column(
            "accepts_legacy_verify_names",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )
    # Every domain that exists now was added under the old names. Rows added later keep the
    # default, so the old names retire on their own.
    op.execute("UPDATE domains SET accepts_legacy_verify_names = true")


def downgrade() -> None:
    op.drop_column("domains", "accepts_legacy_verify_names")
