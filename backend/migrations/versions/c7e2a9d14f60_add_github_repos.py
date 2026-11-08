"""add github installations, repos and repo finding columns

Revision ID: c7e2a9d14f60
Revises: b3d81f6a4c52
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "c7e2a9d14f60"
down_revision: str | None = "b3d81f6a4c52"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TEXT = sqlmodel.sql.sqltypes.AutoString


def upgrade() -> None:
    op.create_table(
        "github_install_states",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", _TEXT(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_github_install_states_token_hash"),
    )
    op.create_table(
        "github_installations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("account_id", sa.BigInteger(), nullable=False),
        sa.Column("account_login", _TEXT(length=39), nullable=False),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("installation_id", name="uq_github_installations_installation_id"),
    )
    op.create_index("ix_github_installations_owner_id", "github_installations", ["owner_id"])
    op.create_table(
        "repos",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("installation_id", sa.Uuid(), nullable=False),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=False),
        sa.Column("full_name", _TEXT(length=140), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("first_full_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("needs_full_scan", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["installation_id"], ["github_installations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("github_repo_id", name="uq_repos_github_repo_id"),
    )
    op.create_index("ix_repos_owner_id", "repos", ["owner_id"])
    op.create_index("ix_repos_installation_id", "repos", ["installation_id"])
    op.create_table(
        "github_deliveries",
        sa.Column("delivery_id", _TEXT(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("delivery_id"),
    )
    op.create_index("ix_github_deliveries_received_at", "github_deliveries", ["received_at"])

    op.create_foreign_key(
        "fk_scans_repo_id_repos", "scans", "repos", ["repo_id"], ["id"], ondelete="SET NULL"
    )
    op.add_column("scans", sa.Column("before_sha", _TEXT(length=40), nullable=True))
    op.add_column("scans", sa.Column("after_sha", _TEXT(length=40), nullable=True))
    op.create_index("ix_scans_repo_id_created_at", "scans", ["repo_id", "created_at"])

    op.add_column("findings", sa.Column("repo_id", sa.Uuid(), nullable=True))
    op.add_column("findings", sa.Column("rule_id", _TEXT(length=128), nullable=True))
    op.add_column("findings", sa.Column("file_path", _TEXT(), nullable=True))
    op.add_column("findings", sa.Column("line", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("commit_sha", _TEXT(length=40), nullable=True))
    op.add_column("findings", sa.Column("fingerprint", _TEXT(length=64), nullable=True))
    op.create_foreign_key(
        "fk_findings_repo_id_repos", "findings", "repos", ["repo_id"], ["id"], ondelete="CASCADE"
    )
    op.create_unique_constraint(
        "uq_findings_repo_fingerprint", "findings", ["repo_id", "fingerprint"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_findings_repo_fingerprint", "findings", type_="unique")
    op.drop_constraint("fk_findings_repo_id_repos", "findings", type_="foreignkey")
    op.drop_column("findings", "fingerprint")
    op.drop_column("findings", "commit_sha")
    op.drop_column("findings", "line")
    op.drop_column("findings", "file_path")
    op.drop_column("findings", "rule_id")
    op.drop_column("findings", "repo_id")

    op.drop_index("ix_scans_repo_id_created_at", table_name="scans")
    op.drop_column("scans", "after_sha")
    op.drop_column("scans", "before_sha")
    op.drop_constraint("fk_scans_repo_id_repos", "scans", type_="foreignkey")

    op.drop_index("ix_github_deliveries_received_at", table_name="github_deliveries")
    op.drop_table("github_deliveries")
    op.drop_index("ix_repos_installation_id", table_name="repos")
    op.drop_index("ix_repos_owner_id", table_name="repos")
    op.drop_table("repos")
    op.drop_index("ix_github_installations_owner_id", table_name="github_installations")
    op.drop_table("github_installations")
    op.drop_table("github_install_states")
