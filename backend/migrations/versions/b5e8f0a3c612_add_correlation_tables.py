"""add repo and site correlation tables

Revision ID: b5e8f0a3c612
Revises: a7d4e6c21f08
"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "b5e8f0a3c612"
down_revision: str | None = "a7d4e6c21f08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TEXT = sqlmodel.sql.sqltypes.AutoString


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=16)


def _stamp(name: str, *, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.add_column("domain_backends", sa.Column("firebase_project_id", _TEXT(length=63)))
    op.add_column("findings", sa.Column("backend_identifier", _TEXT(length=253)))
    op.add_column(
        "findings",
        sa.Column(
            "identifier_basis", _enum("identifierbasis", "key_claim", "same_file", "only_project")
        ),
    )

    op.create_table(
        "repo_identifiers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repo_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            _enum(
                "repoidentifierkind",
                "supabase_ref",
                "firebase_project",
                "firebase_rtdb",
                "firebase_bucket",
            ),
            nullable=False,
        ),
        sa.Column("value", _TEXT(length=253), nullable=False),
        _stamp("first_seen_at"),
        _stamp("last_seen_at"),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("repo_id", "kind", "value", name="uq_repo_identifiers_repo_kind_value"),
    )
    op.create_index("ix_repo_identifiers_kind_value", "repo_identifiers", ["kind", "value"])

    op.create_table(
        "repo_domain_links",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("repo_id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column(
            "state", _enum("linkstate", "suggested", "confirmed", "dismissed"), nullable=False
        ),
        sa.Column("origin", _enum("linkorigin", "manual", "automatic"), nullable=False),
        _stamp("created_at"),
        _stamp("updated_at"),
        sa.ForeignKeyConstraint(["owner_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("repo_id", "domain_id", name="uq_repo_domain_links_repo_domain"),
    )
    op.create_index("ix_repo_domain_links_domain_id", "repo_domain_links", ["domain_id"])

    op.create_table(
        "correlated_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column("repo_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            _enum("correlationkind", "supabase_admin", "firebase_admin", "firebase_config"),
            nullable=False,
        ),
        sa.Column(
            "severity",
            _enum("severity", "critical", "high", "medium", "low", "info"),
            nullable=False,
        ),
        sa.Column("confidence", _enum("matchconfidence", "confirmed", "likely"), nullable=False),
        sa.Column("identifier", _TEXT(length=253), nullable=False),
        _stamp("first_seen_at"),
        _stamp("last_seen_at"),
        _stamp("rotated_at", nullable=True),
        sa.Column("rotated_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["owner_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["repo_id"], ["repos.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["rotated_by"], ["profiles.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_correlated_findings_open",
        "correlated_findings",
        ["domain_id", "repo_id", "kind", "identifier"],
        unique=True,
        postgresql_where=sa.text("rotated_at IS NULL"),
    )
    op.create_index("ix_correlated_findings_repo_id", "correlated_findings", ["repo_id"])

    op.create_table(
        "correlated_finding_members",
        sa.Column("correlated_finding_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["correlated_finding_id"], ["correlated_findings.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("correlated_finding_id", "finding_id"),
    )


def downgrade() -> None:
    op.drop_table("correlated_finding_members")
    op.drop_index("ix_correlated_findings_repo_id", table_name="correlated_findings")
    op.drop_index(
        "uq_correlated_findings_open",
        table_name="correlated_findings",
        postgresql_where=sa.text("rotated_at IS NULL"),
    )
    op.drop_table("correlated_findings")
    op.drop_index("ix_repo_domain_links_domain_id", table_name="repo_domain_links")
    op.drop_table("repo_domain_links")
    op.drop_index("ix_repo_identifiers_kind_value", table_name="repo_identifiers")
    op.drop_table("repo_identifiers")
    op.drop_column("findings", "identifier_basis")
    op.drop_column("findings", "backend_identifier")
    op.drop_column("domain_backends", "firebase_project_id")
