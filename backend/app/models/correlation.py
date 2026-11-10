"""Links between connected repos and verified domains, and the combined findings they produce.

Security: everything here is an identifier that is already public to the project's own code,
such as a Supabase project ref. No key, token or row of data has a column to live in.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Index, UniqueConstraint, Uuid, text
from sqlmodel import Field, SQLModel

from app.checks.base import Severity
from app.models.scan import _enum_column, utc_now


class RepoIdentifierKind(StrEnum):
    SUPABASE_REF = "supabase_ref"
    FIREBASE_PROJECT = "firebase_project"
    FIREBASE_RTDB = "firebase_rtdb"
    FIREBASE_BUCKET = "firebase_bucket"


class LinkState(StrEnum):
    SUGGESTED = "suggested"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class LinkOrigin(StrEnum):
    MANUAL = "manual"
    AUTOMATIC = "automatic"


class CorrelationKind(StrEnum):
    SUPABASE_ADMIN = "supabase_admin"
    FIREBASE_ADMIN = "firebase_admin"
    FIREBASE_CONFIG = "firebase_config"


class MatchConfidence(StrEnum):
    # The identifier came from the leaked key itself, or from the file holding it.
    CONFIRMED = "confirmed"
    # Inferred because the repo names only one project. Shown, but never affects the score.
    LIKELY = "likely"


def _timestamp(*, nullable: bool = False) -> Column[Any]:
    return Column(DateTime(timezone=True), nullable=nullable)


def _reference(table: str, *, ondelete: str = "CASCADE", nullable: bool = False) -> Column[Any]:
    return Column(Uuid, ForeignKey(f"{table}.id", ondelete=ondelete), nullable=nullable)


class RepoIdentifier(SQLModel, table=True):
    """A backend a repo's own files point at."""

    __tablename__ = "repo_identifiers"
    __table_args__ = (
        UniqueConstraint("repo_id", "kind", "value", name="uq_repo_identifiers_repo_kind_value"),
        # Matching looks these up by value, across one owner's repos.
        Index("ix_repo_identifiers_kind_value", "kind", "value"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    repo_id: UUID = Field(sa_column=_reference("repos"))
    kind: RepoIdentifierKind = Field(sa_column=_enum_column(RepoIdentifierKind))
    value: str = Field(max_length=253)
    first_seen_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())
    last_seen_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())


class RepoDomainLink(SQLModel, table=True):
    """ "This repo powers this site", said by the owner or suggested from matching identifiers."""

    __tablename__ = "repo_domain_links"
    __table_args__ = (
        UniqueConstraint("repo_id", "domain_id", name="uq_repo_domain_links_repo_domain"),
        Index("ix_repo_domain_links_domain_id", "domain_id"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    owner_id: UUID = Field(sa_column=_reference("profiles"))
    repo_id: UUID = Field(sa_column=_reference("repos"))
    domain_id: UUID = Field(sa_column=_reference("domains"))
    state: LinkState = Field(sa_column=_enum_column(LinkState))
    origin: LinkOrigin = Field(sa_column=_enum_column(LinkOrigin))
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())
    updated_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())


class CorrelatedFinding(SQLModel, table=True):
    """One combined finding across a repo and a site. It never holds a secret.

    Kept apart from the findings table, so the scorer can't sum it by accident.
    """

    __tablename__ = "correlated_findings"
    __table_args__ = (
        # Only among cards still open. A card marked as rotated stays as history, so a key
        # found later for the same project can open a new card beside it.
        Index(
            "uq_correlated_findings_open",
            "domain_id",
            "repo_id",
            "kind",
            "identifier",
            unique=True,
            postgresql_where=text("rotated_at IS NULL"),
            sqlite_where=text("rotated_at IS NULL"),
        ),
        Index("ix_correlated_findings_repo_id", "repo_id"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    owner_id: UUID = Field(sa_column=_reference("profiles"))
    domain_id: UUID = Field(sa_column=_reference("domains"))
    repo_id: UUID = Field(sa_column=_reference("repos"))
    kind: CorrelationKind = Field(sa_column=_enum_column(CorrelationKind))
    severity: Severity = Field(sa_column=_enum_column(Severity))
    confidence: MatchConfidence = Field(sa_column=_enum_column(MatchConfidence))
    identifier: str = Field(max_length=253)
    first_seen_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())
    last_seen_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())
    # The owner's word, because confirming a rotation would need the key or a network call.
    rotated_at: datetime | None = Field(default=None, sa_column=_timestamp(nullable=True))
    rotated_by: UUID | None = Field(
        default=None, sa_column=_reference("profiles", ondelete="SET NULL", nullable=True)
    )
    # The latest time the owner took a "rotated" answer back.
    reopened_at: datetime | None = Field(default=None, sa_column=_timestamp(nullable=True))
    reopened_by: UUID | None = Field(
        default=None, sa_column=_reference("profiles", ondelete="SET NULL", nullable=True)
    )


class CorrelatedFindingMember(SQLModel, table=True):
    """The original findings behind a combined one, which all stay viewable.

    A separate table because one repo finding can sit behind cards for two domains. On a card
    marked as rotated, these rows also record which fingerprints that rotation covered.
    """

    __tablename__ = "correlated_finding_members"

    correlated_finding_id: UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("correlated_findings.id", ondelete="CASCADE"), primary_key=True
        )
    )
    finding_id: UUID = Field(
        sa_column=Column(Uuid, ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True)
    )
