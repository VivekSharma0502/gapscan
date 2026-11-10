"""Domains a user has added, and the proof that they control them."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, UniqueConstraint, Uuid, false
from sqlmodel import Field, SQLModel

from app.checks.base import BaasKind, TableAccess
from app.models.scan import _enum_column, utc_now


class Domain(SQLModel, table=True):
    __tablename__ = "domains"
    # Security: per user, not global. A global rule would let anyone block a domain's real
    # owner by adding it first, and adding one proves nothing until it's verified.
    __table_args__ = (UniqueConstraint("owner_id", "hostname", name="uq_domains_owner_hostname"),)

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    owner_id: UUID = Field(
        sa_column=Column(Uuid, ForeignKey("profiles.id", ondelete="CASCADE"), nullable=False)
    )
    hostname: str = Field(max_length=253)
    # Kept readable because the user has to publish it. It only proves control once published.
    verify_token: str = Field(max_length=64)
    # When ownership was last proven. Null means active checks must not run.
    verified_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    verified_method: str | None = Field(default=None, max_length=8)
    # True only for domains added before the rename to GapScan, which may have published
    # the scankit-verify names. New domains use the current names only.
    accepts_legacy_verify_names: bool = Field(
        default=False, sa_column=Column(Boolean, nullable=False, server_default=false())
    )
    created_at: datetime = Field(
        default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False)
    )


class DomainBackend(SQLModel, table=True):
    """A Firebase or Supabase backend named in a verified site's code."""

    __tablename__ = "domain_backends"
    __table_args__ = (
        UniqueConstraint(
            "domain_id", "kind", "identifier", name="uq_domain_backends_domain_kind_identifier"
        ),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    domain_id: UUID = Field(
        sa_column=Column(Uuid, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    )
    kind: BaasKind = Field(sa_column=_enum_column(BaasKind))
    identifier: str = Field(max_length=253)
    first_seen_at: datetime = Field(
        default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    last_seen_at: datetime = Field(
        default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    # Security: null means never send this backend a request. Owning a site doesn't prove
    # owning everything its code names, and a site could name someone else's project on purpose.
    confirmed_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )


class DomainBackendTable(SQLModel, table=True):
    """A table named in a site's code, and what a public key could do with it.

    Security: a name and a state only. There is no column that could hold a row.
    """

    __tablename__ = "domain_backend_tables"
    __table_args__ = (
        UniqueConstraint("backend_id", "name", name="uq_domain_backend_tables_backend_name"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    backend_id: UUID = Field(
        sa_column=Column(Uuid, ForeignKey("domain_backends.id", ondelete="CASCADE"), nullable=False)
    )
    name: str = Field(max_length=63)
    access: TableAccess = Field(sa_column=_enum_column(TableAccess))
    last_seen_at: datetime = Field(
        default_factory=utc_now, sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    # Set when the owner says this table is meant to be public, which keeps it off the grade.
    meant_to_be_public_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
