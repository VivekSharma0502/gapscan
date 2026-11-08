"""Domains a user has added, and the proof that they control them."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, UniqueConstraint, Uuid, false
from sqlmodel import Field, SQLModel

from app.models.scan import utc_now


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
