"""GitHub App installations linked to users, and the repos they give access to."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
    Uuid,
    false,
)
from sqlmodel import Field, SQLModel

from app.models.scan import utc_now


def _timestamp(*, nullable: bool = False) -> Column[Any]:
    return Column(DateTime(timezone=True), nullable=nullable)


def _profile_reference() -> Column[Any]:
    return Column(Uuid, ForeignKey("profiles.id", ondelete="CASCADE"), nullable=False)


class GithubInstallState(SQLModel, table=True):
    """A one-time value tying an "install the app" redirect to the user who started it."""

    __tablename__ = "github_install_states"
    __table_args__ = (UniqueConstraint("token_hash", name="uq_github_install_states_token_hash"),)

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    owner_id: UUID = Field(sa_column=_profile_reference())
    # Security: only the hash is stored, so a database leak can't be used to complete a link.
    token_hash: str = Field(max_length=64)
    expires_at: datetime = Field(sa_column=_timestamp())
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())


class GithubInstallation(SQLModel, table=True):
    __tablename__ = "github_installations"
    # Security: GitHub's installation id is unique here, so one install can't serve two users.
    __table_args__ = (
        UniqueConstraint("installation_id", name="uq_github_installations_installation_id"),
        Index("ix_github_installations_owner_id", "owner_id"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    owner_id: UUID = Field(sa_column=_profile_reference())
    installation_id: int = Field(sa_column=Column(BigInteger, nullable=False))
    # The numeric id is what ownership is checked against. Logins can change hands.
    account_id: int = Field(sa_column=Column(BigInteger, nullable=False))
    account_login: str = Field(max_length=39)
    suspended_at: datetime | None = Field(default=None, sa_column=_timestamp(nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())


class Repo(SQLModel, table=True):
    __tablename__ = "repos"
    __table_args__ = (
        UniqueConstraint("github_repo_id", name="uq_repos_github_repo_id"),
        Index("ix_repos_owner_id", "owner_id"),
        Index("ix_repos_installation_id", "installation_id"),
    )

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    owner_id: UUID = Field(sa_column=_profile_reference())
    # Uninstalling the app removes its repos, and with them their stored findings.
    installation_id: UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("github_installations.id", ondelete="CASCADE"), nullable=False
        )
    )
    # Survives renames and transfers, unlike full_name.
    github_repo_id: int = Field(sa_column=Column(BigInteger, nullable=False))
    # Always copied from a GitHub API response, never from user input. Max owner plus name.
    full_name: str = Field(max_length=140)
    is_private: bool
    # Null until a whole-history scan has finished, so the first scan is never a partial one.
    first_full_scan_at: datetime | None = Field(default=None, sa_column=_timestamp(nullable=True))
    # Set when a push couldn't be scanned, so the next scan covers the commits it missed.
    needs_full_scan: bool = Field(
        default=False, sa_column=Column(Boolean, nullable=False, server_default=false())
    )
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())


class GithubDelivery(SQLModel, table=True):
    """Webhook deliveries already handled, so a replay can't start the same work twice."""

    __tablename__ = "github_deliveries"
    __table_args__ = (Index("ix_github_deliveries_received_at", "received_at"),)

    delivery_id: str = Field(primary_key=True, max_length=64)
    received_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp())
