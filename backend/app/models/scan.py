"""Tables for scan jobs, their findings, and claims on anonymous scans."""

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, Column, DateTime, Enum, ForeignKey, Index, Uuid
from sqlmodel import Field, SQLModel

from app.checks.base import Category, Severity
from app.checks.runner import ScanStatus

# A scan still unfinished after this long has lost its worker. Celery's time limits don't
# work with the solo pool used on Windows, so scans are expired by age as well.
SCAN_STALE_AFTER = timedelta(minutes=5)


class ScanJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


UNFINISHED_STATUSES = (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING)


class TargetType(StrEnum):
    WEB = "web"
    REPO = "repo"


class ScanMode(StrEnum):
    QUICK = "quick"
    FULL = "full"


def utc_now() -> datetime:
    return datetime.now(UTC)


def _enum_column(enum_type: type[StrEnum], *, nullable: bool = False) -> Column[Any]:
    # Stored as plain strings, so a later phase can add a value without altering a Postgres type.
    return Column(
        Enum(
            enum_type,
            native_enum=False,
            length=16,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=nullable,
    )


def _timestamp_column(*, nullable: bool = False) -> Column[Any]:
    return Column(DateTime(timezone=True), nullable=nullable)


class Scan(SQLModel, table=True):
    __tablename__ = "scans"
    # Serves the per-hostname reuse window and hourly cap on every quick scan request.
    __table_args__ = (Index("ix_scans_target_mode_created_at", "target", "mode", "created_at"),)

    # Security: a random UUID, because anyone holding the id can read the scan's teaser.
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    # Null means nobody has claimed this anonymous scan yet. Others who scanned the same site
    # can also hold a redeemed ScanClaim for it. Domains and repos arrive in later steps.
    owner_id: UUID | None = Field(
        default=None,
        sa_column=Column(
            Uuid, ForeignKey("profiles.id", ondelete="SET NULL"), nullable=True, index=True
        ),
    )
    domain_id: UUID | None = None
    repo_id: UUID | None = None
    target_type: TargetType = Field(sa_column=_enum_column(TargetType))
    target: str = Field(max_length=253)
    mode: ScanMode = Field(sa_column=_enum_column(ScanMode))
    # The job's lifecycle. result_status says how complete the finished scan was.
    status: ScanJobStatus = Field(
        default=ScanJobStatus.QUEUED, sa_column=_enum_column(ScanJobStatus)
    )
    progress_json: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    result_status: ScanStatus | None = Field(
        default=None, sa_column=_enum_column(ScanStatus, nullable=True)
    )
    score: int | None = None
    grade: str | None = Field(default=None, max_length=2)
    grade_cap_reason: str | None = None
    score_label: str | None = None
    incomplete_reason: str | None = None
    skipped_json: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp_column())
    started_at: datetime | None = Field(default=None, sa_column=_timestamp_column(nullable=True))
    finished_at: datetime | None = Field(default=None, sa_column=_timestamp_column(nullable=True))


class FindingRecord(SQLModel, table=True):
    """A stored finding. The explanation and fixes stay in code, keyed by check_id."""

    __tablename__ = "findings"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
        )
    )
    check_id: str = Field(max_length=64)
    category: Category = Field(sa_column=_enum_column(Category))
    severity: Severity = Field(sa_column=_enum_column(Severity))
    title: str
    evidence_masked: str
    location: str | None = None
    linked_finding_id: UUID | None = Field(
        default=None,
        sa_column=Column(Uuid, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
    )
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp_column())


class ScanClaim(SQLModel, table=True):
    """One claim token for an anonymous scan, redeemed after signup in Phase 2.

    Tokens get their own table because scans are shared within the reuse window. Each
    requester needs a token of their own, since handing one person's to another would let
    a stranger claim their scan.
    """

    __tablename__ = "scan_claims"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_id: UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
        )
    )
    # Security: only the hash is stored, so a database leak can't be used to claim scans.
    token_hash: str = Field(max_length=64, unique=True)
    created_at: datetime = Field(default_factory=utc_now, sa_column=_timestamp_column())
    # Set once redeemed. This row is then what lets that user read the full report, which
    # is how several people can hold a report for one shared scan.
    claimed_by: UUID | None = Field(
        default=None,
        sa_column=Column(Uuid, ForeignKey("profiles.id", ondelete="CASCADE"), nullable=True),
    )
    claimed_at: datetime | None = Field(default=None, sa_column=_timestamp_column(nullable=True))
