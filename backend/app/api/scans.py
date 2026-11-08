"""Quick scan routes: start a passive scan and read its status and results."""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from kombu.exceptions import OperationalError
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import and_, func, or_
from sqlmodel import Session, select, update

from app.checks.base import Category, Fix, Severity
from app.checks.catalog import CATALOG
from app.checks.runner import ScanStatus, SkippedCheck
from app.core.auth import Viewer, ensure_profile, get_viewer, require_viewer
from app.core.db import get_session
from app.core.rate_limit import limiter
from app.core.safe_http import BlockedTargetError, normalize_scan_target
from app.models.scan import (
    SCAN_STALE_AFTER,
    UNFINISHED_STATUSES,
    FindingRecord,
    Scan,
    ScanClaim,
    ScanJobStatus,
    ScanMode,
    TargetType,
    utc_now,
)
from app.workers.tasks import initial_quick_progress, run_quick_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])

SessionDep = Annotated[Session, Depends(get_session)]
ViewerDep = Annotated[Viewer | None, Depends(get_viewer)]
SignedInDep = Annotated[Viewer, Depends(require_viewer)]

QUICK_SCAN_RATE_LIMIT = "5/minute"
CLAIM_RATE_LIMIT = "20/minute"
# Matches MAX_CLAIMS in frontend/lib/claims.ts.
MAX_CLAIMS_PER_REQUEST = 20
REUSE_WINDOW = timedelta(minutes=10)
HOURLY_TARGET_CAP = 20
TEASER_FINDINGS = 3

_SEVERITY_ORDER = list(Severity)


class QuickScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        try:
            return normalize_scan_target(value)
        except BlockedTargetError as exc:
            raise ValueError("Enter a public domain name, like example.com.") from exc


class QuickScanCreated(BaseModel):
    id: UUID
    status: ScanJobStatus
    # True when a recent scan of this hostname was returned instead of starting a new one.
    reused: bool
    # Shown once, only here. None for signed-in users, who own their scans directly.
    claim_token: str | None


ClaimToken = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class ClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens: list[ClaimToken] = Field(min_length=1, max_length=MAX_CLAIMS_PER_REQUEST)


class ClaimResult(BaseModel):
    # Security: only the scans this viewer now holds. Tokens that failed aren't itemized, so
    # the response can't be used to learn which tokens exist or who redeemed them.
    claimed: list[UUID]


class ProgressStep(BaseModel):
    # Security: a fixed shape with no result field. "done" means the step ran, not that it
    # passed, so the log can't reveal findings hidden from anonymous viewers.
    name: str
    status: Literal["done", "running"]


class ScanProgress(BaseModel):
    completed: int
    total: int
    current: str | None
    # Defaults to empty because scans saved before this field existed don't have it.
    steps: list[ProgressStep] = []


class FindingOut(BaseModel):
    check_id: str
    category: Category
    severity: Severity
    title: str
    evidence: str
    # None only if a stored finding's check has since been removed from the catalog.
    fix: Fix | None


class ScanOut(BaseModel):
    id: UUID
    target: str
    mode: ScanMode
    status: ScanJobStatus
    progress: ScanProgress
    result_status: ScanStatus | None
    score: int | None
    grade: str | None
    grade_cap_reason: str | None
    score_label: str | None
    incomplete_reason: str | None
    findings: list[FindingOut]
    # Every finding, including those cut from a teaser. The count reveals no details.
    total_findings: int
    skipped: list[SkippedCheck]
    # True when findings are cut to the top few, so the UI can offer the full report.
    teaser: bool


def lock_target(session: Session, hostname: str) -> None:
    # Without this, simultaneous requests could all see no recent scan and all start one,
    # getting past both per-target limits. The lock is held until this transaction ends.
    if session.get_bind().dialect.name == "postgresql":
        session.exec(select(func.pg_advisory_xact_lock(func.hashtextextended(hostname, 0))))


def _find_reusable_scan(session: Session, hostname: str, now: datetime) -> Scan | None:
    # A failed or abandoned scan produced no report, so it must not block a fresh attempt.
    return session.exec(
        select(Scan)
        .where(
            Scan.target == hostname,
            Scan.mode == ScanMode.QUICK,
            Scan.created_at >= now - REUSE_WINDOW,
            or_(
                Scan.status == ScanJobStatus.DONE,
                and_(
                    Scan.status.in_(UNFINISHED_STATUSES),
                    Scan.created_at >= now - SCAN_STALE_AFTER,
                ),
            ),
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()


def _enforce_hourly_cap(session: Session, hostname: str, now: datetime) -> None:
    # Security: stops many IPs from using us to flood one site. Failed scans count, because
    # they may still have sent the site traffic. Reused scans send none, so they don't.
    started = session.exec(
        select(func.count())
        .select_from(Scan)
        .where(
            Scan.target == hostname,
            Scan.mode == ScanMode.QUICK,
            Scan.created_at >= now - timedelta(hours=1),
        )
    ).one()
    if started >= HOURLY_TARGET_CAP:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="This site has been scanned too many times recently. Try again later.",
            headers={"Retry-After": "3600"},
        )


def _hash_token(token: str) -> str:
    # Security: only the hash is stored. SHA-256 is enough because the token is 256 random
    # bits, so unlike a password it can't be guessed from a wordlist.
    return hashlib.sha256(token.encode()).hexdigest()


def _issue_claim(session: Session, scan_id: UUID) -> str:
    token = secrets.token_urlsafe(32)
    session.add(ScanClaim(scan_id=scan_id, token_hash=_hash_token(token)))
    return token


def _has_full_access(session: Session, scan: Scan, viewer_id: UUID | None) -> bool:
    # Security: the full report is for the scan's owner and anyone who redeemed a claim on
    # it. Anyone else holding the id, signed in or not, gets the teaser.
    if viewer_id is None:
        return False
    if scan.owner_id == viewer_id:
        return True
    held = select(ScanClaim.id).where(
        ScanClaim.scan_id == scan.id, ScanClaim.claimed_by == viewer_id
    )
    return session.exec(held.limit(1)).first() is not None


def _adopt_unowned_scans(session: Session, scan_ids: list[UUID], viewer_id: UUID) -> None:
    # In the WHERE clause so that of two simultaneous claimers, only the first becomes owner.
    session.exec(
        update(Scan)
        .where(Scan.id.in_(scan_ids), Scan.owner_id.is_(None))
        .values(owner_id=viewer_id)
    )


def _grant_access_to_reused_scan(session: Session, scan: Scan, viewer_id: UUID) -> None:
    # A signed-in viewer who asks for a site that was just scanned gets that scan back, and
    # must see the same report a fresh scan would have given them. Passive results for a
    # public site are nothing they couldn't get by waiting out the reuse window.
    if _has_full_access(session, scan, viewer_id):
        return
    # The token is discarded: this row is already redeemed and only records the access.
    session.add(
        ScanClaim(
            scan_id=scan.id,
            token_hash=_hash_token(secrets.token_urlsafe(32)),
            claimed_by=viewer_id,
            claimed_at=utc_now(),
        )
    )
    _adopt_unowned_scans(session, [scan.id], viewer_id)


def enqueue_scan(session: Session, scan_id: UUID, task: Any) -> None:
    try:
        # retry=False: if the broker is down, the visitor gets an error now, not a long hang.
        task.apply_async((str(scan_id),), retry=False)
    except OperationalError as exc:
        logger.error("could not queue scan %s: %s", scan_id, type(exc).__name__)
        session.exec(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status=ScanJobStatus.FAILED, finished_at=utc_now())
        )
        session.commit()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Scanning is unavailable right now."
        ) from exc


@router.post("/quick", response_model=QuickScanCreated, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(QUICK_SCAN_RATE_LIMIT)
def create_quick_scan(
    request: Request,
    response: Response,
    body: QuickScanRequest,
    session: SessionDep,
    viewer: ViewerDep,
) -> QuickScanCreated:
    now = utc_now()
    viewer_id = viewer.id if viewer is not None else None
    if viewer is not None:
        ensure_profile(session, viewer)
    lock_target(session, body.target)

    scan = _find_reusable_scan(session, body.target, now)
    reused = scan is not None
    if scan is None:
        _enforce_hourly_cap(session, body.target, now)
        scan = Scan(
            owner_id=viewer_id,
            target_type=TargetType.WEB,
            target=body.target,
            mode=ScanMode.QUICK,
            progress_json=initial_quick_progress(),
        )
        session.add(scan)

    scan_id, scan_status = scan.id, scan.status
    if reused and viewer_id is not None:
        _grant_access_to_reused_scan(session, scan, viewer_id)
    # A reused scan still gets a new token, so each requester's claim is their own.
    claim_token = _issue_claim(session, scan_id) if viewer_id is None else None
    # Committed before queueing, so the worker can't look for a row that doesn't exist yet.
    session.commit()

    if reused:
        response.status_code = status.HTTP_200_OK
    else:
        enqueue_scan(session, scan_id, run_quick_scan)
    return QuickScanCreated(id=scan_id, status=scan_status, reused=reused, claim_token=claim_token)


@router.post("/claim", response_model=ClaimResult)
@limiter.limit(CLAIM_RATE_LIMIT)
def claim_scans(
    request: Request,
    response: Response,
    body: ClaimRequest,
    session: SessionDep,
    viewer: SignedInDep,
) -> ClaimResult:
    ensure_profile(session, viewer)
    # Security: one conditional UPDATE, so of two users racing with a leaked token only one
    # can win. Matching the viewer's own earlier claims makes a retry safe.
    redeemed = session.exec(
        update(ScanClaim)
        .where(
            ScanClaim.token_hash.in_({_hash_token(token) for token in body.tokens}),
            or_(ScanClaim.claimed_by.is_(None), ScanClaim.claimed_by == viewer.id),
        )
        .values(claimed_by=viewer.id, claimed_at=utc_now())
        .returning(ScanClaim.scan_id)
    )
    scan_ids = list(set(redeemed.scalars()))
    if scan_ids:
        _adopt_unowned_scans(session, scan_ids, viewer.id)
    session.commit()
    return ClaimResult(claimed=scan_ids)


def _expire_if_stale(session: Session, scan_id: UUID, now: datetime) -> None:
    session.exec(
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.status.in_(UNFINISHED_STATUSES),
            Scan.created_at < now - SCAN_STALE_AFTER,
        )
        .values(status=ScanJobStatus.FAILED, finished_at=now)
    )
    session.commit()


def _finding_out(record: FindingRecord) -> FindingOut:
    text = CATALOG.get(record.check_id)
    return FindingOut(
        check_id=record.check_id,
        category=record.category,
        severity=record.severity,
        title=record.title,
        evidence=record.evidence_masked,
        fix=text.fix if text is not None else None,
    )


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: UUID, session: SessionDep, viewer: ViewerDep) -> ScanOut:
    _expire_if_stale(session, scan_id, utc_now())
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    full_report = _has_full_access(session, scan, viewer.id if viewer is not None else None)
    # Security: a full scan has no teaser. Even its top findings could name an exposed .env
    # and its keys, so to anyone but the owner it doesn't exist.
    if scan.mode is ScanMode.FULL and not full_report:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    records = sorted(
        session.exec(select(FindingRecord).where(FindingRecord.scan_id == scan_id)),
        key=lambda item: (_SEVERITY_ORDER.index(item.severity), item.check_id),
    )
    shown = records if full_report else records[:TEASER_FINDINGS]

    return ScanOut(
        id=scan.id,
        target=scan.target,
        mode=scan.mode,
        status=scan.status,
        progress=ScanProgress(**scan.progress_json),
        result_status=scan.result_status,
        score=scan.score,
        grade=scan.grade,
        grade_cap_reason=scan.grade_cap_reason,
        score_label=scan.score_label,
        incomplete_reason=scan.incomplete_reason,
        findings=[_finding_out(record) for record in shown],
        total_findings=len(records),
        skipped=[SkippedCheck(**item) for item in scan.skipped_json] if full_report else [],
        teaser=not full_report,
    )
