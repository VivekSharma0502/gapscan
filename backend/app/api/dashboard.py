"""The signed-in landing page: how each domain stands, and recent scans."""

from collections import defaultdict
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import ColumnElement, func
from sqlmodel import Session, select

from app.api.scans import ScanSummary, SessionDep, SignedInDep, readable_by, scan_summary
from app.checks.runner import ScanStatus
from app.models.domain import Domain
from app.models.scan import Scan, ScanJobStatus, ScanMode, TargetType, utc_now

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

RECENT_SCANS = 10


class DashboardDomain(BaseModel):
    # Security: no verification token. This page has no need for it.
    id: UUID
    hostname: str
    verified: bool
    created_at: datetime
    # The newest graded scan: a full scan if verified, otherwise a quick one. Its mode says
    # which, so the page can label a quick result as not covering the active checks.
    latest: ScanSummary | None
    # The newest attempt of that kind in any state, for "last scanned" and "scan running".
    last_scan: ScanSummary | None
    # Score change from the previous graded scan. None when there's nothing fair to compare.
    trend: int | None


class DashboardOut(BaseModel):
    domains: list[DashboardDomain]
    recent_scans: list[ScanSummary]


def newest_per_group(
    session: Session, group: Any, limit: int, *conditions: ColumnElement[bool]
) -> dict[Any, list[Scan]]:
    """The newest `limit` matching scans for each value of `group`, newest first.

    One query however many domains a user has, which matters once plans allow 25.
    """
    position = (
        func.row_number()
        .over(partition_by=group, order_by=(Scan.created_at.desc(), Scan.id.desc()))
        .label("position")
    )
    ranked = select(Scan.id, position).where(*conditions).subquery()
    scans = session.exec(
        select(Scan)
        .join(ranked, Scan.id == ranked.c.id)
        .where(ranked.c.position <= limit)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
    )
    grouped: dict[Any, list[Scan]] = defaultdict(list)
    for scan in scans:
        grouped[getattr(scan, group.key)].append(scan)
    return grouped


def _trend(graded: list[Scan]) -> int | None:
    if len(graded) < 2:
        return None
    latest, previous = graded[0], graded[1]
    # A partial scan skipped checks, so its score can be generous. Comparing one would show
    # an improvement that never happened.
    for scan in (latest, previous):
        if scan.score is None or scan.result_status is not ScanStatus.COMPLETE:
            return None
    return latest.score - previous.score


@router.get("", response_model=DashboardOut)
def get_dashboard(session: SessionDep, viewer: SignedInDep) -> DashboardOut:
    now = utc_now()
    domains = list(
        session.exec(
            select(Domain)
            .where(Domain.owner_id == viewer.id)
            .order_by(Domain.created_at, Domain.id)
        )
    )
    graded = (Scan.status == ScanJobStatus.DONE, Scan.grade.is_not(None))

    # Full scans only, so a score change is like for like: a quick scan runs fewer checks.
    verified_ids = [domain.id for domain in domains if domain.verified_at is not None]
    full = (
        Scan.domain_id.in_(verified_ids),
        Scan.owner_id == viewer.id,
        Scan.mode == ScanMode.FULL,
    )
    full_graded = newest_per_group(session, Scan.domain_id, 2, *full, *graded)
    full_attempts = newest_per_group(session, Scan.domain_id, 1, *full)

    # Quick scans aren't linked to a domain, so these are found by hostname.
    hostnames = [domain.hostname for domain in domains if domain.verified_at is None]
    quick = (Scan.target.in_(hostnames), Scan.mode == ScanMode.QUICK, readable_by(viewer.id))
    quick_graded = newest_per_group(session, Scan.target, 1, *quick, *graded)
    quick_attempts = newest_per_group(session, Scan.target, 1, *quick)

    def summary_of(scans: list[Scan]) -> ScanSummary | None:
        return scan_summary(scans[0], now) if scans else None

    cards = []
    for domain in domains:
        verified = domain.verified_at is not None
        if verified:
            results, attempts = full_graded[domain.id], full_attempts[domain.id]
        else:
            results, attempts = quick_graded[domain.hostname], quick_attempts[domain.hostname]
        cards.append(
            DashboardDomain(
                id=domain.id,
                hostname=domain.hostname,
                verified=verified,
                created_at=domain.created_at,
                latest=summary_of(results),
                last_scan=summary_of(attempts),
                trend=_trend(results) if verified else None,
            )
        )

    # Websites only. A repo scan has no grade, and its results live on the Repositories page.
    recent = session.exec(
        select(Scan)
        .where(readable_by(viewer.id), Scan.target_type == TargetType.WEB)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(RECENT_SCANS)
    )
    return DashboardOut(domains=cards, recent_scans=[scan_summary(scan, now) for scan in recent])
