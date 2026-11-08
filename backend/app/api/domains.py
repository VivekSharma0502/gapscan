"""Domains a user owns: adding, verifying and running full scans."""

import secrets
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func
from sqlmodel import Session, select

from app.api.scans import SessionDep, SignedInDep, enqueue_scan, lock_target
from app.checks.domains import registrable_domain, shared_platform_suffix
from app.checks.ownership import (
    FailureCode,
    VerificationMethod,
    prove_ownership,
    txt_record_name,
    txt_record_value,
    verification_file_url,
)
from app.core.auth import ensure_profile
from app.core.rate_limit import limiter
from app.core.safe_http import BlockedTargetError, normalize_scan_target
from app.models.domain import Domain
from app.models.profile import Profile
from app.models.scan import (
    SCAN_STALE_AFTER,
    UNFINISHED_STATUSES,
    Scan,
    ScanJobStatus,
    ScanMode,
    TargetType,
    utc_now,
)
from app.workers.tasks import initial_full_progress, run_full_scan

router = APIRouter(prefix="/api/domains", tags=["domains"])

MAX_DOMAINS_PER_USER = 3
ADD_RATE_LIMIT = "10/minute"
VERIFY_RATE_LIMIT = "10/minute"
SCAN_RATE_LIMIT = "5/minute"
HOURLY_FULL_SCAN_CAP = 10

_INVALID_HOSTNAME = "Enter a public domain name, like example.com."


class DomainCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str = Field(min_length=1, max_length=2048)

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        try:
            name = normalize_scan_target(value)
        except BlockedTargetError as exc:
            raise ValueError(_INVALID_HOSTNAME) from exc
        # Security: a suffix like vercel.app covers many customers, so nobody can own it.
        if registrable_domain(name) is None:
            raise ValueError(_INVALID_HOSTNAME)
        return name


class VerificationInstructions(BaseModel):
    txt_name: str
    txt_value: str
    file_url: str
    file_content: str


class DomainOut(BaseModel):
    id: UUID
    hostname: str
    verified: bool
    verified_at: datetime | None
    verified_method: VerificationMethod | None
    # True for hosts like foo.vercel.app, where the owner can't edit DNS.
    shared_platform: bool
    instructions: VerificationInstructions
    # True when a record or file published under the old scankit-verify names still counts.
    legacy_names_accepted: bool
    created_at: datetime


class VerifyFailure(BaseModel):
    method: VerificationMethod
    code: FailureCode
    message: str


class VerifyResult(BaseModel):
    domain: DomainOut
    # Empty when verification succeeded.
    failures: list[VerifyFailure]


class FullScanCreated(BaseModel):
    id: UUID
    status: ScanJobStatus
    # True when a full scan of this domain was already running.
    reused: bool


def _domain_out(domain: Domain) -> DomainOut:
    return DomainOut(
        id=domain.id,
        hostname=domain.hostname,
        verified=domain.verified_at is not None,
        verified_at=domain.verified_at,
        verified_method=domain.verified_method,
        shared_platform=shared_platform_suffix(domain.hostname) is not None,
        instructions=VerificationInstructions(
            txt_name=txt_record_name(domain.hostname),
            txt_value=txt_record_value(domain.verify_token),
            file_url=verification_file_url(domain.hostname),
            file_content=domain.verify_token,
        ),
        legacy_names_accepted=domain.accepts_legacy_verify_names,
        created_at=domain.created_at,
    )


def _owned_domain(session: Session, domain_id: UUID, viewer_id: UUID) -> Domain:
    domain = session.get(Domain, domain_id)
    # Security: 404 for someone else's domain too, so ids can't be probed for existence.
    if domain is None or domain.owner_id != viewer_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Domain not found.")
    return domain


@router.get("", response_model=list[DomainOut])
def list_domains(session: SessionDep, viewer: SignedInDep) -> list[DomainOut]:
    domains = session.exec(
        select(Domain).where(Domain.owner_id == viewer.id).order_by(Domain.created_at)
    )
    return [_domain_out(domain) for domain in domains]


@router.post("", response_model=DomainOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(ADD_RATE_LIMIT)
def add_domain(
    request: Request,
    response: Response,
    body: DomainCreate,
    session: SessionDep,
    viewer: SignedInDep,
) -> DomainOut:
    ensure_profile(session, viewer)
    # Held until commit, so simultaneous requests can't all count below the limit.
    session.exec(select(Profile.id).where(Profile.id == viewer.id).with_for_update())

    hostnames = session.exec(select(Domain.hostname).where(Domain.owner_id == viewer.id)).all()
    if body.hostname in hostnames:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="You've already added this domain.")
    if len(hostnames) >= MAX_DOMAINS_PER_USER:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"You can have up to {MAX_DOMAINS_PER_USER} domains. Delete one to add another.",
        )

    domain = Domain(
        owner_id=viewer.id, hostname=body.hostname, verify_token=secrets.token_urlsafe(32)
    )
    session.add(domain)
    session.commit()
    return _domain_out(domain)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_domain(domain_id: UUID, session: SessionDep, viewer: SignedInDep) -> None:
    # Past scans stay readable by their owner. The database clears their link to the domain.
    session.delete(_owned_domain(session, domain_id, viewer.id))
    session.commit()


@router.post("/{domain_id}/verify", response_model=VerifyResult)
@limiter.limit(VERIFY_RATE_LIMIT)
def verify_domain(
    request: Request,
    response: Response,
    domain_id: UUID,
    session: SessionDep,
    viewer: SignedInDep,
) -> VerifyResult:
    domain = _owned_domain(session, domain_id, viewer.id)
    hostname, token = domain.hostname, domain.verify_token
    accept_legacy = domain.accepts_legacy_verify_names
    # Ends the transaction, so a database connection isn't held through the network checks.
    session.commit()

    result = prove_ownership(hostname, token, accept_legacy=accept_legacy)

    domain = _owned_domain(session, domain_id, viewer.id)
    if result.proven:
        domain.verified_at = utc_now()
        domain.verified_method = result.method
    elif result.definitely_gone:
        domain.verified_at = None
        domain.verified_method = None
    session.commit()
    return VerifyResult(
        domain=_domain_out(domain),
        failures=[
            VerifyFailure(method=item.method, code=item.code, message=item.message)
            for item in result.failures
        ],
    )


def _running_scan(session: Session, domain_id: UUID, now: datetime) -> Scan | None:
    return session.exec(
        select(Scan)
        .where(
            Scan.domain_id == domain_id,
            Scan.mode == ScanMode.FULL,
            Scan.status.in_(UNFINISHED_STATUSES),
            Scan.created_at >= now - SCAN_STALE_AFTER,
        )
        .limit(1)
    ).first()


def _enforce_hourly_cap(session: Session, domain_id: UUID, now: datetime) -> None:
    started = session.exec(
        select(func.count())
        .select_from(Scan)
        .where(
            Scan.domain_id == domain_id,
            Scan.mode == ScanMode.FULL,
            Scan.created_at >= now - timedelta(hours=1),
        )
    ).one()
    if started >= HOURLY_FULL_SCAN_CAP:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="This domain has had too many full scans recently. Try again later.",
            headers={"Retry-After": "3600"},
        )


@router.post(
    "/{domain_id}/scan", response_model=FullScanCreated, status_code=status.HTTP_202_ACCEPTED
)
@limiter.limit(SCAN_RATE_LIMIT)
def start_full_scan(
    request: Request,
    response: Response,
    domain_id: UUID,
    session: SessionDep,
    viewer: SignedInDep,
) -> FullScanCreated:
    domain = _owned_domain(session, domain_id, viewer.id)
    # Security: checked here for a clear error. The worker confirms it again before probing.
    if domain.verified_at is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, detail="Verify this domain before running a full scan."
        )

    now = utc_now()
    lock_target(session, domain.hostname)
    running = _running_scan(session, domain.id, now)
    if running is not None:
        response.status_code = status.HTTP_200_OK
        return FullScanCreated(id=running.id, status=running.status, reused=True)

    _enforce_hourly_cap(session, domain.id, now)
    scan = Scan(
        owner_id=viewer.id,
        domain_id=domain.id,
        target_type=TargetType.WEB,
        target=domain.hostname,
        mode=ScanMode.FULL,
        progress_json=initial_full_progress(),
    )
    session.add(scan)
    scan_id, scan_status = scan.id, scan.status
    # Committed before queueing, so the worker can't look for a row that doesn't exist yet.
    session.commit()
    enqueue_scan(session, scan_id, run_full_scan)
    return FullScanCreated(id=scan_id, status=scan_status, reused=False)
