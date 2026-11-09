"""Connecting a GitHub App installation to a user, and listing their repos."""

import logging
import secrets
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.api.scans import (
    ScanSummary,
    SessionDep,
    SignedInDep,
    enqueue_scan,
    hash_token,
    lock_target,
    scan_summary,
)
from app.checks.base import Severity
from app.core.auth import (
    AuthUnavailableError,
    ensure_profile,
    fetch_github_account_id,
    require_access_token,
)
from app.core.config import settings
from app.core.github_app import (
    GithubApiError,
    GithubAppNotConfiguredError,
    GithubInstallationInfo,
    GithubRepository,
    GithubRepositoryRef,
    create_installation_token,
    get_installation,
    list_installation_repositories,
    revoke_installation_token,
)
from app.core.rate_limit import limiter
from app.models.github import GithubInstallation, GithubInstallState, Repo
from app.models.scan import (
    REPO_SCAN_STALE_AFTER,
    UNFINISHED_STATUSES,
    FindingRecord,
    Scan,
    ScanJobStatus,
    ScanMode,
    TargetType,
    utc_now,
)
from app.repos.guides import GUIDES, HISTORY_WARNING, RULE_NOTES, SecretGuide
from app.workers.tasks import initial_repo_progress, run_repo_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["github"])

INSTALL_URL_RATE_LIMIT = "10/minute"
LINK_RATE_LIMIT = "10/minute"
REPO_SCAN_RATE_LIMIT = "5/minute"
HOURLY_FULL_REPO_SCAN_CAP = 10
INSTALL_STATE_LIFETIME = timedelta(minutes=10)
MAX_POSTGRES_BIGINT = 2**63 - 1

_SEVERITY_ORDER = list(Severity)

_NOT_CONFIGURED = "Connecting GitHub isn't available right now."
_GITHUB_UNAVAILABLE = "We couldn't reach GitHub. Please try connecting again."
_BAD_STATE = "This connection link has expired or was already used. Please start again."
_NO_GITHUB_IDENTITY = "Sign in with GitHub first, so we can confirm which account is yours."
# Security: one message for an unknown id, someone else's account and an organization, so
# trying ids can't reveal which installations exist or what kind of account owns them.
_NOT_YOUR_ACCOUNT = (
    "This installation doesn't belong to the GitHub account you signed in with. "
    "GapScan can connect personal accounts only for now."
)
_SUSPENDED = "This installation is suspended on GitHub. Unsuspend it and try again."
_ALREADY_LINKED = "This installation is already connected to another GapScan account."


AccessTokenDep = Annotated[str, Depends(require_access_token)]


class InstallUrlOut(BaseModel):
    url: str


class LinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installation_id: int = Field(ge=1, le=MAX_POSTGRES_BIGINT)
    state: str = Field(min_length=1, max_length=128)


class LinkResult(BaseModel):
    account_login: str
    repositories: int


class RepoScanCreated(BaseModel):
    id: UUID
    status: ScanJobStatus
    # True when a whole-history scan of this repo was already running.
    reused: bool


class RepoOut(BaseModel):
    id: UUID
    full_name: str
    is_private: bool
    account_login: str
    created_at: datetime


class RepoFindingOut(BaseModel):
    # Security: a fixed list of fields. The stored fingerprint isn't needed by the page.
    id: UUID
    severity: Severity
    title: str
    rule_id: str
    file_path: str
    line: int
    commit_sha: str
    masked: str
    # A rescan keeps the original row, so this is when the secret was first found.
    first_seen_at: datetime
    # Extra advice for this exact rule, where its provider's guide doesn't cover it.
    note: str | None
    # None only if a stored finding's guide has since been removed.
    guide: SecretGuide | None


class RepoLatestScan(ScanSummary):
    incomplete_reason: str | None


class RepoFindingsOut(BaseModel):
    id: UUID
    full_name: str
    is_private: bool
    history_warning: str
    latest_scan: RepoLatestScan | None
    counts: dict[Severity, int]
    findings: list[RepoFindingOut]


def _repo_finding_out(record: FindingRecord) -> RepoFindingOut:
    return RepoFindingOut(
        id=record.id,
        severity=record.severity,
        title=record.title,
        rule_id=record.rule_id,
        file_path=record.file_path,
        line=record.line,
        commit_sha=record.commit_sha,
        masked=record.evidence_masked,
        first_seen_at=record.created_at,
        note=RULE_NOTES.get(record.rule_id),
        guide=GUIDES.get(record.check_id),
    )


def _latest_scan_out(scan: Scan) -> RepoLatestScan:
    return RepoLatestScan(
        **scan_summary(scan, utc_now()).model_dump(), incomplete_reason=scan.incomplete_reason
    )


def _unavailable(status_code: int, detail: str, exc: Exception) -> HTTPException:
    # Security: only the error type is logged, in case a message ever carries response text.
    logger.error("github linking failed: %s", type(exc).__name__)
    return HTTPException(status_code, detail=detail)


def _consume_state(session: Session, state: str, viewer_id: UUID) -> None:
    """Use up a state value, or refuse the request.

    Security: one conditional DELETE, so of two simultaneous uses only one can succeed. It
    also has to be this user's own, which stops an attacker sending a victim to a link
    carrying the attacker's state to attach the wrong account. Committed before any checks
    run, so a failed attempt can't be retried with the same value.
    """
    result = session.exec(
        delete(GithubInstallState).where(
            GithubInstallState.token_hash == hash_token(state),
            GithubInstallState.owner_id == viewer_id,
            GithubInstallState.expires_at > utc_now(),
        )
    )
    session.commit()
    if result.rowcount == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=_BAD_STATE)


def _verified_installation(installation_id: int, github_account_id: int) -> GithubInstallationInfo:
    """Return the installation only if GitHub says this person's own account owns it.

    Security: installation_id arrives in a URL that anyone can write, so on its own it proves
    nothing. Without this check, guessing an id would attach someone else's private repos.
    The ids compared are numeric, because a GitHub login can be renamed and re-registered.
    """
    info = get_installation(installation_id)
    if info is None or info.account.type != "User" or info.account.id != github_account_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_NOT_YOUR_ACCOUNT)
    if info.suspended_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=_SUSPENDED)
    return info


def _fetch_repositories(installation_id: int) -> list[GithubRepository]:
    token = create_installation_token(installation_id)
    try:
        return list_installation_repositories(token)
    finally:
        revoke_installation_token(token)


def _remove_replaced_installations(session: Session, info: GithubInstallationInfo) -> None:
    # An account has one live installation of an app. An older row means the app was
    # reinstalled and the uninstall webhook never arrived, so that row is dead.
    replaced = select(GithubInstallation.id).where(
        GithubInstallation.account_id == info.account.id,
        GithubInstallation.installation_id != info.id,
    )
    session.exec(delete(Repo).where(Repo.installation_id.in_(replaced)))
    session.exec(delete(GithubInstallation).where(GithubInstallation.id.in_(replaced)))


def _save_installation(
    session: Session, viewer_id: UUID, info: GithubInstallationInfo
) -> GithubInstallation:
    installation = session.exec(
        select(GithubInstallation).where(GithubInstallation.installation_id == info.id)
    ).first()
    if installation is not None:
        if installation.owner_id != viewer_id:
            raise HTTPException(status.HTTP_409_CONFLICT, detail=_ALREADY_LINKED)
        installation.account_login = info.account.login
        installation.suspended_at = None
        return installation

    _remove_replaced_installations(session, info)
    installation = GithubInstallation(
        owner_id=viewer_id,
        installation_id=info.id,
        account_id=info.account.id,
        account_login=info.account.login,
    )
    try:
        with session.begin_nested():
            session.add(installation)
    except IntegrityError as exc:
        # A simultaneous request linked it first.
        raise HTTPException(status.HTTP_409_CONFLICT, detail=_ALREADY_LINKED) from exc
    return installation


def upsert_repositories(
    session: Session,
    installation: GithubInstallation,
    repositories: Sequence[GithubRepositoryRef],
) -> None:
    """Add these repos to an installation, or refresh the ones it already has."""
    ids = {repository.id for repository in repositories}
    existing = {
        repo.github_repo_id: repo
        for repo in session.exec(
            select(Repo).where(
                Repo.installation_id == installation.id, Repo.github_repo_id.in_(ids)
            )
        )
    }
    # Security: a repo arriving from another installation was transferred. Its old row is
    # removed instead of moved, so the new owner doesn't inherit the old owner's findings.
    transferred = session.exec(
        select(Repo).where(Repo.github_repo_id.in_(ids), Repo.installation_id != installation.id)
    )
    for repo in transferred:
        session.delete(repo)
    session.flush()

    for repository in repositories:
        repo = existing.get(repository.id)
        if repo is None:
            session.add(
                Repo(
                    owner_id=installation.owner_id,
                    installation_id=installation.id,
                    github_repo_id=repository.id,
                    full_name=repository.full_name,
                    is_private=repository.private,
                )
            )
        else:
            repo.full_name = repository.full_name
            repo.is_private = repository.private


def sync_repositories(
    session: Session, installation: GithubInstallation, repositories: list[GithubRepository]
) -> None:
    """Make the stored repos for an installation match what GitHub says it can access."""
    current_ids = {repository.id for repository in repositories}
    for repo in session.exec(select(Repo).where(Repo.installation_id == installation.id)):
        if repo.github_repo_id not in current_ids:
            session.delete(repo)
    upsert_repositories(session, installation, repositories)


@router.post("/github/install-url", response_model=InstallUrlOut)
@limiter.limit(INSTALL_URL_RATE_LIMIT)
def create_install_url(
    request: Request,
    response: Response,
    session: SessionDep,
    viewer: SignedInDep,
) -> InstallUrlOut:
    if not settings.github_app_slug:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=_NOT_CONFIGURED)

    ensure_profile(session, viewer)
    now = utc_now()
    session.exec(
        delete(GithubInstallState).where(
            GithubInstallState.owner_id == viewer.id, GithubInstallState.expires_at <= now
        )
    )
    state = secrets.token_urlsafe(32)
    session.add(
        GithubInstallState(
            owner_id=viewer.id,
            token_hash=hash_token(state),
            expires_at=now + INSTALL_STATE_LIFETIME,
        )
    )
    session.commit()
    return InstallUrlOut(
        url=f"https://github.com/apps/{settings.github_app_slug}/installations/new?state={state}"
    )


@router.post("/github/installations/link", response_model=LinkResult)
@limiter.limit(LINK_RATE_LIMIT)
def link_installation(
    request: Request,
    response: Response,
    body: LinkRequest,
    session: SessionDep,
    viewer: SignedInDep,
    access_token: AccessTokenDep,
) -> LinkResult:
    ensure_profile(session, viewer)
    # Also ends the transaction, so no database connection waits on the network calls below.
    _consume_state(session, body.state, viewer.id)

    try:
        github_account_id = fetch_github_account_id(access_token, viewer.id)
    except AuthUnavailableError as exc:
        raise _unavailable(status.HTTP_503_SERVICE_UNAVAILABLE, _NOT_CONFIGURED, exc) from exc
    if github_account_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_NO_GITHUB_IDENTITY)

    try:
        info = _verified_installation(body.installation_id, github_account_id)
        repositories = _fetch_repositories(info.id)
    except GithubAppNotConfiguredError as exc:
        raise _unavailable(status.HTTP_503_SERVICE_UNAVAILABLE, _NOT_CONFIGURED, exc) from exc
    except GithubApiError as exc:
        raise _unavailable(status.HTTP_502_BAD_GATEWAY, _GITHUB_UNAVAILABLE, exc) from exc

    # The installation and its repos commit together, so a link is never half saved.
    installation = _save_installation(session, viewer.id, info)
    sync_repositories(session, installation, repositories)
    session.commit()
    return LinkResult(account_login=info.account.login, repositories=len(repositories))


def _owned_repo(session: Session, repo_id: UUID, viewer_id: UUID) -> Repo:
    repo = session.get(Repo, repo_id)
    # Security: 404 for someone else's repo too, so ids can't be probed for existence.
    if repo is None or repo.owner_id != viewer_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Repository not found.")
    return repo


def _running_full_scan(session: Session, repo_id: UUID, now: datetime) -> Scan | None:
    return session.exec(
        select(Scan)
        .where(
            Scan.repo_id == repo_id,
            Scan.before_sha.is_(None),
            Scan.after_sha.is_(None),
            Scan.status.in_(UNFINISHED_STATUSES),
            Scan.created_at >= now - REPO_SCAN_STALE_AFTER,
        )
        .limit(1)
    ).first()


@router.post(
    "/repos/{repo_id}/scan", response_model=RepoScanCreated, status_code=status.HTTP_202_ACCEPTED
)
@limiter.limit(REPO_SCAN_RATE_LIMIT)
def start_repo_scan(
    request: Request,
    response: Response,
    repo_id: UUID,
    session: SessionDep,
    viewer: SignedInDep,
) -> RepoScanCreated:
    repo = _owned_repo(session, repo_id, viewer.id)
    installation = session.get_one(GithubInstallation, repo.installation_id)
    if installation.suspended_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=_SUSPENDED)

    now = utc_now()
    lock_target(session, f"repo:{repo.id}")
    running = _running_full_scan(session, repo.id, now)
    if running is not None:
        response.status_code = status.HTTP_200_OK
        return RepoScanCreated(id=running.id, status=running.status, reused=True)

    started = session.exec(
        select(func.count())
        .select_from(Scan)
        .where(
            Scan.repo_id == repo.id,
            Scan.before_sha.is_(None),
            Scan.after_sha.is_(None),
            Scan.created_at >= now - timedelta(hours=1),
        )
    ).one()
    if started >= HOURLY_FULL_REPO_SCAN_CAP:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="This repository has been scanned too many times recently. Try again later.",
            headers={"Retry-After": "3600"},
        )

    # Security: FULL mode, because only the owner may ever read a full scan.
    scan = Scan(
        owner_id=viewer.id,
        repo_id=repo.id,
        target_type=TargetType.REPO,
        target=repo.full_name,
        mode=ScanMode.FULL,
        progress_json=initial_repo_progress(),
    )
    session.add(scan)
    scan_id, scan_status = scan.id, scan.status
    # Committed before queueing, so the worker can't look for a row that doesn't exist yet.
    session.commit()
    enqueue_scan(session, scan_id, run_repo_scan)
    return RepoScanCreated(id=scan_id, status=scan_status, reused=False)


@router.get("/repos/{repo_id}/findings", response_model=RepoFindingsOut)
def list_repo_findings(repo_id: UUID, session: SessionDep, viewer: SignedInDep) -> RepoFindingsOut:
    repo = _owned_repo(session, repo_id, viewer.id)
    records = sorted(
        session.exec(select(FindingRecord).where(FindingRecord.repo_id == repo.id)),
        key=lambda record: (
            _SEVERITY_ORDER.index(record.severity),
            record.file_path or "",
            record.line or 0,
        ),
    )
    # Security: owner_id as well as repo_id, so a scan can't be shown to anyone but its owner.
    latest = session.exec(
        select(Scan)
        .where(Scan.repo_id == repo.id, Scan.owner_id == viewer.id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    ).first()

    counts = Counter(record.severity for record in records)
    return RepoFindingsOut(
        id=repo.id,
        full_name=repo.full_name,
        is_private=repo.is_private,
        history_warning=HISTORY_WARNING,
        latest_scan=_latest_scan_out(latest) if latest is not None else None,
        counts={severity: counts[severity] for severity in Severity},
        findings=[_repo_finding_out(record) for record in records],
    )


@router.get("/repos", response_model=list[RepoOut])
def list_repos(session: SessionDep, viewer: SignedInDep) -> list[RepoOut]:
    rows = session.exec(
        select(Repo, GithubInstallation.account_login)
        .join(GithubInstallation, Repo.installation_id == GithubInstallation.id)
        .where(Repo.owner_id == viewer.id)
        .order_by(Repo.full_name)
    )
    return [
        RepoOut(
            id=repo.id,
            full_name=repo.full_name,
            is_private=repo.is_private,
            account_login=account_login,
            created_at=repo.created_at,
        )
        for repo, account_login in rows
    ]
