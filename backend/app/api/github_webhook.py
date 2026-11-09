"""GitHub's webhook: keeps installations and repos in step, and notices new commits.

Anyone on the internet can POST here, so nothing about a request is believed, or even parsed,
until its signature has been checked against the raw bytes that arrived.
"""

import hashlib
import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, StringConstraints, TypeAdapter, ValidationError
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.api.github import upsert_repositories
from app.api.scans import SessionDep
from app.core.config import settings
from app.core.github_app import GithubRepositoryRef
from app.models.github import GithubDelivery, GithubInstallation, Repo
from app.models.scan import utc_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/github", tags=["github"])

# Security: read before anything is verified, so an unsigned request can't exhaust memory.
# Far above a normal delivery. A push too large to accept shows as failed on GitHub.
MAX_WEBHOOK_BYTES = 10 * 1024 * 1024
# Longer than the 3 days GitHub keeps a delivery available to resend.
DELIVERY_RETENTION = timedelta(days=7)
ZERO_SHA = "0" * 40
BRANCH_REF_PREFIX = "refs/heads/"

_SIGNATURE_PREFIX = "sha256="
_BAD_SIGNATURE = "Invalid signature."
_BAD_DELIVERY = "Invalid delivery id."
_BAD_PAYLOAD = "Invalid payload."

_DELIVERY_ID = TypeAdapter(Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F-]{36}$")])

Sha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
HeaderValue = Annotated[str | None, Header()]


class WebhookResult(BaseModel):
    status: Literal["processed", "ignored", "duplicate"]


class _Payload(BaseModel):
    # Security: only the fields declared here are read. A push also carries author names and
    # emails, which GapScan must never store, so they are dropped at the door.
    model_config = ConfigDict(hide_input_in_errors=True)


class _InstallationRef(_Payload):
    id: int


class _RepositoryId(_Payload):
    id: int


class _InstallationEvent(_Payload):
    action: str
    installation: _InstallationRef


class _InstallationRepositoriesEvent(_Payload):
    action: str
    installation: _InstallationRef
    repositories_added: list[GithubRepositoryRef] = []
    repositories_removed: list[_RepositoryId] = []


class PushEvent(_Payload):
    ref: str
    before: Sha
    after: Sha
    deleted: bool = False
    forced: bool = False
    installation: _InstallationRef
    repository: _RepositoryId


@dataclass(frozen=True)
class PushRange:
    """Which commits to scan. Both null means the whole history."""

    before_sha: str | None
    after_sha: str | None


FULL_HISTORY = PushRange(None, None)


def is_valid_signature(body: bytes, header: str | None, secret: str) -> bool:
    if not header or not header.startswith(_SIGNATURE_PREFIX):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    # Security: constant time, so response timing can't reveal the signature byte by byte.
    # Compared as bytes because compare_digest refuses a str with non-ASCII characters.
    return hmac.compare_digest(expected.encode(), header[len(_SIGNATURE_PREFIX) :].encode())


async def read_capped_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, detail="Payload too large.")
    return bytes(body)


def _find_installation(session: Session, installation_id: int) -> GithubInstallation | None:
    return session.exec(
        select(GithubInstallation).where(GithubInstallation.installation_id == installation_id)
    ).first()


def _handle_installation(session: Session, event: _InstallationEvent) -> None:
    # Security: "created" is ignored on purpose. Only the signed-in flow, with its state and
    # account check, can tie an installation to a user. A webhook says nothing about who.
    installation = _find_installation(session, event.installation.id)
    if installation is None:
        return

    if event.action == "deleted":
        # Uninstalling means we no longer have permission, so what we hold about it goes too.
        session.exec(delete(Repo).where(Repo.installation_id == installation.id))
        session.exec(delete(GithubInstallation).where(GithubInstallation.id == installation.id))
    elif event.action == "suspend":
        installation.suspended_at = utc_now()
    elif event.action == "unsuspend":
        installation.suspended_at = None


def _handle_installation_repositories(
    session: Session, event: _InstallationRepositoriesEvent
) -> None:
    installation = _find_installation(session, event.installation.id)
    if installation is None:
        return

    removed = {repository.id for repository in event.repositories_removed}
    if removed:
        session.exec(
            delete(Repo).where(
                Repo.installation_id == installation.id, Repo.github_repo_id.in_(removed)
            )
        )
    if event.repositories_added:
        upsert_repositories(session, installation, event.repositories_added)


def find_push_repo(session: Session, event: PushEvent) -> Repo | None:
    """Return the linked repo a push belongs to, or None if GapScan shouldn't act on it."""
    # Security: matched on both numbers, so an event can only reach a repo through the
    # installation it was linked under. Suspended installations aren't scanned.
    return session.exec(
        select(Repo)
        .join(GithubInstallation, Repo.installation_id == GithubInstallation.id)
        .where(
            Repo.github_repo_id == event.repository.id,
            GithubInstallation.installation_id == event.installation.id,
            GithubInstallation.suspended_at.is_(None),
        )
    ).first()


def push_scan_range(event: PushEvent, repo: Repo) -> PushRange | None:
    """Decide which commits a push needs scanned. None means there is nothing to scan."""
    if not event.ref.startswith(BRANCH_REF_PREFIX) or event.deleted or event.after == ZERO_SHA:
        return None
    # A repo's first scan always covers everything, and so does one catching up on a missed
    # push. After a force-push the old commit is gone from a fresh clone, so no range exists.
    if repo.first_full_scan_at is None or repo.needs_full_scan or event.forced:
        return FULL_HISTORY
    if event.before == ZERO_SHA:
        return PushRange(None, event.after)
    return PushRange(event.before, event.after)


def _handle_push(session: Session, event: PushEvent) -> None:
    repo = find_push_repo(session, event)
    if repo is None:
        return
    scan_range = push_scan_range(event, repo)
    if scan_range is not None:
        # The scan itself is started here once the repo scanner exists.
        logger.info("push needs a scan: repo %s", repo.id)


# Each event's payload shape and what to do with it. Anything else is ignored.
_EVENTS: dict[str, tuple[type[_Payload], Callable[[Session, Any], None]]] = {
    "push": (PushEvent, _handle_push),
    "installation": (_InstallationEvent, _handle_installation),
    "installation_repositories": (
        _InstallationRepositoriesEvent,
        _handle_installation_repositories,
    ),
}


def _is_new_delivery(session: Session, delivery_id: str) -> bool:
    # Security: a captured request stays correctly signed forever, so without this it could
    # be replayed. The unique key decides, which also settles two copies arriving at once.
    try:
        with session.begin_nested():
            session.add(GithubDelivery(delivery_id=delivery_id))
    except IntegrityError:
        return False
    return True


@router.post("/webhook", response_model=WebhookResult)
def receive_webhook(
    body: Annotated[bytes, Depends(read_capped_body)],
    session: SessionDep,
    x_hub_signature_256: HeaderValue = None,
    x_github_event: HeaderValue = None,
    x_github_delivery: HeaderValue = None,
) -> WebhookResult:
    secret = settings.github_webhook_secret.get_secret_value()
    # Security: fails closed. With no secret, nothing could be verified, so nothing is accepted.
    if not secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Webhook not configured.")
    if not is_valid_signature(body, x_hub_signature_256, secret):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=_BAD_SIGNATURE)

    registered = _EVENTS.get(x_github_event or "")
    if registered is None:
        return WebhookResult(status="ignored")
    payload_model, handler = registered

    try:
        delivery_id = _DELIVERY_ID.validate_python(x_github_delivery)
    except ValidationError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=_BAD_DELIVERY) from None

    # Validated before the delivery is recorded, so a refused one can be sent again.
    try:
        event = payload_model.model_validate_json(body)
    except ValidationError:
        logger.warning("webhook payload failed validation: %s", x_github_event)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=_BAD_PAYLOAD) from None

    if not _is_new_delivery(session, delivery_id):
        return WebhookResult(status="duplicate")

    # An error from here on leaves the transaction uncommitted, delivery record included.
    handler(session, event)
    session.exec(
        delete(GithubDelivery).where(GithubDelivery.received_at < utc_now() - DELIVERY_RETENTION)
    )
    # The record of this delivery and what it changed commit together.
    session.commit()
    return WebhookResult(status="processed")
