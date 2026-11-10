"""Saying which repo powers which site, and answering GapScan's suggestions.

Security: every route checks the signed-in user owns both sides, and answers 404 otherwise, so
ids can't be probed. Nothing here contacts GitHub or a website.
"""

import logging
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session, col, select

from app.api.scans import SessionDep, SignedInDep
from app.core.rate_limit import limiter
from app.models.correlation import LinkOrigin, LinkState, RepoDomainLink
from app.models.domain import Domain
from app.models.github import Repo
from app.models.scan import utc_now
from app.repos.correlation import refresh_correlations

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/repo-links", tags=["correlation"])

CHANGE_LINK_RATE_LIMIT = "30/minute"

_NOT_FOUND = "Link not found."
_VERIFY_FIRST = "Verify this domain before linking a repository to it."


class LinkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: UUID
    domain_id: UUID


class LinkAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal["confirmed", "dismissed"]


class LinkOut(BaseModel):
    id: UUID
    repo_id: UUID
    repo_full_name: str
    domain_id: UUID
    hostname: str
    state: LinkState
    origin: LinkOrigin
    updated_at: datetime


def _owned_link(session: Session, link_id: UUID, viewer_id: UUID) -> RepoDomainLink:
    link = session.get(RepoDomainLink, link_id)
    if link is None or link.owner_id != viewer_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    return link


def _require_verified(domain: Domain | None) -> None:
    # Security: a link can make a combined finding, and those are for proven owners only.
    if domain is None or domain.verified_at is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_VERIFY_FIRST)


def _refresh(session: Session, owner_id: UUID) -> None:
    # The owner's answer is already saved. If this fails, the next scan brings it up to date.
    try:
        refresh_correlations(session, owner_id)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.warning("could not refresh correlations: %s", type(exc).__name__)


def _link_out(session: Session, link: RepoDomainLink) -> LinkOut:
    return LinkOut(
        id=link.id,
        repo_id=link.repo_id,
        repo_full_name=session.get_one(Repo, link.repo_id).full_name,
        domain_id=link.domain_id,
        hostname=session.get_one(Domain, link.domain_id).hostname,
        state=link.state,
        origin=link.origin,
        updated_at=link.updated_at,
    )


@router.get("", response_model=list[LinkOut])
def list_links(session: SessionDep, viewer: SignedInDep) -> list[LinkOut]:
    rows = session.exec(
        select(RepoDomainLink)
        .join(Domain, col(Domain.id) == col(RepoDomainLink.domain_id))
        .join(Repo, col(Repo.id) == col(RepoDomainLink.repo_id))
        .where(RepoDomainLink.owner_id == viewer.id)
        .order_by(col(Domain.hostname), col(Repo.full_name))
    ).all()
    return [_link_out(session, row) for row in rows]


@router.post("", response_model=LinkOut)
@limiter.limit(CHANGE_LINK_RATE_LIMIT)
def create_link(
    request: Request,
    response: Response,
    body: LinkCreate,
    session: SessionDep,
    viewer: SignedInDep,
) -> LinkOut:
    repo = session.get(Repo, body.repo_id)
    domain = session.get(Domain, body.domain_id)
    if repo is None or repo.owner_id != viewer.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Repository not found.")
    if domain is None or domain.owner_id != viewer.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Domain not found.")
    _require_verified(domain)

    link = session.exec(
        select(RepoDomainLink).where(
            RepoDomainLink.repo_id == repo.id, RepoDomainLink.domain_id == domain.id
        )
    ).first()
    if link is None:
        link = RepoDomainLink(
            owner_id=viewer.id,
            repo_id=repo.id,
            domain_id=domain.id,
            state=LinkState.CONFIRMED,
            origin=LinkOrigin.MANUAL,
        )
        session.add(link)
    else:
        link.state = LinkState.CONFIRMED
        link.updated_at = utc_now()
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="That link was just changed. Please try again."
        ) from exc
    _refresh(session, viewer.id)
    return _link_out(session, link)


@router.patch("/{link_id}", response_model=LinkOut)
@limiter.limit(CHANGE_LINK_RATE_LIMIT)
def answer_link(
    request: Request,
    response: Response,
    link_id: UUID,
    body: LinkAnswer,
    session: SessionDep,
    viewer: SignedInDep,
) -> LinkOut:
    link = _owned_link(session, link_id, viewer.id)
    # Saying "not related" is always allowed, like taking back a backend confirmation.
    if body.state == "confirmed":
        _require_verified(session.get(Domain, link.domain_id))
    link.state = LinkState(body.state)
    link.updated_at = utc_now()
    session.commit()
    _refresh(session, viewer.id)
    return _link_out(session, link)


@router.delete("/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(CHANGE_LINK_RATE_LIMIT)
def delete_link(
    request: Request,
    response: Response,
    link_id: UUID,
    session: SessionDep,
    viewer: SignedInDep,
) -> None:
    # If the repo and site still share a backend, this returns as a suggestion, which is
    # what makes it the way to undo "not related".
    session.delete(_owned_link(session, link_id, viewer.id))
    session.commit()
    _refresh(session, viewer.id)
