"""Reading combined findings, and recording that a leaked key was replaced.

Security: owner only, with 404 for anyone else's. Only masked evidence is returned, because
nothing else is stored. Nothing here contacts GitHub, a provider or a website.
"""

from collections import defaultdict
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, col, select

from app.api.repo_links import refresh_saved_change
from app.api.scans import SessionDep, SignedInDep
from app.checks.base import Severity
from app.core.rate_limit import limiter
from app.models.correlation import (
    CorrelatedFinding,
    CorrelatedFindingMember,
    CorrelationKind,
    LinkState,
    MatchConfidence,
    RepoDomainLink,
)
from app.models.domain import Domain
from app.models.github import Repo
from app.models.scan import FindingRecord, utc_now
from app.repos.combined_guides import (
    HISTORY_DOCS_URL,
    LIKELY_NOTE,
    ROTATED_NOTE,
    HistoryStep,
    can_be_rotated,
    combined_title,
    guide_for,
)
from app.repos.correlation import refresh_correlations

router = APIRouter(prefix="/api/combined-findings", tags=["correlation"])

MARK_ROTATED_RATE_LIMIT = "30/minute"

_SEVERITY_ORDER = list(Severity)
_NOT_FOUND = "Finding not found."


class OriginalFindingOut(BaseModel):
    id: UUID
    source: Literal["repository", "website"]
    title: str
    masked: str
    location: str | None
    first_seen_at: datetime


class CombinedFindingOut(BaseModel):
    id: UUID
    kind: CorrelationKind
    severity: Severity
    confidence: MatchConfidence
    identifier: str
    domain_id: UUID
    hostname: str
    repo_id: UUID
    repo_full_name: str
    title: str
    # Why this needs a caveat, when it does.
    note: str | None
    what_it_means: str
    provider_name: str
    rotate_steps: tuple[str, ...]
    rotate_url: str
    docs_url: str
    history_steps: tuple[HistoryStep, ...]
    history_docs_url: str | None
    can_mark_rotated: bool
    can_reopen: bool
    rotated_at: datetime | None
    reopened_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime
    originals: list[OriginalFindingOut]


def _original_out(finding: FindingRecord) -> OriginalFindingOut:
    return OriginalFindingOut(
        id=finding.id,
        source="website" if finding.repo_id is None else "repository",
        title=finding.title,
        masked=finding.evidence_masked,
        location=finding.location,
        first_seen_at=finding.created_at,
    )


def _originals_by_card(session: Session, card_ids: list[UUID]) -> dict[UUID, list[FindingRecord]]:
    found: dict[UUID, list[FindingRecord]] = defaultdict(list)
    rows = session.exec(
        select(CorrelatedFindingMember, FindingRecord)
        .join(FindingRecord, col(FindingRecord.id) == col(CorrelatedFindingMember.finding_id))
        .where(col(CorrelatedFindingMember.correlated_finding_id).in_(card_ids))
        .order_by(col(FindingRecord.created_at))
    )
    for member, finding in rows:
        found[member.correlated_finding_id].append(finding)
    return found


def _card_out(
    session: Session, card: CorrelatedFinding, originals: list[FindingRecord]
) -> CombinedFindingOut:
    guide = guide_for(card.kind)
    repo = session.get_one(Repo, card.repo_id).full_name
    likely = card.confidence is MatchConfidence.LIKELY
    has_history = bool(guide.history_steps)
    return CombinedFindingOut(
        id=card.id,
        kind=card.kind,
        severity=card.severity,
        confidence=card.confidence,
        identifier=card.identifier,
        domain_id=card.domain_id,
        hostname=session.get_one(Domain, card.domain_id).hostname,
        repo_id=card.repo_id,
        repo_full_name=repo,
        title=combined_title(card.kind, card.confidence, repo),
        note=ROTATED_NOTE if card.rotated_at else LIKELY_NOTE if likely else None,
        what_it_means=guide.what_it_means,
        provider_name=guide.provider_name,
        rotate_steps=guide.rotate_steps,
        rotate_url=guide.rotate_url,
        docs_url=guide.docs_url,
        history_steps=guide.history_steps,
        history_docs_url=HISTORY_DOCS_URL if has_history else None,
        can_mark_rotated=can_be_rotated(card.kind) and card.rotated_at is None,
        can_reopen=can_be_rotated(card.kind) and card.rotated_at is not None,
        rotated_at=card.rotated_at,
        reopened_at=card.reopened_at,
        first_seen_at=card.first_seen_at,
        last_seen_at=card.last_seen_at,
        originals=[_original_out(item) for item in originals],
    )


def _owned_card(session: Session, card_id: UUID, viewer_id: UUID) -> CorrelatedFinding:
    card = session.get(CorrelatedFinding, card_id)
    if card is None or card.owner_id != viewer_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=_NOT_FOUND)
    return card


def _display_order(card: CorrelatedFinding) -> tuple[bool, int, bool]:
    return (
        card.rotated_at is not None,
        _SEVERITY_ORDER.index(card.severity),
        card.confidence is MatchConfidence.LIKELY,
    )


@router.get("", response_model=list[CombinedFindingOut])
def list_combined_findings(
    session: SessionDep,
    viewer: SignedInDep,
    domain_id: UUID | None = None,
    repo_id: UUID | None = None,
) -> list[CombinedFindingOut]:
    query = select(CorrelatedFinding).where(CorrelatedFinding.owner_id == viewer.id)
    if domain_id is not None:
        query = query.where(CorrelatedFinding.domain_id == domain_id)
    if repo_id is not None:
        query = query.where(CorrelatedFinding.repo_id == repo_id)
    # "Not related" also hides the history of cards already marked as rotated.
    dismissed = {
        (link.domain_id, link.repo_id)
        for link in session.exec(
            select(RepoDomainLink).where(
                RepoDomainLink.owner_id == viewer.id,
                RepoDomainLink.state == LinkState.DISMISSED,
            )
        )
    }
    cards = sorted(
        (card for card in session.exec(query) if (card.domain_id, card.repo_id) not in dismissed),
        key=_display_order,
    )
    originals = _originals_by_card(session, [card.id for card in cards])
    return [_card_out(session, card, originals[card.id]) for card in cards]


@router.post("/{card_id}/rotated", response_model=CombinedFindingOut)
@limiter.limit(MARK_ROTATED_RATE_LIMIT)
def mark_rotated(
    request: Request,
    response: Response,
    card_id: UUID,
    session: SessionDep,
    viewer: SignedInDep,
) -> CombinedFindingOut:
    card = _owned_card(session, card_id, viewer.id)
    if not can_be_rotated(card.kind):
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="This finding isn't about a key that can be replaced."
        )
    # Marking it twice changes nothing, so the first answer's who and when stay on record.
    if card.rotated_at is None:
        # The owner's word: checking it would mean holding the key or contacting the provider.
        card.rotated_at = utc_now()
        card.rotated_by = viewer.id
        card.severity = Severity.INFO
        session.commit()
        refresh_saved_change(session, viewer.id)
    return _card_out(session, card, _originals_by_card(session, [card.id])[card.id])


def _open_twin(session: Session, card: CorrelatedFinding) -> CorrelatedFinding | None:
    return session.exec(
        select(CorrelatedFinding).where(
            CorrelatedFinding.domain_id == card.domain_id,
            CorrelatedFinding.repo_id == card.repo_id,
            CorrelatedFinding.kind == card.kind,
            CorrelatedFinding.identifier == card.identifier,
            col(CorrelatedFinding.rotated_at).is_(None),
        )
    ).first()


@router.post("/{card_id}/reopen", response_model=CombinedFindingOut)
@limiter.limit(MARK_ROTATED_RATE_LIMIT)
def reopen(
    request: Request,
    response: Response,
    card_id: UUID,
    session: SessionDep,
    viewer: SignedInDep,
) -> CombinedFindingOut:
    """Take back "I've rotated this key". Only the owner can, and it's recorded."""
    card = _owned_card(session, card_id, viewer.id)
    if card.rotated_at is None:
        return _card_out(session, card, _originals_by_card(session, [card.id])[card.id])

    # A key found since the rotation may already have its own open card, and only one can be
    # open per project. Its findings join that one, so nothing is shown twice.
    twin = _open_twin(session, card)
    if twin is None:
        card.rotated_at = None
        card.rotated_by = None
        reopened = card
    else:
        members = session.exec(
            select(CorrelatedFindingMember).where(
                CorrelatedFindingMember.correlated_finding_id == card.id
            )
        )
        for member in members:
            session.delete(member)
        session.delete(card)
        reopened = twin
    reopened.reopened_at = utc_now()
    reopened.reopened_by = viewer.id
    reopened_id = reopened.id

    # One transaction, unlike the routes that only record an answer. Whether this finding can
    # reopen depends on the refresh, so a failure must leave the rotated card as it was.
    try:
        session.flush()
        refresh_correlations(session, viewer.id)
        session.flush()
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Couldn't reopen this. Please try again."
        ) from exc
    current = session.get(CorrelatedFinding, reopened_id)
    if current is None:
        session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="This repository and website no longer match, so it can't be reopened.",
        )
    session.commit()
    return _card_out(session, current, _originals_by_card(session, [current.id])[current.id])
