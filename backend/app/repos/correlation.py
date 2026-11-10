"""Combines what repo scans and site scans already stored into one finding per problem.

Security: reads and writes the database and nothing else, so correlation adds no outbound
requests. It compares project identifiers only, because no part of any key is kept to compare.
Matching stays inside one owner's repos and verified domains, so a site can't pull another
account's repo into a report by naming the same project.

Originals are never changed. A combined finding only points at them.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from itertools import product
from uuid import UUID

from sqlmodel import Session, col, select

from app.checks.base import BaasKind, Severity
from app.models.correlation import (
    CorrelatedFinding,
    CorrelatedFindingMember,
    CorrelationKind,
    LinkOrigin,
    LinkState,
    MatchConfidence,
    RepoDomainLink,
    RepoIdentifier,
    RepoIdentifierKind,
)
from app.models.domain import Domain, DomainBackend, DomainFirebaseProject
from app.models.github import Repo
from app.models.scan import (
    FindingRecord,
    IdentifierBasis,
    Scan,
    ScanJobStatus,
    ScanMode,
    utc_now,
)
from app.repos.identifiers import PRIVATE_KEY_RULE, SUPABASE_RULES

SITE_SERVICE_KEY_CHECK = "baas.supabase_service_key"
_FIREBASE_WEB_KEY_RULE = "gcp-api-key"
_RULES_READ = SUPABASE_RULES | {PRIVATE_KEY_RULE, _FIREBASE_WEB_KEY_RULE}
# Worked out from the key or the file holding it. Anything else is a guess.
_CONFIRMING_BASES = frozenset({IdentifierBasis.KEY_CLAIM, IdentifierBasis.SAME_FILE})

_Pair = tuple[UUID, UUID]
_CardKey = tuple[UUID, UUID, CorrelationKind, str]
_Covered = dict[_CardKey, set[UUID]]


@dataclass
class _Site:
    domain_id: UUID
    supabase: set[str] = field(default_factory=set)
    firebase_projects: set[str] = field(default_factory=set)
    # Each database or bucket, and the project it belongs to when that's known.
    firebase_hosts: dict[str, str | None] = field(default_factory=dict)
    firebase_buckets: dict[str, str | None] = field(default_factory=dict)
    # The service-key findings in the latest full scan, by project.
    key_findings: dict[str, set[UUID]] = field(default_factory=lambda: defaultdict(set))


@dataclass
class _Repo:
    repo_id: UUID
    identifiers: dict[RepoIdentifierKind, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    findings: list[FindingRecord] = field(default_factory=list)

    def with_rules(self, rules: frozenset[str] | set[str]) -> list[FindingRecord]:
        return [item for item in self.findings if item.rule_id in rules]


@dataclass(frozen=True)
class _Match:
    key: _CardKey
    severity: Severity
    confidence: MatchConfidence
    finding_ids: frozenset[UUID]


def _load_sites(session: Session, owner_id: UUID) -> dict[UUID, _Site]:
    domains = session.exec(
        select(Domain).where(Domain.owner_id == owner_id, col(Domain.verified_at).is_not(None))
    )
    sites = {domain.id: _Site(domain.id) for domain in domains}

    for row in session.exec(
        select(DomainBackend).where(col(DomainBackend.domain_id).in_(list(sites)))
    ):
        site = sites[row.domain_id]
        if row.kind is BaasKind.SUPABASE:
            site.supabase.add(row.identifier)
        elif row.kind is BaasKind.FIREBASE_RTDB:
            site.firebase_hosts[row.identifier] = row.firebase_project_id
        elif row.kind is BaasKind.FIREBASE_STORAGE:
            site.firebase_buckets[row.identifier] = row.firebase_project_id
        if row.firebase_project_id is not None:
            site.firebase_projects.add(row.firebase_project_id)

    for project in session.exec(
        select(DomainFirebaseProject).where(col(DomainFirebaseProject.domain_id).in_(list(sites)))
    ):
        sites[project.domain_id].firebase_projects.add(project.project_id)

    # Ordered oldest first, so the newest scan of each domain is the one left in the dict.
    # Older reports stay as they were, but only the latest says what the site exposes now.
    latest = {
        scan.id: scan.domain_id
        for scan in session.exec(
            select(Scan)
            .where(
                Scan.owner_id == owner_id,
                col(Scan.domain_id).in_(list(sites)),
                Scan.mode == ScanMode.FULL,
                Scan.status == ScanJobStatus.DONE,
            )
            .order_by(col(Scan.finished_at))
        )
    }
    newest_scan = {domain_id: scan_id for scan_id, domain_id in latest.items()}
    for finding in session.exec(
        select(FindingRecord).where(
            col(FindingRecord.scan_id).in_(list(newest_scan.values())),
            FindingRecord.check_id == SITE_SERVICE_KEY_CHECK,
            col(FindingRecord.backend_identifier).is_not(None),
        )
    ):
        site = sites[latest[finding.scan_id]]
        ref = str(finding.backend_identifier)
        site.key_findings[ref].add(finding.id)
        # The key names its project even if no URL for it was seen on the site.
        site.supabase.add(ref)
    return sites


def _load_repos(session: Session, owner_id: UUID) -> dict[UUID, _Repo]:
    repos = {
        repo.id: _Repo(repo.id)
        for repo in session.exec(select(Repo).where(Repo.owner_id == owner_id))
    }
    for row in session.exec(
        select(RepoIdentifier).where(col(RepoIdentifier.repo_id).in_(list(repos)))
    ):
        repos[row.repo_id].identifiers[row.kind].add(row.value)
    for finding in session.exec(
        select(FindingRecord).where(
            col(FindingRecord.repo_id).in_(list(repos)),
            col(FindingRecord.rule_id).in_(sorted(_RULES_READ)),
        )
    ):
        if finding.repo_id is not None:
            repos[finding.repo_id].findings.append(finding)
    return repos


def _covered_by_rotation(session: Session, owner_id: UUID) -> _Covered:
    """Which repo findings each key's earlier "I've rotated this" already dealt with."""
    rotated = list(
        session.exec(
            select(CorrelatedFinding).where(
                CorrelatedFinding.owner_id == owner_id,
                col(CorrelatedFinding.rotated_at).is_not(None),
            )
        )
    )
    keys = {card.id: (card.domain_id, card.repo_id, card.kind, card.identifier) for card in rotated}
    covered: _Covered = defaultdict(set)
    for member in session.exec(
        select(CorrelatedFindingMember).where(
            col(CorrelatedFindingMember.correlated_finding_id).in_(list(keys))
        )
    ):
        covered[keys[member.correlated_finding_id]].add(member.finding_id)
    return covered


def _admin_match(
    kind: CorrelationKind,
    site: _Site,
    repo: _Repo,
    project: str,
    findings: list[FindingRecord],
    covered: _Covered,
) -> _Match | None:
    key = (site.domain_id, repo.repo_id, kind, project)
    # A finding that a rotation didn't cover could be a new key, so it raises a new card.
    fresh = [item for item in findings if item.id not in covered.get(key, set())]
    if not fresh:
        return None
    confirmed = any(item.identifier_basis in _CONFIRMING_BASES for item in fresh)
    site_findings = site.key_findings.get(project, set())
    if kind is not CorrelationKind.SUPABASE_ADMIN:
        site_findings = set()
    return _Match(
        key,
        Severity.CRITICAL,
        MatchConfidence.CONFIRMED if confirmed else MatchConfidence.LIKELY,
        frozenset(item.id for item in fresh) | frozenset(site_findings),
    )


def _supabase_matches(
    site: _Site, repo: _Repo, *, link_confirmed: bool, covered: _Covered
) -> list[_Match]:
    by_project: dict[str, list[FindingRecord]] = defaultdict(list)
    unattributed: list[FindingRecord] = []
    for finding in repo.with_rules(SUPABASE_RULES):
        if finding.backend_identifier is None:
            unattributed.append(finding)
        elif finding.backend_identifier in site.supabase:
            by_project[finding.backend_identifier].append(finding)
    # The owner saying "this repo powers this site" helps name the project, but it's still
    # not proof about this key. These findings have no basis, so they can only be "likely".
    if link_confirmed and len(site.supabase) == 1:
        by_project[next(iter(site.supabase))].extend(unattributed)
    matches = (
        _admin_match(CorrelationKind.SUPABASE_ADMIN, site, repo, project, findings, covered)
        for project, findings in by_project.items()
    )
    return [item for item in matches if item is not None]


def _firebase_admin_matches(site: _Site, repo: _Repo, covered: _Covered) -> list[_Match]:
    by_project: dict[str, list[FindingRecord]] = defaultdict(list)
    for finding in repo.with_rules({PRIVATE_KEY_RULE}):
        if finding.backend_identifier in site.firebase_projects:
            by_project[str(finding.backend_identifier)].append(finding)
    matches = (
        _admin_match(CorrelationKind.FIREBASE_ADMIN, site, repo, project, findings, covered)
        for project, findings in by_project.items()
    )
    return [item for item in matches if item is not None]


def _shared_firebase(site: _Site, repo: _Repo) -> set[str]:
    """What this repo and site both name, by project wherever the project is known."""
    shared = repo.identifiers[RepoIdentifierKind.FIREBASE_PROJECT] & site.firebase_projects
    for value in repo.identifiers[RepoIdentifierKind.FIREBASE_RTDB] & set(site.firebase_hosts):
        shared.add(site.firebase_hosts[value] or value)
    for value in repo.identifiers[RepoIdentifierKind.FIREBASE_BUCKET] & set(site.firebase_buckets):
        shared.add(site.firebase_buckets[value] or value)
    return shared


def _firebase_config_matches(site: _Site, repo: _Repo, admin_projects: set[str]) -> list[_Match]:
    # One project gets one card, and an admin key for it already says more than a config does.
    shared = _shared_firebase(site, repo) - admin_projects
    named = repo.identifiers[RepoIdentifierKind.FIREBASE_PROJECT]
    # A web key doesn't name its project, so it's only linked when the repo has just one.
    web_keys = frozenset(item.id for item in repo.with_rules({_FIREBASE_WEB_KEY_RULE}))
    return [
        _Match(
            (site.domain_id, repo.repo_id, CorrelationKind.FIREBASE_CONFIG, identifier),
            Severity.INFO,
            MatchConfidence.CONFIRMED,
            web_keys if named == {identifier} else frozenset(),
        )
        for identifier in shared
    ]


def _shares_a_backend(site: _Site, repo: _Repo) -> bool:
    supabase = repo.identifiers[RepoIdentifierKind.SUPABASE_REF] | {
        str(item.backend_identifier)
        for item in repo.with_rules(SUPABASE_RULES)
        if item.backend_identifier is not None
    }
    admin = {
        item.backend_identifier
        for item in repo.with_rules({PRIVATE_KEY_RULE})
        if item.backend_identifier is not None
    }
    return bool(
        supabase & site.supabase or admin & site.firebase_projects or _shared_firebase(site, repo)
    )


def _sync_links(
    session: Session,
    owner_id: UUID,
    links: dict[_Pair, RepoDomainLink],
    shared: set[_Pair],
    now: datetime,
) -> None:
    for domain_id, repo_id in shared - set(links):
        session.add(
            RepoDomainLink(
                owner_id=owner_id,
                repo_id=repo_id,
                domain_id=domain_id,
                state=LinkState.SUGGESTED,
                origin=LinkOrigin.AUTOMATIC,
                created_at=now,
                updated_at=now,
            )
        )
    # Only our own open suggestions are withdrawn. The owner's answers are kept.
    for pair, link in links.items():
        if (
            pair not in shared
            and link.state is LinkState.SUGGESTED
            and link.origin is LinkOrigin.AUTOMATIC
        ):
            session.delete(link)


def _sync_cards(
    session: Session, owner_id: UUID, matches: dict[_CardKey, _Match], now: datetime
) -> None:
    open_cards = {
        (card.domain_id, card.repo_id, card.kind, card.identifier): card
        for card in session.exec(
            select(CorrelatedFinding).where(
                CorrelatedFinding.owner_id == owner_id,
                col(CorrelatedFinding.rotated_at).is_(None),
            )
        )
    }
    members: dict[UUID, dict[UUID, CorrelatedFindingMember]] = defaultdict(dict)
    for member in session.exec(
        select(CorrelatedFindingMember).where(
            col(CorrelatedFindingMember.correlated_finding_id).in_(
                [card.id for card in open_cards.values()]
            )
        )
    ):
        members[member.correlated_finding_id][member.finding_id] = member

    # Only open cards. One marked as rotated is the record of what that rotation covered.
    for key, card in open_cards.items():
        if key not in matches:
            for member in members[card.id].values():
                session.delete(member)
            session.delete(card)
    session.flush()

    for key, match in matches.items():
        card = open_cards.get(key)
        if card is None:
            domain_id, repo_id, kind, identifier = key
            card = CorrelatedFinding(
                owner_id=owner_id,
                domain_id=domain_id,
                repo_id=repo_id,
                kind=kind,
                severity=match.severity,
                confidence=match.confidence,
                identifier=identifier,
                first_seen_at=now,
                last_seen_at=now,
            )
            session.add(card)
        else:
            card.severity = match.severity
            card.confidence = match.confidence
            card.last_seen_at = now
        current = members[card.id]
        for finding_id, member in current.items():
            if finding_id not in match.finding_ids:
                session.delete(member)
        session.add_all(
            CorrelatedFindingMember(correlated_finding_id=card.id, finding_id=finding_id)
            for finding_id in match.finding_ids - set(current)
        )


def refresh_correlations(session: Session, owner_id: UUID) -> None:
    """Rebuild one owner's link suggestions and combined findings. The caller commits."""
    sites = _load_sites(session, owner_id)
    repos = _load_repos(session, owner_id)
    links = {
        (link.domain_id, link.repo_id): link
        for link in session.exec(select(RepoDomainLink).where(RepoDomainLink.owner_id == owner_id))
    }
    covered = _covered_by_rotation(session, owner_id)

    matches: dict[_CardKey, _Match] = {}
    shared: set[_Pair] = set()
    for site, repo in product(sites.values(), repos.values()):
        pair = (site.domain_id, repo.repo_id)
        if _shares_a_backend(site, repo):
            shared.add(pair)
        link = links.get(pair)
        if link is not None and link.state is LinkState.DISMISSED:
            continue
        confirmed = link is not None and link.state is LinkState.CONFIRMED
        admin = _firebase_admin_matches(site, repo, covered)
        admin_projects = {match.key[3] for match in admin}
        for match in (
            *_supabase_matches(site, repo, link_confirmed=confirmed, covered=covered),
            *admin,
            *_firebase_config_matches(site, repo, admin_projects),
        ):
            matches[match.key] = match

    now = utc_now()
    _sync_links(session, owner_id, links, shared, now)
    _sync_cards(session, owner_id, matches, now)
