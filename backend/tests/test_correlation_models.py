"""The tables behind repo and site correlation. No correlation logic exists yet."""

from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from app.checks.base import BaasKind, Category, Severity
from app.models import (
    CorrelatedFinding,
    CorrelatedFindingMember,
    Domain,
    DomainBackend,
    FindingRecord,
    GithubInstallation,
    Profile,
    Repo,
    RepoDomainLink,
    RepoIdentifier,
    Scan,
)
from app.models.correlation import (
    CorrelationKind,
    LinkOrigin,
    LinkState,
    MatchConfidence,
    RepoIdentifierKind,
)
from app.models.scan import IdentifierBasis, ScanMode, TargetType, utc_now

REF = "abcdefghijklmnopqrst"


@dataclass(frozen=True)
class World:
    owner: UUID
    domain: UUID
    repo: UUID
    scan: UUID


def seed(engine: Engine) -> World:
    owner = uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        domain = Domain(owner_id=owner, hostname="example.com", verify_token="tok")  # noqa: S106
        installation = GithubInstallation(
            owner_id=owner, installation_id=7, account_id=70, account_login="me"
        )
        session.add_all([domain, installation])
        session.flush()
        repo = Repo(
            owner_id=owner,
            installation_id=installation.id,
            github_repo_id=100,
            full_name="me/project",
            is_private=True,
        )
        scan = Scan(
            owner_id=owner,
            target_type=TargetType.REPO,
            target="me/project",
            mode=ScanMode.FULL,
        )
        session.add_all([repo, scan])
        session.commit()
        return World(owner, domain.id, repo.id, scan.id)


def card(world: World, **overrides: object) -> CorrelatedFinding:
    fields: dict[str, object] = {
        "owner_id": world.owner,
        "domain_id": world.domain,
        "repo_id": world.repo,
        "kind": CorrelationKind.SUPABASE_ADMIN,
        "severity": Severity.CRITICAL,
        "confidence": MatchConfidence.CONFIRMED,
        "identifier": REF,
    }
    return CorrelatedFinding(**(fields | overrides))


def add(engine: Engine, *rows: object) -> None:
    with Session(engine) as session:
        session.add_all(rows)
        session.commit()


def test_a_repo_records_each_identifier_once(db_engine: Engine) -> None:
    world = seed(db_engine)
    row = RepoIdentifier(repo_id=world.repo, kind=RepoIdentifierKind.SUPABASE_REF, value=REF)
    add(db_engine, row)

    with pytest.raises(IntegrityError):
        add(
            db_engine,
            RepoIdentifier(repo_id=world.repo, kind=RepoIdentifierKind.SUPABASE_REF, value=REF),
        )


def test_the_same_value_can_be_a_different_kind(db_engine: Engine) -> None:
    world = seed(db_engine)

    add(
        db_engine,
        RepoIdentifier(repo_id=world.repo, kind=RepoIdentifierKind.FIREBASE_PROJECT, value="app"),
        RepoIdentifier(repo_id=world.repo, kind=RepoIdentifierKind.FIREBASE_BUCKET, value="app"),
    )

    with Session(db_engine) as session:
        kinds = {row.kind for row in session.exec(select(RepoIdentifier))}
    assert kinds == {RepoIdentifierKind.FIREBASE_PROJECT, RepoIdentifierKind.FIREBASE_BUCKET}


def test_a_repo_and_domain_have_one_link(db_engine: Engine) -> None:
    world = seed(db_engine)

    def link() -> RepoDomainLink:
        return RepoDomainLink(
            owner_id=world.owner,
            repo_id=world.repo,
            domain_id=world.domain,
            state=LinkState.SUGGESTED,
            origin=LinkOrigin.AUTOMATIC,
        )

    add(db_engine, link())
    with pytest.raises(IntegrityError):
        add(db_engine, link())


def test_only_one_card_can_be_open_for_a_project_repo_and_domain(db_engine: Engine) -> None:
    world = seed(db_engine)
    add(db_engine, card(world))

    with pytest.raises(IntegrityError):
        add(db_engine, card(world))


def test_a_rotated_card_leaves_room_for_a_new_one(db_engine: Engine) -> None:
    world = seed(db_engine)
    add(db_engine, card(world, rotated_at=utc_now(), rotated_by=world.owner))

    add(db_engine, card(world))

    with Session(db_engine) as session:
        cards = list(session.exec(select(CorrelatedFinding)))
    assert len(cards) == 2
    assert sum(item.rotated_at is None for item in cards) == 1


def test_rotation_records_who_and_when(db_engine: Engine) -> None:
    world = seed(db_engine)
    when = utc_now()
    add(db_engine, card(world, rotated_at=when, rotated_by=world.owner))

    with Session(db_engine) as session:
        saved = session.exec(select(CorrelatedFinding)).one()
    assert saved.rotated_by == world.owner
    assert saved.rotated_at is not None


def test_different_projects_get_different_cards(db_engine: Engine) -> None:
    world = seed(db_engine)

    add(db_engine, card(world), card(world, identifier="tsrqponmlkjihgfedcba"))

    with Session(db_engine) as session:
        assert len(list(session.exec(select(CorrelatedFinding)))) == 2


def test_a_likely_match_is_recorded_as_likely(db_engine: Engine) -> None:
    world = seed(db_engine)
    add(db_engine, card(world, confidence=MatchConfidence.LIKELY))

    with Session(db_engine) as session:
        assert session.exec(select(CorrelatedFinding)).one().confidence is MatchConfidence.LIKELY


def finding(world: World, fingerprint: str) -> FindingRecord:
    return FindingRecord(
        scan_id=world.scan,
        repo_id=world.repo,
        check_id="secrets.supabase",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        title="Supabase service role key found in your code",
        evidence_masked="eyJ****",
        fingerprint=fingerprint,
        backend_identifier=REF,
        identifier_basis=IdentifierBasis.KEY_CLAIM,
    )


def test_one_finding_can_sit_behind_two_cards(db_engine: Engine) -> None:
    world = seed(db_engine)
    original = finding(world, "a" * 64)
    first = card(world)
    second = card(world, kind=CorrelationKind.FIREBASE_CONFIG, severity=Severity.INFO)
    finding_id, first_id, second_id = original.id, first.id, second.id
    add(db_engine, original, first, second)

    add(
        db_engine,
        CorrelatedFindingMember(correlated_finding_id=first_id, finding_id=finding_id),
        CorrelatedFindingMember(correlated_finding_id=second_id, finding_id=finding_id),
    )

    with Session(db_engine) as session:
        assert len(list(session.exec(select(CorrelatedFindingMember)))) == 2


def test_a_finding_is_listed_once_per_card(db_engine: Engine) -> None:
    world = seed(db_engine)
    original = finding(world, "a" * 64)
    combined = card(world)
    finding_id, combined_id = original.id, combined.id
    add(db_engine, original, combined)

    def member() -> CorrelatedFindingMember:
        return CorrelatedFindingMember(correlated_finding_id=combined_id, finding_id=finding_id)

    add(db_engine, member())
    with pytest.raises(IntegrityError):
        add(db_engine, member())


def test_finding_records_which_project_and_how_it_was_decided(db_engine: Engine) -> None:
    world = seed(db_engine)
    add(db_engine, finding(world, "a" * 64))

    with Session(db_engine) as session:
        saved = session.exec(select(FindingRecord)).one()
    assert saved.backend_identifier == REF
    assert saved.identifier_basis is IdentifierBasis.KEY_CLAIM


def test_new_columns_stay_empty_for_existing_kinds_of_row(db_engine: Engine) -> None:
    world = seed(db_engine)
    add(
        db_engine,
        DomainBackend(domain_id=world.domain, kind=BaasKind.SUPABASE, identifier=REF),
        FindingRecord(
            scan_id=world.scan,
            check_id="tls.hsts_missing",
            category=Category.TLS,
            severity=Severity.LOW,
            title="t",
            evidence_masked="e",
        ),
    )

    with Session(db_engine) as session:
        assert session.exec(select(DomainBackend)).one().firebase_project_id is None
        saved = session.exec(select(FindingRecord)).one()
    assert (saved.backend_identifier, saved.identifier_basis) == (None, None)


@pytest.mark.parametrize("table", ["repo_identifiers", "repo_domain_links", "correlated_findings"])
def test_no_table_has_a_column_for_a_secret(db_engine: Engine, table: str) -> None:
    names = {column["name"] for column in inspect(db_engine).get_columns(table)}

    assert not names & {"secret", "key", "token", "raw", "value_raw", "api_key"}


def test_combined_findings_are_not_in_the_findings_table() -> None:
    # The scorer sums findings, so a combined one living there could be counted twice.
    assert CorrelatedFinding.__tablename__ != FindingRecord.__tablename__
