"""Combining stored repo and site findings. Scoring and the screens come in later steps."""

import socket
import subprocess
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks.base import BaasKind, Category, Severity
from app.core import safe_http
from app.models import (
    CorrelatedFinding,
    CorrelatedFindingMember,
    Domain,
    DomainBackend,
    DomainFirebaseProject,
    FindingRecord,
    Profile,
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
from app.models.scan import (
    IdentifierBasis,
    ScanJobStatus,
    ScanMode,
    TargetType,
    utc_now,
)
from app.repos import correlation
from app.repos.correlation import SITE_SERVICE_KEY_CHECK, refresh_correlations
from app.workers import tasks
from app.workers.tasks import run_repo_scan
from tests.test_correlation_models import REF, World, seed
from tests.test_repo_scan_flow import FakeScanner, add_scan, hit, result
from tests.test_repo_scan_flow import seed as flow_seed

OTHER = "tsrqponmlkjihgfedcba"
PROJECT = "my-app-1"
HOST = "my-app-default-rtdb.firebaseio.com"
BUCKET = "my-app.appspot.com"
SERVICE = "supabase-service-role-jwt"
SECRET = "supabase-secret-key"  # noqa: S105
PRIVATE = "private-key"
WEB_KEY = "gcp-api-key"


def add(engine: Engine, *rows: Any) -> None:
    # Not expired on commit, so tests can read the ids of what they just saved.
    with Session(engine, expire_on_commit=False) as session:
        session.add_all(rows)
        session.commit()


@pytest.fixture
def world(db_engine: Engine) -> World:
    seeded = seed(db_engine)
    with Session(db_engine) as session:
        session.get_one(Domain, seeded.domain).verified_at = utc_now()
        session.commit()
    return seeded


def site_backend(
    world: World,
    identifier: str = REF,
    kind: BaasKind = BaasKind.SUPABASE,
    project: str | None = None,
) -> DomainBackend:
    return DomainBackend(
        domain_id=world.domain, kind=kind, identifier=identifier, firebase_project_id=project
    )


def repo_name(world: World, kind: RepoIdentifierKind, value: str) -> RepoIdentifier:
    return RepoIdentifier(repo_id=world.repo, kind=kind, value=value)


def repo_key(
    world: World,
    name: str = "a",
    ref: str | None = REF,
    basis: IdentifierBasis | None = IdentifierBasis.KEY_CLAIM,
    rule: str = SERVICE,
) -> FindingRecord:
    return FindingRecord(
        scan_id=world.scan,
        repo_id=world.repo,
        check_id="secrets.supabase",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        title="t",
        evidence_masked="****",
        rule_id=rule,
        fingerprint=name.ljust(64, "0"),
        backend_identifier=ref,
        identifier_basis=basis,
    )


def site_scan(engine: Engine, world: World, *, minutes: int = 0, ref: str | None = REF) -> UUID:
    """Save a finished full scan holding a service-key finding, and return the finding's id."""
    scan = Scan(
        owner_id=world.owner,
        domain_id=world.domain,
        target_type=TargetType.WEB,
        target="example.com",
        mode=ScanMode.FULL,
        status=ScanJobStatus.DONE,
        finished_at=utc_now() + timedelta(minutes=minutes),
    )
    finding = FindingRecord(
        scan_id=scan.id,
        check_id=SITE_SERVICE_KEY_CHECK,
        category=Category.BAAS,
        severity=Severity.CRITICAL,
        title="t",
        evidence_masked="eyJ****",
        backend_identifier=ref,
    )
    add(engine, scan)
    add(engine, finding)
    return finding.id


def refresh(engine: Engine, world: World) -> None:
    with Session(engine) as session:
        refresh_correlations(session, world.owner)
        session.commit()


def cards(engine: Engine) -> list[CorrelatedFinding]:
    with Session(engine) as session:
        return list(session.exec(select(CorrelatedFinding)))


def only_card(engine: Engine) -> CorrelatedFinding:
    found = cards(engine)
    assert len(found) == 1
    return found[0]


def members_of(engine: Engine, card_id: UUID) -> set[UUID]:
    with Session(engine) as session:
        rows = session.exec(
            select(CorrelatedFindingMember).where(
                CorrelatedFindingMember.correlated_finding_id == card_id
            )
        )
        return {row.finding_id for row in rows}


def links(engine: Engine) -> list[RepoDomainLink]:
    with Session(engine) as session:
        return list(session.exec(select(RepoDomainLink)))


def link(world: World, state: LinkState, origin: LinkOrigin = LinkOrigin.MANUAL) -> RepoDomainLink:
    return RepoDomainLink(
        owner_id=world.owner,
        repo_id=world.repo,
        domain_id=world.domain,
        state=state,
        origin=origin,
    )


def mark_rotated(engine: Engine, world: World) -> None:
    with Session(engine) as session:
        for card in session.exec(select(CorrelatedFinding)):
            if card.rotated_at is None:
                card.rotated_at = utc_now()
                card.rotated_by = world.owner
        session.commit()


# --- Supabase admin keys ---


@pytest.mark.parametrize("basis", [IdentifierBasis.KEY_CLAIM, IdentifierBasis.SAME_FILE])
def test_a_repo_key_for_the_sites_project_is_a_confirmed_critical(
    db_engine: Engine, world: World, basis: IdentifierBasis
) -> None:
    key = repo_key(world, basis=basis)
    add(db_engine, site_backend(world), key)

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.kind is CorrelationKind.SUPABASE_ADMIN
    assert card.severity is Severity.CRITICAL
    assert card.confidence is MatchConfidence.CONFIRMED
    assert card.identifier == REF
    assert members_of(db_engine, card.id) == {key.id}


def test_a_guessed_project_is_critical_but_only_likely(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world, basis=IdentifierBasis.ONLY_PROJECT))

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.severity is Severity.CRITICAL
    assert card.confidence is MatchConfidence.LIKELY


def test_one_confirmed_key_makes_the_whole_card_confirmed(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world),
        repo_key(world, "a", basis=IdentifierBasis.ONLY_PROJECT),
        repo_key(world, "b", basis=IdentifierBasis.KEY_CLAIM),
    )

    refresh(db_engine, world)

    assert only_card(db_engine).confidence is MatchConfidence.CONFIRMED


def test_many_keys_for_one_project_make_one_card(db_engine: Engine, world: World) -> None:
    keys = [repo_key(world, name) for name in "abc"]
    add(db_engine, site_backend(world), *keys)

    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == {key.id for key in keys}


def test_a_key_for_another_project_makes_no_card(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world, ref=OTHER))

    refresh(db_engine, world)

    assert cards(db_engine) == []


def test_another_owners_site_never_matches(db_engine: Engine, world: World) -> None:
    stranger = uuid4()
    add(db_engine, Profile(id=stranger))
    theirs = Domain(
        owner_id=stranger,
        hostname="other.example",
        verify_token="t",  # noqa: S106
        verified_at=utc_now(),
    )
    add(db_engine, theirs)
    add(
        db_engine,
        DomainBackend(domain_id=theirs.id, kind=BaasKind.SUPABASE, identifier=REF),
        repo_key(world),
    )

    refresh(db_engine, world)
    with Session(db_engine) as session:
        refresh_correlations(session, stranger)
        session.commit()

    assert cards(db_engine) == []
    assert links(db_engine) == []


def test_an_unverified_site_never_matches(db_engine: Engine) -> None:
    unverified = seed(db_engine)
    add(db_engine, site_backend(unverified), repo_key(unverified))

    refresh(db_engine, unverified)

    assert cards(db_engine) == []


def test_a_site_that_loses_verification_loses_its_card(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    refresh(db_engine, world)
    assert len(cards(db_engine)) == 1

    with Session(db_engine) as session:
        session.get_one(Domain, world.domain).verified_at = None
        session.commit()
    refresh(db_engine, world)

    assert cards(db_engine) == []


def test_the_originals_are_not_changed(db_engine: Engine, world: World) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)

    refresh(db_engine, world)

    with Session(db_engine) as session:
        saved = session.get_one(FindingRecord, key.id)
    assert saved.severity is Severity.CRITICAL
    assert saved.title == "t"
    assert saved.evidence_masked == "****"


def test_refreshing_twice_changes_nothing_but_the_last_seen(
    db_engine: Engine, world: World
) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)
    refresh(db_engine, world)
    first = only_card(db_engine)

    refresh(db_engine, world)

    again = only_card(db_engine)
    assert again.id == first.id
    assert again.first_seen_at == first.first_seen_at
    assert members_of(db_engine, again.id) == {key.id}
    assert len(links(db_engine)) == 1


# --- the site's own finding ---


def test_the_sites_own_finding_sits_under_the_card(db_engine: Engine, world: World) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)
    site_finding = site_scan(db_engine, world)

    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == {key.id, site_finding}


def test_only_the_latest_full_scan_counts(db_engine: Engine, world: World) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)
    site_scan(db_engine, world, minutes=-5)
    newest = site_scan(db_engine, world, minutes=5)

    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == {key.id, newest}


def test_a_new_scan_replaces_the_sites_finding_on_an_open_card(
    db_engine: Engine, world: World
) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)
    old = site_scan(db_engine, world, minutes=-5)
    refresh(db_engine, world)
    assert old in members_of(db_engine, only_card(db_engine).id)

    newest = site_scan(db_engine, world, minutes=5)
    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == {key.id, newest}


def test_a_site_key_for_another_project_is_not_listed(db_engine: Engine, world: World) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)
    site_scan(db_engine, world, ref=OTHER)

    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == {key.id}


def test_a_key_on_the_site_counts_as_the_site_using_that_project(
    db_engine: Engine, world: World
) -> None:
    add(db_engine, repo_key(world))
    site_scan(db_engine, world)

    refresh(db_engine, world)

    assert only_card(db_engine).identifier == REF


# --- rotation ---


def test_a_rotated_key_is_not_raised_again(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    refresh(db_engine, world)
    mark_rotated(db_engine, world)

    refresh(db_engine, world)

    assert only_card(db_engine).rotated_at is not None


def test_a_new_fingerprint_after_rotation_opens_a_new_card(db_engine: Engine, world: World) -> None:
    old_key = repo_key(world, "a")
    add(db_engine, site_backend(world), old_key)
    refresh(db_engine, world)
    mark_rotated(db_engine, world)

    new_key = repo_key(world, "b")
    add(db_engine, new_key)
    refresh(db_engine, world)

    found = cards(db_engine)
    assert len(found) == 2
    rotated = next(card for card in found if card.rotated_at is not None)
    still_open = next(card for card in found if card.rotated_at is None)
    assert members_of(db_engine, rotated.id) == {old_key.id}
    assert members_of(db_engine, still_open.id) == {new_key.id}


def test_every_earlier_rotation_counts_as_covered(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world, "a"))
    refresh(db_engine, world)
    mark_rotated(db_engine, world)
    add(db_engine, repo_key(world, "b"))
    refresh(db_engine, world)
    mark_rotated(db_engine, world)

    refresh(db_engine, world)

    assert len(cards(db_engine)) == 2
    assert all(card.rotated_at is not None for card in cards(db_engine))


def test_a_rotated_card_survives_losing_its_match(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    refresh(db_engine, world)
    mark_rotated(db_engine, world)

    with Session(db_engine) as session:
        session.get_one(Domain, world.domain).verified_at = None
        session.commit()
    refresh(db_engine, world)

    assert only_card(db_engine).rotated_at is not None


def test_a_rotated_cards_list_is_not_touched_by_a_new_scan(db_engine: Engine, world: World) -> None:
    key = repo_key(world)
    add(db_engine, site_backend(world), key)
    site_finding = site_scan(db_engine, world, minutes=-5)
    refresh(db_engine, world)
    mark_rotated(db_engine, world)

    site_scan(db_engine, world, minutes=5)
    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == {key.id, site_finding}


# --- Firebase ---


def service_account(world: World, project: str = PROJECT) -> FindingRecord:
    return repo_key(world, ref=project, basis=IdentifierBasis.SAME_FILE, rule=PRIVATE)


def test_a_service_account_for_the_sites_project_is_critical(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        site_backend(world, HOST, BaasKind.FIREBASE_RTDB, PROJECT),
        service_account(world),
    )

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.kind is CorrelationKind.FIREBASE_ADMIN
    assert card.severity is Severity.CRITICAL
    assert card.confidence is MatchConfidence.CONFIRMED
    assert card.identifier == PROJECT


def test_a_service_account_for_another_project_makes_no_card(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        site_backend(world, HOST, BaasKind.FIREBASE_RTDB, PROJECT),
        service_account(world, "another-app"),
    )

    refresh(db_engine, world)

    assert cards(db_engine) == []


def test_a_site_with_only_a_project_id_can_still_match(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        DomainFirebaseProject(domain_id=world.domain, project_id=PROJECT),
        service_account(world),
    )

    refresh(db_engine, world)

    assert only_card(db_engine).kind is CorrelationKind.FIREBASE_ADMIN


def test_a_site_with_only_a_project_id_matches_a_repos_config(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        DomainFirebaseProject(domain_id=world.domain, project_id=PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, PROJECT),
    )

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.kind is CorrelationKind.FIREBASE_CONFIG
    assert card.severity is Severity.INFO


def test_database_bucket_and_project_make_one_info_card(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world, HOST, BaasKind.FIREBASE_RTDB, PROJECT),
        site_backend(world, BUCKET, BaasKind.FIREBASE_STORAGE, PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_RTDB, HOST),
        repo_name(world, RepoIdentifierKind.FIREBASE_BUCKET, BUCKET),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, PROJECT),
    )

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.severity is Severity.INFO
    assert card.identifier == PROJECT


def test_a_config_match_without_a_known_project_uses_the_host(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        site_backend(world, HOST, BaasKind.FIREBASE_RTDB),
        repo_name(world, RepoIdentifierKind.FIREBASE_RTDB, HOST),
    )

    refresh(db_engine, world)

    assert only_card(db_engine).identifier == HOST


def test_an_admin_key_replaces_the_info_card_for_that_project(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        site_backend(world, HOST, BaasKind.FIREBASE_RTDB, PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, PROJECT),
        service_account(world),
    )

    refresh(db_engine, world)

    assert only_card(db_engine).kind is CorrelationKind.FIREBASE_ADMIN


def web_key(world: World) -> FindingRecord:
    return repo_key(world, "w", ref=None, basis=None, rule=WEB_KEY)


def test_a_web_key_is_listed_when_the_repo_names_one_project(
    db_engine: Engine, world: World
) -> None:
    key = web_key(world)
    add(
        db_engine,
        DomainFirebaseProject(domain_id=world.domain, project_id=PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, PROJECT),
        key,
    )

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.severity is Severity.INFO
    assert members_of(db_engine, card.id) == {key.id}


def test_a_web_key_is_not_listed_when_the_repo_names_two_projects(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        DomainFirebaseProject(domain_id=world.domain, project_id=PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, "another-app"),
        web_key(world),
    )

    refresh(db_engine, world)

    assert members_of(db_engine, only_card(db_engine).id) == set()


# --- links ---


def test_a_matching_repo_and_site_get_a_suggested_link(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world),
        repo_name(world, RepoIdentifierKind.SUPABASE_REF, REF),
    )

    refresh(db_engine, world)

    saved = links(db_engine)[0]
    assert saved.state is LinkState.SUGGESTED
    assert saved.origin is LinkOrigin.AUTOMATIC
    assert (saved.repo_id, saved.domain_id) == (world.repo, world.domain)
    # Naming the same project isn't a leaked key.
    assert cards(db_engine) == []


def test_no_match_means_no_suggestion(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world),
        repo_name(world, RepoIdentifierKind.SUPABASE_REF, OTHER),
    )

    refresh(db_engine, world)

    assert links(db_engine) == []


def test_a_suggestion_is_withdrawn_when_the_match_goes(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), link(world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC))

    refresh(db_engine, world)

    assert links(db_engine) == []


@pytest.mark.parametrize("state", [LinkState.CONFIRMED, LinkState.DISMISSED])
def test_the_owners_answer_is_kept_without_a_match(
    db_engine: Engine, world: World, state: LinkState
) -> None:
    add(db_engine, link(world, state, LinkOrigin.AUTOMATIC))

    refresh(db_engine, world)

    assert links(db_engine)[0].state is state


def test_a_dismissed_link_hides_the_card(db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    refresh(db_engine, world)
    assert len(cards(db_engine)) == 1

    with Session(db_engine) as session:
        session.exec(select(RepoDomainLink)).one().state = LinkState.DISMISSED
        session.commit()
    refresh(db_engine, world)

    assert cards(db_engine) == []
    assert links(db_engine)[0].state is LinkState.DISMISSED


def unattributed(world: World) -> FindingRecord:
    return repo_key(world, ref=None, basis=None, rule=SECRET)


def test_a_confirmed_link_attributes_a_key_as_likely(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world),
        unattributed(world),
        link(world, LinkState.CONFIRMED),
    )

    refresh(db_engine, world)

    card = only_card(db_engine)
    assert card.identifier == REF
    assert card.confidence is MatchConfidence.LIKELY


def test_a_confirmed_link_never_guesses_between_two_projects(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        site_backend(world),
        site_backend(world, OTHER),
        unattributed(world),
        link(world, LinkState.CONFIRMED),
    )

    refresh(db_engine, world)

    assert cards(db_engine) == []


def test_a_suggested_link_attributes_nothing(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world),
        unattributed(world),
        repo_name(world, RepoIdentifierKind.SUPABASE_REF, REF),
        link(world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC),
    )

    refresh(db_engine, world)

    assert cards(db_engine) == []


def test_a_confirmed_link_does_not_move_a_key_tied_to_another_project(
    db_engine: Engine, world: World
) -> None:
    add(
        db_engine,
        site_backend(world),
        repo_key(world, ref=OTHER),
        link(world, LinkState.CONFIRMED),
    )

    refresh(db_engine, world)

    assert cards(db_engine) == []


# --- no outbound requests ---


def test_correlation_makes_no_outbound_requests(
    db_engine: Engine, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("correlation tried to reach outside the database")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(safe_http, "safe_get", refuse)
    monkeypatch.setattr(safe_http, "safe_api_request", refuse)
    add(db_engine, site_backend(world), repo_key(world))

    refresh(db_engine, world)

    assert len(cards(db_engine)) == 1


def test_the_module_has_no_way_to_reach_the_network() -> None:
    source = Path(correlation.__file__).read_text(encoding="utf-8")

    for name in ("httpx", "safe_http", "subprocess", "socket", "requests"):
        assert f"import {name}" not in source
        assert f"from app.core.{name}" not in source


# --- from the worker ---


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeScanner:
    scanner_fake = FakeScanner()
    monkeypatch.setattr(tasks, "scan_repository", scanner_fake)
    return scanner_fake


def verified_site(engine: Engine, owner: UUID) -> None:
    domain = Domain(
        owner_id=owner,
        hostname="example.com",
        verify_token="t",  # noqa: S106
        verified_at=utc_now(),
    )
    add(engine, domain)
    add(engine, DomainBackend(domain_id=domain.id, kind=BaasKind.SUPABASE, identifier=REF))


def leaked_hit() -> Any:
    return replace(
        hit(),
        rule_id=SERVICE,
        backend_identifier=REF,
        identifier_basis=IdentifierBasis.KEY_CLAIM,
    )


def test_a_repo_scan_refreshes_the_combined_findings(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = flow_seed(db_engine)
    verified_site(db_engine, seeded.owner)
    fake.result = result(leaked_hit())

    run_repo_scan(str(add_scan(db_engine, seeded)))

    assert only_card(db_engine).identifier == REF


def test_a_failed_refresh_does_not_fail_the_scan(
    db_engine: Engine, fake: FakeScanner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("database went away")

    monkeypatch.setattr(tasks, "refresh_correlations", boom)
    seeded = flow_seed(db_engine)
    fake.result = result(leaked_hit())

    scan_id = add_scan(db_engine, seeded)
    run_repo_scan(str(scan_id))

    with Session(db_engine) as session:
        assert session.get_one(Scan, scan_id).status is ScanJobStatus.DONE
