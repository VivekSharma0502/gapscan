"""Reading combined findings through the API, and marking a key as rotated."""

from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select

from app.api import combined_findings, repo_links
from app.checks.base import Severity
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.main import app
from app.models import Domain, DomainFirebaseProject, Profile, RepoDomainLink, Scan
from app.models.correlation import (
    CorrelationKind,
    LinkState,
    MatchConfidence,
    RepoIdentifierKind,
)
from app.models.scan import IdentifierBasis, ScanJobStatus, ScanMode, TargetType, utc_now
from app.repos.combined_guides import HISTORY_DOCS_URL, combined_title, guide_for
from app.workers.tasks import initial_full_progress, initial_quick_progress
from tests.test_correlation import (
    PROJECT,
    add,
    cards,
    only_card,
    refresh,
    repo_key,
    repo_name,
    site_backend,
    site_scan,
)
from tests.test_correlation_models import REF, World, seed

URL = "/api/combined-findings"


@pytest.fixture
def world(db_engine: Engine) -> World:
    seeded = seed(db_engine)
    with Session(db_engine) as session:
        session.get_one(Domain, seeded.domain).verified_at = utc_now()
        session.commit()
    return seeded


@pytest.fixture
def client(db_engine: Engine) -> Iterator[TestClient]:
    limiter.reset()
    yield TestClient(app)
    limiter.reset()
    app.dependency_overrides.clear()


def sign_in(viewer_id: UUID) -> None:
    viewer = Viewer(id=viewer_id, email="person@example.com", name=None)
    app.dependency_overrides[get_viewer] = lambda: viewer


def leak(engine: Engine, world: World, **key: Any) -> None:
    add(engine, site_backend(world), repo_key(world, **key))
    refresh(engine, world)


def config_match(engine: Engine, world: World) -> None:
    add(
        engine,
        DomainFirebaseProject(domain_id=world.domain, project_id=PROJECT),
        repo_name(world, RepoIdentifierKind.FIREBASE_PROJECT, PROJECT),
    )
    refresh(engine, world)


def listed(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    return client.get(URL, params=params).json()


def rotate(client: TestClient, card_id: UUID) -> Any:
    return client.post(f"{URL}/{card_id}/rotated")


# --- reading ---


def test_needs_a_sign_in(client: TestClient) -> None:
    assert client.get(URL).status_code == 401


def test_a_confirmed_leak_says_so_and_how_to_fix_it(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)

    card = listed(client)[0]

    assert card["title"] == "Your site's backend admin key is leaked in me/project"
    assert card["severity"] == "critical"
    assert card["confidence"] == "confirmed"
    assert "counted once per project" in card["note"]
    assert card["hostname"] == "example.com"
    assert card["repo_full_name"] == "me/project"
    assert card["identifier"] == REF
    assert card["can_mark_rotated"] is True
    assert any("Settings, then API Keys" in step for step in card["rotate_steps"])
    assert card["history_docs_url"] == HISTORY_DOCS_URL
    assert any(step["command"] for step in card["history_steps"])


def report(
    world: World,
    owner: UUID | None = None,
    note: str | None = "Includes −25",
    **fields: Any,
) -> Scan:
    return Scan(
        owner_id=owner or world.owner,
        domain_id=world.domain,
        target_type=TargetType.WEB,
        target="example.com",
        mode=ScanMode.FULL,
        status=ScanJobStatus.DONE,
        finished_at=utc_now(),
        correlation_note=note,
        progress_json=initial_full_progress(),
        **fields,
    )


NOT_COUNTED = "This scan didn't count it against your score."
STILL_AHEAD = "It stops affecting your score from your next full scan."


def rotated_note(client: TestClient, engine: Engine, world: World, scan: Scan) -> str:
    add(engine, scan)
    return listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]


def test_a_report_after_the_rotation_says_it_was_not_counted(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    rotated_card(client, db_engine, world)

    note = rotated_note(client, db_engine, world, report(world, note=None, score=98))

    assert NOT_COUNTED in note
    assert "next full scan" not in note


def test_a_report_older_than_the_rotation_keeps_the_future_wording(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)
    scan = report(world, score=73)
    add(db_engine, scan)
    rotate(client, only_card(db_engine).id)

    note = listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]

    assert STILL_AHEAD in note
    assert NOT_COUNTED not in note


def test_a_scan_already_running_at_the_rotation_keeps_the_future_wording(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)
    # Created before the rotation and finished after it, so it may have counted the key.
    scan = report(world, score=73)
    add(db_engine, scan)
    rotate(client, only_card(db_engine).id)
    with Session(db_engine) as session:
        session.get_one(Scan, scan.id).finished_at = utc_now()
        session.commit()

    note = listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]

    assert STILL_AHEAD in note


def test_the_repository_page_keeps_the_future_wording(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    rotated_card(client, db_engine, world)

    assert STILL_AHEAD in listed(client, repo_id=world.repo)[0]["note"]


def test_a_report_with_no_score_keeps_the_future_wording(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    rotated_card(client, db_engine, world)

    note = rotated_note(client, db_engine, world, report(world, note=None))

    assert STILL_AHEAD in note


def test_someone_elses_report_keeps_the_future_wording(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    rotated_card(client, db_engine, world)
    other = uuid4()
    add(db_engine, Profile(id=other))

    note = rotated_note(client, db_engine, world, report(world, owner=other, score=98))

    assert STILL_AHEAD in note


def test_a_report_that_deducted_says_so(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    scan = report(world)
    add(db_engine, scan)
    sign_in(world.owner)

    note = listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]

    assert "This scan deducted 25 points" in note
    assert "next full scan" not in note


def test_a_report_with_no_deduction_still_says_next_scan(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    scan = report(world, note=None)
    add(db_engine, scan)
    sign_in(world.owner)

    note = listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]

    assert "Your next full scan deducts" in note


def test_a_report_older_than_the_leak_still_says_next_scan(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    scan = report(world)
    add(db_engine, scan)
    leak(db_engine, world)
    sign_in(world.owner)

    note = listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]

    assert "Your next full scan deducts" in note


def test_someone_elses_report_changes_nothing(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    other = uuid4()
    add(db_engine, Profile(id=other))
    scan = report(world, owner=other)
    add(db_engine, scan)
    sign_in(world.owner)

    note = listed(client, domain_id=world.domain, scan_id=scan.id)[0]["note"]

    assert "Your next full scan deducts" in note


def test_a_likely_leak_is_hedged(client: TestClient, db_engine: Engine, world: World) -> None:
    leak(db_engine, world, basis=IdentifierBasis.ONLY_PROJECT)
    sign_in(world.owner)

    card = listed(client)[0]

    assert card["title"] == "Your site's backend admin key may be leaked in me/project"
    assert card["severity"] == "critical"
    assert card["confidence"] == "likely"
    assert "never affects your score" in card["note"]


def test_the_originals_are_listed_masked(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    site_scan(db_engine, world)
    refresh(db_engine, world)
    sign_in(world.owner)

    originals = listed(client)[0]["originals"]

    assert {item["source"] for item in originals} == {"repository", "website"}
    assert {item["masked"] for item in originals} == {"****", "eyJ****"}


def test_a_config_match_is_information_with_no_rotate_option(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    config_match(db_engine, world)
    sign_in(world.owner)

    card = listed(client)[0]

    assert card["severity"] == "info"
    assert card["can_mark_rotated"] is False
    assert card["history_steps"] == []
    assert card["history_docs_url"] is None
    assert card["title"] == "me/project uses the same Firebase project as this site"


def test_you_only_see_your_own(client: TestClient, db_engine: Engine, world: World) -> None:
    leak(db_engine, world)
    person = uuid4()
    add(db_engine, Profile(id=person))
    sign_in(person)

    assert listed(client) == []
    assert listed(client, domain_id=world.domain) == []
    assert listed(client, repo_id=world.repo) == []


def test_filtering_by_domain_and_repo(client: TestClient, db_engine: Engine, world: World) -> None:
    leak(db_engine, world)
    sign_in(world.owner)

    assert len(listed(client, domain_id=world.domain)) == 1
    assert len(listed(client, repo_id=world.repo)) == 1
    assert listed(client, domain_id=uuid4()) == []
    assert listed(client, repo_id=uuid4()) == []


def test_bad_filters_are_refused(client: TestClient, world: World) -> None:
    sign_in(world.owner)

    assert client.get(URL, params={"domain_id": "nope"}).status_code == 422


def test_most_urgent_first_and_rotated_last(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)
    rotate(client, only_card(db_engine).id)
    config_match(db_engine, world)
    add(db_engine, repo_key(world, "b"))
    refresh(db_engine, world)

    order = [(card["severity"], card["rotated_at"] is None) for card in listed(client)]

    assert order[0] == ("critical", True)
    assert order[-2] == ("info", True)
    assert order[-1] == ("info", False)


# --- marking as rotated ---


def test_marking_records_who_and_when_and_drops_to_info(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    card_id = only_card(db_engine).id
    sign_in(world.owner)

    response = rotate(client, card_id)

    assert response.status_code == 200
    body = response.json()
    assert body["severity"] == "info"
    assert body["rotated_at"] is not None
    assert body["can_mark_rotated"] is False
    assert "your answer" in body["note"]
    saved = only_card(db_engine)
    assert saved.rotated_by == world.owner
    assert saved.severity is Severity.INFO


def test_the_history_reminder_stays_after_rotating(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)

    body = rotate(client, only_card(db_engine).id).json()

    assert body["history_steps"]
    assert body["history_docs_url"] == HISTORY_DOCS_URL


def test_the_same_finding_is_not_raised_again(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)
    rotate(client, only_card(db_engine).id)

    refresh(db_engine, world)

    assert only_card(db_engine).rotated_at is not None


def test_a_new_fingerprint_raises_a_new_finding(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)
    rotate(client, only_card(db_engine).id)

    add(db_engine, repo_key(world, "b"))
    refresh(db_engine, world)

    severities = sorted(card.severity.value for card in cards(db_engine))
    assert severities == ["critical", "info"]


def test_marking_twice_keeps_the_first_answer(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    card_id = only_card(db_engine).id
    sign_in(world.owner)
    first = rotate(client, card_id).json()["rotated_at"]

    second = rotate(client, card_id)

    assert second.status_code == 200
    assert second.json()["rotated_at"] == first


def test_someone_elses_finding_cannot_be_marked(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    person = uuid4()
    add(db_engine, Profile(id=person))
    sign_in(person)

    assert rotate(client, only_card(db_engine).id).status_code == 404
    assert only_card(db_engine).rotated_at is None


def test_an_unknown_finding_is_a_404(client: TestClient, world: World) -> None:
    sign_in(world.owner)

    assert rotate(client, uuid4()).status_code == 404


def test_a_config_match_cannot_be_marked(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    config_match(db_engine, world)
    sign_in(world.owner)

    assert rotate(client, only_card(db_engine).id).status_code == 409
    assert only_card(db_engine).rotated_at is None


def test_the_answer_is_kept_if_the_refresh_fails(
    client: TestClient,
    db_engine: Engine,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise SQLAlchemyError("database went away")

    monkeypatch.setattr(repo_links, "refresh_correlations", boom)

    assert rotate(client, only_card(db_engine).id).status_code == 200
    assert only_card(db_engine).rotated_at is not None


def test_marking_is_rate_limited(client: TestClient, db_engine: Engine, world: World) -> None:
    leak(db_engine, world)
    card_id = only_card(db_engine).id
    sign_in(world.owner)

    codes = [rotate(client, card_id).status_code for _ in range(31)]

    assert codes[30] == 429


def test_a_dismissed_pair_hides_its_history_too(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)
    rotate(client, only_card(db_engine).id)
    with Session(db_engine) as session:
        session.exec(select(RepoDomainLink)).one().state = LinkState.DISMISSED
        session.commit()

    assert listed(client) == []


# --- where the card can appear ---


def add_scan(engine: Engine, world: World, mode: ScanMode, owner: UUID | None) -> UUID:
    progress = initial_full_progress() if mode is ScanMode.FULL else initial_quick_progress()
    scan = Scan(
        owner_id=owner,
        domain_id=world.domain,
        target_type=TargetType.WEB,
        target="example.com",
        mode=mode,
        status=ScanJobStatus.DONE,
        progress_json=progress,
    )
    add(engine, scan)
    return scan.id


def test_a_full_report_tells_its_owner_which_domain(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    scan_id = add_scan(db_engine, world, ScanMode.FULL, world.owner)
    sign_in(world.owner)

    assert client.get(f"/api/scans/{scan_id}").json()["domain_id"] == str(world.domain)


def test_a_quick_report_never_names_a_domain(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    scan_id = add_scan(db_engine, world, ScanMode.QUICK, world.owner)
    sign_in(world.owner)

    assert client.get(f"/api/scans/{scan_id}").json()["domain_id"] is None


def test_an_anonymous_report_never_names_a_domain(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    scan_id = add_scan(db_engine, world, ScanMode.QUICK, None)

    assert client.get(f"/api/scans/{scan_id}").json()["domain_id"] is None


# --- the guides ---


@pytest.mark.parametrize("kind", list(CorrelationKind))
def test_every_kind_has_a_guide_with_official_links(kind: CorrelationKind) -> None:
    guide = guide_for(kind)

    assert guide.rotate_steps
    hosts = {urlsplit(guide.rotate_url).hostname, urlsplit(guide.docs_url).hostname}
    assert hosts <= {
        "supabase.com",
        "console.firebase.google.com",
        "firebase.google.com",
        "docs.cloud.google.com",
    }


@pytest.mark.parametrize("kind", [CorrelationKind.SUPABASE_ADMIN, CorrelationKind.FIREBASE_ADMIN])
def test_admin_guides_say_to_replace_the_key_before_cleaning_history(
    kind: CorrelationKind,
) -> None:
    guide = guide_for(kind)

    assert "Replace the key first" in guide.history_steps[0].text
    assert "Replace the key first" in guide.what_it_means


def test_the_purge_command_uses_githubs_safe_flag() -> None:
    commands = [
        step.command
        for step in guide_for(CorrelationKind.SUPABASE_ADMIN).history_steps
        if step.command
    ]

    assert "--sensitive-data-removal" in commands[0]
    assert commands[1] == "git push --force --mirror origin"


def test_a_likely_title_is_hedged() -> None:
    confirmed = combined_title(
        CorrelationKind.FIREBASE_ADMIN, MatchConfidence.CONFIRMED, "me/project"
    )
    likely = combined_title(CorrelationKind.FIREBASE_ADMIN, MatchConfidence.LIKELY, "me/project")

    assert " is leaked" in confirmed
    assert " may be leaked" in likely


# --- reopening ---


def reopen(client: TestClient, card_id: UUID) -> Any:
    return client.post(f"{URL}/{card_id}/reopen")


def rotated_card(client: TestClient, engine: Engine, world: World, **key: Any) -> UUID:
    leak(engine, world, **key)
    sign_in(world.owner)
    card_id = only_card(engine).id
    rotate(client, card_id)
    return card_id


def test_reopening_records_who_and_when_and_restores_critical(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    card_id = rotated_card(client, db_engine, world)

    response = reopen(client, card_id)

    assert response.status_code == 200
    body = response.json()
    assert body["severity"] == "critical"
    assert body["rotated_at"] is None
    assert body["reopened_at"] is not None
    assert body["can_mark_rotated"] is True
    assert body["can_reopen"] is False
    saved = only_card(db_engine)
    assert saved.reopened_by == world.owner
    assert saved.rotated_by is None


def test_a_rotated_card_offers_reopening(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    rotated_card(client, db_engine, world)

    assert listed(client)[0]["can_reopen"] is True


def test_who_reopened_is_not_sent_to_the_browser(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    card_id = rotated_card(client, db_engine, world)

    body = reopen(client, card_id).json()

    assert "reopened_by" not in body
    assert "rotated_by" not in body


def test_a_reopened_card_can_be_marked_rotated_again(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    card_id = rotated_card(client, db_engine, world)
    reopen(client, card_id)

    body = rotate(client, card_id).json()

    assert body["severity"] == "info"
    assert only_card(db_engine).rotated_by == world.owner


def test_reopening_an_open_card_changes_nothing(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    leak(db_engine, world)
    sign_in(world.owner)

    response = reopen(client, only_card(db_engine).id)

    assert response.status_code == 200
    assert only_card(db_engine).reopened_at is None


def test_someone_elses_finding_cannot_be_reopened(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    card_id = rotated_card(client, db_engine, world)
    person = uuid4()
    add(db_engine, Profile(id=person))
    sign_in(person)

    assert reopen(client, card_id).status_code == 404
    assert only_card(db_engine).rotated_at is not None


def test_reopening_joins_a_card_already_open_for_that_project(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    card_id = rotated_card(client, db_engine, world)
    add(db_engine, repo_key(world, "b"))
    refresh(db_engine, world)
    assert len(cards(db_engine)) == 2

    body = reopen(client, card_id).json()

    saved = only_card(db_engine)
    assert saved.rotated_at is None
    assert saved.reopened_by == world.owner
    assert body["id"] == str(saved.id)
    assert len(body["originals"]) == 2


def test_a_card_that_no_longer_matches_stays_rotated(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    card_id = rotated_card(client, db_engine, world)
    with Session(db_engine) as session:
        session.get_one(Domain, world.domain).verified_at = None
        session.commit()

    assert reopen(client, card_id).status_code == 409

    saved = only_card(db_engine)
    assert saved.rotated_at is not None
    assert saved.reopened_at is None


def test_a_failed_reopen_leaves_the_card_rotated(
    client: TestClient,
    db_engine: Engine,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    card_id = rotated_card(client, db_engine, world)

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise SQLAlchemyError("database went away")

    monkeypatch.setattr(combined_findings, "refresh_correlations", boom)

    assert reopen(client, card_id).status_code == 503
    saved = only_card(db_engine)
    assert saved.rotated_at is not None
    assert saved.reopened_at is None
