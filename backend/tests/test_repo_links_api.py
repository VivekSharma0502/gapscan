"""Linking repos to sites through the API, and answering suggestions."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session

from app.api import repo_links
from app.checks.base import Severity
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.main import app
from app.models import Domain, Profile, RepoDomainLink
from app.models.correlation import LinkOrigin, LinkState, MatchConfidence
from app.models.scan import IdentifierBasis, utc_now
from tests.test_correlation import (
    SECRET,
    add,
    cards,
    link,
    links,
    only_card,
    repo_key,
    site_backend,
)
from tests.test_correlation_models import World, seed


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


def stranger(engine: Engine) -> UUID:
    person = uuid4()
    add(engine, Profile(id=person))
    return person


def stranger_domain(engine: Engine, person: UUID) -> UUID:
    domain = Domain(
        owner_id=person,
        hostname="other.example",
        verify_token="t",  # noqa: S106
        verified_at=utc_now(),
    )
    add(engine, domain)
    return domain.id


def create(client: TestClient, repo: UUID, domain: UUID) -> Any:
    return client.post("/api/repo-links", json={"repo_id": str(repo), "domain_id": str(domain)})


def unverify(engine: Engine, world: World) -> None:
    with Session(engine) as session:
        session.get_one(Domain, world.domain).verified_at = None
        session.commit()


def saved(engine: Engine) -> RepoDomainLink:
    found = links(engine)
    assert len(found) == 1
    return found[0]


def add_link(engine: Engine, world: World, state: LinkState, origin: LinkOrigin) -> UUID:
    row = link(world, state, origin)
    add(engine, row)
    return row.id


def answer(client: TestClient, link_id: UUID, state: str) -> Any:
    return client.patch(f"/api/repo-links/{link_id}", json={"state": state})


# --- listing ---


def test_listing_needs_a_sign_in(client: TestClient) -> None:
    assert client.get("/api/repo-links").status_code == 401


def test_listing_names_both_sides(client: TestClient, db_engine: Engine, world: World) -> None:
    link_id = add_link(db_engine, world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)

    body = client.get("/api/repo-links").json()

    assert len(body) == 1
    assert body[0]["id"] == str(link_id)
    assert body[0]["repo_full_name"] == "me/project"
    assert body[0]["hostname"] == "example.com"
    assert body[0]["state"] == "suggested"
    assert body[0]["origin"] == "automatic"


def test_listing_shows_only_your_own(client: TestClient, db_engine: Engine, world: World) -> None:
    add_link(db_engine, world, LinkState.CONFIRMED, LinkOrigin.MANUAL)
    sign_in(stranger(db_engine))

    assert client.get("/api/repo-links").json() == []


# --- linking by hand ---


def test_linking_by_hand_is_confirmed_and_manual(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    sign_in(world.owner)

    response = create(client, world.repo, world.domain)

    assert response.status_code == 200
    assert response.json()["state"] == "confirmed"
    row = saved(db_engine)
    assert row.state is LinkState.CONFIRMED
    assert row.origin is LinkOrigin.MANUAL
    assert row.owner_id == world.owner


def test_someone_elses_repo_cannot_be_linked(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    person = stranger(db_engine)
    theirs = stranger_domain(db_engine, person)
    sign_in(person)

    assert create(client, world.repo, theirs).status_code == 404
    assert links(db_engine) == []


def test_someone_elses_domain_cannot_be_linked(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    theirs = stranger_domain(db_engine, stranger(db_engine))
    sign_in(world.owner)

    assert create(client, world.repo, theirs).status_code == 404
    assert links(db_engine) == []


def test_an_unverified_domain_cannot_be_linked(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    unverify(db_engine, world)
    sign_in(world.owner)

    assert create(client, world.repo, world.domain).status_code == 403
    assert links(db_engine) == []


@pytest.mark.parametrize("state", [LinkState.SUGGESTED, LinkState.DISMISSED])
def test_linking_an_existing_pair_updates_its_one_row(
    client: TestClient, db_engine: Engine, world: World, state: LinkState
) -> None:
    add_link(db_engine, world, state, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)

    assert create(client, world.repo, world.domain).status_code == 200

    row = saved(db_engine)
    assert row.state is LinkState.CONFIRMED
    assert row.origin is LinkOrigin.AUTOMATIC


@pytest.mark.parametrize(
    "body",
    [
        {"repo_id": "not-a-uuid", "domain_id": str(uuid4())},
        {"repo_id": str(uuid4())},
        {"repo_id": str(uuid4()), "domain_id": str(uuid4()), "owner_id": str(uuid4())},
    ],
)
def test_bad_input_is_refused(client: TestClient, world: World, body: dict[str, str]) -> None:
    sign_in(world.owner)

    assert client.post("/api/repo-links", json=body).status_code == 422


def test_a_link_alone_makes_no_finding(client: TestClient, db_engine: Engine, world: World) -> None:
    add(db_engine, site_backend(world))
    sign_in(world.owner)

    create(client, world.repo, world.domain)

    assert cards(db_engine) == []


# --- answering ---


def test_dismissing_hides_the_combined_finding(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    link_id = add_link(db_engine, world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)
    create(client, world.repo, world.domain)
    assert len(cards(db_engine)) == 1

    response = answer(client, link_id, "dismissed")

    assert response.status_code == 200
    assert saved(db_engine).state is LinkState.DISMISSED
    assert cards(db_engine) == []


def test_confirming_lets_the_link_name_a_keys_project_as_likely(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    add(db_engine, site_backend(world), repo_key(world, ref=None, basis=None, rule=SECRET))
    link_id = add_link(db_engine, world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)

    answer(client, link_id, "confirmed")

    card = only_card(db_engine)
    assert card.confidence is MatchConfidence.LIKELY
    assert card.severity is Severity.CRITICAL


def test_a_confirmed_link_does_not_make_a_guess_confirmed(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    add(db_engine, site_backend(world), repo_key(world, basis=IdentifierBasis.ONLY_PROJECT))
    sign_in(world.owner)

    create(client, world.repo, world.domain)

    assert only_card(db_engine).confidence is MatchConfidence.LIKELY


@pytest.mark.parametrize("state", ["suggested", "nonsense", ""])
def test_only_real_answers_are_accepted(
    client: TestClient, db_engine: Engine, world: World, state: str
) -> None:
    link_id = add_link(db_engine, world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)

    assert answer(client, link_id, state).status_code == 422


def test_someone_elses_link_cannot_be_answered(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    link_id = add_link(db_engine, world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC)
    sign_in(stranger(db_engine))

    assert answer(client, link_id, "confirmed").status_code == 404
    assert saved(db_engine).state is LinkState.SUGGESTED


def test_confirming_needs_a_verified_domain(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    link_id = add_link(db_engine, world, LinkState.DISMISSED, LinkOrigin.MANUAL)
    unverify(db_engine, world)
    sign_in(world.owner)

    assert answer(client, link_id, "confirmed").status_code == 403
    assert saved(db_engine).state is LinkState.DISMISSED


def test_dismissing_works_on_an_unverified_domain(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    link_id = add_link(db_engine, world, LinkState.CONFIRMED, LinkOrigin.MANUAL)
    unverify(db_engine, world)
    sign_in(world.owner)

    assert answer(client, link_id, "dismissed").status_code == 200
    assert saved(db_engine).state is LinkState.DISMISSED


# --- removing ---


def test_removing_a_link(client: TestClient, db_engine: Engine, world: World) -> None:
    link_id = add_link(db_engine, world, LinkState.CONFIRMED, LinkOrigin.MANUAL)
    sign_in(world.owner)

    assert client.delete(f"/api/repo-links/{link_id}").status_code == 204
    assert links(db_engine) == []


def test_removing_a_dismissal_brings_back_the_suggestion_and_card(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    add(db_engine, site_backend(world), repo_key(world))
    link_id = add_link(db_engine, world, LinkState.DISMISSED, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)

    client.delete(f"/api/repo-links/{link_id}")

    assert saved(db_engine).state is LinkState.SUGGESTED
    assert len(cards(db_engine)) == 1


def test_someone_elses_link_cannot_be_removed(
    client: TestClient, db_engine: Engine, world: World
) -> None:
    link_id = add_link(db_engine, world, LinkState.CONFIRMED, LinkOrigin.MANUAL)
    sign_in(stranger(db_engine))

    assert client.delete(f"/api/repo-links/{link_id}").status_code == 404
    assert len(links(db_engine)) == 1


# --- staying safe ---


def test_the_answer_is_kept_if_the_refresh_fails(
    client: TestClient,
    db_engine: Engine,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise SQLAlchemyError("database went away")

    monkeypatch.setattr(repo_links, "refresh_correlations", boom)
    sign_in(world.owner)

    assert create(client, world.repo, world.domain).status_code == 200
    assert saved(db_engine).state is LinkState.CONFIRMED


def test_changes_are_rate_limited(client: TestClient, db_engine: Engine, world: World) -> None:
    link_id = add_link(db_engine, world, LinkState.SUGGESTED, LinkOrigin.AUTOMATIC)
    sign_in(world.owner)

    codes = [answer(client, link_id, "dismissed").status_code for _ in range(31)]

    assert codes[:30] == [200] * 30
    assert codes[30] == 429


def test_the_routes_have_no_way_to_reach_the_network() -> None:
    source = Path(repo_links.__file__).read_text(encoding="utf-8")

    for name in ("httpx", "safe_http", "github_app", "subprocess"):
        assert name not in source
