from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, inspect
from sqlmodel import Session

from app.checks.base import Category, Severity
from app.checks.runner import ScanStatus
from app.core.auth import Viewer, get_viewer
from app.main import app
from app.models.domain import Domain
from app.models.profile import Profile
from app.models.scan import (
    FindingRecord,
    Scan,
    ScanClaim,
    ScanJobStatus,
    ScanMode,
    TargetType,
    utc_now,
)

BASE_TIME = utc_now() - timedelta(minutes=2)


@pytest.fixture
def client(db_engine: Engine) -> Iterator[TestClient]:
    yield TestClient(app)
    app.dependency_overrides.clear()


def sign_in(viewer_id: UUID) -> None:
    viewer = Viewer(id=viewer_id, email="person@example.com", name=None)
    app.dependency_overrides[get_viewer] = lambda: viewer


@pytest.fixture
def me(client: TestClient, db_engine: Engine) -> UUID:
    viewer = uuid4()
    ensure_profile(db_engine, viewer)
    sign_in(viewer)
    return viewer


def ensure_profile(engine: Engine, owner: UUID) -> None:
    with Session(engine) as session:
        if session.get(Profile, owner) is None:
            session.add(Profile(id=owner))
            session.commit()


def add_domain(
    engine: Engine, owner: UUID, hostname: str = "example.com", verified: bool = True
) -> UUID:
    ensure_profile(engine, owner)
    with Session(engine) as session:
        domain = Domain(
            owner_id=owner,
            hostname=hostname,
            verify_token="secret-verify-token",  # noqa: S106
            verified_at=utc_now() if verified else None,
            verified_method="dns" if verified else None,
        )
        session.add(domain)
        session.commit()
        return domain.id


def add_scan(engine: Engine, age_order: int = 0, **overrides: Any) -> UUID:
    """A finished complete full scan. A higher age_order is newer."""
    fields: dict[str, Any] = {
        "target_type": TargetType.WEB,
        "target": "example.com",
        "mode": ScanMode.FULL,
        "status": ScanJobStatus.DONE,
        "result_status": ScanStatus.COMPLETE,
        "score": 80,
        "grade": "B",
        "created_at": BASE_TIME + timedelta(seconds=age_order),
    }
    with Session(engine) as session:
        scan = Scan(**(fields | overrides))
        session.add(scan)
        session.commit()
        return scan.id


def add_quick(engine: Engine, age_order: int = 0, **overrides: Any) -> UUID:
    return add_scan(engine, age_order, **({"mode": ScanMode.QUICK} | overrides))


def claim(engine: Engine, scan_id: UUID, viewer_id: UUID | None) -> None:
    with Session(engine) as session:
        session.add(
            ScanClaim(
                scan_id=scan_id,
                token_hash=uuid4().hex,
                claimed_by=viewer_id,
                claimed_at=utc_now() if viewer_id else None,
            )
        )
        session.commit()


def dashboard(client: TestClient) -> Any:
    result = client.get("/api/dashboard")
    assert result.status_code == 200
    return result.json()


def only_card(client: TestClient) -> Any:
    [card] = dashboard(client)["domains"]
    return card


def recent_ids(client: TestClient) -> list[str]:
    return [item["id"] for item in dashboard(client)["recent_scans"]]


# Access


@pytest.mark.parametrize("path", ["/api/dashboard", f"/api/domains/{uuid4()}/scans"])
def test_routes_need_sign_in(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 401


def test_new_account_gets_empty_lists(client: TestClient, me: UUID) -> None:
    assert dashboard(client) == {"domains": [], "recent_scans": []}


def test_only_your_domains_appear(client: TestClient, db_engine: Engine, me: UUID) -> None:
    add_domain(db_engine, uuid4(), "theirs.com")
    add_domain(db_engine, me, "mine.com")

    assert [card["hostname"] for card in dashboard(client)["domains"]] == ["mine.com"]


def test_response_has_no_token_or_findings(client: TestClient, db_engine: Engine, me: UUID) -> None:
    domain_id = add_domain(db_engine, me)
    scan_id = add_scan(db_engine, owner_id=me, domain_id=domain_id)
    with Session(db_engine) as session:
        session.add(
            FindingRecord(
                scan_id=scan_id,
                check_id="exposure.env_file",
                category=Category.EXPOSURE,
                severity=Severity.CRITICAL,
                title="Environment file is publicly readable",
                evidence_masked="/.env defines DATABASE_URL",
            )
        )
        session.commit()

    for text in (
        client.get("/api/dashboard").text,
        client.get(f"/api/domains/{domain_id}/scans").text,
    ):
        assert "secret-verify-token" not in text
        assert "DATABASE_URL" not in text


# Domain cards: verified


def test_verified_card_shows_the_latest_full_scan(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    add_scan(db_engine, 1, owner_id=me, domain_id=domain_id, score=60, grade="C")
    newest = add_scan(db_engine, 2, owner_id=me, domain_id=domain_id, score=90, grade="A")

    card = only_card(client)

    assert card["verified"] is True
    assert card["latest"]["id"] == str(newest)
    assert (card["latest"]["score"], card["latest"]["grade"]) == (90, "A")
    assert card["latest"]["mode"] == "full"
    assert card["last_scan"]["id"] == str(newest)


def test_verified_card_ignores_quick_scans(client: TestClient, db_engine: Engine, me: UUID) -> None:
    domain_id = add_domain(db_engine, me)
    full = add_scan(db_engine, 1, owner_id=me, domain_id=domain_id, score=70, grade="B")
    add_quick(db_engine, 2, owner_id=me, score=99, grade="A+")

    card = only_card(client)

    assert card["latest"]["id"] == str(full)
    assert card["last_scan"]["id"] == str(full)
    assert card["trend"] is None


def test_verified_card_without_scans_is_empty(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    add_domain(db_engine, me)

    card = only_card(client)

    assert (card["latest"], card["last_scan"], card["trend"]) == (None, None, None)


def test_cards_keep_each_domains_scans_apart(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    one = add_domain(db_engine, me, "one.com")
    two = add_domain(db_engine, me, "two.com")
    add_scan(db_engine, 1, owner_id=me, domain_id=one, target="one.com", score=50)
    add_scan(db_engine, 2, owner_id=me, domain_id=one, target="one.com", score=60)
    add_scan(db_engine, 3, owner_id=me, domain_id=two, target="two.com", score=90)

    cards = {card["hostname"]: card for card in dashboard(client)["domains"]}

    assert (cards["one.com"]["latest"]["score"], cards["one.com"]["trend"]) == (60, 10)
    assert (cards["two.com"]["latest"]["score"], cards["two.com"]["trend"]) == (90, None)


def test_failed_attempt_is_last_scan_but_not_latest_result(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    good = add_scan(db_engine, 1, owner_id=me, domain_id=domain_id)
    failed = add_scan(
        db_engine,
        2,
        owner_id=me,
        domain_id=domain_id,
        status=ScanJobStatus.FAILED,
        result_status=None,
        score=None,
        grade=None,
    )

    card = only_card(client)

    assert card["latest"]["id"] == str(good)
    assert card["last_scan"]["id"] == str(failed)
    assert card["last_scan"]["status"] == "failed"


def test_grade_without_a_score_still_counts_as_the_latest_result(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    # A site with no HTTPS can't be read, but its F is real and must not be hidden.
    domain_id = add_domain(db_engine, me)
    add_scan(db_engine, 1, owner_id=me, domain_id=domain_id, score=90, grade="A")
    add_scan(
        db_engine,
        2,
        owner_id=me,
        domain_id=domain_id,
        result_status=ScanStatus.INCOMPLETE,
        score=None,
        grade="F",
    )

    card = only_card(client)

    assert (card["latest"]["grade"], card["latest"]["score"]) == ("F", None)
    assert card["trend"] is None


# Trend


@pytest.mark.parametrize(
    ("previous", "latest", "trend"), [(60, 75, 15), (90, 70, -20), (80, 80, 0)]
)
def test_trend_is_the_change_from_the_previous_scan(
    client: TestClient, db_engine: Engine, me: UUID, previous: int, latest: int, trend: int
) -> None:
    domain_id = add_domain(db_engine, me)
    add_scan(db_engine, 1, owner_id=me, domain_id=domain_id, score=previous)
    add_scan(db_engine, 2, owner_id=me, domain_id=domain_id, score=latest)

    assert only_card(client)["trend"] == trend


def test_trend_only_compares_the_two_newest(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    for order, score in enumerate((10, 50, 55)):
        add_scan(db_engine, order, owner_id=me, domain_id=domain_id, score=score)

    assert only_card(client)["trend"] == 5


@pytest.mark.parametrize("partial_scan", ["latest", "previous"])
def test_no_trend_when_either_scan_is_partial(
    client: TestClient, db_engine: Engine, me: UUID, partial_scan: str
) -> None:
    # Skipped checks can inflate a score, which would show an improvement that didn't happen.
    domain_id = add_domain(db_engine, me)
    add_scan(
        db_engine,
        1,
        owner_id=me,
        domain_id=domain_id,
        score=60,
        result_status=ScanStatus.PARTIAL if partial_scan == "previous" else ScanStatus.COMPLETE,
    )
    add_scan(
        db_engine,
        2,
        owner_id=me,
        domain_id=domain_id,
        score=95,
        result_status=ScanStatus.PARTIAL if partial_scan == "latest" else ScanStatus.COMPLETE,
    )

    assert only_card(client)["trend"] is None


# Domain cards: unverified


def test_unverified_card_shows_the_latest_quick_scan(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    add_domain(db_engine, me, verified=False)
    add_quick(db_engine, 1, owner_id=me, score=40, grade="D")
    newest = add_quick(db_engine, 2, owner_id=me, score=72, grade="B")

    card = only_card(client)

    assert card["verified"] is False
    assert card["latest"]["id"] == str(newest)
    assert card["latest"]["mode"] == "quick"
    assert card["trend"] is None


def test_unverified_card_counts_a_claimed_quick_scan(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    add_domain(db_engine, me, verified=False)
    other = uuid4()
    ensure_profile(db_engine, other)
    scan_id = add_quick(db_engine, 1, owner_id=other)
    claim(db_engine, scan_id, me)

    assert only_card(client)["latest"]["id"] == str(scan_id)


def test_unverified_card_ignores_other_peoples_quick_scans(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    add_domain(db_engine, me, verified=False)
    other = uuid4()
    ensure_profile(db_engine, other)
    add_quick(db_engine, 1, owner_id=other)
    add_quick(db_engine, 2)

    assert only_card(client)["latest"] is None


def test_unverified_card_ignores_full_scans_from_when_it_was_verified(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me, verified=False)
    add_scan(db_engine, 1, owner_id=me, domain_id=domain_id, score=90, grade="A")

    assert only_card(client)["latest"] is None


# Stale scans


def test_stuck_scan_is_reported_failed_without_being_saved(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    scan_id = add_scan(
        db_engine,
        owner_id=me,
        domain_id=domain_id,
        status=ScanJobStatus.RUNNING,
        result_status=None,
        score=None,
        grade=None,
        created_at=utc_now() - timedelta(minutes=6),
    )

    body = dashboard(client)

    assert body["domains"][0]["last_scan"]["status"] == "failed"
    assert body["recent_scans"][0]["status"] == "failed"
    with Session(db_engine) as session:
        assert session.get_one(Scan, scan_id).status is ScanJobStatus.RUNNING


def test_scan_in_progress_stays_running(client: TestClient, db_engine: Engine, me: UUID) -> None:
    domain_id = add_domain(db_engine, me)
    add_scan(
        db_engine,
        owner_id=me,
        domain_id=domain_id,
        status=ScanJobStatus.RUNNING,
        result_status=None,
        score=None,
        grade=None,
        created_at=utc_now() - timedelta(minutes=1),
    )

    assert only_card(client)["last_scan"]["status"] == "running"


# Recent scans


def test_recent_scans_are_newest_first_and_capped(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    ids = [add_quick(db_engine, order, owner_id=me) for order in range(12)]

    assert recent_ids(client) == [str(item) for item in reversed(ids[2:])]


def test_recent_scans_include_claimed_scans(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    other = uuid4()
    ensure_profile(db_engine, other)
    shared = add_quick(db_engine, owner_id=other)
    claim(db_engine, shared, me)

    assert recent_ids(client) == [str(shared)]


def test_scan_with_several_claims_is_listed_once(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    # Each anonymous request for a shared scan gets its own claim, so one user can hold many.
    scan_id = add_quick(db_engine)
    claim(db_engine, scan_id, me)
    claim(db_engine, scan_id, me)

    assert recent_ids(client) == [str(scan_id)]


def test_recent_scans_leave_out_what_you_cant_read(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    other = uuid4()
    ensure_profile(db_engine, other)
    add_quick(db_engine, 1, owner_id=other)
    add_quick(db_engine, 2)
    claim(db_engine, add_quick(db_engine, 3), None)
    claim(db_engine, add_quick(db_engine, 4), other)

    assert recent_ids(client) == []


def test_a_claim_row_never_exposes_a_full_scan(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    # Security: full scans are owner-only, even if a claim row somehow points at one.
    other = uuid4()
    ensure_profile(db_engine, other)
    claim(db_engine, add_scan(db_engine, owner_id=other), me)

    assert recent_ids(client) == []


def test_scans_of_a_deleted_domain_stay_in_recent_scans(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    scan_id = add_scan(db_engine, owner_id=me, domain_id=None)

    body = dashboard(client)

    assert body["domains"] == []
    assert [item["id"] for item in body["recent_scans"]] == [str(scan_id)]


# Scan history


def history(client: TestClient, domain_id: UUID, **params: Any) -> Any:
    result = client.get(f"/api/domains/{domain_id}/scans", params=params)
    assert result.status_code == 200
    return result.json()


def test_someone_elses_history_is_404(client: TestClient, db_engine: Engine, me: UUID) -> None:
    other = uuid4()
    theirs = add_domain(db_engine, other)
    add_scan(db_engine, owner_id=other, domain_id=theirs)

    result = client.get(f"/api/domains/{theirs}/scans")

    assert result.status_code == 404
    assert result.json() == {"detail": "Domain not found."}


def test_unknown_domain_history_is_404(client: TestClient, me: UUID) -> None:
    assert client.get(f"/api/domains/{uuid4()}/scans").status_code == 404


def test_history_is_newest_first_and_paginated(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    ids = [str(add_scan(db_engine, n, owner_id=me, domain_id=domain_id)) for n in range(5)]
    newest_first = list(reversed(ids))

    first = history(client, domain_id, limit=2)
    second = history(client, domain_id, limit=2, offset=2)
    last = history(client, domain_id, limit=2, offset=4)

    assert [item["id"] for item in first["items"]] == newest_first[:2]
    assert [item["id"] for item in second["items"]] == newest_first[2:4]
    assert [item["id"] for item in last["items"]] == newest_first[4:]
    assert (first["total"], first["limit"], first["offset"]) == (5, 2, 0)


def test_history_defaults_to_twenty(client: TestClient, db_engine: Engine, me: UUID) -> None:
    domain_id = add_domain(db_engine, me)
    for order in range(25):
        add_scan(db_engine, order, owner_id=me, domain_id=domain_id)

    body = history(client, domain_id)

    assert (len(body["items"]), body["total"], body["limit"]) == (20, 25, 20)


def test_history_past_the_end_is_empty(client: TestClient, db_engine: Engine, me: UUID) -> None:
    domain_id = add_domain(db_engine, me)
    add_scan(db_engine, owner_id=me, domain_id=domain_id)

    body = history(client, domain_id, offset=10)

    assert (body["items"], body["total"]) == ([], 1)


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"offset": 100_001}, {"limit": "many"}],
)
def test_history_refuses_bad_paging(
    client: TestClient, db_engine: Engine, me: UUID, params: dict[str, Any]
) -> None:
    domain_id = add_domain(db_engine, me)

    assert client.get(f"/api/domains/{domain_id}/scans", params=params).status_code == 422


def test_history_lists_failed_scans_unless_scored_only(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    scored = add_scan(db_engine, 1, owner_id=me, domain_id=domain_id)
    add_scan(
        db_engine,
        2,
        owner_id=me,
        domain_id=domain_id,
        status=ScanJobStatus.FAILED,
        result_status=None,
        score=None,
        grade=None,
    )
    add_scan(
        db_engine,
        3,
        owner_id=me,
        domain_id=domain_id,
        result_status=ScanStatus.INCOMPLETE,
        score=None,
        grade="F",
    )

    assert history(client, domain_id)["total"] == 3
    body = history(client, domain_id, scored_only=True)
    assert [item["id"] for item in body["items"]] == [str(scored)]
    assert body["total"] == 1


def test_history_is_full_scans_only_and_only_yours(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    domain_id = add_domain(db_engine, me)
    other = uuid4()
    ensure_profile(db_engine, other)
    mine = add_scan(db_engine, 1, owner_id=me, domain_id=domain_id)
    add_quick(db_engine, 2, owner_id=me, domain_id=domain_id)
    add_scan(db_engine, 3, owner_id=other, domain_id=domain_id)

    assert [item["id"] for item in history(client, domain_id)["items"]] == [str(mine)]


# Indexes


def test_dashboard_indexes_exist(db_engine: Engine) -> None:
    inspector = inspect(db_engine)

    scans = {index["name"] for index in inspector.get_indexes("scans")}
    claims = {index["name"] for index in inspector.get_indexes("scan_claims")}

    assert {"ix_scans_domain_id_created_at", "ix_scans_owner_id_created_at"} <= scans
    assert "ix_scans_owner_id" not in scans
    assert "ix_scan_claims_claimed_by" in claims
