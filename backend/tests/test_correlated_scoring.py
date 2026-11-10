"""How a leaked repo key changes a site's score, and that it's never counted twice."""

from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    ExposedServiceKey,
    ScanContext,
    Severity,
)
from app.checks.registry import make_finding
from app.checks.runner import run_checks
from app.checks.scoring import (
    LEAK_CAP_REASON,
    CorrelatedLeak,
    calculate_score,
    correlation_note,
    counted_leaks,
    final_grade,
)
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.main import app
from app.models import CorrelatedFinding, Domain, FindingRecord, Scan
from app.models.correlation import CorrelationKind, MatchConfidence
from app.models.scan import IdentifierBasis, ScanMode, TargetType, utc_now
from app.workers import tasks
from app.workers.tasks import initial_full_progress, run_full_scan
from tests.checks.test_runner import healthy
from tests.test_check_backends import BLOCKED, PROVEN, proof
from tests.test_correlation import (
    PROJECT,
    add,
    mark_rotated,
    only_card,
    refresh,
    repo_key,
    site_backend,
)
from tests.test_correlation_models import REF, World, seed

OTHER = "tsrqponmlkjihgfedcba"
SUPABASE = CorrelatedLeak(REF, supabase=True)
OTHER_SUPABASE = CorrelatedLeak(OTHER, supabase=True)
FIREBASE = CorrelatedLeak(PROJECT, supabase=False)


def site_key(project: str | None) -> Any:
    finding = make_finding("baas.supabase_service_key", Severity.CRITICAL, "eyJ**** in /a.js")
    return finding.model_copy(update={"backend_identifier": project})


# --- the arithmetic ---


def test_no_leaks_changes_nothing() -> None:
    assert calculate_score([]) == 100
    assert final_grade(100, []) == ("A+", None)
    assert correlation_note(set(), set()) is None


def test_a_leak_costs_25_and_caps_the_grade_at_d() -> None:
    leaks = {SUPABASE}

    score = calculate_score([], leaks)

    assert score == 75
    assert final_grade(score, [], leaks) == ("D", f"Capped at D: {LEAK_CAP_REASON}")


def test_the_same_project_listed_many_times_counts_once() -> None:
    # One card per repo, so three repos leaking one project's key arrive as three.
    leaks = [SUPABASE, CorrelatedLeak(REF, supabase=True), CorrelatedLeak(REF, supabase=True)]

    assert counted_leaks(leaks, []) == {SUPABASE}


def test_different_projects_each_count() -> None:
    leaks = counted_leaks([SUPABASE, OTHER_SUPABASE, FIREBASE], [])

    assert calculate_score([], leaks) == 25


def test_the_score_never_goes_below_zero() -> None:
    leaks = {CorrelatedLeak(f"{i:020d}", supabase=True) for i in range(5)}

    assert calculate_score([], leaks) == 0


def test_a_broken_connection_still_caps_at_f() -> None:
    finding = make_finding("tls.no_https", Severity.CRITICAL, "no https")

    grade, reason = final_grade(50, [finding], {SUPABASE})

    assert grade == "F"
    assert "HTTPS" in str(reason)


def test_an_existing_critical_keeps_its_own_reason() -> None:
    finding = site_key(OTHER)

    _, reason = final_grade(75, [finding], {SUPABASE})

    assert reason == f"Capped at D: {finding.title}"


# --- never twice ---


def test_a_key_the_scan_also_found_on_the_site_adds_nothing() -> None:
    findings = [site_key(REF)]

    assert counted_leaks([SUPABASE], findings) == set()


def test_a_site_key_with_no_known_project_adds_nothing() -> None:
    findings = [site_key(None)]

    assert counted_leaks([SUPABASE, OTHER_SUPABASE], findings) == set()


def test_a_site_key_for_another_project_does_not_excuse_this_one() -> None:
    assert counted_leaks([SUPABASE], [site_key(OTHER)]) == {SUPABASE}


def test_a_supabase_key_on_the_site_does_not_excuse_a_firebase_leak() -> None:
    assert counted_leaks([FIREBASE], [site_key(None)]) == {FIREBASE}


# --- explaining it ---


def test_the_note_explains_one_leak() -> None:
    note = correlation_note({SUPABASE}, {SUPABASE})

    assert note is not None
    assert "−25 points" in note
    assert "Each project counts once" in note


def test_the_note_explains_two_leaks() -> None:
    note = correlation_note({SUPABASE, FIREBASE}, {SUPABASE, FIREBASE})

    assert note is not None
    assert "−50 points" in note
    assert "2 leaked" in note


def test_the_note_says_when_a_key_was_only_counted_once() -> None:
    note = correlation_note(set(), {SUPABASE})

    assert note is not None
    assert "−" not in note
    assert "only counted once" in note


# --- through the runner ---


def exposed(project: str) -> BaasDiscovery:
    return BaasDiscovery(
        backends=(),
        exposed_keys=(ExposedServiceKey("eyJ****", "/a.js", project),),
        scripts_total=1,
        scripts_read=1,
        scripts_failed=0,
    )


def test_a_quick_scan_is_never_affected() -> None:
    report = run_checks(healthy())

    assert report.correlation_note is None


def test_the_runner_deducts_once_and_says_so() -> None:
    before = run_checks(healthy(), allow_active=True)

    after = run_checks(healthy(), allow_active=True, correlated_leaks=[SUPABASE, SUPABASE])

    assert before.score is not None
    assert after.score == before.score - 25
    assert after.grade == "D"
    assert after.correlation_note is not None


def test_a_key_on_the_site_and_in_a_repo_costs_the_same_as_on_the_site_alone() -> None:
    site_only = run_checks(healthy(baas=exposed(REF)), allow_active=True)

    both = run_checks(healthy(baas=exposed(REF)), allow_active=True, correlated_leaks=[SUPABASE])

    assert both.score == site_only.score
    assert both.grade == site_only.grade
    assert both.correlation_note is not None
    assert "only counted once" in both.correlation_note


def test_a_site_that_could_not_be_read_gets_no_score_or_note() -> None:
    report = run_checks(
        ScanContext(hostname="example.com"), allow_active=True, correlated_leaks=[SUPABASE]
    )

    assert report.score is None
    assert report.correlation_note is None


# --- through a real full scan ---


@pytest.fixture
def world(db_engine: Engine) -> World:
    seeded = seed(db_engine)
    with Session(db_engine) as session:
        session.get_one(Domain, seeded.domain).verified_at = utc_now()
        session.commit()
    return seeded


@pytest.fixture
def site(monkeypatch: pytest.MonkeyPatch) -> None:
    proof(monkeypatch, PROVEN)

    def unchanged(ctx: ScanContext, *_args: Any) -> ScanContext:
        return ctx

    monkeypatch.setattr(tasks, "collect_context", lambda _target, on_step=None: healthy())
    for name in ("discover_backends", "attach_probes", "probe_backends", "mark_public_tables"):
        monkeypatch.setattr(tasks, name, unchanged)


def full_scan(engine: Engine, world: World) -> Scan:
    scan = Scan(
        owner_id=world.owner,
        domain_id=world.domain,
        target_type=TargetType.WEB,
        target="example.com",
        mode=ScanMode.FULL,
        progress_json=initial_full_progress(),
    )
    add(engine, scan)
    run_full_scan(str(scan.id))
    with Session(engine) as session:
        return session.get_one(Scan, scan.id)


def baseline() -> int:
    score = run_checks(healthy(), allow_active=True).score
    assert score is not None
    return score


def leak(engine: Engine, world: World, **key: Any) -> None:
    add(engine, site_backend(world), repo_key(world, **key))
    refresh(engine, world)


@pytest.mark.usefixtures("site")
def test_a_confirmed_leak_lowers_the_next_full_scan(db_engine: Engine, world: World) -> None:
    leak(db_engine, world)

    scan = full_scan(db_engine, world)

    assert scan.score == baseline() - 25
    assert scan.grade == "D"
    assert scan.grade_cap_reason == f"Capped at D: {LEAK_CAP_REASON}"
    assert "−25 points" in str(scan.correlation_note)


@pytest.mark.usefixtures("site")
def test_many_keys_for_one_project_count_once(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        site_backend(world),
        repo_key(world, "a"),
        repo_key(world, "b"),
        repo_key(world, "c"),
    )
    refresh(db_engine, world)

    assert full_scan(db_engine, world).score == baseline() - 25


@pytest.mark.usefixtures("site")
def test_a_likely_match_has_no_score_effect(db_engine: Engine, world: World) -> None:
    leak(db_engine, world, basis=IdentifierBasis.ONLY_PROJECT)
    assert only_card(db_engine).confidence is MatchConfidence.LIKELY

    scan = full_scan(db_engine, world)

    assert scan.score == baseline()
    assert scan.grade != "D"
    assert scan.correlation_note is None


@pytest.mark.usefixtures("site")
def test_rotate_reopen_rotate_sticks_through_a_full_scan(db_engine: Engine, world: World) -> None:
    leak(db_engine, world)
    card_id = only_card(db_engine).id
    url = f"/api/combined-findings/{card_id}"
    viewer = Viewer(id=world.owner, email="person@example.com", name=None)
    app.dependency_overrides[get_viewer] = lambda: viewer
    limiter.reset()
    client = TestClient(app)

    try:
        assert client.post(f"{url}/rotated").status_code == 200
        assert client.post(f"{url}/reopen").json()["severity"] == "critical"
        reopened_scan = full_scan(db_engine, world)
        assert reopened_scan.score == baseline() - 25

        # The id the report was showing still works, because reopening kept the same card.
        second = client.post(f"{url}/rotated")
        assert second.status_code == 200
        assert second.json()["id"] == str(card_id)

        scan = full_scan(db_engine, world)
        listed = client.get("/api/combined-findings").json()
    finally:
        limiter.reset()
        app.dependency_overrides.clear()

    assert scan.score == baseline()
    assert scan.grade != "D"
    assert scan.correlation_note is None
    assert [(card["id"], card["severity"]) for card in listed] == [(str(card_id), "info")]
    saved = only_card(db_engine)
    assert saved.rotated_at is not None
    assert saved.rotated_by == world.owner


@pytest.mark.usefixtures("site")
def test_a_rotated_key_has_no_score_effect(db_engine: Engine, world: World) -> None:
    leak(db_engine, world)
    mark_rotated(db_engine, world)

    scan = full_scan(db_engine, world)

    assert scan.score == baseline()
    assert scan.correlation_note is None


@pytest.mark.usefixtures("site")
def test_a_firebase_admin_key_counts_too(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        CorrelatedFinding(
            owner_id=world.owner,
            domain_id=world.domain,
            repo_id=world.repo,
            kind=CorrelationKind.FIREBASE_ADMIN,
            severity=Severity.CRITICAL,
            confidence=MatchConfidence.CONFIRMED,
            identifier=PROJECT,
        ),
    )

    assert full_scan(db_engine, world).score == baseline() - 25


@pytest.mark.usefixtures("site")
def test_an_info_card_has_no_score_effect(db_engine: Engine, world: World) -> None:
    add(
        db_engine,
        CorrelatedFinding(
            owner_id=world.owner,
            domain_id=world.domain,
            repo_id=world.repo,
            kind=CorrelationKind.FIREBASE_CONFIG,
            severity=Severity.INFO,
            confidence=MatchConfidence.CONFIRMED,
            identifier=PROJECT,
        ),
    )

    assert full_scan(db_engine, world).score == baseline()


@pytest.mark.usefixtures("site")
def test_another_sites_leak_does_not_count(db_engine: Engine, world: World) -> None:
    other = Domain(
        owner_id=world.owner,
        hostname="other.example",
        verify_token="t",  # noqa: S106
        verified_at=utc_now(),
    )
    add(db_engine, other)
    add(
        db_engine,
        CorrelatedFinding(
            owner_id=world.owner,
            domain_id=other.id,
            repo_id=world.repo,
            kind=CorrelationKind.SUPABASE_ADMIN,
            severity=Severity.CRITICAL,
            confidence=MatchConfidence.CONFIRMED,
            identifier=REF,
        ),
    )

    assert full_scan(db_engine, world).score == baseline()


@pytest.mark.usefixtures("site")
def test_a_saved_scan_is_never_rewritten(db_engine: Engine, world: World) -> None:
    first = full_scan(db_engine, world)
    assert first.score == baseline()

    leak(db_engine, world)

    with Session(db_engine) as session:
        saved = session.get_one(Scan, first.id)
    assert saved.score == baseline()
    assert saved.correlation_note is None
    assert full_scan(db_engine, world).score == baseline() - 25


@pytest.mark.usefixtures("site")
def test_the_combined_finding_is_not_added_to_the_findings(db_engine: Engine, world: World) -> None:
    clean = full_scan(db_engine, world)
    leak(db_engine, world)

    scan = full_scan(db_engine, world)

    def site_findings(scan_id: UUID) -> list[str]:
        with Session(db_engine) as session:
            rows = session.exec(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
            return sorted(row.check_id for row in rows)

    assert site_findings(scan.id) == site_findings(clean.id)


def test_a_scan_with_an_ownership_problem_does_not_look_up_leaks(
    db_engine: Engine, world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)

    def must_not_run(*_args: Any) -> Any:
        raise AssertionError("looked up leaks for a site whose ownership isn't proven")

    monkeypatch.setattr(tasks, "_correlated_leaks", must_not_run)

    scan = full_scan(db_engine, world)

    assert scan.score is None


def test_kinds_are_used_as_expected() -> None:
    # A guard: a new kind of backend must be a deliberate scoring decision.
    assert {BaasKind.SUPABASE, BaasKind.FIREBASE_RTDB, BaasKind.FIREBASE_STORAGE} == set(BaasKind)
