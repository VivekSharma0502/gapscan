"""Check backends, the 24-hour verification rule, and explicit "Checked" results."""

from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.api import domains as domains_api
from app.checks import active_collector, baas_collector, baas_probes, collector
from app.checks.baas import firebase_rtdb_protected, firebase_storage_protected
from app.checks.base import (
    BaasKind,
    BaasProbes,
    BotProtection,
    RtdbProbe,
    ScanContext,
    Severity,
    StorageProbe,
)
from app.checks.catalog import CATALOG
from app.checks.ownership import (
    FailureCode,
    MethodFailure,
    OwnershipResult,
    VerificationMethod,
)
from app.checks.runner import ScanStatus
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.core.safe_http import SafeResponse
from app.main import app
from app.models.domain import Domain, DomainBackend
from app.models.profile import Profile
from app.models.scan import FindingRecord, Scan, ScanJobStatus, ScanMode, TargetType, utc_now
from app.workers import tasks
from app.workers.tasks import (
    BACKEND_CHECK_IDS,
    initial_backend_progress,
    initial_full_progress,
    run_backend_check,
    run_full_scan,
)
from tests.checks.helpers import response

HOST = "my-app-default-rtdb.firebaseio.com"
BUCKET = "my-app.appspot.com"
HOSTNAME = "example.com"

NO_TXT = MethodFailure(VerificationMethod.DNS, FailureCode.TXT_NOT_FOUND, "no", True)
FILE_BLOCKED = MethodFailure(
    VerificationMethod.FILE, FailureCode.FILE_BLOCKED, "blocked", False, BotProtection.VERCEL
)
FILE_MISMATCH = MethodFailure(VerificationMethod.FILE, FailureCode.FILE_MISMATCH, "wrong", True)
FILE_MISSING = MethodFailure(VerificationMethod.FILE, FailureCode.FILE_MISSING, "gone", True)
FILE_DOWN = MethodFailure(VerificationMethod.FILE, FailureCode.FILE_UNREACHABLE, "down", False)

PROVEN = OwnershipResult(VerificationMethod.FILE)
BLOCKED = OwnershipResult(None, (NO_TXT, FILE_BLOCKED))
WRONG_TOKEN = OwnershipResult(None, (NO_TXT, FILE_MISMATCH))
MISSING = OwnershipResult(None, (NO_TXT, FILE_MISSING))
UNKNOWN = OwnershipResult(None, (NO_TXT, FILE_DOWN))
# A real answer on one name beside a block on the other is not inconclusive.
MIXED = OwnershipResult(None, (NO_TXT, FILE_BLOCKED), (NO_TXT, FILE_MISSING))


class FakeBackends:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.answer: SafeResponse = response(status=401, body=b'{"error":"Permission denied"}')

    def __call__(self, url: str, **_kwargs: Any) -> SafeResponse:
        self.urls.append(url)
        return self.answer


@pytest.fixture
def backends(monkeypatch: pytest.MonkeyPatch) -> FakeBackends:
    fake = FakeBackends()
    monkeypatch.setattr(baas_probes, "safe_get", fake)
    return fake


@pytest.fixture(autouse=True)
def website_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_run(url: str, **_kwargs: Any) -> SafeResponse:
        raise AssertionError(f"the website was contacted: {url}")

    for module in (collector, active_collector, baas_collector):
        monkeypatch.setattr(module, "safe_get", must_not_run)


def proof(monkeypatch: pytest.MonkeyPatch, result: OwnershipResult) -> None:
    monkeypatch.setattr(tasks, "prove_ownership", lambda *_args, **_kwargs: result)


def seed(
    engine: Engine,
    *,
    verified_hours_ago: float | None = 1,
    method: str = "file",
    backends_to_add: tuple[tuple[BaasKind, str, bool], ...] = (
        (BaasKind.FIREBASE_RTDB, HOST, True),
        (BaasKind.FIREBASE_STORAGE, BUCKET, True),
    ),
    owner: UUID | None = None,
) -> tuple[UUID, UUID]:
    owner = owner or uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        domain = Domain(
            owner_id=owner,
            hostname=HOSTNAME,
            verify_token="tok",  # noqa: S106
            verified_at=(
                utc_now() - timedelta(hours=verified_hours_ago)
                if verified_hours_ago is not None
                else None
            ),
            verified_method=method if verified_hours_ago is not None else None,
        )
        session.add(domain)
        session.flush()
        for kind, identifier, confirmed in backends_to_add:
            session.add(
                DomainBackend(
                    domain_id=domain.id,
                    kind=kind,
                    identifier=identifier,
                    confirmed_at=utc_now() if confirmed else None,
                )
            )
        session.commit()
        return owner, domain.id


def add_scan(engine: Engine, owner: UUID, domain: UUID, mode: ScanMode = ScanMode.BACKENDS) -> UUID:
    with Session(engine) as session:
        scan = Scan(
            owner_id=owner,
            domain_id=domain,
            target_type=TargetType.WEB,
            target=HOSTNAME,
            mode=mode,
            progress_json=(
                initial_backend_progress() if mode is ScanMode.BACKENDS else initial_full_progress()
            ),
        )
        session.add(scan)
        session.commit()
        return scan.id


def load_scan(engine: Engine, scan_id: UUID) -> Scan:
    with Session(engine) as session:
        return session.get_one(Scan, scan_id)


def load_domain(engine: Engine, domain_id: UUID) -> Domain:
    with Session(engine) as session:
        return session.get_one(Domain, domain_id)


def findings(engine: Engine, scan_id: UUID) -> dict[str, FindingRecord]:
    with Session(engine) as session:
        rows = session.exec(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
        return {row.check_id: row for row in rows}


def run(engine: Engine, **kwargs: Any) -> tuple[Scan, UUID]:
    owner, domain = seed(engine, **kwargs)
    scan_id = add_scan(engine, owner, domain)
    run_backend_check(str(scan_id))
    return load_scan(engine, scan_id), domain


# --- Check backends ---


def test_probes_confirmed_backends_without_touching_the_website(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)

    scan, _ = run(db_engine)

    assert scan.status is ScanJobStatus.DONE
    assert scan.result_status is ScanStatus.COMPLETE
    assert len(backends.urls) == 2
    assert all("example.com" not in url for url in backends.urls)


def test_has_no_score_or_grade(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    backends.answer = response(body=b'{"users":true}')

    scan, _ = run(db_engine)

    assert (scan.score, scan.grade) == (None, None)


def test_progress_finishes_at_its_total(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)

    scan, _ = run(db_engine)

    assert scan.progress_json["total"] == 2 + len(BACKEND_CHECK_IDS)
    assert scan.progress_json["completed"] == scan.progress_json["total"]


def test_unconfirmed_backends_are_not_contacted(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)

    run(
        db_engine,
        backends_to_add=(
            (BaasKind.FIREBASE_RTDB, HOST, True),
            (BaasKind.FIREBASE_STORAGE, BUCKET, False),
        ),
    )

    assert backends.urls == [f"https://{HOST}/.json?shallow=true"]


def test_open_database_is_critical_here_too(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    backends.answer = response(body=b'{"secret-user-id":true}')

    scan, _ = run(db_engine)

    found = findings(db_engine, scan.id)
    assert found["baas.firebase_rtdb_public"].severity is Severity.CRITICAL
    assert "secret-user-id" not in found["baas.firebase_rtdb_public"].evidence_masked


def test_an_ordinary_proof_adds_no_note_and_updates_verified_at(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    before = utc_now() - timedelta(minutes=1)

    scan, domain = run(db_engine, verified_hours_ago=48)

    assert scan.verification_note is None
    assert load_domain(db_engine, domain).verified_at.replace(tzinfo=before.tzinfo) > before


def test_a_scan_that_is_not_queued_does_nothing(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    owner, domain = seed(db_engine)
    scan_id = add_scan(db_engine, owner, domain)
    run_backend_check(str(scan_id))
    backends.urls.clear()

    run_backend_check(str(scan_id))

    assert backends.urls == []


# --- the 24-hour rule ---


def test_blocked_proof_under_24_hours_runs_and_says_so(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)

    scan, _ = run(db_engine, verified_hours_ago=23)

    assert len(backends.urls) == 2
    assert scan.result_status is ScanStatus.COMPLETE
    note = scan.verification_note or ""
    assert "Vercel's bot protection" in note
    assert "23 hours ago" in note
    assert "24-hour limit" in note
    assert "only the backend checks ran" in note


def test_a_stand_in_does_not_refresh_the_verification(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)
    owner, domain = seed(db_engine, verified_hours_ago=23)
    before = load_domain(db_engine, domain).verified_at
    scan_id = add_scan(db_engine, owner, domain)

    run_backend_check(str(scan_id))

    # Security: otherwise each check would renew the window and it would never run out.
    assert load_domain(db_engine, domain).verified_at == before


def test_blocked_proof_over_24_hours_is_refused(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)

    scan, domain = run(db_engine, verified_hours_ago=25)

    assert backends.urls == []
    assert scan.result_status is ScanStatus.INCOMPLETE
    assert "more than 24 hours old" in (scan.incomplete_reason or "")
    assert scan.blocked_by is BotProtection.VERCEL
    assert load_domain(db_engine, domain).verified_at is not None


@pytest.mark.parametrize("result", [WRONG_TOKEN, MISSING])
def test_wrong_or_missing_token_still_unverifies(
    db_engine: Engine,
    backends: FakeBackends,
    monkeypatch: pytest.MonkeyPatch,
    result: OwnershipResult,
) -> None:
    proof(monkeypatch, result)

    scan, domain = run(db_engine, verified_hours_ago=1)

    assert backends.urls == []
    assert scan.verification_note is None
    assert scan.result_status is ScanStatus.INCOMPLETE
    assert load_domain(db_engine, domain).verified_at is None


def test_a_real_answer_beside_a_block_is_not_inconclusive(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, MIXED)

    scan, _ = run(db_engine, verified_hours_ago=1)

    assert backends.urls == []
    assert scan.verification_note is None


def test_dns_verified_domain_cannot_lean_on_a_blocked_file(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)

    scan, _ = run(db_engine, verified_hours_ago=1, method="dns")

    assert backends.urls == []
    assert scan.result_status is ScanStatus.INCOMPLETE


def test_failure_other_than_bot_protection_gets_no_stand_in(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, UNKNOWN)

    scan, domain = run(db_engine, verified_hours_ago=1)

    assert backends.urls == []
    assert scan.blocked_by is None
    assert "couldn't re-confirm" in (scan.incomplete_reason or "")
    assert load_domain(db_engine, domain).verified_at is not None


def test_unverified_domain_is_refused(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)

    scan, _ = run(db_engine, verified_hours_ago=None)

    assert backends.urls == []
    assert scan.result_status is ScanStatus.INCOMPLETE


def test_full_scan_never_uses_the_stand_in(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Security: the 24-hour rule is for backend checks only.
    proof(monkeypatch, BLOCKED)

    def must_not_run(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("a full scan ran on a stand-in verification")

    monkeypatch.setattr(tasks, "attach_probes", must_not_run)
    monkeypatch.setattr(tasks, "discover_backends", must_not_run)
    monkeypatch.setattr(tasks, "probe_backends", must_not_run)
    owner, domain = seed(db_engine, verified_hours_ago=1)
    scan_id = add_scan(db_engine, owner, domain, ScanMode.FULL)

    run_full_scan(str(scan_id))

    scan = load_scan(db_engine, scan_id)
    assert scan.result_status is ScanStatus.INCOMPLETE
    assert scan.verification_note is None
    assert backends.urls == []


def test_successful_full_scan_proof_updates_verified_at(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    owner, domain = seed(db_engine, verified_hours_ago=48)
    scan_id = add_scan(db_engine, owner, domain, ScanMode.FULL)

    tasks._ownership_problem(scan_id)

    age = tasks._age_since(load_domain(db_engine, domain).verified_at)
    assert age < timedelta(minutes=1)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (BLOCKED, True),
        (WRONG_TOKEN, False),
        (MIXED, False),
        (UNKNOWN, False),
        (OwnershipResult(None, (NO_TXT,)), False),
    ],
)
def test_only_a_fully_blocked_file_check_counts(result: OwnershipResult, expected: bool) -> None:
    assert result.file_proof_only_blocked is expected


# --- explicit results ---


def checked(**probes: Any) -> ScanContext:
    return ScanContext(hostname=HOSTNAME, baas_probes=BaasProbes(**probes))


def test_locked_database_says_it_was_checked() -> None:
    finding = firebase_rtdb_protected(checked(rtdb=(RtdbProbe(HOST, False),)))

    assert finding is not None
    assert finding.title == "Checked: database not publicly readable"
    assert finding.severity is Severity.INFO
    assert HOST in finding.evidence


def test_locked_bucket_says_it_was_checked() -> None:
    finding = firebase_storage_protected(checked(storage=(StorageProbe(BUCKET, False),)))

    assert finding is not None
    assert finding.title == "Checked: storage files can't be listed publicly"
    assert finding.severity is Severity.INFO
    assert BUCKET in finding.evidence


@pytest.mark.parametrize("readable", [True, None])
def test_open_or_unanswered_database_is_never_called_checked(readable: bool | None) -> None:
    assert firebase_rtdb_protected(checked(rtdb=(RtdbProbe(HOST, readable),))) is None


@pytest.mark.parametrize("listable", [True, None])
def test_open_or_unanswered_bucket_is_never_called_checked(listable: bool | None) -> None:
    assert firebase_storage_protected(checked(storage=(StorageProbe(BUCKET, listable),))) is None


def test_nothing_checked_says_nothing() -> None:
    assert firebase_rtdb_protected(checked()) is None
    assert firebase_storage_protected(checked()) is None


@pytest.mark.parametrize(
    "check_id", ["baas.firebase_rtdb_protected", "baas.firebase_storage_protected"]
)
def test_checked_text_says_what_it_did_not_cover(check_id: str) -> None:
    meaning = CATALOG[check_id].fix.what_it_means

    assert "could still" in meaning


def test_locked_backends_appear_in_the_report(
    db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)

    scan, _ = run(db_engine)

    found = findings(db_engine, scan.id)
    assert set(found) == {"baas.firebase_rtdb_protected", "baas.firebase_storage_protected"}
    assert found["baas.firebase_rtdb_protected"].title == "Checked: database not publicly readable"


# --- the route ---


class FakeQueue:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def apply_async(self, args: tuple[str], retry: bool = True) -> None:
        self.sent.append(args[0])


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> FakeQueue:
    fake = FakeQueue()
    monkeypatch.setattr(domains_api, "run_backend_check", fake)
    return fake


@pytest.fixture
def client(db_engine: Engine, queue: FakeQueue) -> Iterator[TestClient]:
    limiter.reset()
    yield TestClient(app)
    limiter.reset()
    app.dependency_overrides.clear()


def sign_in(viewer_id: UUID) -> None:
    viewer = Viewer(id=viewer_id, email="person@example.com", name=None)
    app.dependency_overrides[get_viewer] = lambda: viewer


def start(client: TestClient, domain: UUID) -> Any:
    return client.post(f"/api/domains/{domain}/check-backends")


def test_route_queues_a_backend_check(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    owner, domain = seed(db_engine)
    sign_in(owner)

    result = start(client, domain)

    assert result.status_code == 202
    assert queue.sent == [result.json()["id"]]
    assert load_scan(db_engine, UUID(result.json()["id"])).mode is ScanMode.BACKENDS


def test_route_needs_sign_in(client: TestClient, db_engine: Engine) -> None:
    _, domain = seed(db_engine)

    assert start(client, domain).status_code == 401


def test_route_hides_other_peoples_domains(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    _, domain = seed(db_engine)
    sign_in(uuid4())

    assert start(client, domain).status_code == 404
    assert queue.sent == []


def test_route_refuses_an_unverified_domain(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    owner, domain = seed(db_engine, verified_hours_ago=None)
    sign_in(owner)

    assert start(client, domain).status_code == 403
    assert queue.sent == []


@pytest.mark.parametrize(
    "rows",
    [
        (),
        ((BaasKind.FIREBASE_RTDB, HOST, False),),
        ((BaasKind.SUPABASE, "abcdefghijklmnopqrst", True),),
    ],
)
def test_route_needs_a_confirmed_backend_it_can_test(
    client: TestClient, db_engine: Engine, queue: FakeQueue, rows: tuple[Any, ...]
) -> None:
    owner, domain = seed(db_engine, backends_to_add=rows)
    sign_in(owner)

    assert start(client, domain).status_code == 409
    assert queue.sent == []


def test_route_reuses_a_running_check(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    owner, domain = seed(db_engine)
    sign_in(owner)
    first = start(client, domain).json()

    second = start(client, domain)

    assert second.status_code == 200
    assert second.json() == {"id": first["id"], "status": "queued", "reused": True}
    assert len(queue.sent) == 1


def test_route_has_an_hourly_cap(
    client: TestClient, db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner, domain = seed(db_engine)
    sign_in(owner)
    monkeypatch.setattr(domains_api, "HOURLY_FULL_SCAN_CAP", 1)
    with Session(db_engine) as session:
        scan = session.get_one(Scan, add_scan(db_engine, owner, domain))
        scan.status = ScanJobStatus.DONE
        session.add(scan)
        session.commit()

    result = start(client, domain)

    assert result.status_code == 429
    assert "backend checks" in result.json()["detail"]


def test_report_is_visible_only_to_its_owner(
    client: TestClient, db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED)
    owner, domain = seed(db_engine, verified_hours_ago=2)
    scan_id = add_scan(db_engine, owner, domain)
    run_backend_check(str(scan_id))

    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    sign_in(uuid4())
    assert client.get(f"/api/scans/{scan_id}").status_code == 404

    sign_in(owner)
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["mode"] == "backends"
    assert "24-hour limit" in body["verification_note"]


def test_backend_checks_stay_out_of_the_score_history(
    client: TestClient, db_engine: Engine, backends: FakeBackends, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    owner, domain = seed(db_engine)
    run_backend_check(str(add_scan(db_engine, owner, domain)))
    sign_in(owner)

    assert client.get(f"/api/domains/{domain}/scans").json()["total"] == 0


# --- combined findings follow what a scan learned ---


@pytest.mark.parametrize(
    ("mode", "runner"),
    [(ScanMode.FULL, run_full_scan), (ScanMode.BACKENDS, run_backend_check)],
)
def test_a_finished_site_scan_refreshes_combined_findings(
    db_engine: Engine,
    backends: FakeBackends,
    monkeypatch: pytest.MonkeyPatch,
    mode: ScanMode,
    runner: Any,
) -> None:
    proof(monkeypatch, BLOCKED)
    refreshed: list[UUID] = []
    monkeypatch.setattr(tasks, "_refresh_correlations", refreshed.append)
    owner, domain = seed(db_engine, verified_hours_ago=48)
    scan_id = add_scan(db_engine, owner, domain, mode)

    runner(str(scan_id))

    assert refreshed == [scan_id]
