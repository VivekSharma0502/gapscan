from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.api import domains as domains_api
from app.checks.base import Category, Severity
from app.checks.ownership import (
    FailureCode,
    MethodFailure,
    OwnershipResult,
    VerificationMethod,
)
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.main import app
from app.models.domain import Domain
from app.models.profile import Profile
from app.models.scan import (
    FindingRecord,
    Scan,
    ScanJobStatus,
    ScanMode,
    TargetType,
    utc_now,
)
from app.workers.tasks import initial_full_progress

NOT_FOUND = MethodFailure(VerificationMethod.DNS, FailureCode.TXT_NOT_FOUND, "no txt yet", True)
FILE_GONE = MethodFailure(VerificationMethod.FILE, FailureCode.FILE_MISSING, "no file", True)
FILE_DOWN = MethodFailure(VerificationMethod.FILE, FailureCode.FILE_UNREACHABLE, "down", False)


class FakeQueue:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def apply_async(self, args: tuple[str], retry: bool = True) -> None:
        self.sent.append(args[0])


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> FakeQueue:
    fake = FakeQueue()
    monkeypatch.setattr(domains_api, "run_full_scan", fake)
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


@pytest.fixture
def me(client: TestClient) -> UUID:
    viewer = uuid4()
    sign_in(viewer)
    return viewer


def prove(monkeypatch: pytest.MonkeyPatch, result: OwnershipResult) -> None:
    monkeypatch.setattr(domains_api, "prove_ownership", lambda _host, _token: result)


def add(client: TestClient, hostname: str = "example.com") -> Any:
    return client.post("/api/domains", json={"hostname": hostname})


def seed(engine: Engine, owner: UUID, hostname: str = "example.com", verified: bool = True) -> UUID:
    with Session(engine) as session:
        if session.get(Profile, owner) is None:
            session.add(Profile(id=owner))
        domain = Domain(
            owner_id=owner,
            hostname=hostname,
            verify_token="tok",  # noqa: S106
            verified_at=utc_now() if verified else None,
            verified_method="dns" if verified else None,
        )
        session.add(domain)
        session.commit()
        return domain.id


def load(engine: Engine, domain_id: UUID) -> Domain:
    with Session(engine) as session:
        return session.get_one(Domain, domain_id)


def full_scans(engine: Engine) -> list[Scan]:
    with Session(engine) as session:
        return list(session.exec(select(Scan).where(Scan.mode == ScanMode.FULL)))


# Sign-in required


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/domains"),
        ("post", "/api/domains"),
        ("delete", f"/api/domains/{uuid4()}"),
        ("post", f"/api/domains/{uuid4()}/verify"),
        ("post", f"/api/domains/{uuid4()}/scan"),
    ],
)
def test_every_route_needs_sign_in(client: TestClient, method: str, path: str) -> None:
    assert client.request(method, path, json={"hostname": "example.com"}).status_code == 401


# Adding


def test_adding_normalizes_and_returns_both_methods(client: TestClient, me: UUID) -> None:
    result = add(client, "HTTPS://Example.COM/some/path?x=1")

    assert result.status_code == 201
    body = result.json()
    assert body["hostname"] == "example.com"
    assert body["verified"] is False
    token = body["instructions"]["file_content"]
    assert len(token) >= 40
    assert body["instructions"]["txt_name"] == "_scankit-verify.example.com"
    assert body["instructions"]["txt_value"] == f"scankit-verify={token}"
    assert body["instructions"]["file_url"] == (
        "https://example.com/.well-known/scankit-verify.txt"
    )


def test_tokens_are_different_for_each_domain(client: TestClient, me: UUID) -> None:
    first = add(client, "one.com").json()["instructions"]["file_content"]
    second = add(client, "two.com").json()["instructions"]["file_content"]

    assert first != second


def test_shared_platform_is_flagged(client: TestClient, me: UUID) -> None:
    assert add(client, "my-app.vercel.app").json()["shared_platform"] is True
    assert add(client, "example.org").json()["shared_platform"] is False


@pytest.mark.parametrize(
    "hostname",
    ["localhost", "10.0.0.1", "169.254.169.254", "intranet", "foo.internal", "vercel.app", "co.in"],
)
def test_unownable_hostnames_are_refused(client: TestClient, me: UUID, hostname: str) -> None:
    assert add(client, hostname).status_code == 422


def test_extra_fields_are_refused(client: TestClient, me: UUID) -> None:
    payload = {"hostname": "example.com", "verified_at": "2026-01-01T00:00:00Z"}

    assert client.post("/api/domains", json=payload).status_code == 422


def test_duplicate_is_refused(client: TestClient, me: UUID) -> None:
    add(client, "example.com")

    assert add(client, "https://EXAMPLE.com").status_code == 409


def test_limit_is_three_domains(client: TestClient, me: UUID) -> None:
    for name in ("one.com", "two.com", "three.com"):
        assert add(client, name).status_code == 201

    result = add(client, "four.com")

    assert result.status_code == 409
    assert "up to 3" in result.json()["detail"]


def test_deleting_makes_room_under_the_limit(client: TestClient, me: UUID) -> None:
    ids = [add(client, name).json()["id"] for name in ("one.com", "two.com", "three.com")]

    client.delete(f"/api/domains/{ids[0]}")

    assert add(client, "four.com").status_code == 201


def test_two_users_can_add_the_same_hostname_with_their_own_tokens(client: TestClient) -> None:
    # Security: otherwise adding a domain first would lock its real owner out.
    sign_in(uuid4())
    first = add(client).json()
    sign_in(uuid4())
    second = add(client).json()

    assert first["id"] != second["id"]
    assert first["instructions"]["file_content"] != second["instructions"]["file_content"]


def test_adding_creates_the_profile(client: TestClient, db_engine: Engine, me: UUID) -> None:
    add(client)

    with Session(db_engine) as session:
        assert session.get(Profile, me) is not None


# Listing and deleting


def test_list_shows_only_your_domains(client: TestClient, db_engine: Engine, me: UUID) -> None:
    seed(db_engine, uuid4(), "theirs.com")
    add(client, "mine.com")

    assert [item["hostname"] for item in client.get("/api/domains").json()] == ["mine.com"]


def test_delete_removes_your_domain(client: TestClient, me: UUID) -> None:
    domain_id = add(client).json()["id"]

    assert client.delete(f"/api/domains/{domain_id}").status_code == 204
    assert client.get("/api/domains").json() == []


@pytest.mark.parametrize(
    ("method", "suffix"), [("delete", ""), ("post", "/verify"), ("post", "/scan")]
)
def test_someone_elses_domain_is_404(
    client: TestClient, db_engine: Engine, me: UUID, method: str, suffix: str
) -> None:
    theirs = seed(db_engine, uuid4())

    assert client.request(method, f"/api/domains/{theirs}{suffix}").status_code == 404
    assert load(db_engine, theirs) is not None


# Verifying


def test_verify_success_marks_the_domain(
    client: TestClient, db_engine: Engine, me: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    prove(monkeypatch, OwnershipResult(VerificationMethod.FILE))
    domain_id = seed(db_engine, me, verified=False)

    body = client.post(f"/api/domains/{domain_id}/verify").json()

    assert body["failures"] == []
    assert body["domain"]["verified"] is True
    assert body["domain"]["verified_method"] == "file"
    assert load(db_engine, domain_id).verified_at is not None


def test_verify_failure_returns_each_reason(
    client: TestClient, db_engine: Engine, me: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    prove(monkeypatch, OwnershipResult(None, (NOT_FOUND, FILE_GONE)))
    domain_id = seed(db_engine, me, verified=False)

    result = client.post(f"/api/domains/{domain_id}/verify")

    assert result.status_code == 200
    body = result.json()
    assert body["domain"]["verified"] is False
    assert [item["code"] for item in body["failures"]] == ["txt_not_found", "file_missing"]
    assert body["failures"][0]["message"] == "no txt yet"


def test_failed_reverify_removes_verification_when_proof_is_gone(
    client: TestClient, db_engine: Engine, me: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    prove(monkeypatch, OwnershipResult(None, (NOT_FOUND, FILE_GONE)))
    domain_id = seed(db_engine, me)

    client.post(f"/api/domains/{domain_id}/verify")

    assert load(db_engine, domain_id).verified_at is None


def test_temporary_failure_keeps_verification(
    client: TestClient, db_engine: Engine, me: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    prove(monkeypatch, OwnershipResult(None, (NOT_FOUND, FILE_DOWN)))
    domain_id = seed(db_engine, me)

    client.post(f"/api/domains/{domain_id}/verify")

    assert load(db_engine, domain_id).verified_at is not None


def test_verify_is_rate_limited(
    client: TestClient, db_engine: Engine, me: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    prove(monkeypatch, OwnershipResult(VerificationMethod.DNS))
    domain_id = seed(db_engine, me)

    codes = [client.post(f"/api/domains/{domain_id}/verify").status_code for _ in range(11)]

    assert codes[-1] == 429


# Starting a full scan


def test_unverified_domain_cannot_be_scanned(
    client: TestClient, db_engine: Engine, me: UUID, queue: FakeQueue
) -> None:
    domain_id = seed(db_engine, me, verified=False)

    result = client.post(f"/api/domains/{domain_id}/scan")

    assert result.status_code == 403
    assert queue.sent == []
    assert full_scans(db_engine) == []


def test_verified_domain_starts_a_full_scan(
    client: TestClient, db_engine: Engine, me: UUID, queue: FakeQueue
) -> None:
    domain_id = seed(db_engine, me)

    result = client.post(f"/api/domains/{domain_id}/scan")

    assert result.status_code == 202
    assert queue.sent == [result.json()["id"]]
    [scan] = full_scans(db_engine)
    assert (scan.owner_id, scan.domain_id, scan.target) == (me, domain_id, "example.com")
    assert scan.status is ScanJobStatus.QUEUED
    assert scan.progress_json["total"] == initial_full_progress()["total"]


def add_full_scan(engine: Engine, domain_id: UUID, owner: UUID, **overrides: Any) -> UUID:
    fields: dict[str, Any] = {
        "owner_id": owner,
        "domain_id": domain_id,
        "target_type": TargetType.WEB,
        "target": "example.com",
        "mode": ScanMode.FULL,
        "status": ScanJobStatus.DONE,
        "progress_json": initial_full_progress(),
    }
    with Session(engine) as session:
        scan = Scan(**(fields | overrides))
        session.add(scan)
        session.commit()
        return scan.id


def test_a_running_scan_is_returned_instead_of_starting_another(
    client: TestClient, db_engine: Engine, me: UUID, queue: FakeQueue
) -> None:
    domain_id = seed(db_engine, me)
    running = add_full_scan(db_engine, domain_id, me, status=ScanJobStatus.RUNNING)

    result = client.post(f"/api/domains/{domain_id}/scan")

    assert result.status_code == 200
    assert result.json() == {"id": str(running), "status": "running", "reused": True}
    assert queue.sent == []


def test_a_stuck_scan_does_not_block_a_new_one(
    client: TestClient, db_engine: Engine, me: UUID, queue: FakeQueue
) -> None:
    domain_id = seed(db_engine, me)
    add_full_scan(
        db_engine,
        domain_id,
        me,
        status=ScanJobStatus.RUNNING,
        created_at=utc_now() - timedelta(minutes=6),
    )

    assert client.post(f"/api/domains/{domain_id}/scan").status_code == 202


def test_hourly_cap_per_domain(
    client: TestClient, db_engine: Engine, me: UUID, queue: FakeQueue
) -> None:
    domain_id = seed(db_engine, me)
    for _ in range(10):
        add_full_scan(db_engine, domain_id, me)

    result = client.post(f"/api/domains/{domain_id}/scan")

    assert result.status_code == 429
    assert queue.sent == []


# Reading a full scan


def finished_with_findings(engine: Engine, owner: UUID) -> UUID:
    domain_id = seed(engine, owner)
    scan_id = add_full_scan(engine, domain_id, owner)
    with Session(engine) as session:
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
    return scan_id


def test_owner_reads_a_full_scan(client: TestClient, db_engine: Engine, me: UUID) -> None:
    scan_id = finished_with_findings(db_engine, me)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["mode"] == "full"
    assert body["teaser"] is False
    assert body["findings"][0]["check_id"] == "exposure.env_file"


def test_anonymous_viewer_gets_404_for_a_full_scan(client: TestClient, db_engine: Engine) -> None:
    # Security: no teaser, since even the top finding could name exposed files and keys.
    scan_id = finished_with_findings(db_engine, uuid4())

    result = client.get(f"/api/scans/{scan_id}")

    assert result.status_code == 404
    assert "DATABASE_URL" not in result.text


def test_another_user_gets_404_for_a_full_scan(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    scan_id = finished_with_findings(db_engine, uuid4())

    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_quick_scan_reuse_never_returns_a_full_scan(
    client: TestClient, db_engine: Engine, me: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Security: a quick scan of the same site must not become a way into a full report.
    scan_id = finished_with_findings(db_engine, uuid4())

    class Queue:
        def apply_async(self, args: tuple[str], retry: bool = True) -> None:
            pass

    from app.api import scans as scans_api

    monkeypatch.setattr(scans_api, "run_quick_scan", Queue())

    body = client.post("/api/scans/quick", json={"target": "example.com"}).json()

    assert body["id"] != str(scan_id)
    assert body["reused"] is False


def test_cors_allows_delete(client: TestClient) -> None:
    result = client.options(
        "/api/domains/abc",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "authorization",
        },
    )

    assert result.status_code == 200
