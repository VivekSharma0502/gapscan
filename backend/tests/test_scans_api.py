import hashlib
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from kombu.exceptions import OperationalError
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.api import scans as scans_api
from app.checks.base import Category, Severity
from app.checks.catalog import CATALOG
from app.checks.runner import ScanStatus
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.main import app
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
from app.workers.tasks import initial_quick_progress

CHECK_IDS = sorted(CATALOG)


class FakeQueue:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.error: Exception | None = None

    def apply_async(self, args: tuple[str], retry: bool = True) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append(args[0])


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> FakeQueue:
    fake = FakeQueue()
    monkeypatch.setattr(scans_api, "run_quick_scan", fake)
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


def add_scan(engine: Engine, age_minutes: float = 0, **overrides: Any) -> UUID:
    fields: dict[str, Any] = {
        "target_type": TargetType.WEB,
        "target": "example.com",
        "mode": ScanMode.QUICK,
        "status": ScanJobStatus.DONE,
        "progress_json": initial_quick_progress(),
        "created_at": utc_now() - timedelta(minutes=age_minutes),
    }
    with Session(engine) as session:
        scan = Scan(**(fields | overrides))
        session.add(scan)
        session.commit()
        return scan.id


def add_finding(engine: Engine, scan_id: UUID, check_id: str, severity: Severity) -> None:
    with Session(engine) as session:
        session.add(
            FindingRecord(
                scan_id=scan_id,
                check_id=check_id,
                category=Category.TLS,
                severity=severity,
                title=CATALOG[check_id].title if check_id in CATALOG else "Old check",
                evidence_masked="evidence",
            )
        )
        session.commit()


def load(engine: Engine, scan_id: str | UUID) -> Scan:
    with Session(engine) as session:
        return session.get_one(Scan, UUID(str(scan_id)))


def claims(engine: Engine) -> list[ScanClaim]:
    with Session(engine) as session:
        return list(session.exec(select(ScanClaim)))


def post(client: TestClient, target: str = "example.com") -> Any:
    return client.post("/api/scans/quick", json={"target": target})


# Starting a scan


def test_quick_scan_is_queued(client: TestClient, db_engine: Engine, queue: FakeQueue) -> None:
    result = post(client)

    assert result.status_code == 202
    body = result.json()
    assert body["status"] == "queued"
    assert body["reused"] is False
    assert queue.sent == [body["id"]]
    scan = load(db_engine, body["id"])
    assert scan.target == "example.com"
    assert scan.mode is ScanMode.QUICK
    assert scan.owner_id is None


@pytest.mark.parametrize(
    "target",
    ["example.com", "EXAMPLE.com", "https://example.com/some/path?x=1", "http://example.com:80/"],
)
def test_target_is_reduced_to_its_hostname(
    client: TestClient, db_engine: Engine, target: str
) -> None:
    assert load(db_engine, post(client, target).json()["id"]).target == "example.com"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "localhost",
        "intranet",
        "foo.local",
        "foo.internal",
        "127.0.0.1",
        "8.8.8.8",
        "[::1]",
        "http://[2001:4860:4860::8888]/",
        "https://example.com:8443/",
        "https://user:pw@example.com/",
        "ftp://example.com/",
        "exa mple.com",
        "a" * 300 + ".com",
        "https://example.com/" + "a" * 3000,
    ],
)
def test_bad_targets_are_rejected(client: TestClient, queue: FakeQueue, target: str) -> None:
    assert post(client, target).status_code == 422
    assert queue.sent == []


def test_unknown_fields_are_rejected(client: TestClient) -> None:
    body = {"target": "example.com", "mode": "full"}
    assert client.post("/api/scans/quick", json=body).status_code == 422


def test_rate_limit_is_five_per_minute_per_ip(client: TestClient) -> None:
    codes = [post(client, f"site{index}.example.com").status_code for index in range(6)]
    assert codes == [202, 202, 202, 202, 202, 429]


def test_limiter_outage_fails_closed(
    client: TestClient, queue: FakeQueue, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(*_args: Any, **_kwargs: Any) -> bool:
        raise RedisConnectionError("refused")

    monkeypatch.setattr(limiter._limiter, "hit", down)

    assert post(client).status_code == 503
    assert queue.sent == []


def test_queue_failure_returns_503_and_does_not_block_a_retry(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    queue.error = OperationalError("broker down")
    assert post(client).status_code == 503

    with Session(db_engine) as session:
        [scan] = session.exec(select(Scan)).all()
    assert scan.status is ScanJobStatus.FAILED

    queue.error = None
    retried = post(client)
    assert retried.status_code == 202
    assert retried.json()["id"] != str(scan.id)


# Claim tokens


def test_claim_token_is_stored_only_as_a_hash(client: TestClient, db_engine: Engine) -> None:
    token = post(client).json()["claim_token"]

    assert len(token) >= 40
    [claim] = claims(db_engine)
    assert claim.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert claim.token_hash != token


def test_reused_scan_gets_a_separate_claim_token(client: TestClient, db_engine: Engine) -> None:
    first = post(client).json()
    second = post(client).json()

    assert first["id"] == second["id"]
    assert first["claim_token"] != second["claim_token"]
    assert len(claims(db_engine)) == 2


def test_signed_in_viewer_owns_the_scan_and_gets_no_token(
    client: TestClient, db_engine: Engine
) -> None:
    viewer = uuid4()
    sign_in(viewer)

    body = post(client).json()

    assert body["claim_token"] is None
    assert load(db_engine, body["id"]).owner_id == viewer
    assert claims(db_engine) == []


# Reusing a recent scan


@pytest.mark.parametrize(
    ("age_minutes", "scan_status"),
    [
        (9, ScanJobStatus.DONE),
        (1, ScanJobStatus.QUEUED),
        (4, ScanJobStatus.RUNNING),
    ],
)
def test_recent_scan_is_returned(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    age_minutes: int,
    scan_status: ScanJobStatus,
) -> None:
    existing = add_scan(db_engine, age_minutes=age_minutes, status=scan_status)

    result = post(client)

    assert result.status_code == 200
    assert result.json()["id"] == str(existing)
    assert result.json()["reused"] is True
    assert result.json()["status"] == scan_status.value
    assert queue.sent == []


def test_incomplete_scan_is_still_reused(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    existing = add_scan(db_engine, result_status=ScanStatus.INCOMPLETE)
    assert post(client).json()["id"] == str(existing)
    assert queue.sent == []


@pytest.mark.parametrize(
    ("age_minutes", "scan_status"),
    [
        (11, ScanJobStatus.DONE),
        (1, ScanJobStatus.FAILED),
        (6, ScanJobStatus.QUEUED),
        (6, ScanJobStatus.RUNNING),
    ],
)
def test_old_failed_or_abandoned_scans_are_not_reused(
    client: TestClient,
    db_engine: Engine,
    age_minutes: int,
    scan_status: ScanJobStatus,
) -> None:
    existing = add_scan(db_engine, age_minutes=age_minutes, status=scan_status)

    result = post(client)

    assert result.status_code == 202
    assert result.json()["id"] != str(existing)


def test_other_hostnames_and_modes_are_not_reused(client: TestClient, db_engine: Engine) -> None:
    add_scan(db_engine, target="other.example.com")
    add_scan(db_engine, mode=ScanMode.FULL)
    assert post(client).status_code == 202


# Hourly cap per hostname


def add_old_scans(engine: Engine, count: int, age_minutes: float = 30, **overrides: Any) -> None:
    for _ in range(count):
        add_scan(engine, age_minutes=age_minutes, **overrides)


def test_hourly_cap_blocks_the_twenty_first_scan(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    add_old_scans(db_engine, 20)

    result = post(client)

    assert result.status_code == 429
    assert "retry-after" in result.headers
    assert queue.sent == []


def test_hourly_cap_allows_the_twentieth_scan(client: TestClient, db_engine: Engine) -> None:
    add_old_scans(db_engine, 19)
    assert post(client).status_code == 202


def test_failed_scans_count_towards_the_cap(client: TestClient, db_engine: Engine) -> None:
    add_old_scans(db_engine, 20, age_minutes=1, status=ScanJobStatus.FAILED)
    assert post(client).status_code == 429


def test_scans_older_than_an_hour_do_not_count(client: TestClient, db_engine: Engine) -> None:
    add_old_scans(db_engine, 20, age_minutes=61)
    assert post(client).status_code == 202


def test_cap_applies_per_hostname(client: TestClient, db_engine: Engine) -> None:
    add_old_scans(db_engine, 20)
    assert post(client, "other.example.com").status_code == 202


def test_reuse_is_still_served_when_the_cap_is_full(client: TestClient, db_engine: Engine) -> None:
    add_old_scans(db_engine, 20)
    existing = add_scan(db_engine, age_minutes=2)
    assert post(client).json()["id"] == str(existing)


# Reading a scan


def test_anonymous_viewer_gets_score_and_top_three_findings(
    client: TestClient, db_engine: Engine
) -> None:
    scan_id = add_scan(db_engine, score=61, grade="C", result_status=ScanStatus.COMPLETE)
    add_finding(db_engine, scan_id, CHECK_IDS[0], Severity.LOW)
    add_finding(db_engine, scan_id, CHECK_IDS[1], Severity.CRITICAL)
    add_finding(db_engine, scan_id, CHECK_IDS[2], Severity.INFO)
    add_finding(db_engine, scan_id, CHECK_IDS[3], Severity.HIGH)
    add_finding(db_engine, scan_id, CHECK_IDS[4], Severity.MEDIUM)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["teaser"] is True
    assert body["score"] == 61
    assert body["grade"] == "C"
    assert [item["severity"] for item in body["findings"]] == ["critical", "high", "medium"]
    assert body["findings"][0]["fix"]["how_to_fix"]
    assert body["skipped"] == []


def test_response_never_exposes_owner_or_claim_data(client: TestClient, db_engine: Engine) -> None:
    token = post(client).json()["claim_token"]
    [claim] = claims(db_engine)

    result = client.get(f"/api/scans/{claim.scan_id}")

    assert token not in result.text
    assert claim.token_hash not in result.text
    assert "owner_id" not in result.json()
    assert "claim_token" not in result.json()


def test_owner_gets_every_finding(client: TestClient, db_engine: Engine) -> None:
    viewer = uuid4()
    scan_id = add_scan(
        db_engine,
        owner_id=viewer,
        skipped_json=[{"check_id": "x", "reason": "y", "not_applicable": False}],
    )
    for check_id in CHECK_IDS[:5]:
        add_finding(db_engine, scan_id, check_id, Severity.LOW)
    sign_in(viewer)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["teaser"] is False
    assert len(body["findings"]) == 5
    assert body["skipped"][0]["check_id"] == "x"


def test_signed_in_stranger_gets_only_the_teaser(client: TestClient, db_engine: Engine) -> None:
    scan_id = add_scan(db_engine, owner_id=uuid4())
    for check_id in CHECK_IDS[:5]:
        add_finding(db_engine, scan_id, check_id, Severity.LOW)
    sign_in(uuid4())

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["teaser"] is True
    assert len(body["findings"]) == 3


def test_partial_score_keeps_its_label(client: TestClient, db_engine: Engine) -> None:
    scan_id = add_scan(
        db_engine,
        score=80,
        grade="B",
        result_status=ScanStatus.PARTIAL,
        score_label="Partial — 2 checks skipped",
    )

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["result_status"] == "partial"
    assert body["score_label"] == "Partial — 2 checks skipped"


def test_capped_grade_keeps_its_reason_and_score(client: TestClient, db_engine: Engine) -> None:
    reason = "Capped at F: site doesn't offer HTTPS"
    scan_id = add_scan(db_engine, score=75, grade="F", grade_cap_reason=reason)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert (body["score"], body["grade"]) == (75, "F")
    assert body["grade_cap_reason"] == reason


def test_progress_is_returned_while_running(client: TestClient, db_engine: Engine) -> None:
    progress = {
        "completed": 1,
        "total": 29,
        "current": "https_fetch",
        "steps": [
            {"name": "tls_probe", "status": "done"},
            {"name": "https_fetch", "status": "running"},
        ],
    }
    scan_id = add_scan(db_engine, status=ScanJobStatus.RUNNING, progress_json=progress)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["status"] == "running"
    assert body["progress"] == progress
    assert body["score"] is None
    assert body["findings"] == []


def test_progress_saved_before_the_step_log_still_loads(
    client: TestClient, db_engine: Engine
) -> None:
    progress = {"completed": 2, "total": 29, "current": "http_fetch"}
    scan_id = add_scan(db_engine, status=ScanJobStatus.RUNNING, progress_json=progress)

    assert client.get(f"/api/scans/{scan_id}").json()["progress"]["steps"] == []


def test_step_log_response_cannot_carry_results(client: TestClient, db_engine: Engine) -> None:
    # Security: even if a result were ever stored with a step, the response must drop it.
    progress = {
        "completed": 1,
        "total": 29,
        "current": None,
        "steps": [{"name": "tls_probe", "status": "done", "severity": "high", "passed": False}],
    }
    scan_id = add_scan(db_engine, status=ScanJobStatus.RUNNING, progress_json=progress)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["progress"]["steps"] == [{"name": "tls_probe", "status": "done"}]


def test_total_findings_counts_findings_hidden_from_the_teaser(
    client: TestClient, db_engine: Engine
) -> None:
    scan_id = add_scan(db_engine)
    for check_id in CHECK_IDS[:5]:
        add_finding(db_engine, scan_id, check_id, Severity.LOW)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert len(body["findings"]) == 3
    assert body["total_findings"] == 5


@pytest.mark.parametrize("scan_status", [ScanJobStatus.QUEUED, ScanJobStatus.RUNNING])
def test_abandoned_scan_reads_as_failed(
    client: TestClient, db_engine: Engine, scan_status: ScanJobStatus
) -> None:
    scan_id = add_scan(db_engine, age_minutes=6, status=scan_status)

    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "failed"
    assert load(db_engine, scan_id).status is ScanJobStatus.FAILED


def test_finding_from_a_removed_check_still_loads(client: TestClient, db_engine: Engine) -> None:
    scan_id = add_scan(db_engine)
    add_finding(db_engine, scan_id, "removed.check", Severity.LOW)

    body = client.get(f"/api/scans/{scan_id}").json()

    assert body["findings"][0]["fix"] is None


def test_unknown_scan_is_404(client: TestClient) -> None:
    assert client.get(f"/api/scans/{uuid4()}").status_code == 404


def test_malformed_scan_id_is_rejected(client: TestClient) -> None:
    assert client.get("/api/scans/not-a-uuid").status_code == 422


# Claiming anonymous scans


def claim(client: TestClient, *tokens: str) -> Any:
    return client.post("/api/scans/claim", json={"tokens": list(tokens)})


def anonymous_scan(client: TestClient) -> tuple[str, str]:
    body = post(client).json()
    return body["id"], body["claim_token"]


def add_five_findings(engine: Engine, scan_id: str) -> None:
    for check_id in CHECK_IDS[:5]:
        add_finding(engine, UUID(scan_id), check_id, Severity.LOW)


def sign_out() -> None:
    app.dependency_overrides.pop(get_viewer, None)


def test_claim_requires_signing_in(client: TestClient, db_engine: Engine) -> None:
    _, token = anonymous_scan(client)

    result = claim(client, token)

    assert result.status_code == 401
    assert claims(db_engine)[0].claimed_by is None


def test_claiming_unlocks_the_full_report_and_makes_an_owner(
    client: TestClient, db_engine: Engine
) -> None:
    scan_id, token = anonymous_scan(client)
    add_five_findings(db_engine, scan_id)
    viewer = uuid4()
    sign_in(viewer)

    result = claim(client, token)

    assert result.status_code == 200
    assert result.json() == {"claimed": [scan_id]}
    assert load(db_engine, scan_id).owner_id == viewer
    body = client.get(f"/api/scans/{scan_id}").json()
    assert body["teaser"] is False
    assert len(body["findings"]) == 5


def test_claiming_creates_the_profile(client: TestClient, db_engine: Engine) -> None:
    _, token = anonymous_scan(client)
    viewer = uuid4()
    sign_in(viewer)

    claim(client, token)

    with Session(db_engine) as session:
        assert session.get_one(Profile, viewer).email == "person@example.com"


def test_a_token_only_works_for_the_first_user(client: TestClient, db_engine: Engine) -> None:
    scan_id, token = anonymous_scan(client)
    add_five_findings(db_engine, scan_id)
    first = uuid4()
    sign_in(first)
    claim(client, token)
    sign_in(uuid4())

    assert claim(client, token).json() == {"claimed": []}
    assert client.get(f"/api/scans/{scan_id}").json()["teaser"] is True
    assert load(db_engine, scan_id).owner_id == first


def test_retrying_a_claim_is_safe(client: TestClient, db_engine: Engine) -> None:
    scan_id, token = anonymous_scan(client)
    viewer = uuid4()
    sign_in(viewer)
    claim(client, token)

    assert claim(client, token).json() == {"claimed": [scan_id]}
    assert load(db_engine, scan_id).owner_id == viewer


def test_two_people_can_claim_one_shared_scan(client: TestClient, db_engine: Engine) -> None:
    first_scan, first_token = anonymous_scan(client)
    second_scan, second_token = anonymous_scan(client)
    assert first_scan == second_scan
    add_five_findings(db_engine, first_scan)
    first, second = uuid4(), uuid4()
    sign_in(first)
    claim(client, first_token)
    sign_in(second)

    assert claim(client, second_token).json() == {"claimed": [first_scan]}

    assert client.get(f"/api/scans/{first_scan}").json()["teaser"] is False
    assert load(db_engine, first_scan).owner_id == first


def test_unknown_tokens_are_ignored_alongside_real_ones(
    client: TestClient, db_engine: Engine
) -> None:
    scan_id, token = anonymous_scan(client)
    sign_in(uuid4())

    assert claim(client, "made-up", token).json() == {"claimed": [scan_id]}
    assert len(claims(db_engine)) == 1


def test_a_claim_is_not_readable_while_signed_out(client: TestClient, db_engine: Engine) -> None:
    scan_id, token = anonymous_scan(client)
    add_five_findings(db_engine, scan_id)
    sign_in(uuid4())
    claim(client, token)
    sign_out()

    assert client.get(f"/api/scans/{scan_id}").json()["teaser"] is True


@pytest.mark.parametrize(
    "payload",
    [
        {"tokens": []},
        {"tokens": ["x"] * 21},
        {"tokens": ["x" * 129]},
        {"tokens": [""]},
        {"tokens": ["x"], "scan_id": "y"},
    ],
    ids=["empty", "too-many", "too-long", "blank", "extra-field"],
)
def test_bad_claim_requests_are_rejected(client: TestClient, payload: dict[str, Any]) -> None:
    sign_in(uuid4())

    assert client.post("/api/scans/claim", json=payload).status_code == 422


# Signed-in viewers and reused scans


def test_signed_in_viewer_gets_the_full_report_on_a_reused_scan(
    client: TestClient, db_engine: Engine
) -> None:
    scan_id, _ = anonymous_scan(client)
    add_five_findings(db_engine, scan_id)
    viewer = uuid4()
    sign_in(viewer)

    body = post(client).json()

    assert (body["id"], body["reused"], body["claim_token"]) == (scan_id, True, None)
    assert client.get(f"/api/scans/{scan_id}").json()["teaser"] is False
    assert load(db_engine, scan_id).owner_id == viewer


def test_reusing_someone_elses_scan_does_not_take_it_over(
    client: TestClient, db_engine: Engine
) -> None:
    owner = uuid4()
    scan_id = add_scan(db_engine, owner_id=owner)
    add_five_findings(db_engine, str(scan_id))
    sign_in(uuid4())

    post(client)

    assert load(db_engine, scan_id).owner_id == owner
    assert client.get(f"/api/scans/{scan_id}").json()["teaser"] is False


def test_repeated_reuse_records_access_once(client: TestClient, db_engine: Engine) -> None:
    add_scan(db_engine, owner_id=uuid4())
    sign_in(uuid4())

    post(client)
    post(client)

    assert len(claims(db_engine)) == 1


def test_owner_reusing_their_scan_records_nothing(client: TestClient, db_engine: Engine) -> None:
    viewer = uuid4()
    add_scan(db_engine, owner_id=viewer)
    sign_in(viewer)

    post(client)

    assert claims(db_engine) == []


def test_starting_a_scan_signed_in_creates_the_profile(
    client: TestClient, db_engine: Engine
) -> None:
    viewer = uuid4()
    sign_in(viewer)

    post(client)

    with Session(db_engine) as session:
        assert session.get(Profile, viewer) is not None


# CORS


def test_cors_allows_the_bearer_token(client: TestClient) -> None:
    result = client.options(
        "/api/scans/claim",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert result.status_code == 200
    assert "authorization" in result.headers["access-control-allow-headers"].lower()


def test_cors_allows_the_frontend_to_post_json(client: TestClient) -> None:
    result = client.options(
        "/api/scans/quick",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert result.status_code == 200
    assert result.headers["access-control-allow-origin"] == "http://localhost:3000"
