"""Starting repo scans and saving their results. The scanner itself is faked here."""

import hashlib
import hmac
import json
import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from kombu.exceptions import OperationalError
from pydantic import SecretStr
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.api import github as github_api
from app.api import github_webhook
from app.checks.base import Category, Severity
from app.checks.runner import ScanStatus
from app.core.auth import Viewer, get_viewer
from app.core.config import settings
from app.core.rate_limit import limiter
from app.main import app
from app.models.github import GithubInstallation, Repo
from app.models.profile import Profile
from app.models.scan import FindingRecord, Scan, ScanJobStatus, ScanMode, TargetType, utc_now
from app.repos.report import SecretHit
from app.repos.scanner import STEP_CLONE, STEP_SECRETS, RepoScanLimitError, RepoScanResult
from app.workers import tasks
from app.workers.celery_app import celery_app
from app.workers.tasks import initial_repo_progress, run_repo_scan

GITHUB_REPO_ID = 100
INSTALLATION_ID = 7
SECRET = "test-webhook-secret"  # noqa: S105
BEFORE = "a" * 40
AFTER = "b" * 40


class FakeQueue:
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.down = False

    def apply_async(self, args: tuple[str], retry: bool = True) -> None:
        if self.down:
            raise OperationalError("broker down")
        self.sent.append(args[0])


class Seeded:
    def __init__(self, owner: UUID, installation: UUID, repo: UUID) -> None:
        self.owner = owner
        self.installation = installation
        self.repo = repo


def seed(
    engine: Engine,
    *,
    suspended: bool = False,
    scanned: bool = False,
    installation_id: int = INSTALLATION_ID,
    github_repo_id: int = GITHUB_REPO_ID,
) -> Seeded:
    owner = uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        installation = GithubInstallation(
            owner_id=owner,
            installation_id=installation_id,
            account_id=installation_id * 10,
            account_login="me",
            suspended_at=utc_now() if suspended else None,
        )
        session.add(installation)
        session.flush()
        repo = Repo(
            owner_id=owner,
            installation_id=installation.id,
            github_repo_id=github_repo_id,
            full_name="me/project",
            is_private=True,
            first_full_scan_at=utc_now() if scanned else None,
        )
        session.add(repo)
        session.commit()
        return Seeded(owner, installation.id, repo.id)


def add_scan(engine: Engine, seeded: Seeded, **overrides: Any) -> UUID:
    fields: dict[str, Any] = {
        "owner_id": seeded.owner,
        "repo_id": seeded.repo,
        "target_type": TargetType.REPO,
        "target": "me/project",
        "mode": ScanMode.FULL,
        "progress_json": initial_repo_progress(),
    }
    with Session(engine) as session:
        scan = Scan(**(fields | overrides))
        session.add(scan)
        session.commit()
        return scan.id


def hit(name: str = "a", severity: Severity = Severity.CRITICAL) -> SecretHit:
    return SecretHit(
        check_id="secrets.aws",
        severity=severity,
        title="AWS access key found in your code",
        masked="AKIA****",
        rule_id="aws-access-token",
        file_path=f"{name}.py",
        line=3,
        commit_sha="c" * 40,
        fingerprint=hashlib.sha256(name.encode()).hexdigest(),
    )


def result(*hits: SecretHit, truncated: bool = False, full_history: bool = True) -> RepoScanResult:
    return RepoScanResult("me/renamed", list(hits), truncated, full_history)


class FakeScanner:
    def __init__(self) -> None:
        self.result = result()
        self.error: Exception | None = None
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, installation_id: int, github_repo_id: int, *, on_step: Any, **kwargs: Any
    ) -> RepoScanResult:
        self.calls.append(
            {"installation_id": installation_id, "github_repo_id": github_repo_id} | kwargs
        )
        on_step(STEP_CLONE)
        on_step(STEP_SECRETS)
        if self.error is not None:
            raise self.error
        return self.result


@pytest.fixture
def scanner(monkeypatch: pytest.MonkeyPatch) -> FakeScanner:
    fake = FakeScanner()
    monkeypatch.setattr(tasks, "scan_repository", fake)
    return fake


def load_scan(engine: Engine, scan_id: UUID) -> Scan:
    with Session(engine) as session:
        return session.get_one(Scan, scan_id)


def load_repo(engine: Engine, repo_id: UUID) -> Repo:
    with Session(engine) as session:
        return session.get_one(Repo, repo_id)


def findings(engine: Engine) -> list[FindingRecord]:
    with Session(engine) as session:
        return list(session.exec(select(FindingRecord)))


def scans(engine: Engine) -> list[Scan]:
    with Session(engine) as session:
        return list(session.exec(select(Scan)))


def run(engine: Engine, seeded: Seeded, **overrides: Any) -> UUID:
    scan_id = add_scan(engine, seeded, **overrides)
    run_repo_scan(str(scan_id))
    return scan_id


# --- the worker ---


def test_scan_runs_the_right_repo_and_saves_masked_findings(
    db_engine: Engine, scanner: FakeScanner
) -> None:
    seeded = seed(db_engine)
    scanner.result = result(hit())

    scan_id = run(db_engine, seeded)

    assert scanner.calls == [
        {
            "installation_id": INSTALLATION_ID,
            "github_repo_id": GITHUB_REPO_ID,
            "before_sha": None,
            "after_sha": None,
        }
    ]
    scan = load_scan(db_engine, scan_id)
    assert (scan.status, scan.result_status) == (ScanJobStatus.DONE, ScanStatus.COMPLETE)
    assert scan.progress_json["completed"] == 2
    record = findings(db_engine)[0]
    assert record.category is Category.SECRETS
    assert record.evidence_masked == "AKIA****"
    assert record.repo_id == seeded.repo
    assert (record.file_path, record.line, record.commit_sha) == ("a.py", 3, "c" * 40)
    assert record.location == "a.py:3"


def test_full_scan_records_that_the_first_scan_happened(
    db_engine: Engine, scanner: FakeScanner
) -> None:
    seeded = seed(db_engine)

    run(db_engine, seeded)

    assert load_repo(db_engine, seeded.repo).first_full_scan_at is not None


def test_stored_name_follows_github(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine)

    run(db_engine, seeded)

    assert load_repo(db_engine, seeded.repo).full_name == "me/renamed"


def test_rescan_keeps_one_row_and_its_first_seen_date(
    db_engine: Engine, scanner: FakeScanner
) -> None:
    seeded = seed(db_engine)
    scanner.result = result(hit())
    run(db_engine, seeded)
    original = findings(db_engine)[0]

    run(db_engine, seeded)

    rows = findings(db_engine)
    assert len(rows) == 1
    assert rows[0].id == original.id
    assert rows[0].created_at == original.created_at
    assert rows[0].scan_id == original.scan_id


def test_push_scan_adds_without_removing(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine, scanned=True)
    scanner.result = result(hit("a"))
    run(db_engine, seeded)

    scanner.result = result(hit("b"), full_history=False)
    run(db_engine, seeded, before_sha=BEFORE, after_sha=AFTER)

    assert {row.file_path for row in findings(db_engine)} == {"a.py", "b.py"}


def test_full_scan_drops_findings_rewritten_out_of_history(
    db_engine: Engine, scanner: FakeScanner
) -> None:
    seeded = seed(db_engine)
    scanner.result = result(hit("a"), hit("b"))
    run(db_engine, seeded)

    scanner.result = result(hit("b"))
    run(db_engine, seeded)

    assert {row.file_path for row in findings(db_engine)} == {"b.py"}


def test_truncated_scan_never_drops_findings(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine)
    scanner.result = result(hit("a"), hit("b"))
    run(db_engine, seeded)

    scanner.result = result(hit("b"), truncated=True)
    scan_id = run(db_engine, seeded)

    assert {row.file_path for row in findings(db_engine)} == {"a.py", "b.py"}
    scan = load_scan(db_engine, scan_id)
    assert scan.result_status is ScanStatus.PARTIAL
    assert scan.incomplete_reason


def test_findings_are_separate_per_repo(db_engine: Engine, scanner: FakeScanner) -> None:
    first = seed(db_engine)
    second = seed(db_engine, installation_id=8, github_repo_id=200)
    scanner.result = result(hit("a"))

    run(db_engine, first)
    run(db_engine, second)

    assert {row.repo_id for row in findings(db_engine)} == {first.repo, second.repo}


def test_full_scan_clears_the_catch_up_flag(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine)
    with Session(db_engine) as session:
        repo = session.get_one(Repo, seeded.repo)
        repo.needs_full_scan = True
        session.add(repo)
        session.commit()

    run(db_engine, seeded)

    assert not load_repo(db_engine, seeded.repo).needs_full_scan


def test_partial_scan_leaves_the_catch_up_flag_and_first_scan(
    db_engine: Engine, scanner: FakeScanner
) -> None:
    seeded = seed(db_engine)
    with Session(db_engine) as session:
        repo = session.get_one(Repo, seeded.repo)
        repo.needs_full_scan = True
        session.add(repo)
        session.commit()
    scanner.result = result(full_history=False)

    run(db_engine, seeded, before_sha=BEFORE, after_sha=AFTER)

    repo = load_repo(db_engine, seeded.repo)
    assert repo.needs_full_scan
    assert repo.first_full_scan_at is None


def test_hitting_a_cap_is_an_incomplete_result_with_a_reason(
    db_engine: Engine, scanner: FakeScanner
) -> None:
    seeded = seed(db_engine)
    scanner.error = RepoScanLimitError("Too big to scan.")

    scan_id = run(db_engine, seeded)

    scan = load_scan(db_engine, scan_id)
    assert (scan.status, scan.result_status) == (ScanJobStatus.DONE, ScanStatus.INCOMPLETE)
    assert scan.incomplete_reason == "Too big to scan."
    assert load_repo(db_engine, seeded.repo).first_full_scan_at is None


def test_crash_fails_the_scan_without_logging_its_message(
    db_engine: Engine, scanner: FakeScanner, caplog: pytest.LogCaptureFixture
) -> None:
    seeded = seed(db_engine)
    scanner.error = RuntimeError("leaked-token-value")

    with caplog.at_level(logging.ERROR):
        scan_id = run(db_engine, seeded)

    scan = load_scan(db_engine, scan_id)
    assert scan.status is ScanJobStatus.FAILED
    assert "leaked-token-value" not in (scan.incomplete_reason or "")
    assert "leaked-token-value" not in caplog.text


def test_suspended_installation_is_not_scanned(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine, suspended=True)

    scan_id = run(db_engine, seeded)

    assert scanner.calls == []
    assert load_scan(db_engine, scan_id).status is ScanJobStatus.FAILED


def test_removed_repo_is_not_scanned(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine)

    scan_id = run(db_engine, seeded, repo_id=None)

    assert scanner.calls == []
    assert load_scan(db_engine, scan_id).status is ScanJobStatus.FAILED


def test_scan_owned_by_someone_else_is_not_run(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine)
    other = uuid4()
    with Session(db_engine) as session:
        session.add(Profile(id=other))
        session.commit()

    scan_id = run(db_engine, seeded, owner_id=other)

    assert scanner.calls == []
    assert load_scan(db_engine, scan_id).status is ScanJobStatus.FAILED


def test_scan_that_is_not_queued_does_not_run(db_engine: Engine, scanner: FakeScanner) -> None:
    seeded = seed(db_engine)

    run(db_engine, seeded, status=ScanJobStatus.DONE)

    assert scanner.calls == []


def test_repo_scans_have_their_own_queue_and_time_limit() -> None:
    assert celery_app.conf.task_routes["scans.run_repo"] == {"queue": "repo_scans"}
    assert run_repo_scan.time_limit > celery_app.conf.task_time_limit


# --- Scan now ---


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> FakeQueue:
    fake = FakeQueue()
    monkeypatch.setattr(github_api, "run_repo_scan", fake)
    monkeypatch.setattr(github_webhook, "run_repo_scan", fake)
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


def scan_now(client: TestClient, repo_id: UUID) -> Any:
    return client.post(f"/api/repos/{repo_id}/scan")


def test_scan_now_queues_a_whole_history_owner_only_scan(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    seeded = seed(db_engine, scanned=True)
    sign_in(seeded.owner)

    response = scan_now(client, seeded.repo)

    assert response.status_code == 202
    assert response.json()["reused"] is False
    scan = scans(db_engine)[0]
    assert (scan.mode, scan.target_type) == (ScanMode.FULL, TargetType.REPO)
    assert (scan.before_sha, scan.after_sha) == (None, None)
    assert queue.sent == [str(scan.id)]


def test_scan_now_needs_sign_in(client: TestClient, db_engine: Engine) -> None:
    assert scan_now(client, seed(db_engine).repo).status_code == 401


def test_scan_now_hides_other_peoples_repos(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    seeded = seed(db_engine)
    sign_in(uuid4())

    assert scan_now(client, seeded.repo).status_code == 404
    assert queue.sent == []


def test_scan_now_refuses_a_suspended_installation(client: TestClient, db_engine: Engine) -> None:
    seeded = seed(db_engine, suspended=True)
    sign_in(seeded.owner)

    assert scan_now(client, seeded.repo).status_code == 409


def test_scan_now_reuses_a_running_scan(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    seeded = seed(db_engine)
    sign_in(seeded.owner)
    running = add_scan(db_engine, seeded, status=ScanJobStatus.RUNNING)

    response = scan_now(client, seeded.repo)

    assert response.status_code == 200
    assert response.json()["id"] == str(running)
    assert response.json()["reused"] is True
    assert queue.sent == []


def test_a_running_push_scan_does_not_stand_in_for_a_full_one(
    client: TestClient, db_engine: Engine, queue: FakeQueue
) -> None:
    seeded = seed(db_engine)
    sign_in(seeded.owner)
    add_scan(db_engine, seeded, status=ScanJobStatus.RUNNING, before_sha=BEFORE, after_sha=AFTER)

    assert scan_now(client, seeded.repo).status_code == 202


def test_scan_now_has_an_hourly_cap(client: TestClient, db_engine: Engine) -> None:
    seeded = seed(db_engine)
    sign_in(seeded.owner)
    for _ in range(github_api.HOURLY_FULL_REPO_SCAN_CAP):
        add_scan(db_engine, seeded, status=ScanJobStatus.DONE)

    assert scan_now(client, seeded.repo).status_code == 429


def test_repo_scan_can_only_be_read_by_its_owner(client: TestClient, db_engine: Engine) -> None:
    seeded = seed(db_engine)
    scan_id = add_scan(db_engine, seeded, status=ScanJobStatus.DONE)

    assert client.get(f"/api/scans/{scan_id}").status_code == 404

    sign_in(uuid4())
    assert client.get(f"/api/scans/{scan_id}").status_code == 404

    sign_in(seeded.owner)
    assert client.get(f"/api/scans/{scan_id}").status_code == 200


def test_slow_repo_scan_is_not_expired_at_the_website_limit(
    client: TestClient, db_engine: Engine
) -> None:
    seeded = seed(db_engine)
    sign_in(seeded.owner)
    scan_id = add_scan(
        db_engine,
        seeded,
        status=ScanJobStatus.RUNNING,
        created_at=utc_now() - timedelta(minutes=10),
    )

    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "running"


def test_abandoned_repo_scan_is_expired(client: TestClient, db_engine: Engine) -> None:
    seeded = seed(db_engine)
    sign_in(seeded.owner)
    scan_id = add_scan(
        db_engine,
        seeded,
        status=ScanJobStatus.RUNNING,
        created_at=utc_now() - timedelta(minutes=20),
    )

    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "failed"


def test_dashboard_lists_only_website_scans(client: TestClient, db_engine: Engine) -> None:
    seeded = seed(db_engine)
    sign_in(seeded.owner)
    add_scan(db_engine, seeded, status=ScanJobStatus.DONE)

    assert client.get("/api/dashboard").json()["recent_scans"] == []


# --- pushes ---


def push(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    delivery: str | None = None,
    **overrides: Any,
) -> Any:
    monkeypatch.setattr(settings, "github_webhook_secret", SecretStr(SECRET))
    payload = {
        "ref": "refs/heads/main",
        "before": BEFORE,
        "after": AFTER,
        "installation": {"id": INSTALLATION_ID},
        "repository": {"id": GITHUB_REPO_ID},
    } | overrides
    body = json.dumps(payload).encode()
    return client.post(
        "/api/github/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": delivery or str(uuid4()),
            "X-Hub-Signature-256": "sha256="
            + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest(),
        },
    )


def test_first_push_starts_a_whole_history_scan(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = seed(db_engine)

    assert push(client, monkeypatch).json() == {"status": "processed"}

    scan = scans(db_engine)[0]
    assert (scan.before_sha, scan.after_sha) == (None, None)
    assert (scan.owner_id, scan.repo_id, scan.mode) == (seeded.owner, seeded.repo, ScanMode.FULL)
    assert queue.sent == [str(scan.id)]


def test_later_push_scans_only_new_commits(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed(db_engine, scanned=True)

    push(client, monkeypatch)

    scan = scans(db_engine)[0]
    assert (scan.before_sha, scan.after_sha) == (BEFORE, AFTER)


def test_replayed_push_starts_no_second_scan(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed(db_engine, scanned=True)
    delivery = str(uuid4())

    push(client, monkeypatch, delivery=delivery)
    replay = push(client, monkeypatch, delivery=delivery)

    assert replay.json() == {"status": "duplicate"}
    assert len(queue.sent) == 1


def test_tag_push_starts_no_scan(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed(db_engine, scanned=True)

    push(client, monkeypatch, ref="refs/tags/v1")

    assert queue.sent == []
    assert scans(db_engine) == []


def test_push_to_an_unlinked_repo_starts_no_scan(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    push(client, monkeypatch)

    assert queue.sent == []


def test_burst_of_first_pushes_queues_one_full_scan(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed(db_engine)

    push(client, monkeypatch)
    push(client, monkeypatch)
    push(client, monkeypatch)

    assert len(queue.sent) == 1


def test_push_while_a_full_scan_is_running_still_scans(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = seed(db_engine)
    add_scan(db_engine, seeded, status=ScanJobStatus.RUNNING)

    push(client, monkeypatch)

    assert len(queue.sent) == 1


def test_pushes_over_the_cap_are_caught_up_later(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = seed(db_engine, scanned=True)
    monkeypatch.setattr(github_webhook, "HOURLY_PUSH_SCAN_CAP", 1)
    add_scan(db_engine, seeded, status=ScanJobStatus.DONE, before_sha=BEFORE, after_sha=AFTER)

    assert push(client, monkeypatch).status_code == 200

    assert queue.sent == []
    assert load_repo(db_engine, seeded.repo).needs_full_scan


def test_broker_outage_is_caught_up_later(
    client: TestClient,
    db_engine: Engine,
    queue: FakeQueue,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = seed(db_engine, scanned=True)
    queue.down = True

    response = push(client, monkeypatch)

    assert response.status_code == 200
    assert load_repo(db_engine, seeded.repo).needs_full_scan
    assert scans(db_engine)[0].status is ScanJobStatus.FAILED
