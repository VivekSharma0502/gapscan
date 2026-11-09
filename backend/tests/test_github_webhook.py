"""GitHub webhook tests: signatures, replay protection and keeping repos in step."""

import hashlib
import hmac
import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.api import github_webhook
from app.api.github_webhook import (
    FULL_HISTORY,
    ZERO_SHA,
    PushEvent,
    PushRange,
    find_push_repo,
    is_valid_signature,
    push_scan_range,
)
from app.core.config import settings
from app.main import app
from app.models.github import GithubDelivery, GithubInstallation, Repo
from app.models.profile import Profile
from app.models.scan import utc_now

SECRET = "test-webhook-secret"  # noqa: S105
INSTALLATION_ID = 7
REPO_ID = 100
DELIVERY = "72d3162e-cc78-11e3-81ab-4c9367dc0958"
BEFORE = "a" * 40
AFTER = "b" * 40
URL = "/api/github/webhook"


def sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def repo_payload(repo_id: int = REPO_ID, name: str = "me/project") -> dict[str, Any]:
    return {"id": repo_id, "full_name": name, "private": True}


def push_payload(**overrides: Any) -> dict[str, Any]:
    return {
        "ref": "refs/heads/main",
        "before": BEFORE,
        "after": AFTER,
        "deleted": False,
        "forced": False,
        "installation": {"id": INSTALLATION_ID},
        "repository": {"id": REPO_ID},
    } | overrides


class FakeQueue:
    def apply_async(self, args: tuple[str], retry: bool = True) -> None:
        pass


@pytest.fixture
def client(db_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(settings, "github_webhook_secret", SecretStr(SECRET))
    monkeypatch.setattr(github_webhook, "run_repo_scan", FakeQueue())
    yield TestClient(app)


def post(
    client: TestClient,
    payload: Any,
    event: str = "installation",
    delivery: str | None = DELIVERY,
    signature: str | None = None,
) -> Any:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-Hub-Signature-256": signature if signature is not None else sign(body),
    }
    if delivery is not None:
        headers["X-GitHub-Delivery"] = delivery
    return client.post(URL, content=body, headers=headers)


def next_delivery() -> str:
    return str(uuid4())


def seed(
    engine: Engine,
    installation_id: int = INSTALLATION_ID,
    repo_ids: tuple[int, ...] = (REPO_ID,),
    owner: UUID | None = None,
    suspended: bool = False,
) -> UUID:
    owner = owner or uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        row = GithubInstallation(
            owner_id=owner,
            installation_id=installation_id,
            account_id=installation_id * 10,
            account_login="me",
            suspended_at=utc_now() if suspended else None,
        )
        session.add(row)
        session.flush()
        for repo_id in repo_ids:
            session.add(
                Repo(
                    owner_id=owner,
                    installation_id=row.id,
                    github_repo_id=repo_id,
                    full_name=f"me/repo-{repo_id}",
                    is_private=True,
                )
            )
        session.commit()
    return owner


def repo_ids(engine: Engine) -> set[int]:
    with Session(engine) as session:
        return {repo.github_repo_id for repo in session.exec(select(Repo))}


def installations(engine: Engine) -> list[GithubInstallation]:
    with Session(engine) as session:
        return list(session.exec(select(GithubInstallation)))


def deliveries(engine: Engine) -> list[str]:
    with Session(engine) as session:
        return [row.delivery_id for row in session.exec(select(GithubDelivery))]


def added(*repositories: dict[str, Any], installation_id: int = INSTALLATION_ID) -> dict[str, Any]:
    return {
        "action": "added",
        "installation": {"id": installation_id},
        "repositories_added": list(repositories),
        "repositories_removed": [],
    }


def removed(*ids: int, installation_id: int = INSTALLATION_ID) -> dict[str, Any]:
    return {
        "action": "removed",
        "installation": {"id": installation_id},
        "repositories_added": [],
        "repositories_removed": [{"id": repo_id} for repo_id in ids],
    }


def installation_event(action: str, installation_id: int = INSTALLATION_ID) -> dict[str, Any]:
    return {"action": action, "installation": {"id": installation_id}}


# --- signatures ---


def test_correct_signature_is_valid() -> None:
    assert is_valid_signature(b"body", sign(b"body"), SECRET)


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "sha256=",
        "sha256=not-hex",
        "sha256=" + "0" * 64,
        "sha256=é",
        hashlib.sha256(b"body").hexdigest(),
        "sha1=" + hmac.new(SECRET.encode(), b"body", hashlib.sha1).hexdigest(),  # noqa: S324
    ],
)
def test_bad_signature_headers_are_invalid(header: str | None) -> None:
    assert not is_valid_signature(b"body", header, SECRET)


def test_signature_is_tied_to_the_body() -> None:
    assert not is_valid_signature(b"tampered", sign(b"body"), SECRET)


def test_signature_is_tied_to_the_secret() -> None:
    assert not is_valid_signature(b"body", sign(b"body", "other-secret"), SECRET)


def test_tampered_request_is_refused_and_changes_nothing(
    client: TestClient, db_engine: Engine
) -> None:
    seed(db_engine)
    body = json.dumps(installation_event("deleted")).encode()

    response = post(client, body, signature=sign(b"something else"))

    assert response.status_code == 401
    assert len(installations(db_engine)) == 1
    assert deliveries(db_engine) == []


def test_missing_signature_is_refused(client: TestClient, db_engine: Engine) -> None:
    response = client.post(
        URL,
        content=b"{}",
        headers={"X-GitHub-Event": "installation", "X-GitHub-Delivery": DELIVERY},
    )

    assert response.status_code == 401


def test_nothing_is_accepted_without_a_configured_secret(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", SecretStr(""))
    # An empty secret would otherwise let anyone compute a valid signature.
    body = json.dumps(installation_event("deleted")).encode()

    assert post(client, body, signature=sign(body, "")).status_code == 503


def test_signature_is_checked_before_the_body_is_parsed(client: TestClient) -> None:
    response = post(client, b"not json", signature="sha256=" + "0" * 64)

    assert response.status_code == 401


def test_oversized_body_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, db_engine: Engine
) -> None:
    monkeypatch.setattr(github_webhook, "MAX_WEBHOOK_BYTES", 10)
    body = b"x" * 11

    assert post(client, body).status_code == 413
    assert deliveries(db_engine) == []


# --- events and replays ---


@pytest.mark.parametrize("event", ["ping", "issues", "star", ""])
def test_unknown_events_are_ignored_and_not_recorded(
    client: TestClient, db_engine: Engine, event: str
) -> None:
    response = post(client, b"anything", event=event)

    assert response.status_code == 200
    assert response.json() == {"status": "ignored"}
    assert deliveries(db_engine) == []


def test_unknown_event_still_needs_a_signature(client: TestClient) -> None:
    assert post(client, b"{}", event="star", signature="sha256=bad").status_code == 401


def test_replayed_delivery_does_nothing_the_second_time(
    client: TestClient, db_engine: Engine
) -> None:
    seed(db_engine, repo_ids=(REPO_ID, 200))
    payload = removed(REPO_ID)

    first = post(client, payload, event="installation_repositories")
    # Put the repo back through a fresh delivery, then replay the original removal.
    assert (
        post(
            client,
            added(repo_payload()),
            event="installation_repositories",
            delivery=next_delivery(),
        ).status_code
        == 200
    )
    replay = post(client, payload, event="installation_repositories")

    assert first.json() == {"status": "processed"}
    assert replay.status_code == 200
    assert replay.json() == {"status": "duplicate"}
    assert repo_ids(db_engine) == {REPO_ID, 200}


def test_delivery_is_recorded_when_processed(client: TestClient, db_engine: Engine) -> None:
    post(client, installation_event("created"))

    assert deliveries(db_engine) == [DELIVERY]


@pytest.mark.parametrize("delivery", [None, "", "short", "x" * 36, DELIVERY + "0"])
def test_bad_delivery_id_is_refused(
    client: TestClient, db_engine: Engine, delivery: str | None
) -> None:
    assert post(client, installation_event("created"), delivery=delivery).status_code == 400
    assert deliveries(db_engine) == []


def test_invalid_payload_is_refused_but_can_be_resent(
    client: TestClient, db_engine: Engine
) -> None:
    seed(db_engine)

    assert post(client, b"not json").status_code == 400
    assert deliveries(db_engine) == []

    assert post(client, installation_event("suspend")).json() == {"status": "processed"}


@pytest.mark.parametrize("payload", [{}, {"action": "deleted"}, [], {"installation": "7"}])
def test_payload_of_the_wrong_shape_is_refused(client: TestClient, payload: Any) -> None:
    assert post(client, payload).status_code == 400


def test_old_deliveries_are_pruned(client: TestClient, db_engine: Engine) -> None:
    old = next_delivery()
    with Session(db_engine) as session:
        session.add(GithubDelivery(delivery_id=old, received_at=utc_now() - timedelta(days=8)))
        session.commit()

    post(client, installation_event("created"))

    assert deliveries(db_engine) == [DELIVERY]


# --- installation events ---


def test_installation_created_links_nothing(client: TestClient, db_engine: Engine) -> None:
    response = post(client, installation_event("created"))

    assert response.json() == {"status": "processed"}
    assert installations(db_engine) == []


def test_uninstall_removes_only_that_installation(client: TestClient, db_engine: Engine) -> None:
    seed(db_engine)
    seed(db_engine, installation_id=8, repo_ids=(200,))

    post(client, installation_event("deleted"))

    assert [row.installation_id for row in installations(db_engine)] == [8]
    assert repo_ids(db_engine) == {200}


def test_suspend_and_unsuspend(client: TestClient, db_engine: Engine) -> None:
    seed(db_engine)

    post(client, installation_event("suspend"))
    assert installations(db_engine)[0].suspended_at is not None

    post(client, installation_event("unsuspend"), delivery=next_delivery())
    assert installations(db_engine)[0].suspended_at is None


def test_unknown_action_changes_nothing(client: TestClient, db_engine: Engine) -> None:
    seed(db_engine)

    assert post(client, installation_event("new_permissions_accepted")).status_code == 200
    assert installations(db_engine)[0].suspended_at is None
    assert repo_ids(db_engine) == {REPO_ID}


def test_event_for_an_unlinked_installation_does_nothing(
    client: TestClient, db_engine: Engine
) -> None:
    seed(db_engine)

    post(client, installation_event("deleted", installation_id=999))

    assert len(installations(db_engine)) == 1


# --- repos being added and removed ---


def test_added_repos_are_saved_for_the_installation_owner(
    client: TestClient, db_engine: Engine
) -> None:
    owner = seed(db_engine, repo_ids=())

    post(client, added(repo_payload()), event="installation_repositories")

    with Session(db_engine) as session:
        repo = session.exec(select(Repo)).one()
    assert (repo.github_repo_id, repo.full_name, repo.owner_id) == (REPO_ID, "me/project", owner)


def test_removed_repos_are_deleted(client: TestClient, db_engine: Engine) -> None:
    seed(db_engine, repo_ids=(REPO_ID, 200))

    post(client, removed(REPO_ID), event="installation_repositories")

    assert repo_ids(db_engine) == {200}


def test_removal_cannot_reach_another_installations_repo(
    client: TestClient, db_engine: Engine
) -> None:
    seed(db_engine, repo_ids=())
    seed(db_engine, installation_id=8, repo_ids=(REPO_ID,))

    post(client, removed(REPO_ID), event="installation_repositories")

    assert repo_ids(db_engine) == {REPO_ID}


def test_transferred_repo_moves_to_a_fresh_row(client: TestClient, db_engine: Engine) -> None:
    new_owner = seed(db_engine, repo_ids=())
    seed(db_engine, installation_id=8, repo_ids=(REPO_ID,))
    with Session(db_engine) as session:
        old_id = session.exec(select(Repo)).one().id

    post(client, added(repo_payload()), event="installation_repositories")

    with Session(db_engine) as session:
        repo = session.exec(select(Repo)).one()
    assert repo.owner_id == new_owner
    assert repo.id != old_id


def test_repos_for_an_unlinked_installation_are_not_saved(
    client: TestClient, db_engine: Engine
) -> None:
    post(client, added(repo_payload()), event="installation_repositories")

    assert repo_ids(db_engine) == set()


@pytest.mark.parametrize("name", ["no-slash", "a/b/c", "owner/..", "owner/x y", "-owner/repo"])
def test_unsafe_repo_name_in_a_webhook_is_refused(
    client: TestClient, db_engine: Engine, name: str
) -> None:
    seed(db_engine, repo_ids=())

    response = post(client, added(repo_payload(name=name)), event="installation_repositories")

    assert response.status_code == 400
    assert repo_ids(db_engine) == set()


# --- pushes ---


def event_from(**overrides: Any) -> PushEvent:
    return PushEvent.model_validate(push_payload(**overrides))


def scanned_repo() -> Repo:
    return Repo(
        owner_id=uuid4(),
        installation_id=uuid4(),
        github_repo_id=REPO_ID,
        full_name="me/project",
        is_private=True,
        first_full_scan_at=utc_now(),
    )


def test_push_scans_only_the_new_commits() -> None:
    assert push_scan_range(event_from(), scanned_repo()) == PushRange(BEFORE, AFTER)


def test_first_scan_is_always_the_whole_history() -> None:
    repo = scanned_repo()
    repo.first_full_scan_at = None

    assert push_scan_range(event_from(), repo) == FULL_HISTORY


def test_missed_push_forces_the_whole_history() -> None:
    repo = scanned_repo()
    repo.needs_full_scan = True

    assert push_scan_range(event_from(), repo) == FULL_HISTORY


def test_force_push_scans_the_whole_history() -> None:
    assert push_scan_range(event_from(forced=True), scanned_repo()) == FULL_HISTORY


def test_new_branch_has_no_before() -> None:
    assert push_scan_range(event_from(before=ZERO_SHA), scanned_repo()) == PushRange(None, AFTER)


@pytest.mark.parametrize(
    "overrides",
    [
        {"ref": "refs/tags/v1"},
        {"ref": "refs/pull/1/head"},
        {"deleted": True},
        {"after": ZERO_SHA},
    ],
)
def test_pushes_with_nothing_to_scan(overrides: dict[str, Any]) -> None:
    assert push_scan_range(event_from(**overrides), scanned_repo()) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"before": "--output=/tmp/x"},
        {"after": "main"},
        {"after": "B" * 40},
        {"after": "a" * 39},
        {"after": "a" * 40 + "\n"},
        {"before": "a" * 40 + " --all"},
    ],
)
def test_push_with_an_unsafe_commit_id_is_refused(
    client: TestClient, db_engine: Engine, overrides: dict[str, Any]
) -> None:
    seed(db_engine)

    assert post(client, push_payload(**overrides), event="push").status_code == 400


def test_push_ignores_author_details(client: TestClient, db_engine: Engine) -> None:
    seed(db_engine)
    payload = push_payload(
        pusher={"name": "someone", "email": "person@example.com"},
        commits=[{"author": {"email": "person@example.com"}, "message": "hello"}],
    )

    assert post(client, payload, event="push").json() == {"status": "processed"}
    assert not hasattr(PushEvent.model_validate(payload), "pusher")


def test_push_finds_a_linked_repo(db_engine: Engine) -> None:
    seed(db_engine)

    with Session(db_engine) as session:
        repo = find_push_repo(session, event_from())

    assert repo is not None
    assert repo.github_repo_id == REPO_ID


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository": {"id": 999}},
        {"installation": {"id": 999}},
    ],
)
def test_push_for_an_unknown_repo_or_installation_finds_nothing(
    db_engine: Engine, overrides: dict[str, Any]
) -> None:
    seed(db_engine)

    with Session(db_engine) as session:
        assert find_push_repo(session, event_from(**overrides)) is None


def test_push_cannot_reach_a_repo_through_another_installation(db_engine: Engine) -> None:
    seed(db_engine, repo_ids=(REPO_ID,))
    seed(db_engine, installation_id=8, repo_ids=())

    with Session(db_engine) as session:
        assert find_push_repo(session, event_from(installation={"id": 8})) is None


def test_push_on_a_suspended_installation_finds_nothing(db_engine: Engine) -> None:
    seed(db_engine, suspended=True)

    with Session(db_engine) as session:
        assert find_push_repo(session, event_from()) is None
