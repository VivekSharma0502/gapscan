"""Linking a GitHub App installation to a user. Offline: GitHub and Supabase are faked."""

import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.api import github as github_api
from app.api.scans import hash_token
from app.core import auth
from app.core.auth import AuthUnavailableError, Viewer, fetch_github_account_id, get_viewer
from app.core.config import settings
from app.core.github_app import (
    GithubAccount,
    GithubApiError,
    GithubInstallationInfo,
    GithubRepository,
    InstallationToken,
)
from app.core.rate_limit import limiter
from app.core.safe_http import RequestFailedError, SafeResponse
from app.main import app
from app.models.github import GithubInstallation, GithubInstallState, Repo
from app.models.profile import Profile
from app.models.scan import utc_now

MY_GITHUB_ID = 42
OTHER_GITHUB_ID = 99
INSTALLATION_ID = 7
AUTH_HEADER = {"Authorization": "Bearer user-access-token"}
TOKEN = InstallationToken("ghs_listing_token")


def repository(repo_id: int = 1, name: str = "me/project") -> GithubRepository:
    return GithubRepository(id=repo_id, full_name=name, private=True, size=10)


def installation(
    account_id: int = MY_GITHUB_ID,
    account_type: str = "User",
    suspended: bool = False,
) -> GithubInstallationInfo:
    return GithubInstallationInfo(
        id=INSTALLATION_ID,
        account=GithubAccount(id=account_id, login="me", type=account_type),
        suspended_at=utc_now() if suspended else None,
    )


class FakeGithub:
    """Stands in for the GitHub and Supabase lookups, and records what was asked."""

    def __init__(self) -> None:
        self.github_account_id: int | None = MY_GITHUB_ID
        self.identity_error: Exception | None = None
        self.installation: GithubInstallationInfo | None = installation()
        self.repositories = [repository()]
        self.list_error: Exception | None = None
        self.lookups: list[int] = []
        self.revoked: list[InstallationToken] = []
        self.access_tokens: list[str] = []

    def identity(self, access_token: str, _viewer_id: UUID) -> int | None:
        self.access_tokens.append(access_token)
        if self.identity_error is not None:
            raise self.identity_error
        return self.github_account_id

    def get_installation(self, installation_id: int) -> GithubInstallationInfo | None:
        self.lookups.append(installation_id)
        return self.installation

    def list_repositories(self, _token: InstallationToken) -> list[GithubRepository]:
        if self.list_error is not None:
            raise self.list_error
        return self.repositories


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> FakeGithub:
    fake = FakeGithub()
    monkeypatch.setattr(github_api, "fetch_github_account_id", fake.identity)
    monkeypatch.setattr(github_api, "get_installation", fake.get_installation)
    monkeypatch.setattr(github_api, "create_installation_token", lambda _id: TOKEN)
    monkeypatch.setattr(github_api, "list_installation_repositories", fake.list_repositories)
    monkeypatch.setattr(github_api, "revoke_installation_token", fake.revoked.append)
    monkeypatch.setattr(settings, "github_app_slug", "gapscan-dev")
    return fake


@pytest.fixture
def client(db_engine: Engine, github: FakeGithub) -> Iterator[TestClient]:
    limiter.reset()
    yield TestClient(app, headers=AUTH_HEADER)
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


def new_state(client: TestClient) -> str:
    response = client.post("/api/github/install-url")
    assert response.status_code == 200
    return parse_qs(urlparse(response.json()["url"]).query)["state"][0]


def link(client: TestClient, state: str, installation_id: int = INSTALLATION_ID) -> Any:
    return client.post(
        "/api/github/installations/link",
        json={"installation_id": installation_id, "state": state},
    )


def saved_installations(engine: Engine) -> list[GithubInstallation]:
    with Session(engine) as session:
        return list(session.exec(select(GithubInstallation)))


def saved_repos(engine: Engine) -> list[Repo]:
    with Session(engine) as session:
        return list(session.exec(select(Repo)))


def seed_installation(
    engine: Engine,
    owner: UUID,
    installation_id: int = INSTALLATION_ID,
    account_id: int = MY_GITHUB_ID,
    repo_ids: tuple[int, ...] = (),
) -> UUID:
    with Session(engine) as session:
        if session.get(Profile, owner) is None:
            session.add(Profile(id=owner))
            session.flush()
        row = GithubInstallation(
            owner_id=owner,
            installation_id=installation_id,
            account_id=account_id,
            account_login="me",
        )
        session.add(row)
        session.flush()
        for repo_id in repo_ids:
            session.add(
                Repo(
                    owner_id=owner,
                    installation_id=row.id,
                    github_repo_id=repo_id,
                    full_name=f"me/old-{repo_id}",
                    is_private=False,
                )
            )
        session.commit()
        return row.id


# --- starting an install ---


def test_install_url_needs_sign_in(db_engine: Engine, github: FakeGithub) -> None:
    limiter.reset()
    response = TestClient(app).post("/api/github/install-url")

    assert response.status_code == 401


@pytest.mark.usefixtures("me")
def test_install_url_points_at_the_app_with_a_state(client: TestClient) -> None:
    url = urlparse(client.post("/api/github/install-url").json()["url"])

    assert (url.scheme, url.netloc) == ("https", "github.com")
    assert url.path == "/apps/gapscan-dev/installations/new"
    assert len(parse_qs(url.query)["state"][0]) >= 32


def test_only_a_hash_of_the_state_is_stored(
    client: TestClient, db_engine: Engine, me: UUID
) -> None:
    state = new_state(client)

    with Session(db_engine) as session:
        row = session.exec(select(GithubInstallState)).one()
    assert row.owner_id == me
    assert row.token_hash == hash_token(state)
    assert state not in row.token_hash


@pytest.mark.usefixtures("me")
def test_install_url_is_unavailable_without_an_app(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "github_app_slug", "")

    assert client.post("/api/github/install-url").status_code == 503


# --- linking ---


def test_link_saves_the_verified_installation_and_its_repos(
    client: TestClient, db_engine: Engine, github: FakeGithub, me: UUID
) -> None:
    github.repositories = [repository(1, "me/one"), repository(2, "me/two")]

    response = link(client, new_state(client))

    assert response.status_code == 200
    assert response.json() == {"account_login": "me", "repositories": 2}
    row = saved_installations(db_engine)[0]
    assert (row.owner_id, row.installation_id, row.account_id) == (me, 7, MY_GITHUB_ID)
    assert {repo.full_name for repo in saved_repos(db_engine)} == {"me/one", "me/two"}
    assert github.access_tokens == ["user-access-token"]


@pytest.mark.usefixtures("me")
def test_listing_token_is_revoked_after_use(client: TestClient, github: FakeGithub) -> None:
    link(client, new_state(client))

    assert github.revoked == [TOKEN]


@pytest.mark.usefixtures("me")
def test_listing_token_is_revoked_when_listing_fails(
    client: TestClient, github: FakeGithub
) -> None:
    github.list_error = GithubApiError("down")

    assert link(client, new_state(client)).status_code == 502
    assert github.revoked == [TOKEN]


@pytest.mark.usefixtures("me")
def test_forged_installation_of_another_account_is_refused(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    github.installation = installation(account_id=OTHER_GITHUB_ID)

    response = link(client, new_state(client))

    assert response.status_code == 403
    assert saved_installations(db_engine) == []
    assert saved_repos(db_engine) == []


@pytest.mark.usefixtures("me")
def test_unknown_and_foreign_installations_look_the_same(
    client: TestClient, github: FakeGithub
) -> None:
    github.installation = None
    unknown = link(client, new_state(client))
    github.installation = installation(account_id=OTHER_GITHUB_ID)
    foreign = link(client, new_state(client))
    github.installation = installation(account_id=OTHER_GITHUB_ID, account_type="Organization")
    organization = link(client, new_state(client))

    assert unknown.status_code == foreign.status_code == organization.status_code == 403
    assert unknown.json() == foreign.json() == organization.json()


@pytest.mark.usefixtures("me")
def test_organization_is_refused_even_if_the_ids_match(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    github.installation = installation(account_type="Organization")

    assert link(client, new_state(client)).status_code == 403
    assert saved_installations(db_engine) == []


@pytest.mark.usefixtures("me")
def test_user_without_a_github_sign_in_is_refused(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    github.github_account_id = None

    response = link(client, new_state(client))

    assert response.status_code == 403
    assert "Sign in with GitHub" in response.json()["detail"]
    assert github.lookups == []
    assert saved_installations(db_engine) == []


@pytest.mark.usefixtures("me")
def test_suspended_installation_is_refused(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    github.installation = installation(suspended=True)

    assert link(client, new_state(client)).status_code == 409
    assert saved_installations(db_engine) == []


@pytest.mark.usefixtures("me")
def test_unknown_state_is_refused_before_asking_github(
    client: TestClient, github: FakeGithub
) -> None:
    assert link(client, "made-up-state").status_code == 400
    assert github.lookups == []
    assert github.access_tokens == []


@pytest.mark.usefixtures("me")
def test_state_works_only_once(client: TestClient, github: FakeGithub) -> None:
    state = new_state(client)

    assert link(client, state).status_code == 200
    assert link(client, state).status_code == 400
    assert github.lookups == [INSTALLATION_ID]


@pytest.mark.usefixtures("me")
def test_expired_state_is_refused(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    state = new_state(client)
    with Session(db_engine) as session:
        row = session.exec(select(GithubInstallState)).one()
        row.expires_at = utc_now() - timedelta(seconds=1)
        session.add(row)
        session.commit()

    assert link(client, state).status_code == 400
    assert github.lookups == []


@pytest.mark.usefixtures("me")
def test_failed_check_uses_up_the_state(client: TestClient, github: FakeGithub) -> None:
    github.installation = installation(account_id=OTHER_GITHUB_ID)
    state = new_state(client)

    assert link(client, state).status_code == 403
    github.installation = installation()
    assert link(client, state).status_code == 400


def test_state_of_another_user_is_refused_and_not_used_up(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    victim, attacker = uuid4(), uuid4()
    sign_in(victim)
    state = new_state(client)

    sign_in(attacker)
    assert link(client, state).status_code == 400
    assert github.lookups == []
    assert saved_installations(db_engine) == []

    sign_in(victim)
    assert link(client, state).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"installation_id": 0, "state": "x"},
        {"installation_id": -1, "state": "x"},
        {"installation_id": 2**63, "state": "x"},
        {"installation_id": "7; drop", "state": "x"},
        {"installation_id": 7, "state": ""},
        {"installation_id": 7, "state": "x" * 129},
        {"installation_id": 7, "state": "x", "owner_id": "someone"},
        {"state": "x"},
    ],
)
@pytest.mark.usefixtures("me")
def test_malformed_link_requests_are_rejected(client: TestClient, body: dict[str, Any]) -> None:
    response = client.post("/api/github/installations/link", json=body)

    assert response.status_code == 422


def test_link_needs_sign_in(db_engine: Engine, github: FakeGithub) -> None:
    limiter.reset()
    response = TestClient(app).post(
        "/api/github/installations/link", json={"installation_id": 7, "state": "x"}
    )

    assert response.status_code == 401
    assert github.lookups == []


def test_installation_owned_by_another_user_is_not_taken_over(
    client: TestClient, db_engine: Engine, github: FakeGithub, me: UUID
) -> None:
    earlier_owner = uuid4()
    seed_installation(db_engine, earlier_owner, repo_ids=(1,))

    response = link(client, new_state(client))

    assert response.status_code == 409
    rows = saved_installations(db_engine)
    assert [row.owner_id for row in rows] == [earlier_owner]
    assert saved_repos(db_engine)[0].owner_id == earlier_owner


def test_linking_again_updates_the_repo_list(
    client: TestClient, db_engine: Engine, github: FakeGithub, me: UUID
) -> None:
    seed_installation(db_engine, me, repo_ids=(1, 2))
    github.repositories = [repository(1, "me/renamed"), repository(3, "me/new")]

    assert link(client, new_state(client)).status_code == 200

    assert len(saved_installations(db_engine)) == 1
    repos = {repo.github_repo_id: repo.full_name for repo in saved_repos(db_engine)}
    assert repos == {1: "me/renamed", 3: "me/new"}


def test_transferred_repo_is_recreated_for_its_new_owner(
    client: TestClient, db_engine: Engine, github: FakeGithub, me: UUID
) -> None:
    old_owner = uuid4()
    seed_installation(db_engine, old_owner, 55, OTHER_GITHUB_ID, repo_ids=(1,))
    old_row = saved_repos(db_engine)[0]

    assert link(client, new_state(client)).status_code == 200

    repos = saved_repos(db_engine)
    assert len(repos) == 1
    assert repos[0].owner_id == me
    assert repos[0].id != old_row.id


def test_reinstalling_replaces_the_dead_installation(
    client: TestClient, db_engine: Engine, github: FakeGithub, me: UUID
) -> None:
    seed_installation(db_engine, me, installation_id=3, repo_ids=(1,))

    assert link(client, new_state(client)).status_code == 200

    assert [row.installation_id for row in saved_installations(db_engine)] == [INSTALLATION_ID]
    assert len(saved_repos(db_engine)) == 1


@pytest.mark.usefixtures("me")
def test_github_outage_saves_nothing(
    client: TestClient, db_engine: Engine, github: FakeGithub
) -> None:
    github.list_error = GithubApiError("down")

    assert link(client, new_state(client)).status_code == 502
    assert saved_installations(db_engine) == []


@pytest.mark.usefixtures("me")
def test_supabase_outage_is_not_treated_as_no_identity(
    client: TestClient, github: FakeGithub
) -> None:
    github.identity_error = AuthUnavailableError("down")

    assert link(client, new_state(client)).status_code == 503
    assert github.lookups == []


# --- listing repos ---


def test_repo_list_shows_only_your_own(
    client: TestClient, db_engine: Engine, github: FakeGithub, me: UUID
) -> None:
    seed_installation(db_engine, me, repo_ids=(1,))
    seed_installation(db_engine, uuid4(), 8, OTHER_GITHUB_ID, repo_ids=(2,))

    response = client.get("/api/repos")

    assert response.status_code == 200
    assert [repo["full_name"] for repo in response.json()] == ["me/old-1"]
    assert response.json()[0]["account_login"] == "me"


def test_repo_list_needs_sign_in(db_engine: Engine) -> None:
    assert TestClient(app).get("/api/repos").status_code == 401


# --- which GitHub account a user really is ---

VIEWER_ID = uuid4()
GITHUB_IDENTITY = {"provider": "github", "id": str(MY_GITHUB_ID)}


class FakeSupabase:
    def __init__(self) -> None:
        self.status = 200
        self.body: Any = {"id": str(VIEWER_ID), "identities": [GITHUB_IDENTITY]}
        self.calls: list[dict[str, Any]] = []
        self.error: Exception | None = None

    def __call__(self, method: str, url: str, *, headers: dict[str, str]) -> SafeResponse:
        self.calls.append({"method": method, "url": url, "headers": headers})
        if self.error is not None:
            raise self.error
        content = json.dumps(self.body).encode()
        return SafeResponse(url, self.status, httpx.Headers(), content, False, ())


@pytest.fixture
def supabase(monkeypatch: pytest.MonkeyPatch) -> FakeSupabase:
    fake = FakeSupabase()
    monkeypatch.setattr(auth, "safe_api_request", fake)
    monkeypatch.setattr(settings, "supabase_url", "https://abcd.supabase.co")
    monkeypatch.setattr(settings, "supabase_publishable_key", "sb_publishable_x")
    return fake


def test_identity_is_asked_of_supabase_as_the_user(supabase: FakeSupabase) -> None:
    assert fetch_github_account_id("the-token", VIEWER_ID) == MY_GITHUB_ID

    call = supabase.calls[0]
    assert call["url"] == "https://abcd.supabase.co/auth/v1/user"
    assert call["headers"]["apikey"] == "sb_publishable_x"
    assert call["headers"]["Authorization"] == "Bearer the-token"


def test_user_editable_metadata_cannot_change_the_answer(supabase: FakeSupabase) -> None:
    supabase.body |= {
        "user_metadata": {
            "provider_id": str(OTHER_GITHUB_ID),
            "sub": str(OTHER_GITHUB_ID),
            "user_name": "victim",
        }
    }

    assert fetch_github_account_id("t", VIEWER_ID) == MY_GITHUB_ID


def test_metadata_alone_is_not_an_identity(supabase: FakeSupabase) -> None:
    supabase.body = {
        "id": str(VIEWER_ID),
        "identities": [],
        "user_metadata": {"provider_id": str(OTHER_GITHUB_ID)},
    }

    assert fetch_github_account_id("t", VIEWER_ID) is None


@pytest.mark.parametrize(
    "identities",
    [
        None,
        [],
        [{"provider": "email", "id": "123"}],
        [{"provider": "github", "id": "not-a-number"}],
        [{"provider": "github", "id": "٤٢"}],
    ],
)
def test_no_usable_github_identity_is_none(
    supabase: FakeSupabase, identities: list[dict[str, str]] | None
) -> None:
    supabase.body["identities"] = identities

    assert fetch_github_account_id("t", VIEWER_ID) is None


def test_github_identity_is_found_among_several(supabase: FakeSupabase) -> None:
    supabase.body["identities"] = [{"provider": "email", "id": "abc"}, GITHUB_IDENTITY]

    assert fetch_github_account_id("t", VIEWER_ID) == MY_GITHUB_ID


def test_a_different_user_in_the_answer_is_refused(supabase: FakeSupabase) -> None:
    supabase.body["id"] = str(uuid4())

    with pytest.raises(AuthUnavailableError):
        fetch_github_account_id("t", VIEWER_ID)


@pytest.mark.parametrize("status", [401, 500])
def test_supabase_error_is_not_read_as_no_identity(supabase: FakeSupabase, status: int) -> None:
    supabase.status = status

    with pytest.raises(AuthUnavailableError):
        fetch_github_account_id("t", VIEWER_ID)


def test_unreachable_supabase_is_unavailable(supabase: FakeSupabase) -> None:
    supabase.error = RequestFailedError("down")

    with pytest.raises(AuthUnavailableError):
        fetch_github_account_id("t", VIEWER_ID)


def test_malformed_supabase_answer_is_unavailable(supabase: FakeSupabase) -> None:
    supabase.body = {"unexpected": True}

    with pytest.raises(AuthUnavailableError):
        fetch_github_account_id("t", VIEWER_ID)


def test_missing_publishable_key_is_unavailable(
    supabase: FakeSupabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "supabase_publishable_key", "")

    with pytest.raises(AuthUnavailableError):
        fetch_github_account_id("t", VIEWER_ID)

    assert supabase.calls == []
