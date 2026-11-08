"""GitHub App client tests. Offline: the guarded request function is faked."""

import base64
import json
import logging
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from app.core import github_app
from app.core.config import settings
from app.core.github_app import (
    GithubApiError,
    GithubAppNotConfiguredError,
    GithubRepository,
    InstallationToken,
    app_jwt,
    create_installation_token,
    get_installation,
    get_repository,
    list_installation_repositories,
    revoke_installation_token,
)
from app.core.safe_http import RequestFailedError, SafeResponse

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
TOKEN = InstallationToken("ghs_example_token_value")
INSTALLATION = {"id": 7, "account": {"id": 42, "login": "someone", "type": "User"}}
REPO = {"id": 9, "full_name": "someone/project", "private": True, "size": 120}


class FakeGithub:
    def __init__(self) -> None:
        self.responses: list[SafeResponse] = []
        self.calls: list[dict[str, Any]] = []
        self.error: Exception | None = None

    def queue(self, status: int, body: Any = None, truncated: bool = False) -> None:
        content = b"" if body is None else json.dumps(body).encode()
        self.responses.append(
            SafeResponse("https://api.github.com", status, httpx.Headers(), content, truncated, ())
        )

    def __call__(
        self, method: str, url: str, *, headers: dict[str, str], json_body: Any = None
    ) -> SafeResponse:
        self.calls.append({"method": method, "url": url, "headers": headers, "body": json_body})
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


@pytest.fixture
def github(monkeypatch: pytest.MonkeyPatch) -> FakeGithub:
    fake = FakeGithub()
    monkeypatch.setattr(github_app, "safe_api_request", fake)
    monkeypatch.setattr(settings, "github_app_id", "12345")
    monkeypatch.setattr(
        settings, "github_app_private_key_b64", SecretStr(base64.b64encode(PEM).decode())
    )
    return fake


@pytest.mark.usefixtures("github")
def test_app_jwt_is_signed_short_lived_and_names_the_app() -> None:
    claims = jwt.decode(
        app_jwt(),
        KEY.public_key(),
        algorithms=["RS256"],
        options={"verify_iat": False, "require": ["iat", "exp", "iss"]},
    )

    assert claims["iss"] == "12345"
    assert claims["exp"] - claims["iat"] <= 600


@pytest.mark.parametrize("value", ["", "not base64!", base64.b64encode(b"not a pem").decode()])
def test_unusable_private_key_is_refused(
    github: FakeGithub, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setattr(settings, "github_app_private_key_b64", SecretStr(value))

    with pytest.raises(GithubAppNotConfiguredError):
        app_jwt()


def test_a_valid_pem_that_is_not_a_key_is_refused(
    github: FakeGithub, monkeypatch: pytest.MonkeyPatch
) -> None:
    garbage = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    monkeypatch.setattr(
        settings, "github_app_private_key_b64", SecretStr(base64.b64encode(garbage).decode())
    )

    with pytest.raises(GithubAppNotConfiguredError):
        app_jwt()


def test_missing_app_id_is_refused(github: FakeGithub, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "github_app_id", "")

    with pytest.raises(GithubAppNotConfiguredError):
        app_jwt()


def test_get_installation_uses_the_app_jwt_and_returns_the_numeric_account(
    github: FakeGithub,
) -> None:
    github.queue(200, INSTALLATION)

    installation = get_installation(7)

    assert installation is not None
    assert installation.account.id == 42
    call = github.calls[0]
    assert call["url"] == "https://api.github.com/app/installations/7"
    claims = jwt.decode(
        call["headers"]["Authorization"].removeprefix("Bearer "),
        KEY.public_key(),
        algorithms=["RS256"],
        options={"verify_iat": False},
    )
    assert claims["iss"] == "12345"


def test_unknown_installation_is_none(github: FakeGithub) -> None:
    github.queue(404)

    assert get_installation(7) is None


def test_server_error_is_not_mistaken_for_a_missing_installation(github: FakeGithub) -> None:
    github.queue(500)

    with pytest.raises(GithubApiError):
        get_installation(7)


def test_network_failure_becomes_a_github_error(github: FakeGithub) -> None:
    github.error = RequestFailedError("request failed")

    with pytest.raises(GithubApiError):
        get_installation(7)


def test_truncated_response_is_not_parsed(github: FakeGithub) -> None:
    github.queue(200, INSTALLATION, truncated=True)

    with pytest.raises(GithubApiError):
        get_installation(7)


def test_scan_token_is_limited_to_one_repo_and_read_only(github: FakeGithub) -> None:
    github.queue(201, {"token": TOKEN.value})

    token = create_installation_token(7, [9])

    assert token == TOKEN
    assert github.calls[0]["url"].endswith("/app/installations/7/access_tokens")
    assert github.calls[0]["body"] == {
        "repository_ids": [9],
        "permissions": {"contents": "read", "metadata": "read"},
    }


def test_listing_token_cannot_read_code(github: FakeGithub) -> None:
    github.queue(201, {"token": TOKEN.value})

    create_installation_token(7)

    assert github.calls[0]["body"] == {"permissions": {"metadata": "read"}}


def test_token_is_not_in_the_repr() -> None:
    assert TOKEN.value not in repr(TOKEN)


def test_token_is_not_in_a_parse_error(github: FakeGithub) -> None:
    leaked_value = "ghs_should_never_appear"
    github.queue(201, {"token": {"nested": leaked_value}})

    with pytest.raises(GithubApiError) as caught:
        create_installation_token(7)

    assert leaked_value not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_revoke_uses_the_token_itself(github: FakeGithub) -> None:
    github.queue(204)

    revoke_installation_token(TOKEN)

    call = github.calls[0]
    assert call["method"] == "DELETE"
    assert call["url"].endswith("/installation/token")
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN.value}"


def test_failed_revoke_does_not_raise_or_log_the_token(
    github: FakeGithub, caplog: pytest.LogCaptureFixture
) -> None:
    github.error = RequestFailedError("request failed")

    with caplog.at_level(logging.WARNING):
        revoke_installation_token(TOKEN)

    assert caplog.records
    assert TOKEN.value not in caplog.text


def test_repositories_are_collected_across_pages(github: FakeGithub) -> None:
    second = REPO | {"id": 10, "full_name": "someone/other"}
    github.queue(200, {"total_count": 2, "repositories": [REPO]})
    github.queue(200, {"total_count": 2, "repositories": [second]})

    repositories = list_installation_repositories(TOKEN)

    assert [repo.id for repo in repositories] == [9, 10]
    assert "page=2" in github.calls[1]["url"]


def test_incomplete_repository_list_is_an_error(
    github: FakeGithub, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(github_app, "MAX_REPO_PAGES", 1)
    github.queue(200, {"total_count": 2, "repositories": [REPO]})

    with pytest.raises(GithubApiError):
        list_installation_repositories(TOKEN)


def test_repository_is_looked_up_by_numeric_id(github: FakeGithub) -> None:
    github.queue(200, REPO)

    repository = get_repository(TOKEN, 9)

    assert repository is not None
    assert repository.full_name == "someone/project"
    assert github.calls[0]["url"].endswith("/repositories/9")


def test_missing_repository_is_none(github: FakeGithub) -> None:
    github.queue(404)

    assert get_repository(TOKEN, 9) is None


@pytest.mark.parametrize(
    "full_name",
    [
        "someone/project",
        "some-one/project.name_x-1",
        "enterprise_user/repo",
    ],
)
def test_valid_repository_names_are_accepted(full_name: str) -> None:
    assert GithubRepository(**REPO | {"full_name": full_name}).full_name == full_name


@pytest.mark.parametrize(
    "full_name",
    [
        "project",
        "a/b/c",
        "-owner/repo",
        "owner/..",
        "owner/.",
        "owner/repo name",
        "owner/repo\n",
        "owner/repo@evil.example",
        "owner/repo:8080",
        "https://evil.example/owner/repo",
        "../owner/repo",
        "owner/" + "x" * 101,
        "o" * 40 + "/repo",
    ],
)
def test_unsafe_repository_names_are_refused(github: FakeGithub, full_name: str) -> None:
    github.queue(200, REPO | {"full_name": full_name})

    with pytest.raises(GithubApiError):
        get_repository(TOKEN, 9)
