"""GitHub App API calls. Everything goes through safe_http, and no token is ever stored.

The app proves who it is with a JWT signed by its private key, then swaps that for an
installation token that expires within the hour.
"""

import base64
import binascii
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, TypeVar

import jwt
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.core.config import settings
from app.core.safe_http import SafeHttpError, SafeResponse, safe_api_request

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
API_VERSION = "2022-11-28"

# GitHub rejects a JWT that lasts over 10 minutes or is dated in the future by its clock, so
# it is backdated a minute and kept under the limit to allow for clock drift.
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 540

REPOS_PER_PAGE = 100
MAX_REPO_PAGES = 10

# Security: this name ends up in a git URL. A strict pattern means a value GitHub returns can
# only ever be one owner and one repo, with no room for another host, path or git option.
_FULL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}/[A-Za-z0-9._-]{1,100}")
_DOT_NAMES = {".", ".."}

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class GithubAppNotConfiguredError(Exception):
    """The app's id or private key is missing or unusable."""


class GithubApiError(Exception):
    """GitHub couldn't be reached or gave an unusable answer. Messages never include bodies."""


class _Response(BaseModel):
    # Security: a validation error normally quotes its input, which here could be a token.
    model_config = ConfigDict(hide_input_in_errors=True)


class GithubAccount(_Response):
    # The numeric id is the identity. A login can be renamed and then claimed by someone else.
    id: int
    login: str = Field(min_length=1, max_length=39)
    type: str


class GithubInstallationInfo(_Response):
    id: int
    account: GithubAccount
    suspended_at: datetime | None = None


class GithubRepository(_Response):
    id: int
    full_name: str
    private: bool
    # In kilobytes, as GitHub last measured it, so only a first check on size.
    size: int = Field(ge=0)

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        if not _FULL_NAME_RE.fullmatch(value) or value.split("/")[1] in _DOT_NAMES:
            raise ValueError("not an owner/name pair")
        return value


class _TokenResponse(_Response):
    token: str = Field(min_length=1)


class _RepositoryPage(_Response):
    total_count: int = Field(ge=0)
    repositories: list[GithubRepository]


@dataclass(frozen=True)
class InstallationToken:
    # Security: repr=False keeps the token out of logs and tracebacks that print this object.
    value: str = field(repr=False)


def _private_key() -> str:
    encoded = settings.github_app_private_key_b64.get_secret_value().strip()
    if not encoded or not settings.github_app_id:
        raise GithubAppNotConfiguredError("the GitHub App is not configured")
    try:
        key = base64.b64decode(encoded, validate=True).decode("ascii")
    except (binascii.Error, ValueError):
        # Security: "from None", so the traceback carries no part of the key.
        raise GithubAppNotConfiguredError("the private key is not valid base64") from None
    if not key.lstrip().startswith("-----BEGIN"):
        raise GithubAppNotConfiguredError("the private key is not a PEM file")
    return key


def app_jwt() -> str:
    """Return a short-lived token that identifies the app itself."""
    key = _private_key()
    now = int(time.time())
    payload = {
        "iat": now - JWT_BACKDATE_SECONDS,
        "exp": now + JWT_LIFETIME_SECONDS,
        "iss": settings.github_app_id,
    }
    try:
        return jwt.encode(payload, key, algorithm="RS256")
    except (jwt.PyJWTError, ValueError, TypeError):
        raise GithubAppNotConfiguredError("the private key could not sign a token") from None


def _request(
    method: Literal["GET", "POST", "DELETE"],
    path: str,
    bearer: str,
    json_body: Any = None,
) -> SafeResponse:
    try:
        response = safe_api_request(
            method,
            f"{GITHUB_API}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {bearer}",
                "X-GitHub-Api-Version": API_VERSION,
            },
            json_body=json_body,
        )
    except SafeHttpError as exc:
        raise GithubApiError("could not reach GitHub") from exc
    if response.truncated:
        raise GithubApiError("GitHub's response was too large")
    return response


def _parse(model: type[_ModelT], response: SafeResponse) -> _ModelT:
    try:
        return model.model_validate_json(response.content)
    except ValidationError:
        raise GithubApiError("GitHub returned an unexpected response") from None


def _unexpected(response: SafeResponse) -> GithubApiError:
    return GithubApiError(f"GitHub returned status {response.status_code}")


def get_installation(installation_id: int) -> GithubInstallationInfo | None:
    """Ask GitHub who an installation belongs to. None means it doesn't exist."""
    response = _request("GET", f"/app/installations/{installation_id}", app_jwt())
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise _unexpected(response)
    return _parse(GithubInstallationInfo, response)


def create_installation_token(
    installation_id: int, repository_ids: list[int] | None = None
) -> InstallationToken:
    """Return a token limited to these repos, or a metadata-only token if none are given.

    Security: narrower than the app's own permissions, so a token that listed repos can't
    read code, and a token for one scan can't reach any other repo.
    """
    body: dict[str, Any] = {"permissions": {"metadata": "read"}}
    if repository_ids is not None:
        body = {
            "repository_ids": repository_ids,
            "permissions": {"contents": "read", "metadata": "read"},
        }
    response = _request(
        "POST", f"/app/installations/{installation_id}/access_tokens", app_jwt(), body
    )
    if response.status_code != 201:
        raise _unexpected(response)
    return InstallationToken(_parse(_TokenResponse, response).token)


def revoke_installation_token(token: InstallationToken) -> None:
    """Revoke a token that is finished with. It expires within the hour if this fails."""
    try:
        response = _request("DELETE", "/installation/token", token.value)
    except GithubApiError as exc:
        logger.warning("could not revoke an installation token: %s", exc)
        return
    if response.status_code != 204:
        logger.warning("could not revoke an installation token: %s", response.status_code)


def list_installation_repositories(token: InstallationToken) -> list[GithubRepository]:
    """Return every repo the installation can access."""
    repositories: list[GithubRepository] = []
    for page_number in range(1, MAX_REPO_PAGES + 1):
        response = _request(
            "GET",
            f"/installation/repositories?per_page={REPOS_PER_PAGE}&page={page_number}",
            token.value,
        )
        if response.status_code != 200:
            raise _unexpected(response)
        page = _parse(_RepositoryPage, response)
        repositories.extend(page.repositories)
        if len(repositories) >= page.total_count or not page.repositories:
            return repositories
    # An incomplete list would look like repos had been removed, so it isn't returned.
    raise GithubApiError("the installation has too many repositories")


def get_repository(token: InstallationToken, repository_id: int) -> GithubRepository | None:
    """Look a repo up by its numeric id, which stays the same through renames and transfers."""
    response = _request("GET", f"/repositories/{repository_id}", token.value)
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise _unexpected(response)
    return _parse(GithubRepository, response)
