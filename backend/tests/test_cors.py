"""What a browser on the frontend's origin is allowed to send, and can read back."""

from collections.abc import Iterator

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.api import repo_links
from app.core.auth import get_viewer
from app.core.config import settings
from app.main import app

ORIGIN = settings.cors_origins[0]
LEAKY_ERROR = "postgres://user:hunter2@db"  # noqa: S105

# Built from the router, so a repo-link route added later is covered without editing this list.
REPO_LINK_ROUTES = [
    (method, route.path.replace("{link_id}", "00000000-0000-0000-0000-000000000001"))
    for route in repo_links.router.routes
    if isinstance(route, APIRoute)
    for method in sorted(route.methods)
]


@pytest.fixture
def client(db_engine: Engine) -> Iterator[TestClient]:
    # Off so a test sees the response a browser would get, not the raised exception.
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


def preflight(client: TestClient, path: str, method: str, headers: str):
    return client.options(
        path,
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": headers,
        },
    )


def test_every_repo_link_method_is_covered() -> None:
    assert {method for method, _ in REPO_LINK_ROUTES} == {"GET", "POST", "PATCH", "DELETE"}


@pytest.mark.parametrize(("method", "path"), REPO_LINK_ROUTES)
def test_repo_link_preflight_is_allowed(client: TestClient, method: str, path: str) -> None:
    response = preflight(client, path, method, "authorization,content-type")

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN


def test_preflight_refuses_a_method_no_route_uses(client: TestClient) -> None:
    response = preflight(client, "/api/repo-links", "PUT", "authorization")

    assert response.status_code == 400


def test_preflight_refuses_a_header_the_frontend_never_sends(client: TestClient) -> None:
    response = preflight(client, "/api/repo-links", "GET", "x-not-ours")

    assert response.status_code == 400


def test_unhandled_error_is_readable_by_the_frontend(client: TestClient) -> None:
    def crash() -> None:
        raise RuntimeError(LEAKY_ERROR)

    app.dependency_overrides[get_viewer] = crash

    response = client.get("/api/repo-links", headers={"Origin": ORIGIN})

    assert response.status_code == 500
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.json() == {"detail": "Something went wrong on our side. Please try again."}
    assert LEAKY_ERROR not in response.text
