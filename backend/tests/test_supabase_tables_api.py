"""Marking Supabase tables as meant to be public, through the API."""

from collections.abc import Iterator
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks.base import BaasKind, TableAccess
from app.core.auth import Viewer, get_viewer
from app.core.rate_limit import limiter
from app.main import app
from app.models.domain import Domain, DomainBackend, DomainBackendTable
from app.models.profile import Profile
from app.models.scan import utc_now

REF = "abcdefghijklmnopqrst"
OTHER_REF = "tsrqponmlkjihgfedcba"


def seed(engine: Engine) -> tuple[UUID, UUID, UUID]:
    owner = uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        domain = Domain(
            owner_id=owner,
            hostname="example.com",
            verify_token="tok",  # noqa: S106
            verified_at=utc_now(),
            verified_method="dns",
        )
        session.add(domain)
        session.flush()
        backend = DomainBackend(
            domain_id=domain.id,
            kind=BaasKind.SUPABASE,
            identifier=REF,
            confirmed_at=utc_now(),
        )
        session.add(backend)
        session.commit()
        return owner, domain.id, backend.id


def saved_tables(engine: Engine) -> list[DomainBackendTable]:
    with Session(engine) as session:
        return list(session.exec(select(DomainBackendTable)))


@pytest.fixture
def client(db_engine: Engine) -> Iterator[TestClient]:
    limiter.reset()
    yield TestClient(app)
    limiter.reset()
    app.dependency_overrides.clear()


def sign_in(viewer_id: UUID) -> None:
    viewer = Viewer(id=viewer_id, email="person@example.com", name=None)
    app.dependency_overrides[get_viewer] = lambda: viewer


def add_table(engine: Engine, backend: UUID, name: str = "todos") -> UUID:
    with Session(engine) as session:
        row = DomainBackendTable(backend_id=backend, name=name, access=TableAccess.READABLE)
        session.add(row)
        session.commit()
        return row.id


def choose(client: TestClient, domain: UUID, backend: UUID, table: UUID, value: bool = True) -> Any:
    return client.post(
        f"/api/domains/{domain}/backends/{backend}/tables/{table}/public",
        json={"meant_to_be_public": value},
    )


def test_tables_are_listed_with_their_backend(client: TestClient, db_engine: Engine) -> None:
    owner, domain, backend = seed(db_engine)
    add_table(db_engine, backend)
    sign_in(owner)

    tables = client.get(f"/api/domains/{domain}/backends").json()[0]["tables"]

    assert tables[0]["name"] == "todos"
    assert tables[0]["access"] == "readable"
    assert tables[0]["meant_to_be_public"] is False


def test_owner_can_mark_and_unmark_a_table(client: TestClient, db_engine: Engine) -> None:
    owner, domain, backend = seed(db_engine)
    table = add_table(db_engine, backend)
    sign_in(owner)

    assert choose(client, domain, backend, table).json()["meant_to_be_public"] is True
    assert choose(client, domain, backend, table, False).json()["meant_to_be_public"] is False


def test_other_peoples_tables_are_hidden(client: TestClient, db_engine: Engine) -> None:
    _, domain, backend = seed(db_engine)
    table = add_table(db_engine, backend)
    sign_in(uuid4())

    assert choose(client, domain, backend, table).status_code == 404
    assert saved_tables(db_engine)[0].meant_to_be_public_at is None


def test_a_table_cannot_be_reached_through_another_backend(
    client: TestClient, db_engine: Engine
) -> None:
    owner, domain, backend = seed(db_engine)
    with Session(db_engine) as session:
        other = DomainBackend(domain_id=domain, kind=BaasKind.SUPABASE, identifier=OTHER_REF)
        session.add(other)
        session.commit()
        other_id = other.id
    table = add_table(db_engine, other_id)
    sign_in(owner)

    assert choose(client, domain, backend, table).status_code == 404


def test_unverified_domain_cannot_mark_a_table(client: TestClient, db_engine: Engine) -> None:
    owner, domain, backend = seed(db_engine)
    table = add_table(db_engine, backend)
    with Session(db_engine) as session:
        row = session.get_one(Domain, domain)
        row.verified_at = None
        session.add(row)
        session.commit()
    sign_in(owner)

    assert choose(client, domain, backend, table).status_code == 403
    assert choose(client, domain, backend, table, False).status_code == 200


def test_marking_needs_sign_in(client: TestClient, db_engine: Engine) -> None:
    _, domain, backend = seed(db_engine)

    assert choose(client, domain, backend, add_table(db_engine, backend)).status_code == 401


@pytest.mark.parametrize("body", [{}, {"meant_to_be_public": "maybe"}, {"extra": True}])
def test_malformed_choice_is_rejected(
    client: TestClient, db_engine: Engine, body: dict[str, Any]
) -> None:
    owner, domain, backend = seed(db_engine)
    table = add_table(db_engine, backend)
    sign_in(owner)

    url = f"/api/domains/{domain}/backends/{backend}/tables/{table}/public"
    assert client.post(url, json=body).status_code == 422
