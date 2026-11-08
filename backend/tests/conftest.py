import os
from collections.abc import Iterator

# Set before any app import, so the rate limiter is built without needing Redis.
os.environ["RATE_LIMIT_STORAGE_URL"] = "memory://"

import pytest  # noqa: E402
from sqlalchemy import Engine  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import SQLModel, create_engine  # noqa: E402

import app.models  # noqa: E402, F401
from app.core import db  # noqa: E402


@pytest.fixture
def db_engine(monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """An in-memory database standing in for Postgres, shared by every session in the test."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(db, "engine", engine)
    yield engine
    engine.dispose()
