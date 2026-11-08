"""Database engine and sessions, shared by the API and the worker."""

from collections.abc import Iterator

from sqlmodel import Session, create_engine

from app.core.config import settings

# pool_pre_ping replaces connections that dropped while the worker sat idle. The connect
# timeout makes an unreachable database fail quickly instead of hanging a request.
engine = create_engine(
    settings.database_url, pool_pre_ping=True, connect_args={"connect_timeout": 5}
)


def new_session() -> Session:
    return Session(engine)


def get_session() -> Iterator[Session]:
    with new_session() as session:
        yield session
