import socket
from typing import NoReturn

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Checks are pure functions of a fixture, so any real connection fails the test."""

    def refuse(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("tests in this package must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
