"""Authenticated API requests through the SSRF guard. Offline: DNS and transport are faked."""

import ipaddress
import json
from typing import Any

import httpx
import pytest

from app.core import safe_http
from app.core.config import settings
from app.core.safe_http import BlockedTargetError, RedirectRefusedError, safe_api_request

PUBLIC_IP = "93.184.216.34"
URL = "https://api.example.com/thing"
AUTH = {"Authorization": "Bearer token-value"}


class FakeApi:
    def __init__(self) -> None:
        self.dns: dict[str, list[str]] = {"api.example.com": [PUBLIC_IP]}
        self.response = httpx.Response(200, content=b"{}")
        self.requests: list[httpx.Request] = []

    def resolve(self, host: str, deadline: float) -> list[Any]:
        return [ipaddress.ip_address(address) for address in self.dns.get(host, [])]

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    fake = FakeApi()
    monkeypatch.setattr(safe_http, "_resolve", fake.resolve)
    monkeypatch.setattr(safe_http, "_make_transport", lambda: httpx.MockTransport(fake.handle))
    return fake


def test_sends_method_headers_and_json_body(api: FakeApi) -> None:
    response = safe_api_request(
        "POST", URL, headers=AUTH | {"Accept": "application/json"}, json_body={"a": 1}
    )

    sent = api.requests[0]
    assert response.status_code == 200
    assert sent.method == "POST"
    assert sent.headers["authorization"] == "Bearer token-value"
    assert sent.headers["accept"] == "application/json"
    assert sent.headers["content-type"] == "application/json"
    assert json.loads(sent.content) == {"a": 1}


def test_connects_to_the_validated_ip_and_keeps_the_real_host(api: FakeApi) -> None:
    safe_api_request("GET", URL, headers=AUTH)

    sent = api.requests[0]
    assert sent.url.host == PUBLIC_IP
    assert sent.headers["host"] == "api.example.com"
    assert sent.extensions["sni_hostname"] == "api.example.com"


@pytest.mark.parametrize("name", ["Host", "host", "HOST"])
def test_caller_cannot_override_host(api: FakeApi, name: str) -> None:
    safe_api_request("GET", URL, headers={name: "internal.example"})

    assert api.requests[0].headers.get_list("host") == ["api.example.com"]


def test_caller_cannot_override_user_agent(api: FakeApi) -> None:
    safe_api_request("GET", URL, headers={"user-agent": "something-else"})

    assert api.requests[0].headers.get_list("user-agent") == [settings.scanner_user_agent]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_is_refused_and_not_followed(api: FakeApi, status: int) -> None:
    api.response = httpx.Response(status, headers={"location": "https://api.example.com/other"})

    with pytest.raises(RedirectRefusedError):
        safe_api_request("GET", URL, headers=AUTH)

    assert len(api.requests) == 1


def test_plain_http_is_refused_before_any_request(api: FakeApi) -> None:
    with pytest.raises(BlockedTargetError):
        safe_api_request("GET", "http://api.example.com/thing", headers=AUTH)

    assert api.requests == []


def test_private_address_is_refused_before_any_request(api: FakeApi) -> None:
    api.dns["api.example.com"] = ["169.254.169.254"]

    with pytest.raises(BlockedTargetError):
        safe_api_request("GET", URL, headers=AUTH)

    assert api.requests == []


def test_no_body_is_sent_without_json_body(api: FakeApi) -> None:
    safe_api_request("DELETE", URL, headers=AUTH)

    sent = api.requests[0]
    assert sent.method == "DELETE"
    assert sent.content == b""
    assert "content-type" not in sent.headers
