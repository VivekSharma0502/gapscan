"""SSRF guard tests. All offline: DNS and the network transport are faked."""

import gzip
import ipaddress
import re
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import httpx
import pytest
from pydantic import ValidationError

from app.core import safe_http
from app.core.config import Settings
from app.core.safe_http import (
    BlockedTargetError,
    RequestFailedError,
    TooManyRedirectsError,
    is_public_ip,
    safe_get,
    safe_head,
)

PUBLIC_IP = "93.184.216.34"
PUBLIC_IP6 = "2606:2800:220:1:248:1893:25c8:1946"
Route = httpx.Response | Callable[[httpx.Request], httpx.Response]


class FakeNet:
    """Stands in for DNS and the network, and records what reached them."""

    def __init__(self) -> None:
        self.dns: dict[str, list[str]] = {"example.com": [PUBLIC_IP], "other.com": ["1.1.1.1"]}
        self.routes: dict[str, Route] = {}
        self.requests: list[httpx.Request] = []
        self.lookups: list[str] = []

    def resolve(self, host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        self.lookups.append(host)
        return [ipaddress.ip_address(address) for address in self.dns.get(host, [])]

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get(f"{request.headers['host']}{request.url.path}")
        if route is None:
            return httpx.Response(200, content=b"ok")
        return route(request) if callable(route) else route


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> FakeNet:
    fake = FakeNet()
    monkeypatch.setattr(safe_http, "_resolve", fake.resolve)
    monkeypatch.setattr(safe_http, "_make_transport", lambda: httpx.MockTransport(fake.handle))
    return fake


def redirect(location: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"location": location})


BLOCKED_IPS = [
    "0.0.0.0",  # noqa: S104
    "10.0.0.1",
    "100.64.0.1",  # CGNAT
    "100.127.255.254",  # CGNAT upper end
    "127.0.0.1",
    "169.254.169.254",  # cloud metadata
    "172.16.0.1",
    "192.0.0.1",
    "192.0.2.1",
    "192.88.99.1",
    "192.168.1.1",
    "198.18.0.1",
    "224.0.0.1",  # multicast
    "240.0.0.1",  # reserved
    "255.255.255.255",
    "::",
    "::1",
    "::7f00:1",  # IPv4-compatible
    "fc00::1",  # ULA
    "fd12:3456::1",  # ULA
    "fe80::1",  # link-local
    "fec0::1",  # site-local
    "ff0e::1",  # multicast
    "::ffff:127.0.0.1",  # IPv4-mapped private
    "::ffff:169.254.169.254",
    "::ffff:8.8.8.8",  # IPv4-mapped public is refused too
    "64:ff9b::7f00:1",  # NAT64
    "2001:0:7f00:1::",  # Teredo
    "2002:7f00:1::",  # 6to4
    "2001:db8::1",  # documentation
]


@pytest.mark.parametrize("address", BLOCKED_IPS)
def test_is_public_ip_rejects_blocked_ranges(address: str) -> None:
    assert not is_public_ip(ipaddress.ip_address(address))


@pytest.mark.parametrize("address", ["8.8.8.8", PUBLIC_IP, "2606:4700:4700::1111", PUBLIC_IP6])
def test_is_public_ip_accepts_public_addresses(address: str) -> None:
    assert is_public_ip(ipaddress.ip_address(address))


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://LOCALHOST/",
        "http://localhost./",
        "http://foo.localhost/",
        "http://printer.local/",
        "http://db.internal/",
        "http://127.0.0.1/",
        "https://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f000001/",  # hex
        "http://0x7f.1/",
        "http://0177.0.0.1/",  # octal
        "http://127.1/",  # short form
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:8.8.8.8]/",
        "http://[fe80::1]/",
        "http://[fd00::1]/",
    ],
)
def test_internal_targets_are_blocked_without_dns_or_network(net: FakeNet, url: str) -> None:
    with pytest.raises(BlockedTargetError):
        safe_get(url)
    assert net.lookups == []
    assert net.requests == []


@pytest.mark.parametrize("address", BLOCKED_IPS)
def test_hostname_resolving_to_blocked_ip_is_refused(net: FakeNet, address: str) -> None:
    net.dns["evil.example"] = [address]
    with pytest.raises(BlockedTargetError):
        safe_get("http://evil.example/")
    assert net.requests == []


def test_mixed_public_and_private_records_are_refused(net: FakeNet) -> None:
    net.dns["mixed.example"] = [PUBLIC_IP, "10.0.0.5"]
    with pytest.raises(BlockedTargetError):
        safe_get("http://mixed.example/")
    assert net.requests == []


def test_unresolvable_host_fails(net: FakeNet) -> None:
    with pytest.raises(RequestFailedError):
        safe_get("http://nothing.example/")
    assert net.requests == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "example.com",
        "http://example.com:8080/",
        "http://example.com:22/",
        "https://example.com:8443/",
        "http://example.com:0/",
        "http://user:pass@example.com/",
        "http://example.com@127.0.0.1/",
        "http://example.com\\@127.0.0.1/",
        "http:///path",
        "http://exa%6dple.com/",
    ],
)
def test_disallowed_urls_are_blocked(net: FakeNet, url: str) -> None:
    with pytest.raises(BlockedTargetError):
        safe_get(url)
    assert net.requests == []


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "https://example.com/",
        "http://example.com:443/",
        "https://example.com:80/",
    ],
)
def test_allowed_ports_succeed(net: FakeNet, url: str) -> None:
    assert safe_get(url).status_code == 200


def test_connects_to_validated_ip_with_real_host_and_sni(net: FakeNet) -> None:
    response = safe_get("https://example.com/page?q=1")

    sent = net.requests[0]
    assert sent.url.host == PUBLIC_IP
    assert sent.url.path == "/page"
    assert sent.url.query == b"q=1"
    assert sent.headers["host"] == "example.com"
    assert sent.extensions["sni_hostname"] == "example.com"
    assert response.url == "https://example.com/page?q=1"


def test_connects_to_validated_ipv6(net: FakeNet) -> None:
    net.dns["six.example"] = [PUBLIC_IP6]
    safe_get("https://six.example/")
    assert net.requests[0].url.host == PUBLIC_IP6
    assert net.requests[0].headers["host"] == "six.example"


def test_prefers_first_resolved_address(net: FakeNet) -> None:
    net.dns["dual.example"] = [PUBLIC_IP, PUBLIC_IP6]
    safe_get("http://dual.example/")
    assert net.requests[0].url.host == PUBLIC_IP


def test_plain_http_does_not_set_sni(net: FakeNet) -> None:
    safe_get("http://example.com/")
    assert "sni_hostname" not in net.requests[0].extensions


def test_host_header_keeps_non_default_port(net: FakeNet) -> None:
    safe_get("http://example.com:443/")
    assert net.requests[0].headers["host"] == "example.com:443"


def test_sends_honest_user_agent(net: FakeNet) -> None:
    safe_get("http://example.com/")
    assert net.requests[0].headers["user-agent"] == safe_http.settings.scanner_user_agent


def test_proxy_environment_is_ignored(net: FakeNet, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    safe_get("http://example.com/")
    assert len(net.requests) == 1


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/",
        "http://[::1]/",
        "http://internal.example/",
        "http://example.com:8080/",
        "file:///etc/passwd",
    ],
)
def test_redirect_to_internal_target_is_blocked(net: FakeNet, location: str) -> None:
    net.dns["internal.example"] = ["10.0.0.5"]
    net.routes["example.com/"] = redirect(location)
    with pytest.raises(BlockedTargetError):
        safe_get("http://example.com/")
    assert len(net.requests) == 1


def test_dns_is_rechecked_on_each_hop(net: FakeNet) -> None:
    """A host that was public on the first lookup cannot turn private on a later one."""

    def rebind(request: httpx.Request) -> httpx.Response:
        net.dns["example.com"] = ["127.0.0.1"]
        return redirect("/next")

    net.routes["example.com/"] = rebind
    with pytest.raises(BlockedTargetError):
        safe_get("http://example.com/")
    assert net.lookups == ["example.com", "example.com"]
    assert len(net.requests) == 1


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_followed_and_recorded(net: FakeNet, status: int) -> None:
    net.routes["example.com/"] = redirect("https://other.com/landing", status)
    response = safe_get("http://example.com/")

    assert response.status_code == 200
    assert response.url == "https://other.com/landing"
    assert response.redirects == ("https://other.com/landing",)
    assert net.requests[1].url.host == "1.1.1.1"
    assert net.requests[1].headers["host"] == "other.com"
    assert net.requests[1].extensions["sni_hostname"] == "other.com"


def test_relative_redirect_is_resolved(net: FakeNet) -> None:
    net.routes["example.com/a/b"] = redirect("../c")
    assert safe_get("http://example.com/a/b").url == "http://example.com/c"


def test_redirect_without_location_is_returned(net: FakeNet) -> None:
    net.routes["example.com/"] = httpx.Response(302)
    response = safe_get("http://example.com/")
    assert response.status_code == 302
    assert response.redirects == ()


def chain(net: FakeNet, length: int) -> None:
    for index in range(length):
        net.routes[f"example.com/{index}"] = redirect(f"/{index + 1}")


def test_five_redirects_are_allowed(net: FakeNet) -> None:
    chain(net, 5)
    response = safe_get("http://example.com/0")
    assert response.status_code == 200
    assert len(response.redirects) == 5
    assert len(net.requests) == 6


def test_six_redirects_are_refused(net: FakeNet) -> None:
    chain(net, 6)
    with pytest.raises(TooManyRedirectsError):
        safe_get("http://example.com/0")
    assert len(net.requests) == 6


class CountingStream(httpx.SyncByteStream):
    def __init__(self, chunks: int, chunk_size: int, delay: float = 0.0) -> None:
        self.chunks = chunks
        self.chunk_size = chunk_size
        self.delay = delay
        self.served = 0

    def __iter__(self) -> Iterator[bytes]:
        for _ in range(self.chunks):
            self.served += 1
            yield b"x" * self.chunk_size
            time.sleep(self.delay)


def test_body_at_cap_is_not_truncated(net: FakeNet) -> None:
    net.routes["example.com/"] = httpx.Response(200, content=b"x" * safe_http.MAX_RESPONSE_BYTES)
    response = safe_get("http://example.com/")
    assert len(response.content) == safe_http.MAX_RESPONSE_BYTES
    assert response.truncated is False


def test_body_over_cap_is_truncated(net: FakeNet) -> None:
    body = b"x" * (safe_http.MAX_RESPONSE_BYTES + 1)
    net.routes["example.com/"] = httpx.Response(200, content=body)
    response = safe_get("http://example.com/")
    assert len(response.content) == safe_http.MAX_RESPONSE_BYTES
    assert response.truncated is True


def test_reading_stops_at_cap(net: FakeNet) -> None:
    stream = CountingStream(chunks=1000, chunk_size=64 * 1024)
    net.routes["example.com/"] = httpx.Response(200, stream=stream)
    response = safe_get("http://example.com/")
    assert response.truncated is True
    assert stream.served < 40


def test_cap_counts_decompressed_bytes(net: FakeNet) -> None:
    bomb = gzip.compress(b"\0" * (10 * 1024 * 1024))
    assert len(bomb) < safe_http.MAX_RESPONSE_BYTES
    net.routes["example.com/"] = httpx.Response(
        200, headers={"content-encoding": "gzip"}, content=bomb
    )
    response = safe_get("http://example.com/")
    assert len(response.content) == safe_http.MAX_RESPONSE_BYTES
    assert response.truncated is True


def test_head_uses_head_and_reads_no_body(net: FakeNet) -> None:
    response = safe_head("http://example.com/")
    assert net.requests[0].method == "HEAD"
    assert response.content == b""


def test_timeouts_are_applied(net: FakeNet) -> None:
    safe_get("http://example.com/")
    timeout = net.requests[0].extensions["timeout"]
    assert timeout["connect"] == pytest.approx(safe_http.CONNECT_TIMEOUT_SECONDS, abs=0.5)
    assert timeout["read"] == pytest.approx(safe_http.READ_TIMEOUT_SECONDS, abs=0.5)


def test_deadline_stops_slow_body(net: FakeNet, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_http, "TOTAL_DEADLINE_SECONDS", 0.05)
    stream = CountingStream(chunks=100, chunk_size=10, delay=0.06)
    net.routes["example.com/"] = httpx.Response(200, stream=stream)
    with pytest.raises(RequestFailedError):
        safe_get("http://example.com/")
    assert stream.served < 100


def test_deadline_stops_before_next_hop(net: FakeNet, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_http, "TOTAL_DEADLINE_SECONDS", 0.0)
    with pytest.raises(RequestFailedError):
        safe_get("http://example.com/")
    assert net.requests == []


def test_network_errors_become_safe_errors(net: FakeNet) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connect to 10.1.2.3 failed")

    net.routes["example.com/"] = fail
    with pytest.raises(RequestFailedError) as caught:
        safe_get("http://example.com/")
    assert "10.1.2.3" not in str(caught.value)


class FakeRecord:
    def __init__(self, address: str) -> None:
        self.address = address


def fake_resolver(
    monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[str] | Exception]
) -> list[Any]:
    created: list[Any] = []

    class Resolver:
        lifetime = 0.0

        def __init__(self, configure: bool = True) -> None:
            self.configure = configure
            self.nameservers = ["system-dns"] if configure else []
            created.append(self)

        def resolve(self, host: str, record_type: str) -> list[FakeRecord]:
            answer = answers[record_type]
            if isinstance(answer, Exception):
                raise answer
            return [FakeRecord(address) for address in answer]

    monkeypatch.setattr(dns.resolver, "Resolver", Resolver)
    return created


def test_resolve_uses_system_dns_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_http.settings, "scanner_dns_servers", [])
    created = fake_resolver(monkeypatch, {"A": [PUBLIC_IP], "AAAA": []})
    safe_http._resolve("example.com")
    assert created[0].configure is True
    assert created[0].nameservers == ["system-dns"]


def test_resolve_uses_configured_dns_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    servers = [ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("8.8.8.8")]
    monkeypatch.setattr(safe_http.settings, "scanner_dns_servers", servers)
    created = fake_resolver(monkeypatch, {"A": [PUBLIC_IP], "AAAA": []})
    safe_http._resolve("example.com")
    assert created[0].configure is False
    assert created[0].nameservers == ["1.1.1.1", "8.8.8.8"]


def test_dns_servers_default_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCANNER_DNS_SERVERS", raising=False)
    assert Settings(_env_file=None).scanner_dns_servers == []


@pytest.mark.parametrize("value", ["", " , "])
def test_blank_dns_servers_mean_system_dns(value: str) -> None:
    assert Settings(_env_file=None, scanner_dns_servers=value).scanner_dns_servers == []


def test_dns_servers_are_parsed_from_comma_list() -> None:
    parsed = Settings(_env_file=None, scanner_dns_servers="1.1.1.1, 2606:4700:4700::1111")
    assert [str(server) for server in parsed.scanner_dns_servers] == [
        "1.1.1.1",
        "2606:4700:4700::1111",
    ]


@pytest.mark.parametrize("value", ["not-an-ip", "1.1.1.1,dns.google", "1.1.1"])
def test_invalid_dns_servers_are_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, scanner_dns_servers=value)


def test_resolve_returns_ipv4_before_ipv6(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_resolver(monkeypatch, {"A": [PUBLIC_IP], "AAAA": [PUBLIC_IP6]})
    assert [str(ip) for ip in safe_http._resolve("example.com")] == [PUBLIC_IP, PUBLIC_IP6]


def test_resolve_tolerates_missing_record_type(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_resolver(monkeypatch, {"A": [PUBLIC_IP], "AAAA": dns.resolver.NoAnswer()})
    assert [str(ip) for ip in safe_http._resolve("example.com")] == [PUBLIC_IP]


def test_resolve_fails_closed_on_partial_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A timed-out AAAA lookup could be hiding a private record."""
    fake_resolver(monkeypatch, {"A": [PUBLIC_IP], "AAAA": dns.exception.Timeout()})
    with pytest.raises(RequestFailedError):
        safe_http._resolve("example.com")


def test_only_safe_http_imports_httpx() -> None:
    """Enforces the project rule that no other app code can make direct HTTP calls."""
    app_dir = Path(safe_http.__file__).resolve().parents[1]
    pattern = re.compile(r"^\s*(import|from)\s+httpx\b", re.MULTILINE)
    offenders = [
        str(path.relative_to(app_dir))
        for path in app_dir.rglob("*.py")
        if path.name != "safe_http.py" and pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
