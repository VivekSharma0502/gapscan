"""SSRF guard tests. All offline: DNS and the network transport are faked."""

import gzip
import ipaddress
import re
import socket
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

    def resolve(
        self, host: str, deadline: float
    ) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
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


Answers = dict[str, list[str] | Exception]
FULL_CHAIN = ["udp", "tcp", "doh:1.1.1.1", "doh:8.8.8.8", "system"]
CONFIGURED = [ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("8.8.8.8")]


def dns_down() -> Answers:
    return {"A": dns.exception.Timeout(), "AAAA": dns.exception.Timeout()}


def dns_ok(*addresses: str) -> Answers:
    return {"A": list(addresses), "AAAA": dns.resolver.NoAnswer()}


def doh_json(
    a: tuple[str, ...] = (), aaaa: tuple[str, ...] = (), status: int = 0
) -> Callable[[httpx.Request], httpx.Response]:
    def respond(request: httpx.Request) -> httpx.Response:
        wanted = request.url.params["type"]
        code, data = (1, a) if wanted == "A" else (28, aaaa)
        records = [{"name": "example.com", "type": code, "data": item} for item in data]
        return httpx.Response(200, json={"Status": status, "Answer": records})

    return respond


class DnsTiers:
    """Fakes each resolver in the chain. All of them fail until a test says otherwise."""

    def __init__(self) -> None:
        self.udp: Answers = dns_down()
        self.tcp: Answers = dns_down()
        self.doh: dict[str, Route] = {}
        self.system: list[str] | Exception = socket.gaierror(11001, "failed")
        self.log: list[str] = []
        self.resolvers: list[Any] = []
        self.doh_requests: list[httpx.Request] = []

    def note(self, tier: str) -> None:
        if not self.log or self.log[-1] != tier:
            self.log.append(tier)

    def handle_doh(self, request: httpx.Request) -> httpx.Response:
        self.doh_requests.append(request)
        self.note(f"doh:{request.url.host}")
        route = self.doh.get(request.url.host)
        if route is None:
            raise httpx.ConnectError("blocked")
        return route(request) if callable(route) else route

    def getaddrinfo(self, host: str, port: None, **kwargs: Any) -> list[Any]:
        self.note("system")
        if isinstance(self.system, Exception):
            raise self.system
        return [(0, 1, 6, "", (address, 0)) for address in self.system]


@pytest.fixture
def tiers(monkeypatch: pytest.MonkeyPatch) -> DnsTiers:
    fake = DnsTiers()

    class Resolver:
        lifetime = 0.0

        def __init__(self, configure: bool = True) -> None:
            self.configure = configure
            self.nameservers = ["system-dns"] if configure else []
            fake.resolvers.append(self)

        def resolve(self, host: str, record_type: str, tcp: bool = False) -> list[FakeRecord]:
            fake.note("tcp" if tcp else "udp")
            answer = (fake.tcp if tcp else fake.udp)[record_type]
            if isinstance(answer, Exception):
                raise answer
            return [FakeRecord(address) for address in answer]

    monkeypatch.setattr(dns.resolver, "Resolver", Resolver)
    monkeypatch.setattr(safe_http, "_make_transport", lambda: httpx.MockTransport(fake.handle_doh))
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", fake.getaddrinfo)
    monkeypatch.setattr(safe_http.settings, "scanner_dns_servers", CONFIGURED)
    monkeypatch.setattr(safe_http.settings, "scanner_dns_timeout_seconds", 5.0)
    return fake


def far_deadline() -> float:
    return time.monotonic() + 60


def resolved(host: str = "example.com") -> list[str]:
    return [str(address) for address in safe_http._resolve(host, far_deadline())]


def test_uses_system_dns_when_no_servers_configured(
    tiers: DnsTiers, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(safe_http.settings, "scanner_dns_servers", [])
    tiers.udp = dns_ok(PUBLIC_IP)
    resolved()
    assert tiers.resolvers[0].configure is True
    assert tiers.resolvers[0].nameservers == ["system-dns"]


def test_uses_configured_dns_servers(tiers: DnsTiers) -> None:
    tiers.udp = dns_ok(PUBLIC_IP)
    resolved()
    assert tiers.resolvers[0].configure is False
    assert tiers.resolvers[0].nameservers == ["1.1.1.1", "8.8.8.8"]


def test_tcp_tier_uses_same_servers_as_udp(tiers: DnsTiers) -> None:
    tiers.tcp = dns_ok(PUBLIC_IP)
    resolved()
    assert [resolver.nameservers for resolver in tiers.resolvers] == [
        ["1.1.1.1", "8.8.8.8"],
        ["1.1.1.1", "8.8.8.8"],
    ]


def test_chain_order_when_everything_fails(tiers: DnsTiers) -> None:
    with pytest.raises(RequestFailedError):
        resolved()
    assert tiers.log == FULL_CHAIN


def test_udp_answer_ends_chain(tiers: DnsTiers) -> None:
    tiers.udp = dns_ok(PUBLIC_IP)
    assert resolved() == [PUBLIC_IP]
    assert tiers.log == ["udp"]


def test_falls_back_to_tcp(tiers: DnsTiers) -> None:
    tiers.tcp = dns_ok(PUBLIC_IP)
    assert resolved() == [PUBLIC_IP]
    assert tiers.log == ["udp", "tcp"]


def test_falls_back_to_cloudflare_doh(tiers: DnsTiers) -> None:
    tiers.doh["1.1.1.1"] = doh_json(a=(PUBLIC_IP,), aaaa=(PUBLIC_IP6,))
    assert resolved() == [PUBLIC_IP, PUBLIC_IP6]
    assert tiers.log == ["udp", "tcp", "doh:1.1.1.1"]


def test_falls_back_to_google_doh(tiers: DnsTiers) -> None:
    tiers.doh["8.8.8.8"] = doh_json(a=(PUBLIC_IP,))
    assert resolved() == [PUBLIC_IP]
    assert tiers.log == ["udp", "tcp", "doh:1.1.1.1", "doh:8.8.8.8"]


def test_falls_back_to_system_resolver(tiers: DnsTiers) -> None:
    tiers.system = [PUBLIC_IP6, PUBLIC_IP, PUBLIC_IP]
    assert resolved() == [PUBLIC_IP, PUBLIC_IP6]  # IPv4 first, duplicates removed
    assert tiers.log == FULL_CHAIN


def test_system_resolver_timeout_is_a_failure(
    tiers: DnsTiers, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(safe_http.settings, "scanner_dns_timeout_seconds", 0.02)

    def hang(host: str, port: None, **kwargs: Any) -> list[Any]:
        time.sleep(0.2)
        return [(0, 1, 6, "", (PUBLIC_IP, 0))]

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", hang)
    with pytest.raises(RequestFailedError):
        resolved()


def test_servfail_moves_to_next_tier(tiers: DnsTiers) -> None:
    tiers.udp = {"A": dns.resolver.NoNameservers(), "AAAA": dns.resolver.NoNameservers()}
    tiers.tcp = dns_ok(PUBLIC_IP)
    assert resolved() == [PUBLIC_IP]


@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
def test_definite_no_records_ends_chain(tiers: DnsTiers, error: type[Exception]) -> None:
    tiers.udp = {"A": error(), "AAAA": error()}
    tiers.tcp = dns_ok(PUBLIC_IP)
    assert resolved() == []
    assert tiers.log == ["udp"]


def test_doh_nxdomain_ends_chain(tiers: DnsTiers) -> None:
    tiers.doh["1.1.1.1"] = doh_json(status=3)
    tiers.doh["8.8.8.8"] = doh_json(a=(PUBLIC_IP,))
    assert resolved() == []
    assert tiers.log[-1] == "doh:1.1.1.1"


def test_partial_answer_is_not_merged_across_tiers(tiers: DnsTiers) -> None:
    """A from UDP plus a failed AAAA must not count, or the AAAA could hide a private IP."""
    tiers.udp = {"A": ["8.8.4.4"], "AAAA": dns.exception.Timeout()}
    tiers.tcp = dns_ok(PUBLIC_IP)
    assert resolved() == [PUBLIC_IP]


def test_private_aaaa_hidden_by_udp_failure_is_caught(tiers: DnsTiers) -> None:
    tiers.udp = {"A": [PUBLIC_IP], "AAAA": dns.exception.Timeout()}
    tiers.tcp = {"A": [PUBLIC_IP], "AAAA": ["fd00::1"]}
    with pytest.raises(BlockedTargetError):
        safe_http._validated_ip("example.com", far_deadline())


@pytest.mark.parametrize("private", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"])
@pytest.mark.parametrize("tier", FULL_CHAIN)
def test_private_answer_from_any_tier_is_blocked(tiers: DnsTiers, tier: str, private: str) -> None:
    """A private answer must block, not trigger a search for a resolver that says otherwise."""
    if tier == "udp":
        tiers.udp = dns_ok(private)
    elif tier == "tcp":
        tiers.tcp = dns_ok(private)
    elif tier == "system":
        tiers.system = [private]
    else:
        tiers.doh[tier.removeprefix("doh:")] = doh_json(a=(private,))

    with pytest.raises(BlockedTargetError):
        safe_http._validated_ip("example.com", far_deadline())
    assert tiers.log[-1] == tier


def test_fallback_answer_is_pinned_for_the_real_request(
    tiers: DnsTiers, monkeypatch: pytest.MonkeyPatch
) -> None:
    site_requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.host == "1.1.1.1":
            return doh_json(a=(PUBLIC_IP,))(request)
        site_requests.append(request)
        return httpx.Response(200, content=b"ok")

    monkeypatch.setattr(safe_http, "_make_transport", lambda: httpx.MockTransport(handle))
    assert safe_get("https://example.com/").status_code == 200
    assert site_requests[0].url.host == PUBLIC_IP
    assert site_requests[0].headers["host"] == "example.com"


def test_doh_request_shape(tiers: DnsTiers) -> None:
    tiers.doh["1.1.1.1"] = doh_json(a=(PUBLIC_IP,))
    resolved()
    first, second = tiers.doh_requests
    assert first.url.host == "1.1.1.1"  # an IP literal, so no DNS is needed to reach it
    assert first.url.path == "/dns-query"
    assert first.url.params["name"] == "example.com"
    assert [first.url.params["type"], second.url.params["type"]] == ["A", "AAAA"]
    assert first.headers["accept"] == "application/dns-json"
    assert first.extensions["timeout"]["read"] <= 5.0


def test_google_doh_uses_ip_literal(tiers: DnsTiers) -> None:
    tiers.doh["8.8.8.8"] = doh_json(a=(PUBLIC_IP,))
    resolved()
    assert tiers.doh_requests[-1].url.host == "8.8.8.8"
    assert tiers.doh_requests[-1].url.path == "/resolve"


def test_doh_ignores_cname_records(tiers: DnsTiers) -> None:
    records = [
        {"name": "example.com", "type": 5, "data": "cdn.example.net."},
        {"name": "cdn.example.net", "type": 1, "data": PUBLIC_IP},
    ]
    tiers.doh["1.1.1.1"] = httpx.Response(200, json={"Status": 0, "Answer": records})
    assert resolved() == [PUBLIC_IP]


def test_doh_without_answer_section_means_no_records(tiers: DnsTiers) -> None:
    tiers.doh["1.1.1.1"] = httpx.Response(200, json={"Status": 0})
    assert resolved() == []


@pytest.mark.parametrize(
    "bad_response",
    [
        httpx.Response(500),
        # A valid-looking body must not be trusted on an error status.
        httpx.Response(500, json={"Status": 0, "Answer": [{"type": 1, "data": "9.9.9.9"}]}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json=[1, 2]),
        httpx.Response(200, json="text"),
        httpx.Response(200, json={"Answer": []}),
        httpx.Response(200, json={"Status": 2}),
        httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": "not-an-ip"}]}),
        httpx.Response(200, json={"Status": 0, "Answer": [{"data": PUBLIC_IP}]}),
        httpx.Response(200, content=b"x" * (safe_http.MAX_RESPONSE_BYTES + 1)),
        # Still parses as JSON after being cut off, so only the truncation check rejects it.
        httpx.Response(200, content=b'{"Status":0}' + b" " * safe_http.MAX_RESPONSE_BYTES),
    ],
)
def test_bad_doh_response_moves_to_next_tier(tiers: DnsTiers, bad_response: httpx.Response) -> None:
    tiers.doh["1.1.1.1"] = bad_response
    tiers.doh["8.8.8.8"] = doh_json(a=(PUBLIC_IP,))
    assert resolved() == [PUBLIC_IP]
    assert tiers.log[-1] == "doh:8.8.8.8"


def test_dns_timeout_defaults_to_five_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCANNER_DNS_TIMEOUT_SECONDS", raising=False)
    assert Settings(_env_file=None).scanner_dns_timeout_seconds == 5.0


def test_dns_timeout_is_configurable() -> None:
    parsed = Settings(_env_file=None, scanner_dns_timeout_seconds="2.5")
    assert parsed.scanner_dns_timeout_seconds == 2.5


@pytest.mark.parametrize("value", ["0", "-1", "31", "soon"])
def test_invalid_dns_timeout_is_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, scanner_dns_timeout_seconds=value)


def test_dns_timeout_setting_reaches_resolver(
    tiers: DnsTiers, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(safe_http.settings, "scanner_dns_timeout_seconds", 2.0)
    tiers.udp = dns_ok(PUBLIC_IP)
    resolved()
    assert tiers.resolvers[0].lifetime == pytest.approx(2.0, abs=0.5)


def test_tier_budget_is_limited_by_request_deadline(tiers: DnsTiers) -> None:
    tiers.udp = dns_ok(PUBLIC_IP)
    safe_http._resolve("example.com", time.monotonic() + 1.0)
    assert tiers.resolvers[0].lifetime <= 1.0


def test_expired_deadline_stops_chain(tiers: DnsTiers) -> None:
    tiers.udp = dns_ok(PUBLIC_IP)
    with pytest.raises(RequestFailedError):
        safe_http._resolve("example.com", time.monotonic() - 1)
    assert tiers.log == []


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


def test_resolve_returns_ipv4_before_ipv6(tiers: DnsTiers) -> None:
    tiers.udp = {"A": [PUBLIC_IP], "AAAA": [PUBLIC_IP6]}
    assert resolved() == [PUBLIC_IP, PUBLIC_IP6]


def test_resolve_tolerates_missing_record_type(tiers: DnsTiers) -> None:
    tiers.udp = dns_ok(PUBLIC_IP)
    assert resolved() == [PUBLIC_IP]


def test_resolve_fails_closed_when_every_tier_is_partial(tiers: DnsTiers) -> None:
    """A timed-out AAAA lookup could be hiding a private record."""
    tiers.udp = {"A": [PUBLIC_IP], "AAAA": dns.exception.Timeout()}
    tiers.tcp = {"A": [PUBLIC_IP], "AAAA": dns.exception.Timeout()}
    with pytest.raises(RequestFailedError):
        resolved()


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
