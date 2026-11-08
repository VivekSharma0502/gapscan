"""Tests for the TLS probe and TXT/CAA lookups in the SSRF guard. All offline."""

import ipaddress
import ssl
from typing import Any

import dns.exception
import dns.resolver
import httpx
import pytest

from app.core import safe_http
from app.core.safe_http import (
    BlockedTargetError,
    RequestFailedError,
    TlsStatus,
    safe_dns_records,
    safe_tls_probe,
)

PUBLIC_IP = "93.184.216.34"
CERT = {"notAfter": "Jun  1 12:00:00 2030 GMT"}


def verify_error(code: int) -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError(1, "verify failed")
    error.verify_code = code
    error.verify_message = "raw openssl text"
    return error


class FakeTlsSocket:
    def __init__(self, cert: Any) -> None:
        self.cert = cert

    def __enter__(self) -> "FakeTlsSocket":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def version(self) -> str:
        return "TLSv1.3"

    def getpeercert(self) -> Any:
        return self.cert


class FakeRaw:
    def __init__(self) -> None:
        self.closed = False
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def close(self) -> None:
        self.closed = True


class FakeContext:
    def __init__(self, outcome: Exception | Any) -> None:
        self.outcome = outcome
        self.server_hostnames: list[str] = []

    def wrap_socket(self, raw: FakeRaw, server_hostname: str) -> Any:
        self.server_hostnames.append(server_hostname)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class TlsNet:
    def __init__(self) -> None:
        self.addresses = [PUBLIC_IP]
        self.connected: list[tuple[str, int]] = []
        self.connect_error: Exception | None = None
        self.modern = FakeContext(FakeTlsSocket(CERT))
        self.legacy: FakeContext | None = FakeContext(ssl.SSLError(1, "refused"))
        self.raw = FakeRaw()


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> TlsNet:
    fake = TlsNet()

    def resolve(host: str, deadline: float) -> list[Any]:
        return [ipaddress.ip_address(address) for address in fake.addresses]

    def create_connection(address: tuple[str, int], timeout: float) -> FakeRaw:
        fake.connected.append(address)
        if fake.connect_error is not None:
            raise fake.connect_error
        return fake.raw

    monkeypatch.setattr(safe_http, "_resolve", resolve)
    monkeypatch.setattr(safe_http.socket, "create_connection", create_connection)
    monkeypatch.setattr(safe_http, "_make_tls_context", lambda: fake.modern)
    monkeypatch.setattr(safe_http, "_make_legacy_tls_context", lambda: fake.legacy)
    return fake


def test_probe_reports_healthy_certificate(net: TlsNet) -> None:
    probe = safe_tls_probe("example.com")
    assert probe.status is TlsStatus.OK
    assert probe.protocol == "TLSv1.3"
    assert probe.not_after is not None
    assert (probe.not_after.year, probe.not_after.month) == (2030, 6)
    assert probe.legacy_accepted is False


def test_probe_connects_to_validated_ip_on_443_with_real_sni(net: TlsNet) -> None:
    safe_tls_probe("example.com")
    assert net.connected == [(PUBLIC_IP, 443), (PUBLIC_IP, 443)]
    assert net.modern.server_hostnames == ["example.com"]


@pytest.mark.parametrize("private", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "fd00::1"])
def test_probe_blocks_private_answers_before_connecting(net: TlsNet, private: str) -> None:
    net.addresses = [PUBLIC_IP, private]
    with pytest.raises(BlockedTargetError):
        safe_tls_probe("example.com")
    assert net.connected == []


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "169.254.169.254", "localhost", "intranet.local", "2130706433"]
)
def test_probe_blocks_internal_hosts(net: TlsNet, host: str) -> None:
    with pytest.raises(BlockedTargetError):
        safe_tls_probe(host)
    assert net.connected == []


@pytest.mark.parametrize("host", ["example.com:8443", "user@example.com"])
def test_probe_rejects_ports_and_credentials(net: TlsNet, host: str) -> None:
    with pytest.raises(BlockedTargetError):
        safe_tls_probe(host)
    assert net.connected == []


def test_probe_detects_expired_certificate(net: TlsNet) -> None:
    net.modern.outcome = verify_error(10)
    probe = safe_tls_probe("example.com")
    assert probe.status is TlsStatus.EXPIRED
    assert probe.detail == "the certificate has expired"


@pytest.mark.parametrize(
    ("code", "detail"),
    [
        (18, "the certificate is self-signed"),
        (20, "the certificate was issued by an authority browsers do not trust"),
        (21, "the server did not send its full certificate chain"),
        (62, "the certificate was issued for a different domain"),
        (999, "the certificate could not be verified"),
    ],
)
def test_probe_explains_untrusted_certificates(net: TlsNet, code: int, detail: str) -> None:
    net.modern.outcome = verify_error(code)
    probe = safe_tls_probe("example.com")
    assert probe.status is TlsStatus.UNTRUSTED
    assert probe.detail == detail


def test_refused_port_means_no_https(net: TlsNet) -> None:
    net.connect_error = ConnectionRefusedError()
    assert safe_tls_probe("example.com").status is TlsStatus.NO_HTTPS


def test_non_tls_server_on_443_means_no_https(net: TlsNet) -> None:
    net.modern.outcome = ssl.SSLError(1, "wrong version number")
    assert safe_tls_probe("example.com").status is TlsStatus.NO_HTTPS


def test_server_only_speaking_old_tls_is_reported_as_legacy(net: TlsNet) -> None:
    net.modern.outcome = ssl.SSLError(1, "unsupported protocol")
    net.legacy = FakeContext(FakeTlsSocket({}))
    probe = safe_tls_probe("example.com")
    assert probe.status is TlsStatus.NO_HTTPS
    assert probe.legacy_accepted is True


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError(),
        ConnectionResetError(),
        OSError("unreachable"),
        ssl.SSLEOFError(8, "eof"),
    ],
)
def test_unknown_outcomes_raise_instead_of_guessing(net: TlsNet, error: Exception) -> None:
    net.modern.outcome = error
    with pytest.raises(RequestFailedError):
        safe_tls_probe("example.com")


def test_failed_handshake_closes_the_socket(net: TlsNet) -> None:
    net.modern.outcome = TimeoutError()
    with pytest.raises(RequestFailedError):
        safe_tls_probe("example.com")
    assert net.raw.closed is True


def test_certificate_without_expiry_is_tolerated(net: TlsNet) -> None:
    net.modern.outcome = FakeTlsSocket({})
    assert safe_tls_probe("example.com").not_after is None


def test_legacy_accepted(net: TlsNet) -> None:
    net.legacy = FakeContext(FakeTlsSocket({}))
    assert safe_tls_probe("example.com").legacy_accepted is True


def test_legacy_unknown_when_context_unavailable(net: TlsNet) -> None:
    net.legacy = None
    assert safe_tls_probe("example.com").legacy_accepted is None


def test_legacy_unknown_when_local_openssl_cannot_offer_it(net: TlsNet) -> None:
    error = ssl.SSLError(1, "no protocols")
    error.reason = "NO_PROTOCOLS_AVAILABLE"
    assert net.legacy is not None
    net.legacy.outcome = error
    assert safe_tls_probe("example.com").legacy_accepted is None


def test_legacy_refused_when_connection_is_dropped(net: TlsNet) -> None:
    assert net.legacy is not None
    net.legacy.outcome = ConnectionResetError()
    assert safe_tls_probe("example.com").legacy_accepted is False


def test_legacy_unknown_on_timeout(net: TlsNet) -> None:
    assert net.legacy is not None
    net.legacy.outcome = TimeoutError()
    assert safe_tls_probe("example.com").legacy_accepted is None


def test_real_legacy_context_only_offers_old_versions() -> None:
    context = safe_http._make_legacy_tls_context()
    if context is None:
        pytest.skip("this OpenSSL has no TLS 1.0/1.1")
    assert context.minimum_version is ssl.TLSVersion.TLSv1
    assert context.maximum_version is ssl.TLSVersion.TLSv1_1


def test_real_modern_context_verifies_certificates() -> None:
    context = safe_http._make_tls_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


# TXT and CAA lookups


class TxtRecord:
    def __init__(self, *chunks: bytes) -> None:
        self.strings = chunks


class CaaRecord:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_text(self) -> str:
        return self.text


class RecordTiers:
    def __init__(self) -> None:
        self.udp: Any = dns.exception.Timeout()
        self.tcp: Any = dns.exception.Timeout()
        self.doh: dict[str, Any] = {}
        self.log: list[str] = []
        self.asked: list[tuple[str, str]] = []


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> RecordTiers:
    fake = RecordTiers()

    class Resolver:
        lifetime = 0.0

        def __init__(self, configure: bool = True) -> None:
            self.nameservers: list[str] = []

        def resolve(self, name: str, record_type: str, tcp: bool = False) -> Any:
            fake.log.append("tcp" if tcp else "udp")
            fake.asked.append((name, record_type))
            answer = fake.tcp if tcp else fake.udp
            if isinstance(answer, Exception):
                raise answer
            return answer

    def handle(request: httpx.Request) -> httpx.Response:
        fake.log.append(f"doh:{request.url.host}")
        route = fake.doh.get(request.url.host)
        if route is None:
            raise httpx.ConnectError("blocked")
        return route

    monkeypatch.setattr(dns.resolver, "Resolver", Resolver)
    monkeypatch.setattr(safe_http, "_make_transport", lambda: httpx.MockTransport(handle))
    return fake


def doh_response(type_code: int, *data: str, status: int = 0) -> httpx.Response:
    answers = [{"type": type_code, "data": item} for item in data]
    return httpx.Response(200, json={"Status": status, "Answer": answers})


def test_txt_chunks_are_joined(records: RecordTiers) -> None:
    records.udp = [TxtRecord(b"v=spf1 ", b"-all")]
    assert safe_dns_records("example.com", "TXT") == ["v=spf1 -all"]
    assert records.asked == [("example.com", "TXT")]


def test_caa_records_are_returned_as_text(records: RecordTiers) -> None:
    records.udp = [CaaRecord('0 issue "letsencrypt.org"')]
    assert safe_dns_records("example.com", "CAA") == ['0 issue "letsencrypt.org"']


def test_underscore_names_are_allowed(records: RecordTiers) -> None:
    records.udp = [TxtRecord(b"v=DMARC1; p=reject")]
    assert safe_dns_records("_dmarc.example.com", "TXT") == ["v=DMARC1; p=reject"]


@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
def test_no_records_is_a_definite_empty_answer(
    records: RecordTiers, error: type[Exception]
) -> None:
    records.udp = error()
    records.tcp = [TxtRecord(b"should not be asked")]
    assert safe_dns_records("example.com", "TXT") == []
    assert records.log == ["udp"]


def test_records_fall_back_to_tcp(records: RecordTiers) -> None:
    records.tcp = [TxtRecord(b"v=spf1 -all")]
    assert safe_dns_records("example.com", "TXT") == ["v=spf1 -all"]
    assert records.log == ["udp", "tcp"]


def test_doh_quoted_txt_is_unquoted(records: RecordTiers) -> None:
    records.doh["1.1.1.1"] = doh_response(16, '"v=spf1 " "include:a.com -all"')
    assert safe_dns_records("example.com", "TXT") == ["v=spf1 include:a.com -all"]


def test_doh_escaped_quotes_are_unescaped(records: RecordTiers) -> None:
    records.doh["1.1.1.1"] = doh_response(16, '"a\\"b"')
    assert safe_dns_records("example.com", "TXT") == ['a"b']


def test_google_style_unquoted_txt_is_kept(records: RecordTiers) -> None:
    records.doh["8.8.8.8"] = doh_response(16, "v=DMARC1; p=reject")
    assert safe_dns_records("_dmarc.example.com", "TXT") == ["v=DMARC1; p=reject"]
    assert records.log[-2:] == ["doh:1.1.1.1", "doh:8.8.8.8"]


def test_doh_caa_is_returned(records: RecordTiers) -> None:
    records.doh["1.1.1.1"] = doh_response(257, '0 issue "pki.goog"')
    assert safe_dns_records("example.com", "CAA") == ['0 issue "pki.goog"']


def test_doh_ignores_other_record_types(records: RecordTiers) -> None:
    records.doh["1.1.1.1"] = httpx.Response(
        200,
        json={
            "Status": 0,
            "Answer": [{"type": 5, "data": "x.example."}, {"type": 16, "data": "v=spf1 -all"}],
        },
    )
    assert safe_dns_records("example.com", "TXT") == ["v=spf1 -all"]


def test_doh_nxdomain_is_empty(records: RecordTiers) -> None:
    records.doh["1.1.1.1"] = doh_response(16, status=3)
    assert safe_dns_records("example.com", "TXT") == []


def test_every_resolver_failing_raises(records: RecordTiers) -> None:
    with pytest.raises(RequestFailedError):
        safe_dns_records("example.com", "TXT")
    assert records.log == ["udp", "tcp", "doh:1.1.1.1", "doh:8.8.8.8"]


@pytest.mark.parametrize(
    "name", ["localhost", "db.internal", "printer.local", "127.0.0.1", "bad name.com", "2130706433"]
)
def test_internal_names_are_never_looked_up(records: RecordTiers, name: str) -> None:
    with pytest.raises(BlockedTargetError):
        safe_dns_records(name, "TXT")
    assert records.log == []


def test_expired_deadline_asks_no_resolver(
    records: RecordTiers, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(safe_http, "TOTAL_DEADLINE_SECONDS", -1.0)
    with pytest.raises(RequestFailedError):
        safe_dns_records("example.com", "TXT")
    assert records.log == []
