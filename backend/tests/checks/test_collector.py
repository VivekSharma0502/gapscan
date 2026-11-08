from dataclasses import dataclass, field
from typing import Any

import pytest

from app.checks import collector
from app.checks.base import Input
from app.checks.collector import collect_context
from app.core.safe_http import (
    BlockedTargetError,
    RequestFailedError,
    TlsProbe,
    TlsStatus,
    TooManyRedirectsError,
)
from tests.checks.helpers import response


@dataclass
class FakeScanner:
    tls: Any = field(default_factory=lambda: TlsProbe(TlsStatus.OK, protocol="TLSv1.3"))
    https: Any = field(default_factory=lambda: response())
    http: Any = field(default_factory=lambda: response(url="https://example.com/"))
    dns: dict[tuple[str, str], Any] = field(default_factory=dict)
    fetched: list[str] = field(default_factory=list)
    dns_asked: list[tuple[str, str]] = field(default_factory=list)

    def probe(self, host: str) -> TlsProbe:
        if isinstance(self.tls, Exception):
            raise self.tls
        return self.tls

    def get(self, url: str) -> Any:
        self.fetched.append(url)
        result = self.https if url.startswith("https://") else self.http
        if isinstance(result, Exception):
            raise result
        return result

    def records(self, name: str, record_type: str) -> list[str]:
        self.dns_asked.append((name, record_type))
        result = self.dns.get((name, record_type), [])
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def scanner(monkeypatch: pytest.MonkeyPatch) -> FakeScanner:
    fake = FakeScanner()
    monkeypatch.setattr(collector, "safe_tls_probe", fake.probe)
    monkeypatch.setattr(collector, "safe_get", fake.get)
    monkeypatch.setattr(collector, "safe_dns_records", fake.records)
    return fake


def test_collects_everything_on_success(scanner: FakeScanner) -> None:
    scanner.dns[("example.com", "TXT")] = ["v=spf1 -all"]
    scanner.dns[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=reject"]
    scanner.dns[("example.com", "CAA")] = ['0 issue "pki.goog"']

    ctx = collect_context("example.com")

    assert ctx.https is scanner.https
    assert ctx.http is scanner.http
    assert ctx.tls is scanner.tls
    assert ctx.email_domain == "example.com"
    assert ctx.spf_records == ["v=spf1 -all"]
    assert ctx.dmarc_records == ["v=DMARC1; p=reject"]
    assert ctx.caa_records == ['0 issue "pki.goog"']
    assert ctx.skip_reasons == {}


def test_fetches_both_schemes_of_the_homepage(scanner: FakeScanner) -> None:
    collect_context("example.com")
    assert scanner.fetched == ["https://example.com/", "http://example.com/"]


def test_hostname_is_normalised(scanner: FakeScanner) -> None:
    ctx = collect_context("Example.COM.")
    assert ctx.hostname == "example.com"
    assert scanner.fetched[0] == "https://example.com/"


def test_blocked_target_gets_no_further_traffic(scanner: FakeScanner) -> None:
    scanner.tls = BlockedTargetError("address not allowed")
    ctx = collect_context("internal.example.com")
    assert scanner.fetched == []
    assert scanner.dns_asked == []
    assert ctx.https is None
    assert ctx.skip_reasons[Input.HTTPS] == collector.BLOCKED_REASON
    assert set(ctx.skip_reasons) == set(Input)


@pytest.mark.parametrize(
    ("probe", "expected"),
    [
        (
            TlsProbe(TlsStatus.EXPIRED, "the certificate has expired"),
            "The certificate has expired, so the site can't be reached securely.",
        ),
        (
            TlsProbe(TlsStatus.UNTRUSTED, "the certificate is self-signed"),
            "Certificate problem: the certificate is self-signed, so the site can't be reached "
            "securely.",
        ),
        (
            TlsProbe(TlsStatus.NO_HTTPS, "refused"),
            "The site doesn't offer HTTPS, so its homepage can't be read securely.",
        ),
        (
            TlsProbe(TlsStatus.NO_HTTPS, "old", legacy_accepted=True),
            "The site only supports outdated TLS, so it can't be reached securely.",
        ),
    ],
)
def test_tls_problem_explains_unreachable_homepage(
    scanner: FakeScanner, probe: TlsProbe, expected: str
) -> None:
    scanner.tls = probe
    scanner.https = RequestFailedError("request failed")
    scanner.http = RequestFailedError("request failed")
    ctx = collect_context("example.com")
    assert ctx.homepage is None
    assert ctx.skip_reasons[Input.HOMEPAGE] == expected


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (BlockedTargetError("x"), "The site redirected to an address that can't be scanned."),
        (TooManyRedirectsError("x"), "The site redirected too many times."),
        (RequestFailedError("x"), "We could not reach the site over HTTPS."),
    ],
)
def test_request_errors_explain_unreachable_homepage(
    scanner: FakeScanner, error: Exception, expected: str
) -> None:
    scanner.https = error
    assert collect_context("example.com").skip_reasons[Input.HTTPS] == expected


@pytest.mark.parametrize("status", [403, 429, 503])
def test_blocked_homepage_says_so(scanner: FakeScanner, status: int) -> None:
    scanner.https = response(status=status)
    ctx = collect_context("example.com")
    assert ctx.homepage is None
    reason = ctx.skip_reasons[Input.HOMEPAGE]
    assert "bot protection" in reason
    assert "Cloudflare" in reason
    assert f"HTTP {status}" in reason


@pytest.mark.parametrize("status", [400, 401, 404, 410])
def test_other_client_errors_still_show_real_headers(scanner: FakeScanner, status: int) -> None:
    scanner.https = response(status=status)
    ctx = collect_context("example.com")
    assert ctx.homepage is scanner.https
    assert Input.HOMEPAGE not in ctx.skip_reasons


@pytest.mark.parametrize("status", [500, 502, 504])
def test_server_errors_are_not_treated_as_the_homepage(scanner: FakeScanner, status: int) -> None:
    scanner.https = response(status=status)
    ctx = collect_context("example.com")
    assert ctx.homepage is None
    reason = ctx.skip_reasons[Input.HOMEPAGE]
    assert f"HTTP {status}" in reason
    assert "bot protection" not in reason


NO_HTTPS = TlsProbe(TlsStatus.NO_HTTPS, "port 443 refused the connection")


def http_only(scanner: FakeScanner, status: int = 200) -> None:
    scanner.tls = NO_HTTPS
    scanner.https = RequestFailedError("request failed")
    scanner.http = response(url="http://example.com/", status=status)


def test_http_only_site_uses_the_http_homepage(scanner: FakeScanner) -> None:
    http_only(scanner)
    ctx = collect_context("example.com")
    assert ctx.https is None
    assert ctx.homepage is scanner.http
    assert ctx.homepage_via_http is True
    assert Input.HOMEPAGE not in ctx.skip_reasons
    assert Input.HTTPS in ctx.not_applicable
    assert "HSTS" in ctx.skip_reasons[Input.HTTPS]


def test_http_only_404_still_counts_as_the_homepage(scanner: FakeScanner) -> None:
    http_only(scanner, status=404)
    assert collect_context("example.com").homepage is scanner.http


@pytest.mark.parametrize("status", [403, 429, 503])
def test_http_only_but_blocked_is_incomplete(scanner: FakeScanner, status: int) -> None:
    http_only(scanner, status=status)
    ctx = collect_context("example.com")
    assert ctx.homepage is None
    assert "bot protection" in ctx.skip_reasons[Input.HOMEPAGE]


@pytest.mark.parametrize(
    "probe",
    [
        RequestFailedError("TLS probe failed"),
        TlsProbe(TlsStatus.EXPIRED, "the certificate has expired"),
        TlsProbe(TlsStatus.UNTRUSTED, "the certificate is self-signed"),
        TlsProbe(TlsStatus.NO_HTTPS, "old", legacy_accepted=True),
    ],
)
def test_http_is_only_used_when_https_definitely_does_not_exist(
    scanner: FakeScanner, probe: object
) -> None:
    scanner.tls = probe
    scanner.https = RequestFailedError("request failed")
    scanner.http = response(url="http://example.com/")
    ctx = collect_context("example.com")
    assert ctx.homepage is None
    assert ctx.homepage_via_http is False
    assert Input.HTTPS not in ctx.not_applicable


def test_dns_failure_is_not_marked_not_applicable(scanner: FakeScanner) -> None:
    scanner.dns[("example.com", "TXT")] = RequestFailedError("DNS lookup failed")
    assert collect_context("example.com").not_applicable == frozenset()


@pytest.mark.parametrize("host", ["foo.vercel.app", "93.184.216.34"])
def test_dns_skipped_by_design_is_marked_not_applicable(scanner: FakeScanner, host: str) -> None:
    ctx = collect_context(host)
    assert {Input.SPF, Input.DMARC, Input.CAA} <= ctx.not_applicable


def test_tls_timeout_is_skipped_and_scan_continues(scanner: FakeScanner) -> None:
    scanner.tls = RequestFailedError("TLS probe failed")
    ctx = collect_context("example.com")
    assert ctx.tls is None
    assert Input.TLS in ctx.skip_reasons
    assert ctx.https is scanner.https


def test_http_failure_is_skipped(scanner: FakeScanner) -> None:
    scanner.http = RequestFailedError("request failed")
    ctx = collect_context("example.com")
    assert ctx.http is None
    assert Input.HTTP in ctx.skip_reasons


def test_subdomain_uses_registered_domain_for_email(scanner: FakeScanner) -> None:
    ctx = collect_context("shop.example.co.in")
    assert ctx.email_domain == "example.co.in"
    assert ("example.co.in", "TXT") in scanner.dns_asked
    assert ("_dmarc.example.co.in", "TXT") in scanner.dns_asked


def test_caa_climbs_to_the_registered_domain_and_stops(scanner: FakeScanner) -> None:
    ctx = collect_context("a.shop.example.co.in")
    assert [name for name, kind in scanner.dns_asked if kind == "CAA"] == [
        "a.shop.example.co.in",
        "shop.example.co.in",
        "example.co.in",
    ]
    assert ctx.caa_records == []


def test_caa_stops_at_first_match(scanner: FakeScanner) -> None:
    scanner.dns[("shop.example.com", "CAA")] = ['0 issue "pki.goog"']
    ctx = collect_context("shop.example.com")
    assert ctx.caa_records == ['0 issue "pki.goog"']
    assert [name for name, kind in scanner.dns_asked if kind == "CAA"] == ["shop.example.com"]


def test_shared_platform_skips_dns_with_a_reason(scanner: FakeScanner) -> None:
    ctx = collect_context("foo.vercel.app")
    assert ctx.shared_platform_suffix == "vercel.app"
    assert scanner.dns_asked == []
    assert ctx.spf_records is None
    for needed in (Input.SPF, Input.DMARC, Input.CAA):
        assert "vercel.app" in ctx.skip_reasons[needed]


def test_failed_dns_lookup_only_skips_that_input(scanner: FakeScanner) -> None:
    scanner.dns[("_dmarc.example.com", "TXT")] = RequestFailedError("DNS lookup failed")
    ctx = collect_context("example.com")
    assert ctx.spf_records == []
    assert ctx.dmarc_records is None
    assert Input.DMARC in ctx.skip_reasons
    assert Input.SPF not in ctx.skip_reasons


def test_empty_dns_answer_is_not_a_skip(scanner: FakeScanner) -> None:
    ctx = collect_context("example.com")
    assert ctx.spf_records == []
    assert Input.SPF not in ctx.skip_reasons


def test_ip_address_skips_dns(scanner: FakeScanner) -> None:
    ctx = collect_context("93.184.216.34")
    assert scanner.dns_asked == []
    assert "IP address" in ctx.skip_reasons[Input.SPF]
