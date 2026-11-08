from datetime import UTC, datetime, timedelta

import pytest

from app.checks import tls
from app.checks.base import Category, ScanContext, Severity, SkipCheck
from app.core.safe_http import TlsProbe, TlsStatus
from tests.checks.helpers import response

NOW = datetime(2026, 11, 8, tzinfo=UTC)


def ctx(**kwargs: object) -> ScanContext:
    return ScanContext(hostname="example.com", checked_at=NOW, **kwargs)


def healthy(days_left: int = 60, legacy: bool | None = False) -> TlsProbe:
    return TlsProbe(
        TlsStatus.OK,
        protocol="TLSv1.3",
        not_after=NOW + timedelta(days=days_left, hours=1),
        legacy_accepted=legacy,
    )


HTTP_OK = response(url="http://example.com/")


def test_no_https_when_http_works() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "port 443 refused the connection")
    finding = tls.no_https(ctx(tls=probe, http=HTTP_OK))
    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert finding.category is Category.TLS
    assert "port 443" in finding.evidence


def test_no_https_passes_with_healthy_tls() -> None:
    assert tls.no_https(ctx(tls=healthy(), http=HTTP_OK)) is None


def test_no_https_not_claimed_when_http_is_also_failing() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "refused")
    assert tls.no_https(ctx(tls=probe, http=response(status=503))) is None


def test_no_https_not_claimed_for_server_with_only_old_tls() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "no modern handshake", legacy_accepted=True)
    assert tls.no_https(ctx(tls=probe, http=HTTP_OK)) is None


def test_no_https_still_found_when_http_page_is_a_404() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "refused")
    assert tls.no_https(ctx(tls=probe, http=response(url="http://a.com/", status=404))) is not None


@pytest.mark.parametrize("status", [403, 429, 500])
def test_no_https_not_claimed_from_a_block_or_error_page(status: int) -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "refused")
    assert tls.no_https(ctx(tls=probe, http=response(url="http://a.com/", status=status))) is None


def test_no_https_not_claimed_when_http_redirects_to_secure_host() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "refused")
    secure = response(url="https://www.example.com/", redirects=("https://www.example.com/",))
    assert tls.no_https(ctx(tls=probe, http=secure)) is None


def test_no_https_skips_when_http_could_not_be_loaded() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "refused")
    with pytest.raises(SkipCheck):
        tls.no_https(ctx(tls=probe))


def test_no_https_passes_without_http_when_tls_is_healthy() -> None:
    assert tls.no_https(ctx(tls=healthy())) is None


def test_no_http_redirect_not_charged_when_there_is_no_https() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "refused")
    assert tls.no_http_redirect(ctx(tls=probe, http=HTTP_OK)) is None


def test_no_http_redirect_still_found_for_old_tls_only_server() -> None:
    probe = TlsProbe(TlsStatus.NO_HTTPS, "no modern handshake", legacy_accepted=True)
    assert tls.no_http_redirect(ctx(tls=probe, http=HTTP_OK)) is not None


def test_legacy_version_passes_when_there_is_no_tls_to_test() -> None:
    assert tls.legacy_version(ctx(tls=TlsProbe(TlsStatus.NO_HTTPS, "refused"))) is None


def test_cert_expired() -> None:
    probe = TlsProbe(TlsStatus.EXPIRED, "the certificate has expired")
    finding = tls.cert_expired(ctx(tls=probe))
    assert finding is not None
    assert finding.severity is Severity.CRITICAL


def test_cert_expired_passes() -> None:
    assert tls.cert_expired(ctx(tls=healthy())) is None


def test_cert_untrusted_explains_why() -> None:
    probe = TlsProbe(TlsStatus.UNTRUSTED, "the certificate is self-signed")
    finding = tls.cert_untrusted(ctx(tls=probe))
    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert "self-signed" in finding.evidence


def test_cert_untrusted_passes() -> None:
    assert tls.cert_untrusted(ctx(tls=healthy())) is None


@pytest.mark.parametrize(
    ("days", "expected"),
    [
        (0, Severity.HIGH),
        (7, Severity.HIGH),
        (8, Severity.MEDIUM),
        (21, Severity.MEDIUM),
    ],
)
def test_cert_expiring_severity(days: int, expected: Severity) -> None:
    finding = tls.cert_expiring(ctx(tls=healthy(days)))
    assert finding is not None
    assert finding.severity is expected
    assert f"in {days} days" in finding.evidence


def test_cert_expiring_passes_with_time_left() -> None:
    assert tls.cert_expiring(ctx(tls=healthy(22))) is None


def test_cert_expiring_defers_to_other_checks_when_cert_is_bad() -> None:
    assert tls.cert_expiring(ctx(tls=TlsProbe(TlsStatus.EXPIRED, "x"))) is None


def test_cert_expiring_skips_when_date_unreadable() -> None:
    with pytest.raises(SkipCheck):
        tls.cert_expiring(ctx(tls=TlsProbe(TlsStatus.OK)))


def test_legacy_version_found() -> None:
    finding = tls.legacy_version(ctx(tls=healthy(legacy=True)))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM


def test_legacy_version_passes() -> None:
    assert tls.legacy_version(ctx(tls=healthy(legacy=False))) is None


def test_legacy_version_unknown_is_skipped_not_passed() -> None:
    with pytest.raises(SkipCheck):
        tls.legacy_version(ctx(tls=healthy(legacy=None)))


def test_no_http_redirect_found() -> None:
    finding = tls.no_http_redirect(ctx(http=HTTP_OK))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM


def test_http_redirect_to_https_passes() -> None:
    redirected = response(url="https://example.com/", redirects=("https://example.com/",))
    assert tls.no_http_redirect(ctx(http=redirected)) is None


def test_http_error_page_is_not_flagged() -> None:
    assert tls.no_http_redirect(ctx(http=response(url="http://example.com/", status=404))) is None


def hsts(value: str | None) -> ScanContext:
    headers = {"strict-transport-security": value} if value is not None else {}
    return ctx(https=response(headers=headers))


@pytest.mark.parametrize("value", [None, "", "includeSubDomains", "max-age=abc"])
def test_hsts_missing_or_invalid(value: str | None) -> None:
    finding = tls.hsts_missing(hsts(value))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM


def test_hsts_zero_counts_as_missing() -> None:
    finding = tls.hsts_missing(hsts("max-age=0"))
    assert finding is not None
    assert "max-age=0" in finding.evidence


def test_hsts_over_plain_http_counts_as_missing() -> None:
    downgraded = response(
        headers={"strict-transport-security": "max-age=31536000"}, url="http://example.com/"
    )
    assert tls.hsts_missing(ctx(https=downgraded)) is not None


@pytest.mark.parametrize(
    "value",
    [
        "max-age=31536000",
        "MAX-AGE=31536000; includeSubDomains",
        'includeSubDomains; max-age="63072000"',
    ],
)
def test_hsts_present_passes(value: str) -> None:
    assert tls.hsts_missing(hsts(value)) is None
    assert tls.hsts_weak(hsts(value)) is None


def test_hsts_weak_found() -> None:
    finding = tls.hsts_weak(hsts("max-age=3600"))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert tls.hsts_missing(hsts("max-age=3600")) is None


def test_hsts_at_six_months_passes() -> None:
    assert tls.hsts_weak(hsts(f"max-age={tls.HSTS_MIN_SECONDS}")) is None


@pytest.mark.parametrize("value", [None, "max-age=0"])
def test_hsts_weak_leaves_missing_to_its_own_check(value: str | None) -> None:
    assert tls.hsts_weak(hsts(value)) is None
