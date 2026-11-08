from datetime import UTC, datetime, timedelta

import pytest

from app.checks import runner
from app.checks.base import Category, Input, Platform, ScanContext, Severity, SkipCheck
from app.checks.catalog import CATALOG
from app.checks.registry import CheckSpec, all_checks, make_finding
from app.checks.runner import ScanStatus, run_checks
from app.core.safe_http import TlsProbe, TlsStatus
from tests.checks.helpers import response

NOW = datetime(2026, 11, 8, tzinfo=UTC)

HEALTHY_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}

HEALTHY_TLS = TlsProbe(
    TlsStatus.OK, protocol="TLSv1.3", not_after=NOW + timedelta(days=60), legacy_accepted=False
)


def healthy(**overrides: object) -> ScanContext:
    fields: dict[str, object] = {
        "hostname": "example.com",
        "checked_at": NOW,
        "https": response(headers=HEALTHY_HEADERS),
        "http": response(url="https://example.com/"),
        "tls": HEALTHY_TLS,
        "email_domain": "example.com",
        "spf_records": ["v=spf1 -all"],
        "dmarc_records": ["v=DMARC1; p=reject"],
        "caa_records": ['0 issue "letsencrypt.org"'],
    }
    return ScanContext(**(fields | overrides))


def ids(report: runner.ScanReport) -> list[str]:
    return [finding.check_id for finding in report.findings]


EXPECTED_CHECKS = {
    "tls.no_https",
    "tls.cert_expired",
    "tls.cert_untrusted",
    "tls.cert_expiring",
    "tls.legacy_version",
    "tls.no_http_redirect",
    "tls.hsts_missing",
    "tls.hsts_weak",
    "headers.csp_missing",
    "headers.csp_weak",
    "headers.clickjacking",
    "headers.content_type_options",
    "headers.referrer_policy",
    "headers.permissions_policy",
    "headers.server_version",
    "cookies.secure",
    "cookies.httponly",
    "cookies.samesite",
    "dns.spf_missing",
    "dns.spf_weak",
    "dns.dmarc_missing",
    "dns.dmarc_weak",
    "dns.caa_missing",
    "dns.shared_platform_domain",
    "cms.wordpress_version",
    "exposure.env_file",
    "exposure.git_directory",
    "exposure.ds_store",
    "exposure.backup_file",
    "exposure.source_maps",
    "exposure.directory_listing",
}


def test_every_planned_check_is_registered() -> None:
    assert {spec.check_id for spec in all_checks()} == EXPECTED_CHECKS


def test_catalog_has_no_orphaned_text() -> None:
    assert set(CATALOG) == EXPECTED_CHECKS


@pytest.mark.parametrize("check_id", sorted(EXPECTED_CHECKS))
def test_every_check_has_full_text(check_id: str) -> None:
    text = CATALOG[check_id]
    assert text.title.strip()
    assert text.fix.what_it_means.strip()
    assert text.fix.how_to_fix.strip()
    assert set(text.fix.platforms) == set(Platform)
    for fix in text.fix.platforms.values():
        assert fix.instructions.strip()


def test_healthy_site_gets_a_perfect_report() -> None:
    report = run_checks(healthy())
    assert report.status is ScanStatus.COMPLETE
    assert report.findings == []
    assert report.skipped == []
    assert (report.score, report.grade) == (100, "A+")
    assert report.incomplete_reason is None


def test_findings_are_scored_and_graded() -> None:
    https = response(headers=HEALTHY_HEADERS | {"server": "nginx/1.18.0"})
    report = run_checks(healthy(https=https, caa_records=[]))
    assert ids(report) == ["dns.caa_missing", "headers.server_version"]
    assert (report.score, report.grade) == (96, "A+")


def test_findings_are_sorted_most_severe_first() -> None:
    https = response(headers={"strict-transport-security": "max-age=31536000"})
    report = run_checks(healthy(https=https, spf_records=["v=spf1 +all"]))
    severities = [finding.severity for finding in report.findings]
    assert severities == sorted(severities, key=list(Severity).index)


def test_expired_certificate_makes_scan_incomplete_but_keeps_findings() -> None:
    reason = "The certificate has expired, so the site can't be reached securely."
    report = run_checks(
        healthy(
            https=None,
            http=None,
            tls=TlsProbe(TlsStatus.EXPIRED, "the certificate has expired"),
            skip_reasons={Input.HTTPS: reason, Input.HOMEPAGE: reason, Input.HTTP: "failed"},
        )
    )
    assert report.status is ScanStatus.INCOMPLETE
    assert report.incomplete_reason == reason
    assert report.score is None
    # The site can't be read, so there are no points, but a broken connection is still an F.
    assert report.grade == "F"
    assert report.grade_cap_reason == "Capped at F: certificate has expired"
    assert report.score_label is None
    assert "tls.cert_expired" in ids(report)
    skipped = {item.check_id: item.reason for item in report.skipped}
    assert skipped["headers.csp_missing"] == reason
    assert skipped["cookies.secure"] == reason
    assert skipped["cms.wordpress_version"] == reason


def test_incomplete_has_a_reason_even_if_none_was_recorded() -> None:
    report = run_checks(healthy(https=None))
    assert report.status is ScanStatus.INCOMPLETE
    assert report.incomplete_reason


def test_failed_dns_lookup_keeps_the_score_but_labels_it_partial() -> None:
    report = run_checks(healthy(dmarc_records=None, skip_reasons={Input.DMARC: "DNS failed"}))
    assert report.status is ScanStatus.PARTIAL
    assert report.score_label == "Partial — 2 checks skipped"
    assert (report.score, report.grade) == (100, "A+")
    skipped = {item.check_id: item.reason for item in report.skipped}
    assert skipped == {"dns.dmarc_missing": "DNS failed", "dns.dmarc_weak": "DNS failed"}


def test_failed_tls_probe_keeps_the_score_but_labels_it_partial() -> None:
    report = run_checks(healthy(tls=None, skip_reasons={Input.TLS: "timed out"}))
    assert report.status is ScanStatus.PARTIAL
    assert report.score == 100
    assert report.score_label == f"Partial — {len(report.skipped)} checks skipped"


def test_partial_label_uses_singular_for_one_check() -> None:
    probe = TlsProbe(TlsStatus.OK, protocol="TLSv1.3", legacy_accepted=False)
    report = run_checks(healthy(tls=probe))
    assert report.score_label == "Partial — 1 check skipped"


def test_full_scan_has_no_label() -> None:
    report = run_checks(healthy())
    assert report.status is ScanStatus.COMPLETE
    assert report.score_label is None


def http_only_context(**overrides: object) -> ScanContext:
    fields: dict[str, object] = {
        "https": None,
        "http": response(
            headers=[("set-cookie", "session=abc")],
            url="http://example.com/",
        ),
        "tls": TlsProbe(TlsStatus.NO_HTTPS, "port 443 refused the connection"),
        "homepage_via_http": True,
        "not_applicable": frozenset({Input.HTTPS}),
        "skip_reasons": {Input.HTTPS: "HSTS only works over HTTPS."},
    }
    return healthy(**(fields | overrides))


def test_http_only_site_gets_a_real_low_score() -> None:
    report = run_checks(http_only_context())
    assert report.status is ScanStatus.COMPLETE
    assert report.incomplete_reason is None
    assert report.score_label is None
    # no_https 25, CSP 7, clickjacking 7, cookies 7 + 7 + 2, nosniff 2, referrer 2
    # The score alone would earn a D, but a site with no HTTPS can't do better than F.
    assert (report.score, report.grade) == (41, "F")
    assert report.grade_cap_reason == "Capped at F: site doesn't offer HTTPS"
    assert report.findings[0].check_id == "tls.no_https"
    assert report.findings[0].severity is Severity.CRITICAL


def test_http_only_site_runs_header_and_cookie_checks_on_http_page() -> None:
    found = ids(run_checks(http_only_context()))
    assert {"headers.csp_missing", "cookies.secure", "cookies.httponly"} <= set(found)


def test_http_only_site_is_not_charged_for_things_https_would_need() -> None:
    report = run_checks(http_only_context())
    assert not {"tls.no_http_redirect", "tls.hsts_missing", "tls.hsts_weak"} & set(ids(report))
    skipped = {item.check_id: item.not_applicable for item in report.skipped}
    assert skipped == {"tls.hsts_missing": True, "tls.hsts_weak": True}


def test_shared_platform_is_scored_without_dns_penalties() -> None:
    reason = "vercel.app is a shared domain, so these records belong to the platform."
    report = run_checks(
        healthy(
            hostname="foo.vercel.app",
            email_domain=None,
            spf_records=None,
            dmarc_records=None,
            caa_records=None,
            shared_platform_suffix="vercel.app",
            skip_reasons=dict.fromkeys((Input.SPF, Input.DMARC, Input.CAA), reason),
            not_applicable=frozenset({Input.SPF, Input.DMARC, Input.CAA}),
        )
    )
    # Skipped by design, so the grade isn't generous and no "partial" label is shown.
    assert report.status is ScanStatus.COMPLETE
    assert report.score_label is None
    assert ids(report) == ["dns.shared_platform_domain"]
    assert report.findings[0].severity is Severity.INFO
    assert (report.score, report.grade) == (100, "A+")
    assert {item.check_id for item in report.skipped} == {
        "dns.spf_missing",
        "dns.spf_weak",
        "dns.dmarc_missing",
        "dns.dmarc_weak",
        "dns.caa_missing",
    }


def test_check_raising_skip_is_reported_as_skipped() -> None:
    report = run_checks(healthy(tls=TlsProbe(TlsStatus.OK, legacy_accepted=None)))
    skipped = {item.check_id for item in report.skipped}
    assert skipped == {"tls.cert_expiring", "tls.legacy_version"}


def test_skip_reason_defaults_when_not_recorded() -> None:
    report = run_checks(healthy(tls=None))
    assert all(item.reason for item in report.skipped)


def test_crashing_check_does_not_lose_the_report(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def explode(ctx: ScanContext) -> None:
        raise ValueError("SENSITIVE content echoed from the site")

    def skips(ctx: ScanContext) -> None:
        raise SkipCheck("no answer")

    def finds(ctx: ScanContext):
        return make_finding("tls.hsts_weak", Severity.LOW, "seen")

    specs = [
        CheckSpec("tls.cert_expired", Category.TLS, explode, frozenset()),
        CheckSpec("tls.cert_untrusted", Category.TLS, skips, frozenset()),
        CheckSpec("tls.hsts_weak", Category.TLS, finds, frozenset()),
    ]
    monkeypatch.setattr(runner, "all_checks", lambda: specs)

    report = run_checks(healthy())

    assert ids(report) == ["tls.hsts_weak"]
    assert report.score_label == "Partial — 2 checks skipped"
    skipped = {item.check_id: item.reason for item in report.skipped}
    assert skipped["tls.cert_untrusted"] == "no answer"
    assert skipped["tls.cert_expired"] == runner._CHECK_FAILED_REASON
    assert "SENSITIVE" not in caplog.text
    assert "ValueError" in caplog.text


def test_report_serialises_to_the_required_fields() -> None:
    https = response(headers=HEALTHY_HEADERS | {"server": "nginx/1.18.0"})
    finding = run_checks(healthy(https=https)).model_dump(mode="json")["findings"][0]
    assert {"check_id", "category", "severity", "title", "evidence", "fix"} <= set(finding)
    assert {"what_it_means", "how_to_fix", "platforms"} <= set(finding["fix"])
    assert set(finding["fix"]["platforms"]) == {"vercel", "netlify", "nginx", "cloudflare"}
