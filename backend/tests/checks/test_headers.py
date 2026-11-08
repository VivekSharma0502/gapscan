import pytest

from app.checks import headers
from app.checks.base import Category, ScanContext, Severity
from tests.checks.helpers import Headers, response


def ctx(values: Headers | None = None) -> ScanContext:
    return ScanContext(hostname="example.com", https=response(headers=values))


def csp(value: str) -> ScanContext:
    return ctx({"content-security-policy": value})


def test_csp_missing() -> None:
    finding = headers.csp_missing(ctx())
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert finding.category is Category.HEADERS


def test_csp_report_only_does_not_count() -> None:
    finding = headers.csp_missing(
        ctx({"content-security-policy-report-only": "default-src 'self'"})
    )
    assert finding is not None
    assert "Report-Only" in finding.evidence


def test_csp_present_passes() -> None:
    assert headers.csp_missing(csp("default-src 'self'")) is None


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("script-src 'self' 'unsafe-inline'", "'unsafe-inline'"),
        ("script-src 'self' 'unsafe-eval'", "'unsafe-eval'"),
        ("default-src *", "*"),
        ("script-src https:", "https:"),
        ("script-src data:", "data:"),
        ("img-src 'self'", "no script-src or default-src"),
        ("SCRIPT-SRC 'UNSAFE-INLINE'", "'unsafe-inline'"),
    ],
)
def test_csp_weak(policy: str, expected: str) -> None:
    finding = headers.csp_weak(csp(policy))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert expected in finding.evidence


@pytest.mark.parametrize(
    "policy",
    [
        "default-src 'self'",
        "script-src 'self' cdn.example.net",
        # Browsers ignore 'unsafe-inline' when a nonce or hash is present.
        "script-src 'nonce-abc' 'unsafe-inline'",
        "script-src 'sha256-abc=' 'unsafe-inline'",
        # 'strict-dynamic' makes browsers ignore host and scheme sources.
        "script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'",
        # script-src takes over from default-src.
        "default-src *; script-src 'self'",
    ],
)
def test_csp_strong_passes(policy: str) -> None:
    assert headers.csp_weak(csp(policy)) is None


def test_csp_weak_ignores_repeated_directive() -> None:
    assert headers.csp_weak(csp("script-src 'self'; script-src *")) is None


def test_csp_weak_leaves_missing_to_its_own_check() -> None:
    assert headers.csp_weak(ctx()) is None


def test_one_strong_policy_out_of_two_is_enough() -> None:
    values = [
        ("content-security-policy", "script-src *"),
        ("content-security-policy", "script-src 'self'"),
    ]
    assert headers.csp_weak(ctx(values)) is None


def test_clickjacking_found() -> None:
    finding = headers.clickjacking(ctx())
    assert finding is not None
    assert finding.severity is Severity.MEDIUM


@pytest.mark.parametrize("value", ["DENY", "SAMEORIGIN", "sameorigin", "DENY, DENY"])
def test_x_frame_options_passes(value: str) -> None:
    assert headers.clickjacking(ctx({"x-frame-options": value})) is None


@pytest.mark.parametrize("value", ["ALLOW-FROM https://a.com", "nonsense", "DENY, ALLOWALL"])
def test_invalid_x_frame_options_is_flagged(value: str) -> None:
    finding = headers.clickjacking(ctx({"x-frame-options": value}))
    assert finding is not None
    assert value in finding.evidence


@pytest.mark.parametrize("sources", ["'none'", "'self'", "https://partner.example.com"])
def test_frame_ancestors_passes(sources: str) -> None:
    assert headers.clickjacking(csp(f"frame-ancestors {sources}")) is None


@pytest.mark.parametrize("sources", ["*", "https:"])
def test_frame_ancestors_wildcard_overrides_x_frame_options(sources: str) -> None:
    values = {
        "content-security-policy": f"frame-ancestors {sources}",
        "x-frame-options": "DENY",
    }
    finding = headers.clickjacking(ctx(values))
    assert finding is not None
    assert "any website" in finding.evidence


@pytest.mark.parametrize("value", ["nosniff", "NoSniff", "nosniff, nosniff"])
def test_content_type_options_passes(value: str) -> None:
    assert headers.content_type_options(ctx({"x-content-type-options": value})) is None


def test_content_type_options_missing() -> None:
    finding = headers.content_type_options(ctx())
    assert finding is not None
    assert finding.severity is Severity.LOW


def test_content_type_options_wrong_value() -> None:
    finding = headers.content_type_options(ctx({"x-content-type-options": "sniff"}))
    assert finding is not None
    assert "sniff" in finding.evidence


@pytest.mark.parametrize(
    "value",
    ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "UNSAFE-URL, same-origin"],
)
def test_referrer_policy_passes(value: str) -> None:
    assert headers.referrer_policy(ctx({"referrer-policy": value})) is None


@pytest.mark.parametrize(
    "value", ["unsafe-url", "no-referrer-when-downgrade", "origin, unsafe-url"]
)
def test_referrer_policy_leaky(value: str) -> None:
    finding = headers.referrer_policy(ctx({"referrer-policy": value}))
    assert finding is not None
    assert finding.severity is Severity.LOW


@pytest.mark.parametrize("values", [None, {"referrer-policy": "nonsense"}, {"referrer-policy": ""}])
def test_referrer_policy_missing_or_invalid(values: dict[str, str] | None) -> None:
    finding = headers.referrer_policy(ctx(values))
    assert finding is not None
    assert "No valid" in finding.evidence


def test_permissions_policy_missing_costs_nothing() -> None:
    finding = headers.permissions_policy(ctx())
    assert finding is not None
    assert finding.severity is Severity.INFO


@pytest.mark.parametrize("name", ["permissions-policy", "feature-policy"])
def test_permissions_policy_passes(name: str) -> None:
    assert headers.permissions_policy(ctx({name: "camera=()"})) is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("server", "nginx/1.18.0"),
        ("server", "Apache/2.4.41 (Ubuntu)"),
        ("server", "Microsoft-IIS/10.0"),
        ("x-powered-by", "PHP/8.1.2"),
        ("x-powered-by", "PHP/8"),
        ("x-aspnet-version", "4.0.30319"),
        ("x-aspnetmvc-version", "5.2"),
    ],
)
def test_server_version_found(name: str, value: str) -> None:
    finding = headers.server_version(ctx({name: value}))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert finding.evidence == f"{name}: {value}"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("server", "cloudflare"),
        ("server", "nginx"),
        ("server", "Vercel"),
        ("x-powered-by", "Next.js"),
    ],
)
def test_server_without_version_passes(name: str, value: str) -> None:
    assert headers.server_version(ctx({name: value})) is None


def test_every_leaking_header_is_listed() -> None:
    finding = headers.server_version(ctx({"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1"}))
    assert finding is not None
    assert "nginx/1.18.0" in finding.evidence
    assert "PHP/8.1" in finding.evidence
