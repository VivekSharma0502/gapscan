import pytest

from app.checks import cookies
from app.checks.base import Category, ScanContext, Severity
from tests.checks.helpers import response

COOKIE_VALUE = "s3cr3t-token-value"
GOOD = f"session={COOKIE_VALUE}; Path=/; Secure; HttpOnly; SameSite=Lax"


def ctx(*set_cookies: str) -> ScanContext:
    headers = [("set-cookie", value) for value in set_cookies]
    return ScanContext(hostname="example.com", https=response(headers=headers))


@pytest.mark.parametrize("check", [cookies.secure, cookies.httponly, cookies.samesite])
def test_no_cookies_passes(check) -> None:
    assert check(ctx()) is None


@pytest.mark.parametrize("check", [cookies.secure, cookies.httponly, cookies.samesite])
def test_well_configured_cookie_passes(check) -> None:
    assert check(ctx(GOOD)) is None


@pytest.mark.parametrize(
    "check",
    [cookies.secure, cookies.httponly, cookies.samesite],
)
def test_values_never_reach_evidence(check) -> None:
    finding = check(ctx(f"session={COOKIE_VALUE}; Path=/"))
    assert finding is not None
    assert COOKIE_VALUE not in finding.evidence
    assert COOKIE_VALUE not in finding.model_dump_json()
    assert "session" in finding.evidence


def test_secure_missing() -> None:
    finding = cookies.secure(ctx("theme=dark; Path=/"))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert finding.category is Category.COOKIES


def test_flags_are_case_insensitive() -> None:
    assert cookies.secure(ctx("a=1; SECURE")) is None
    assert cookies.httponly(ctx("session=1; httponly")) is None
    assert cookies.samesite(ctx("a=1; SAMESITE=STRICT")) is None


def test_one_finding_lists_all_affected_cookies() -> None:
    finding = cookies.secure(ctx("a=1", "b=2", GOOD))
    assert finding is not None
    assert finding.evidence == "Missing Secure: a, b"


def test_long_cookie_lists_are_shortened() -> None:
    many = [f"c{index}=1" for index in range(13)]
    finding = cookies.secure(ctx(*many))
    assert finding is not None
    assert finding.evidence.endswith("and 3 more")


def test_long_cookie_names_are_cut() -> None:
    finding = cookies.secure(ctx(f"{'x' * 500}=1"))
    assert finding is not None
    assert "x" * cookies.MAX_NAME_CHARS in finding.evidence
    assert "x" * (cookies.MAX_NAME_CHARS + 1) not in finding.evidence


@pytest.mark.parametrize(
    "name",
    [
        "PHPSESSID",
        "JSESSIONID",
        "connect.sid",
        "sessionid",
        "auth_token",
        "__Secure-next-auth.session-token",
        "sb-abc-auth-token",
        "wordpress_logged_in_abc",
        "jwt",
    ],
)
def test_httponly_flags_session_like_names(name: str) -> None:
    finding = cookies.httponly(ctx(f"{name}=1; Secure; SameSite=Lax"))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert name in finding.evidence


@pytest.mark.parametrize("name", ["theme", "locale", "consider", "csrftoken", "XSRF-TOKEN"])
def test_httponly_ignores_cookies_scripts_may_read(name: str) -> None:
    assert cookies.httponly(ctx(f"{name}=1; Secure; SameSite=Lax")) is None


@pytest.mark.parametrize("attributes", ["", "; SameSite=None", "; SameSite=bogus"])
def test_samesite_problem(attributes: str) -> None:
    finding = cookies.samesite(ctx(f"a=1{attributes}"))
    assert finding is not None
    assert finding.severity is Severity.LOW


@pytest.mark.parametrize("value", ["Lax", "Strict", "None; Secure"])
def test_samesite_passes(value: str) -> None:
    assert cookies.samesite(ctx(f"a=1; SameSite={value}")) is None


@pytest.mark.parametrize(
    "header",
    ["session=; Max-Age=0", "session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
)
@pytest.mark.parametrize("check", [cookies.secure, cookies.httponly, cookies.samesite])
def test_cookie_deletions_are_ignored(check, header: str) -> None:
    assert check(ctx(header)) is None


def test_comma_in_expires_is_not_split_into_two_cookies() -> None:
    finding = cookies.secure(ctx("a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT"))
    assert finding is not None
    assert finding.evidence == "Missing Secure: a"


def test_header_without_a_name_is_ignored() -> None:
    assert cookies.secure(ctx("=value")) is None
