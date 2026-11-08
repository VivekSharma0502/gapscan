"""Passive cookie checks.

Security: only cookie names reach findings. Values can be session tokens, so they are
dropped as soon as a header is parsed.

Each check reports at most one finding, listing the affected cookies, so a site with
many cookies doesn't lose more points than a site with one.
"""

import re
from dataclasses import dataclass

from app.checks.base import Category, Finding, Input, ScanContext, Severity
from app.checks.registry import check, make_finding

MAX_NAME_CHARS = 64
MAX_NAMES_LISTED = 10

# Anti-CSRF cookies are meant to be read by scripts, so they are left out.
_ANTI_CSRF_RE = re.compile(r"csrf|xsrf", re.IGNORECASE)
_SESSION_LIKE_RE = re.compile(r"sess|\bsid\b|auth|token|jwt|logged_in", re.IGNORECASE)


@dataclass(frozen=True)
class _Cookie:
    name: str
    attributes: dict[str, str]


def _parse(header: str) -> _Cookie:
    first, *rest = header.split(";")
    attributes: dict[str, str] = {}
    for part in rest:
        key, _, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip()
    return _Cookie(first.partition("=")[0].strip()[:MAX_NAME_CHARS], attributes)


def _is_deletion(cookie: _Cookie) -> bool:
    # A header that clears a cookie carries no value, so its flags don't matter.
    return cookie.attributes.get("max-age", "").strip() == "0" or "1970" in cookie.attributes.get(
        "expires", ""
    )


def _cookies(ctx: ScanContext) -> list[_Cookie]:
    parsed = [_parse(header) for header in ctx.https.headers.get_list("set-cookie")]
    return [cookie for cookie in parsed if cookie.name and not _is_deletion(cookie)]


def _names(cookies: list[_Cookie]) -> str:
    names = [cookie.name for cookie in cookies]
    if len(names) <= MAX_NAMES_LISTED:
        return ", ".join(names)
    return f"{', '.join(names[:MAX_NAMES_LISTED])} and {len(names) - MAX_NAMES_LISTED} more"


@check("cookies.secure", Category.COOKIES, requires=[Input.HTTPS])
def secure(ctx: ScanContext) -> Finding | None:
    affected = [cookie for cookie in _cookies(ctx) if "secure" not in cookie.attributes]
    if not affected:
        return None
    return make_finding("cookies.secure", Severity.MEDIUM, f"Missing Secure: {_names(affected)}")


@check("cookies.httponly", Category.COOKIES, requires=[Input.HTTPS])
def httponly(ctx: ScanContext) -> Finding | None:
    # Only session-like cookies are flagged, because many harmless cookies, such as a
    # theme preference, are meant to be readable by the site's own scripts.
    affected = [
        cookie
        for cookie in _cookies(ctx)
        if "httponly" not in cookie.attributes
        and _SESSION_LIKE_RE.search(cookie.name)
        and not _ANTI_CSRF_RE.search(cookie.name)
    ]
    if not affected:
        return None
    return make_finding(
        "cookies.httponly", Severity.MEDIUM, f"Missing HttpOnly: {_names(affected)}"
    )


def _samesite_problem(cookie: _Cookie) -> bool:
    value = cookie.attributes.get("samesite", "").lower()
    if value in {"lax", "strict"}:
        return False
    # SameSite=None is a valid choice for a cross-site cookie, as long as it is also Secure.
    return not (value == "none" and "secure" in cookie.attributes)


@check("cookies.samesite", Category.COOKIES, requires=[Input.HTTPS])
def samesite(ctx: ScanContext) -> Finding | None:
    affected = [cookie for cookie in _cookies(ctx) if _samesite_problem(cookie)]
    if not affected:
        return None
    return make_finding("cookies.samesite", Severity.LOW, f"No safe SameSite: {_names(affected)}")
