"""Passive HTTP security header checks. MDN Observatory's rules are the reference."""

import re

from app.checks.base import Category, Finding, Input, ScanContext, Severity
from app.checks.registry import check, make_finding

Directives = dict[str, list[str]]

_HASH_OR_NONCE_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
_BROAD_SOURCES = {"*", "http:", "https:", "data:"}
_FRAME_WILDCARDS = {"*", "http:", "https:"}

_VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}
_LEAKY_REFERRER_POLICIES = {"no-referrer-when-downgrade", "unsafe-url"}

_VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
# Matches "nginx/1.18", "PHP/8" and "4.0.30319", but not plain names like "cloudflare".
_VERSION_RE = re.compile(r"/v?\d|\b\d+\.\d+")


def _parse_csp(value: str) -> Directives:
    directives: Directives = {}
    for part in value.split(";"):
        tokens = part.split()
        # Security: browsers ignore a repeated directive, so only the first one counts.
        if tokens and tokens[0].lower() not in directives:
            directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return directives


def _policies(ctx: ScanContext) -> list[Directives]:
    return [_parse_csp(value) for value in ctx.homepage.headers.get_list("content-security-policy")]


def _script_weaknesses(policy: Directives) -> list[str]:
    sources = policy.get("script-src", policy.get("default-src"))
    if sources is None:
        return ["no script-src or default-src"]

    has_nonce_or_hash = any(source.startswith(_HASH_OR_NONCE_PREFIXES) for source in sources)
    # With a nonce or hash, browsers ignore 'unsafe-inline'. With 'strict-dynamic' as well,
    # they also ignore host and scheme sources, so those are not weaknesses in that case.
    trusts_nonce_only = has_nonce_or_hash and "'strict-dynamic'" in sources

    weaknesses: list[str] = []
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        weaknesses.append("'unsafe-inline'")
    if "'unsafe-eval'" in sources:
        weaknesses.append("'unsafe-eval'")
    if not trusts_nonce_only:
        weaknesses.extend(source for source in sources if source in _BROAD_SOURCES)
    return weaknesses


@check("headers.csp_missing", Category.HEADERS, requires=[Input.HOMEPAGE])
def csp_missing(ctx: ScanContext) -> Finding | None:
    if _policies(ctx):
        return None
    # Report-Only never blocks anything, so it doesn't count as having a policy.
    report_only = "content-security-policy-report-only" in ctx.homepage.headers
    evidence = (
        "Only Content-Security-Policy-Report-Only is set, which blocks nothing"
        if report_only
        else "No Content-Security-Policy header"
    )
    return make_finding("headers.csp_missing", Severity.MEDIUM, evidence)


@check("headers.csp_weak", Category.HEADERS, requires=[Input.HOMEPAGE])
def csp_weak(ctx: ScanContext) -> Finding | None:
    policies = _policies(ctx)
    if not policies:
        return None
    # Browsers enforce every policy they receive, so one strong policy is enough.
    weaknesses = [_script_weaknesses(policy) for policy in policies]
    if not all(weaknesses):
        return None
    return make_finding("headers.csp_weak", Severity.LOW, f"Allows: {', '.join(weaknesses[0])}")


@check("headers.clickjacking", Category.HEADERS, requires=[Input.HOMEPAGE])
def clickjacking(ctx: ScanContext) -> Finding | None:
    ancestors = [
        policy["frame-ancestors"] for policy in _policies(ctx) if "frame-ancestors" in policy
    ]
    # Browsers follow frame-ancestors over X-Frame-Options whenever it is present.
    if ancestors:
        if any(not _FRAME_WILDCARDS.intersection(sources) for sources in ancestors):
            return None
        return make_finding(
            "headers.clickjacking", Severity.MEDIUM, "frame-ancestors allows any website"
        )

    frame_options = ctx.homepage.headers.get("x-frame-options")
    if frame_options is None:
        return make_finding(
            "headers.clickjacking",
            Severity.MEDIUM,
            "No X-Frame-Options header and no frame-ancestors directive",
        )
    # ALLOW-FROM is obsolete and modern browsers ignore it.
    if {part.strip().upper() for part in frame_options.split(",")} <= {"DENY", "SAMEORIGIN"}:
        return None
    return make_finding(
        "headers.clickjacking", Severity.MEDIUM, f"X-Frame-Options: {frame_options}"
    )


@check("headers.content_type_options", Category.HEADERS, requires=[Input.HOMEPAGE])
def content_type_options(ctx: ScanContext) -> Finding | None:
    value = ctx.homepage.headers.get("x-content-type-options")
    if value is not None and value.split(",")[0].strip().lower() == "nosniff":
        return None
    evidence = f"X-Content-Type-Options: {value}" if value else "No X-Content-Type-Options header"
    return make_finding("headers.content_type_options", Severity.LOW, evidence)


@check("headers.referrer_policy", Category.HEADERS, requires=[Input.HOMEPAGE])
def referrer_policy(ctx: ScanContext) -> Finding | None:
    value = ctx.homepage.headers.get("referrer-policy", "")
    tokens = [token.strip().lower() for token in value.split(",")]
    # A comma list is a fallback chain: the last value the browser understands wins.
    recognised = [token for token in tokens if token in _VALID_REFERRER_POLICIES]
    if not recognised:
        return make_finding(
            "headers.referrer_policy", Severity.LOW, "No valid Referrer-Policy header"
        )
    if recognised[-1] in _LEAKY_REFERRER_POLICIES:
        return make_finding(
            "headers.referrer_policy", Severity.LOW, f"Referrer-Policy: {recognised[-1]}"
        )
    return None


@check("headers.permissions_policy", Category.HEADERS, requires=[Input.HOMEPAGE])
def permissions_policy(ctx: ScanContext) -> Finding | None:
    if "permissions-policy" in ctx.homepage.headers or "feature-policy" in ctx.homepage.headers:
        return None
    return make_finding("headers.permissions_policy", Severity.INFO, "No Permissions-Policy header")


@check("headers.server_version", Category.HEADERS, requires=[Input.HOMEPAGE])
def server_version(ctx: ScanContext) -> Finding | None:
    leaks = [
        f"{name}: {ctx.homepage.headers[name]}"
        for name in _VERSION_HEADERS
        if name in ctx.homepage.headers and _VERSION_RE.search(ctx.homepage.headers[name])
    ]
    if not leaks:
        return None
    return make_finding("headers.server_version", Severity.LOW, "; ".join(leaks))
