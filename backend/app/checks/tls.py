"""Passive TLS and HTTPS checks."""

import re

from app.checks.base import (
    Category,
    Finding,
    Input,
    ScanContext,
    Severity,
    SkipCheck,
    shows_real_page,
)
from app.checks.registry import check, make_finding
from app.core.safe_http import TlsStatus

EXPIRY_HIGH_DAYS = 7
EXPIRY_MEDIUM_DAYS = 21
HSTS_MIN_SECONDS = 15_768_000  # six months, the minimum MDN Observatory accepts

_MAX_AGE_RE = re.compile(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)


def _has_no_tls(ctx: ScanContext) -> bool:
    # A server that only speaks old TLS does have HTTPS, and tls.legacy_version reports it.
    return (
        ctx.tls is not None
        and ctx.tls.status is TlsStatus.NO_HTTPS
        and ctx.tls.legacy_accepted is not True
    )


@check("tls.no_https", Category.TLS, requires=[Input.TLS])
def no_https(ctx: ScanContext) -> Finding | None:
    if not _has_no_tls(ctx):
        return None
    if ctx.http is None:
        # Without a working HTTP response the site may simply be down.
        raise SkipCheck(ctx.skip_reasons.get(Input.HTTP, "We could not load the site over HTTP."))
    # A redirect to https:// means this name has a secure route after all, for example
    # when only www has a certificate.
    if ctx.http.url.startswith("http://") and shows_real_page(ctx.http.status_code):
        return make_finding(
            "tls.no_https", Severity.CRITICAL, f"{ctx.hostname}: {ctx.tls.detail}, HTTP works"
        )
    return None


@check("tls.cert_expired", Category.TLS, requires=[Input.TLS])
def cert_expired(ctx: ScanContext) -> Finding | None:
    if ctx.tls.status is TlsStatus.EXPIRED:
        return make_finding(
            "tls.cert_expired", Severity.CRITICAL, f"{ctx.hostname}: {ctx.tls.detail}"
        )
    return None


@check("tls.cert_untrusted", Category.TLS, requires=[Input.TLS])
def cert_untrusted(ctx: ScanContext) -> Finding | None:
    if ctx.tls.status is TlsStatus.UNTRUSTED:
        return make_finding(
            "tls.cert_untrusted", Severity.CRITICAL, f"{ctx.hostname}: {ctx.tls.detail}"
        )
    return None


@check("tls.cert_expiring", Category.TLS, requires=[Input.TLS])
def cert_expiring(ctx: ScanContext) -> Finding | None:
    if ctx.tls.status is not TlsStatus.OK:
        return None
    if ctx.tls.not_after is None:
        raise SkipCheck("The certificate's expiry date could not be read.")

    days_left = (ctx.tls.not_after - ctx.checked_at).days
    if days_left > EXPIRY_MEDIUM_DAYS:
        return None
    severity = Severity.HIGH if days_left <= EXPIRY_HIGH_DAYS else Severity.MEDIUM
    evidence = f"Expires {ctx.tls.not_after:%Y-%m-%d}, in {days_left} days"
    return make_finding("tls.cert_expiring", severity, evidence)


@check("tls.legacy_version", Category.TLS, requires=[Input.TLS])
def legacy_version(ctx: ScanContext) -> Finding | None:
    if ctx.tls.legacy_accepted is None:
        if _has_no_tls(ctx):
            return None  # there is no TLS to test, and tls.no_https covers that
        raise SkipCheck("We could not test whether old TLS versions are accepted.")
    if ctx.tls.legacy_accepted:
        return make_finding("tls.legacy_version", Severity.MEDIUM, "Accepted TLS 1.0 or TLS 1.1")
    return None


@check("tls.no_http_redirect", Category.TLS, requires=[Input.HTTP])
def no_http_redirect(ctx: ScanContext) -> Finding | None:
    # With no HTTPS there is nowhere to redirect to. tls.no_https reports that once, so the
    # same problem isn't charged twice.
    if _has_no_tls(ctx):
        return None
    # An error page on HTTP isn't serving the site unencrypted, so it isn't flagged.
    if ctx.http.url.startswith("http://") and ctx.http.status_code < 400:
        return make_finding(
            "tls.no_http_redirect", Severity.MEDIUM, f"{ctx.http.url} was served without HTTPS"
        )
    return None


def _hsts_max_age(ctx: ScanContext) -> int | None:
    # Security: browsers ignore this header unless it arrives over HTTPS, so a site that
    # redirected down to HTTP gets no protection from it.
    if not ctx.https.url.startswith("https://"):
        return None
    match = _MAX_AGE_RE.search(ctx.https.headers.get("strict-transport-security", ""))
    return int(match.group(1)) if match else None


@check("tls.hsts_missing", Category.TLS, requires=[Input.HTTPS])
def hsts_missing(ctx: ScanContext) -> Finding | None:
    max_age = _hsts_max_age(ctx)
    if max_age is None:
        return make_finding(
            "tls.hsts_missing", Severity.MEDIUM, "No valid Strict-Transport-Security header"
        )
    if max_age == 0:  # max-age=0 is an instruction to browsers to forget HSTS
        return make_finding("tls.hsts_missing", Severity.MEDIUM, "HSTS is disabled with max-age=0")
    return None


@check("tls.hsts_weak", Category.TLS, requires=[Input.HTTPS])
def hsts_weak(ctx: ScanContext) -> Finding | None:
    max_age = _hsts_max_age(ctx)
    if max_age is not None and 0 < max_age < HSTS_MIN_SECONDS:
        return make_finding("tls.hsts_weak", Severity.LOW, f"max-age={max_age} seconds")
    return None
