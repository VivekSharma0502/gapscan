"""Types shared by every scanner check.

A check is a pure function of a ScanContext. All network access happens once, in the
collector, so checks can be tested with fixtures and cannot bypass the SSRF guard.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from app.core.safe_http import SafeResponse, TlsProbe

BLOCKED_STATUSES = frozenset({403, 429, 503})

# Told the name of each step as it starts, so a caller can report progress.
StepCallback = Callable[[str], None]


def shows_real_page(status_code: int) -> bool:
    """Whether a response carries the site's own headers.

    A 404 or 401 still comes from the real app. A firewall's block page or a server error
    doesn't, so its headers and cookies say nothing about the site.
    """
    return status_code < 500 and status_code not in BLOCKED_STATUSES


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    TLS = "tls"
    HEADERS = "headers"
    COOKIES = "cookies"
    DNS_EMAIL = "dns_email"
    CMS = "cms"
    EXPOSURE = "exposure"
    SECRETS = "secrets"


class Platform(StrEnum):
    VERCEL = "vercel"
    NETLIFY = "netlify"
    NGINX = "nginx"
    CLOUDFLARE = "cloudflare"


class PlatformFix(BaseModel):
    model_config = ConfigDict(frozen=True)

    instructions: str
    # None when this platform has no config for the fix. The instructions then say where
    # the fix really belongs, because an invented snippet is worse than none.
    snippet: str | None = None


class Fix(BaseModel):
    model_config = ConfigDict(frozen=True)

    what_it_means: str
    how_to_fix: str
    platforms: dict[Platform, PlatformFix]

    @model_validator(mode="after")
    def covers_every_platform(self) -> "Fix":
        missing = set(Platform) - set(self.platforms)
        if missing:
            raise ValueError(f"missing platforms: {sorted(missing)}")
        return self


class CheckText(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str
    fix: Fix


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str
    category: Category
    severity: Severity
    title: str
    evidence: str
    fix: Fix


class Input(StrEnum):
    """Something a check needs from the scan. Each value names a ScanContext field."""

    HTTPS = "https"
    HTTP = "http"
    # The page whose headers, cookies and HTML are checked. See ScanContext.homepage.
    HOMEPAGE = "homepage"
    TLS = "tls"
    SPF = "spf_records"
    DMARC = "dmarc_records"
    CAA = "caa_records"
    # Requests for files that shouldn't be public. Only ever collected for a verified domain.
    PROBES = "probes"


class SkipCheck(Exception):
    """Raised by a check that has its inputs but still cannot give a reliable answer."""


@dataclass(frozen=True)
class Probe:
    """One active request. Lives only in memory during the scan, and is never saved."""

    path: str
    # None when the server gave no trustworthy answer, which is not the same as "not found".
    status_code: int | None = None
    content: bytes = b""


@dataclass(frozen=True)
class ScanContext:
    """Everything collected about a target. A field is None when it could not be collected."""

    hostname: str
    https: SafeResponse | None = None
    http: SafeResponse | None = None
    tls: TlsProbe | None = None
    # The domain SPF and DMARC are published on, and its records. An empty list means the
    # lookup worked and there are no records, which is different from None.
    email_domain: str | None = None
    spf_records: list[str] | None = None
    dmarc_records: list[str] | None = None
    caa_records: list[str] | None = None
    # Keyed by path. None unless ownership was confirmed for this scan.
    probes: Mapping[str, Probe] | None = None
    # Set when the hostname sits under a domain shared by many customers, like vercel.app.
    shared_platform_suffix: str | None = None
    # Why an input is missing, shown to the user next to the checks it prevented.
    skip_reasons: Mapping[Input, str] = field(default_factory=dict)
    # Inputs missing by design, like SPF on vercel.app. Skips caused by these don't count
    # against the scan, unlike a lookup that failed and might have found something.
    not_applicable: frozenset[Input] = frozenset()
    # True when the host has no HTTPS, so the HTTP response stands in as the homepage.
    homepage_via_http: bool = False
    # Part of the context so expiry checks give the same answer every time in tests.
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def homepage(self) -> SafeResponse | None:
        if self.https is not None:
            return self.https
        return self.http if self.homepage_via_http else None
