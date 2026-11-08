"""Types shared by every scanner check.

A check is a pure function of a ScanContext. All network access happens once, in the
collector, so checks can be tested with fixtures and cannot bypass the SSRF guard.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from app.core.safe_http import SafeResponse, TlsProbe


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
    TLS = "tls"


class SkipCheck(Exception):
    """Raised by a check that has its inputs but still cannot give a reliable answer."""


@dataclass(frozen=True)
class ScanContext:
    """Everything collected about a target. A field is None when it could not be collected."""

    hostname: str
    https: SafeResponse | None = None
    http: SafeResponse | None = None
    tls: TlsProbe | None = None
    # Why an input is missing, shown to the user next to the checks it prevented.
    skip_reasons: Mapping[Input, str] = field(default_factory=dict)
    # Part of the context so expiry checks give the same answer every time in tests.
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
