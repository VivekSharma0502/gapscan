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


class BotProtection(StrEnum):
    VERCEL = "vercel"
    CLOUDFLARE = "cloudflare"


@dataclass(frozen=True)
class BotProtectionInfo:
    name: str
    # The platform's own instructions for letting a trusted client through.
    help_url: str


BOT_PROTECTION_INFO = {
    BotProtection.VERCEL: BotProtectionInfo(
        "Vercel", "https://vercel.com/docs/vercel-firewall/vercel-waf/custom-rules"
    ),
    BotProtection.CLOUDFLARE: BotProtectionInfo(
        "Cloudflare", "https://developers.cloudflare.com/waf/custom-rules/skip/"
    ),
}

_BOT_PROTECTION_HEADERS = {
    "x-vercel-mitigated": BotProtection.VERCEL,
    "cf-mitigated": BotProtection.CLOUDFLARE,
}


def bot_protection(response: SafeResponse) -> BotProtection | None:
    """Return the platform whose bot protection answered instead of the site, if any."""
    for header, platform in _BOT_PROTECTION_HEADERS.items():
        if header in response.headers:
            return platform
    return None


def bot_protection_label(platform: BotProtection) -> str:
    return f"{BOT_PROTECTION_INFO[platform].name}'s bot protection"


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
    BAAS = "baas"


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


class BackendFix(BaseModel):
    """A fix made in a backend's own console, which no hosting platform has a say in."""

    model_config = ConfigDict(frozen=True)

    label: str
    snippet: str | None = None
    # The provider's own instructions, so people can check ours against the source.
    docs_url: str | None = None


class Fix(BaseModel):
    model_config = ConfigDict(frozen=True)

    what_it_means: str
    how_to_fix: str
    platforms: dict[Platform, PlatformFix] = {}
    # Set instead of platforms when the fix doesn't depend on where the site is hosted.
    backend: BackendFix | None = None

    @model_validator(mode="after")
    def covers_every_platform(self) -> "Fix":
        if self.backend is not None:
            return self
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
    # Backends named in the site's own code. Only ever collected for a verified domain.
    BAAS = "baas"
    # Read-only answers from backends the domain's owner confirmed as theirs.
    BAAS_PROBES = "baas_probes"


class BaasKind(StrEnum):
    FIREBASE_RTDB = "firebase_rtdb"
    FIREBASE_STORAGE = "firebase_storage"
    SUPABASE = "supabase"


@dataclass(frozen=True)
class DiscoveredBackend:
    kind: BaasKind
    # A database host, a bucket name or a Supabase project ref. None of them are secrets.
    identifier: str


@dataclass(frozen=True)
class ExposedServiceKey:
    """Where a server-only key was found.

    Security: holds a fixed mask and a location, never the key. There is nothing here that
    could be stored, logged or sent by mistake.
    """

    mask: str
    location: str


@dataclass(frozen=True)
class SupabaseAccess:
    """The public key a site's own browser code uses for one project."""

    ref: str
    # Security: held in memory for this scan only. repr=False keeps it out of logs.
    key: str = field(repr=False)
    # Legacy anon keys are JWTs and also go in Authorization. Publishable keys must not.
    is_jwt: bool


@dataclass(frozen=True)
class SkippedScript:
    path: str
    reason: str


@dataclass(frozen=True)
class BaasDiscovery:
    backends: tuple[DiscoveredBackend, ...]
    exposed_keys: tuple[ExposedServiceKey, ...]
    scripts_total: int
    scripts_read: int
    # Couldn't be answered, so a key in them can't be ruled out.
    scripts_failed: int
    # Each script not fully read, and why, so a report can say what wasn't covered.
    skipped: tuple[SkippedScript, ...] = ()
    # Only what browser code already holds. A server-only key is never placed here.
    supabase_access: tuple[SupabaseAccess, ...] = ()
    table_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class RtdbProbe:
    """What a database's rules allow.

    Security: a yes/no and a number. There is no field that could hold a key name or a value.
    """

    host: str
    # None when the database gave no reliable answer.
    readable: bool | None
    # Top-level keys. None when not readable, or when there were too many to count.
    key_count: int | None = None


@dataclass(frozen=True)
class StorageProbe:
    """Whether a bucket's files can be listed. Security: file names are never kept."""

    bucket: str
    # None when the bucket gave no reliable answer.
    listable: bool | None


class TableAccess(StrEnum):
    READABLE = "readable"
    # Allowed, but nothing came back. An empty table looks the same, so this proves little.
    NO_ROWS = "no_rows"
    REFUSED = "refused"
    # Usually not a table at all, since names come from matching code.
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TableProbe:
    """What one table allows. Security: a name and a state, with nowhere to hold a row."""

    name: str
    access: TableAccess
    meant_to_be_public: bool = False


@dataclass(frozen=True)
class SupabaseProbe:
    ref: str
    tables: tuple[TableProbe, ...] = ()
    # False when the site's code had no public key for this project.
    has_key: bool = True


@dataclass(frozen=True)
class BaasProbes:
    rtdb: tuple[RtdbProbe, ...] = ()
    storage: tuple[StorageProbe, ...] = ()
    supabase: tuple[SupabaseProbe, ...] = ()


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
    # None unless ownership was confirmed for this scan.
    baas: BaasDiscovery | None = None
    baas_probes: BaasProbes | None = None
    # Whose bot protection stopped part of this scan, so the report can say how to allow it.
    blocked_by: BotProtection | None = None
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
