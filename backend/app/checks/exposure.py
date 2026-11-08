"""Active checks: files that should never be public. Verified domains only.

Many sites answer every path with 200 and their app's HTML, so a status code proves nothing.
Each check needs the content to look like the file it claims to be.

Security: evidence is built only from fixed paths and regex-captured key names, so the
contents of an exposed file can never reach the database.
"""

import re
from collections.abc import Callable, Iterable

from app.checks.base import Category, Finding, Input, Probe, ScanContext, Severity, SkipCheck
from app.checks.registry import check, make_finding

ENV_PATHS = ("/.env", "/.env.local", "/.env.production")
GIT_HEAD_PATH = "/.git/HEAD"
DS_STORE_PATH = "/.DS_Store"
LISTING_PATHS = ("/uploads/", "/images/", "/assets/", "/static/", "/files/", "/backup/")

MAX_KEY_NAMES = 10
# Most of an .env file's lines must be settings, so prose containing one "=" doesn't count.
_MIN_ENV_LINE_RATIO = 0.6
_UNKNOWN_REASON = "Some of these paths gave no reliable answer, so this could not be confirmed."

_HTML_START_RE = re.compile(
    rb"^\s*<(?:!--|(?:!doctype|html|head|body|script|meta|title|link|div)\b)", re.IGNORECASE
)
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]{0,63})\s*=")
_GIT_HEAD_RE = re.compile(rb"ref: refs/\S+|[0-9a-f]{40}|[0-9a-f]{64}")
_SQL_DUMP_RE = re.compile(
    rb"^\s*(?:--\s*(?:MySQL|MariaDB|PostgreSQL)\b|CREATE TABLE\b|INSERT INTO\b|DROP TABLE\b)",
    re.IGNORECASE | re.MULTILINE,
)
_LISTING_RE = re.compile(
    rb"<(?:title|h1)>\s*(?:Index of /|Directory listing for /)|\[To Parent Directory\]",
    re.IGNORECASE,
)
_SOURCE_MAP_VERSION_RE = re.compile(rb'"version"\s*:\s*3\b')
_SOURCE_MAP_SOURCES_RE = re.compile(rb'"sources"\s*:\s*\[')


def _is_zip(body: bytes) -> bool:
    return body.startswith(b"PK\x03\x04")


def _is_gzip(body: bytes) -> bool:
    return body.startswith(b"\x1f\x8b")


def _is_sql_dump(body: bytes) -> bool:
    return _SQL_DUMP_RE.search(body) is not None


def _is_php(body: bytes) -> bool:
    return body.lstrip().startswith(b"<?php")


BACKUP_FILES: dict[str, tuple[str, Callable[[bytes], bool]]] = {
    "/backup.zip": ("zip archive", _is_zip),
    "/site.zip": ("zip archive", _is_zip),
    "/backup.tar.gz": ("compressed archive", _is_gzip),
    "/backup.sql": ("SQL dump", _is_sql_dump),
    "/dump.sql": ("SQL dump", _is_sql_dump),
    "/database.sql": ("SQL dump", _is_sql_dump),
    "/db.sql": ("SQL dump", _is_sql_dump),
    "/wp-config.php.bak": ("WordPress config copy", _is_php),
}

FIXED_PROBE_PATHS = (
    *ENV_PATHS,
    GIT_HEAD_PATH,
    DS_STORE_PATH,
    *BACKUP_FILES,
    *LISTING_PATHS,
)


def looks_like_html(body: bytes) -> bool:
    """Judged on the body. A server's label is unreliable, and can be wrong either way."""
    return _HTML_START_RE.match(body.removeprefix(b"\xef\xbb\xbf")) is not None


def _confirmed(
    ctx: ScanContext, paths: Iterable[str], matches: Callable[[Probe], bool]
) -> list[Probe]:
    """Return the probes that matched. With none, only a clean set of answers means clear."""
    probes = [ctx.probes[path] for path in paths if path in ctx.probes]
    found = [probe for probe in probes if probe.status_code == 200 and matches(probe)]
    if not found and any(probe.status_code is None for probe in probes):
        raise SkipCheck(_UNKNOWN_REASON)
    return found


def _is_not_html_and(test: Callable[[bytes], bool]) -> Callable[[Probe], bool]:
    return lambda probe: not looks_like_html(probe.content) and test(probe.content)


def env_key_names(body: bytes) -> list[str] | None:
    """Return the names an .env file defines, or None if this isn't one. Values are dropped."""
    text = body.decode("utf-8", "replace")
    lines = [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    names = [match.group(1) for line in lines if (match := _ENV_LINE_RE.match(line))]
    if not names or len(names) / len(lines) < _MIN_ENV_LINE_RATIO:
        return None
    return list(dict.fromkeys(names))


@check("exposure.env_file", Category.EXPOSURE, requires=[Input.PROBES], active=True)
def env_file(ctx: ScanContext) -> Finding | None:
    found = _confirmed(
        ctx, ENV_PATHS, _is_not_html_and(lambda body: env_key_names(body) is not None)
    )
    if not found:
        return None
    parts = []
    for probe in found:
        names = env_key_names(probe.content) or []
        shown = ", ".join(names[:MAX_KEY_NAMES])
        more = f" and {len(names) - MAX_KEY_NAMES} more" if len(names) > MAX_KEY_NAMES else ""
        parts.append(f"{probe.path} defines {shown}{more}")
    return make_finding("exposure.env_file", Severity.CRITICAL, "; ".join(parts))


@check("exposure.git_directory", Category.EXPOSURE, requires=[Input.PROBES], active=True)
def git_directory(ctx: ScanContext) -> Finding | None:
    def is_git_head(probe: Probe) -> bool:
        return _GIT_HEAD_RE.fullmatch(probe.content.strip()) is not None

    if not _confirmed(ctx, [GIT_HEAD_PATH], is_git_head):
        return None
    return make_finding(
        "exposure.git_directory", Severity.CRITICAL, f"{GIT_HEAD_PATH} is publicly readable"
    )


@check("exposure.ds_store", Category.EXPOSURE, requires=[Input.PROBES], active=True)
def ds_store(ctx: ScanContext) -> Finding | None:
    def is_ds_store(probe: Probe) -> bool:
        return probe.content.startswith(b"\x00\x00\x00\x01Bud1")

    if not _confirmed(ctx, [DS_STORE_PATH], is_ds_store):
        return None
    return make_finding(
        "exposure.ds_store", Severity.MEDIUM, f"{DS_STORE_PATH} is publicly readable"
    )


@check("exposure.backup_file", Category.EXPOSURE, requires=[Input.PROBES], active=True)
def backup_file(ctx: ScanContext) -> Finding | None:
    def is_expected_type(probe: Probe) -> bool:
        return not looks_like_html(probe.content) and BACKUP_FILES[probe.path][1](probe.content)

    found = _confirmed(ctx, BACKUP_FILES, is_expected_type)
    if not found:
        return None
    listed = ", ".join(f"{probe.path} ({BACKUP_FILES[probe.path][0]})" for probe in found)
    return make_finding("exposure.backup_file", Severity.CRITICAL, listed)


@check("exposure.source_maps", Category.EXPOSURE, requires=[Input.PROBES], active=True)
def source_maps(ctx: ScanContext) -> Finding | None:
    def is_source_map(body: bytes) -> bool:
        # Only the start of the file is read, so it may be cut off before valid JSON ends.
        return (
            body.lstrip().startswith(b"{")
            and _SOURCE_MAP_VERSION_RE.search(body) is not None
            and _SOURCE_MAP_SOURCES_RE.search(body) is not None
        )

    paths = [path for path in ctx.probes if path.endswith(".map")]
    found = _confirmed(ctx, paths, _is_not_html_and(is_source_map))
    if not found:
        return None
    return make_finding(
        "exposure.source_maps", Severity.MEDIUM, ", ".join(probe.path for probe in found)
    )


@check("exposure.directory_listing", Category.EXPOSURE, requires=[Input.PROBES], active=True)
def directory_listing(ctx: ScanContext) -> Finding | None:
    # The one check that wants HTML, so the title is what tells a listing from an app page.
    found = _confirmed(
        ctx, LISTING_PATHS, lambda probe: _LISTING_RE.search(probe.content) is not None
    )
    if not found:
        return None
    return make_finding(
        "exposure.directory_listing",
        Severity.MEDIUM,
        "Listing shown at " + ", ".join(probe.path for probe in found),
    )
