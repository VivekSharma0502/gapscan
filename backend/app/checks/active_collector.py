"""Requests the paths the active checks read.

Security: nothing here decides whether probing is allowed. The worker calls attach_probes
only after confirming ownership of a verified domain, and quick scans never reach it.
"""

from dataclasses import replace
from html.parser import HTMLParser
from time import monotonic
from urllib.parse import urljoin, urlsplit

from app.checks.base import Input, Probe, ScanContext
from app.checks.exposure import FIXED_PROBE_PATHS
from app.core.safe_http import SafeHttpError, SafeResponse, safe_get

# The signatures only need the start of a file, and a real backup could be gigabytes.
PROBE_MAX_BYTES = 64 * 1024
# The whole set, one at a time. Keeps a slow site inside the limit that expires stuck scans.
PROBE_BUDGET_SECONDS = 90.0
MAX_SCRIPTS = 5
MAX_PATH_LENGTH = 512
MAX_HTML_BYTES = 512 * 1024

_NO_HOMEPAGE_REASON = "We couldn't read the site, so these paths were not checked."


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            src = dict(attrs).get("src")
            if src:
                self.sources.append(src)


def allowed_probe_hosts(hostname: str) -> frozenset[str]:
    """The verified host and its www name, which proof for the parent also covers."""
    return frozenset({hostname, f"www.{hostname}"})


def source_map_paths(homepage: SafeResponse, allowed: frozenset[str]) -> list[str]:
    """Return "<script>.map" paths for this site's own scripts. Other hosts aren't probed."""
    parser = _ScriptParser()
    parser.feed(homepage.content[:MAX_HTML_BYTES].decode("utf-8", "replace"))
    paths: list[str] = []
    for source in parser.sources:
        parts = urlsplit(urljoin(homepage.url, source))
        if parts.hostname not in allowed or not parts.path.endswith((".js", ".mjs")):
            continue
        path = f"{parts.path}.map"
        if len(path) <= MAX_PATH_LENGTH and path not in paths:
            paths.append(path)
        if len(paths) == MAX_SCRIPTS:
            break
    return paths


def _gave_no_real_answer(response: SafeResponse) -> bool:
    # A challenge page or an overloaded server says nothing about whether the file exists.
    return (
        response.status_code == 429
        or response.status_code >= 500
        or "cf-mitigated" in response.headers
    )


def attach_probes(ctx: ScanContext) -> ScanContext:
    """Return the context with its probes. A probe that couldn't be answered is marked so."""
    if ctx.homepage is None:
        reason = ctx.skip_reasons.get(Input.HOMEPAGE, _NO_HOMEPAGE_REASON)
        return without_probes(ctx, reason)

    allowed = allowed_probe_hosts(ctx.hostname)
    scheme = "http" if ctx.homepage_via_http else "https"
    deadline = monotonic() + PROBE_BUDGET_SECONDS
    rate_limited = False
    probes: dict[str, Probe] = {}

    for path in (*FIXED_PROBE_PATHS, *source_map_paths(ctx.homepage, allowed)):
        probes[path] = Probe(path)
        if rate_limited or monotonic() >= deadline:
            continue
        try:
            # Security: allowed_hosts stops a redirect from sending this probe to a site
            # nobody has verified. Such a probe stays unanswered rather than counting as clear.
            response = safe_get(
                f"{scheme}://{ctx.hostname}{path}",
                allowed_hosts=allowed,
                max_bytes=PROBE_MAX_BYTES,
            )
        except SafeHttpError:
            continue
        # The site asked us to slow down, so the remaining requests aren't sent at all.
        rate_limited = response.status_code == 429
        if not _gave_no_real_answer(response):
            probes[path] = Probe(path, response.status_code, response.content)

    return replace(ctx, probes=probes)


def without_probes(ctx: ScanContext, reason: str) -> ScanContext:
    return replace(ctx, skip_reasons={**ctx.skip_reasons, Input.PROBES: reason})
