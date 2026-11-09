"""Reads a verified site's own scripts to find the backends they use.

Security: this only ever requests the verified site. Nothing here contacts Firebase or
Supabase. The worker calls it only after confirming ownership, and quick scans never reach it.
"""

from dataclasses import replace
from time import monotonic

from app.checks.active_collector import (
    MAX_HTML_BYTES,
    allowed_probe_hosts,
    gave_no_real_answer,
    same_origin_script_paths,
)
from app.checks.baas_discovery import find_backends, find_exposed_keys
from app.checks.base import BaasDiscovery, DiscoveredBackend, ExposedServiceKey, ScanContext
from app.checks.exposure import looks_like_html
from app.core.safe_http import SafeHttpError, safe_get

MAX_BUNDLE_SCRIPTS = 20
BUNDLE_MAX_BYTES = 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 6 * 1024 * 1024
# Keeps the whole scan inside the limit that expires stuck scans.
DISCOVERY_BUDGET_SECONDS = 30.0
# Security: a page can name as many backends as it likes, so only this many are remembered.
MAX_BACKENDS = 10

_HOMEPAGE_LOCATION = "your homepage"


def _text(content: bytes) -> str:
    return content.decode("utf-8", "replace")


def discover_backends(ctx: ScanContext) -> ScanContext:
    """Return the context with what its scripts reveal. Script contents are not kept."""
    if ctx.homepage is None:
        return ctx

    allowed = allowed_probe_hosts(ctx.hostname)
    scheme = "http" if ctx.homepage_via_http else "https"
    paths = same_origin_script_paths(ctx.homepage, allowed)
    deadline = monotonic() + DISCOVERY_BUDGET_SECONDS

    homepage = _text(ctx.homepage.content[:MAX_HTML_BYTES])
    backends: set[DiscoveredBackend] = find_backends(homepage)
    exposed: dict[ExposedServiceKey, None] = dict.fromkeys(
        find_exposed_keys(homepage, _HOMEPAGE_LOCATION)
    )
    read, failed, total_bytes = 0, 0, 0

    for path in paths[:MAX_BUNDLE_SCRIPTS]:
        if monotonic() >= deadline or total_bytes >= MAX_BUNDLE_TOTAL_BYTES:
            break
        try:
            # Security: allowed_hosts stops a redirect from carrying this request off the site.
            response = safe_get(
                f"{scheme}://{ctx.hostname}{path}",
                allowed_hosts=allowed,
                max_bytes=BUNDLE_MAX_BYTES,
            )
        except SafeHttpError:
            failed += 1
            continue
        if gave_no_real_answer(response):
            failed += 1
            continue
        # A single-page app answers a missing script with its HTML, which is not a script.
        if response.status_code != 200 or looks_like_html(response.content):
            continue
        total_bytes += len(response.content)
        read += 1
        text = _text(response.content)
        backends |= find_backends(text)
        exposed.update(dict.fromkeys(find_exposed_keys(text, path)))

    ordered = sorted(backends, key=lambda item: (item.kind.value, item.identifier))
    return replace(
        ctx,
        baas=BaasDiscovery(
            backends=tuple(ordered[:MAX_BACKENDS]),
            exposed_keys=tuple(exposed),
            scripts_total=len(paths),
            scripts_read=read,
            scripts_failed=failed,
        ),
    )
