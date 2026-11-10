"""Reads a verified site's own scripts to find the backends they use.

Security: this only ever requests the verified site. Nothing here contacts Firebase or
Supabase. The worker calls it only after confirming ownership, and quick scans never reach it.
"""

from dataclasses import dataclass, replace
from time import monotonic

from app.checks.active_collector import (
    MAX_HTML_BYTES,
    allowed_probe_hosts,
    gave_no_real_answer,
    polite_pause,
    same_origin_script_paths,
)
from app.checks.baas_discovery import (
    find_anon_keys,
    find_backends,
    find_exposed_keys,
    find_publishable_keys,
    find_table_names,
)
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    DiscoveredBackend,
    ExposedServiceKey,
    Input,
    ScanContext,
    SkippedScript,
    SupabaseAccess,
    bot_protection,
    bot_protection_label,
    shows_real_page,
)
from app.checks.exposure import looks_like_html
from app.core.safe_http import OffHostRedirectError, SafeHttpError, SafeResponse, safe_get

MAX_BUNDLE_SCRIPTS = 20
BUNDLE_MAX_BYTES = 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 6 * 1024 * 1024
# Keeps the whole scan inside the limit that expires stuck scans.
DISCOVERY_BUDGET_SECONDS = 30.0
# Security: a page can name as many backends as it likes, so only this many are remembered.
MAX_BACKENDS = 10
MAX_TABLES = 25

_HOMEPAGE_LOCATION = "your homepage"

_BLOCKED_HOMEPAGE_REASON = "Our request was blocked, so the site's scripts couldn't be read."
_NOT_REQUESTED = "not requested, because bot protection was already blocking the site"
_REDIRECTED = "redirected off the site"
_UNREACHABLE = "couldn't be fetched"
_WEB_PAGE = "returned a web page, not a script"
_TOO_LARGE = "too large, only the first 1 MB was read"
_OVER_SCRIPT_LIMIT = f"over the {MAX_BUNDLE_SCRIPTS}-script limit"
_OVER_SIZE_LIMIT = "over the 6 MB total limit"
_OUT_OF_TIME = "ran out of time"


@dataclass(frozen=True)
class _Skip:
    reason: str
    # True when the script exists but couldn't be read, so it could be hiding a key.
    can_hide_a_key: bool


def _text(content: bytes) -> str:
    return content.decode("utf-8", "replace")


def _why_unusable(response: SafeResponse) -> _Skip | None:
    """Return why this answer isn't the script, or None if it is."""
    platform = bot_protection(response)
    if platform is not None:
        return _Skip(f"blocked by {bot_protection_label(platform)}", can_hide_a_key=True)
    if gave_no_real_answer(response) or response.status_code in (401, 403):
        return _Skip(f"refused (HTTP {response.status_code})", can_hide_a_key=True)
    if response.status_code != 200:
        return _Skip(f"HTTP {response.status_code}", can_hide_a_key=False)
    # A single-page app answers a missing script with its HTML, which is not a script.
    if looks_like_html(response.content):
        return _Skip(_WEB_PAGE, can_hide_a_key=False)
    return None


def _limit_reached(index: int, deadline: float, total_bytes: int, blocked: bool) -> _Skip | None:
    if blocked:
        return _Skip(_NOT_REQUESTED, can_hide_a_key=True)
    if index >= MAX_BUNDLE_SCRIPTS:
        return _Skip(_OVER_SCRIPT_LIMIT, can_hide_a_key=False)
    if total_bytes >= MAX_BUNDLE_TOTAL_BYTES:
        return _Skip(_OVER_SIZE_LIMIT, can_hide_a_key=False)
    if monotonic() >= deadline:
        return _Skip(_OUT_OF_TIME, can_hide_a_key=False)
    return None


def _supabase_access(
    backends: set[DiscoveredBackend], anon: dict[str, str], publishable: set[str]
) -> tuple[SupabaseAccess, ...]:
    refs = sorted(item.identifier for item in backends if item.kind is BaasKind.SUPABASE)
    # An anon key names its own project. A publishable key doesn't, so it's only used when
    # there is exactly one project it could belong to.
    only_key = next(iter(publishable)) if len(refs) == 1 and len(publishable) == 1 else None
    access: list[SupabaseAccess] = []
    for ref in refs:
        if ref in anon:
            access.append(SupabaseAccess(ref, anon[ref], is_jwt=True))
        elif only_key is not None:
            access.append(SupabaseAccess(ref, only_key, is_jwt=False))
    return tuple(access)


def discover_backends(ctx: ScanContext) -> ScanContext:
    """Return the context with what its code reveals, including inline scripts.

    Script contents are not kept.
    """
    homepage_response = ctx.homepage
    if homepage_response is None:
        return ctx
    # A challenge page has no scripts, and "found nothing" would be a false all-clear.
    platform = bot_protection(homepage_response)
    if platform is not None or not shows_real_page(homepage_response.status_code):
        reason = (
            f"{bot_protection_label(platform)} blocked our request, so the site's scripts "
            "couldn't be read."
            if platform is not None
            else _BLOCKED_HOMEPAGE_REASON
        )
        return replace(
            ctx,
            skip_reasons={**ctx.skip_reasons, Input.BAAS: reason, Input.BAAS_PROBES: reason},
            blocked_by=ctx.blocked_by or platform,
        )

    allowed = allowed_probe_hosts(ctx.hostname)
    scheme = "http" if ctx.homepage_via_http else "https"
    paths = same_origin_script_paths(homepage_response, allowed)
    deadline = monotonic() + DISCOVERY_BUDGET_SECONDS

    # The whole page is searched, which covers everything inside inline <script> blocks.
    homepage = _text(homepage_response.content[:MAX_HTML_BYTES])
    backends: set[DiscoveredBackend] = find_backends(homepage)
    exposed: dict[ExposedServiceKey, None] = dict.fromkeys(
        find_exposed_keys(homepage, _HOMEPAGE_LOCATION)
    )
    anon = find_anon_keys(homepage)
    publishable = find_publishable_keys(homepage)
    tables = find_table_names(homepage)
    skipped: list[SkippedScript] = []
    read, failed, total_bytes = 0, 0, 0
    blocked_by = ctx.blocked_by
    # Security: a challenge earlier in the scan means no more requests to this site.
    blocked = ctx.blocked_by is not None

    def skip(path: str, reason: _Skip) -> None:
        nonlocal failed
        skipped.append(SkippedScript(path, reason.reason))
        failed += int(reason.can_hide_a_key)

    for index, path in enumerate(paths):
        limit = _limit_reached(index, deadline, total_bytes, blocked)
        if limit is not None:
            skip(path, limit)
            continue
        polite_pause()
        try:
            # Security: allowed_hosts stops a redirect from carrying this request off the site.
            response = safe_get(
                f"{scheme}://{ctx.hostname}{path}",
                allowed_hosts=allowed,
                max_bytes=BUNDLE_MAX_BYTES,
            )
        except OffHostRedirectError:
            skip(path, _Skip(_REDIRECTED, can_hide_a_key=True))
            continue
        except SafeHttpError:
            skip(path, _Skip(_UNREACHABLE, can_hide_a_key=True))
            continue

        unusable = _why_unusable(response)
        if unusable is not None:
            skip(path, unusable)
            # The site has asked for automated traffic to stop, so no more is sent.
            challenged_by = bot_protection(response)
            blocked = challenged_by is not None
            blocked_by = blocked_by or challenged_by
            continue

        total_bytes += len(response.content)
        read += 1
        if response.truncated:
            skipped.append(SkippedScript(path, _TOO_LARGE))
        text = _text(response.content)
        backends |= find_backends(text)
        exposed.update(dict.fromkeys(find_exposed_keys(text, path)))
        anon.update(find_anon_keys(text))
        publishable |= find_publishable_keys(text)
        tables |= find_table_names(text)

    ordered = sorted(backends, key=lambda item: (item.kind.value, item.identifier))
    return replace(
        ctx,
        baas=BaasDiscovery(
            backends=tuple(ordered[:MAX_BACKENDS]),
            exposed_keys=tuple(exposed),
            scripts_total=len(paths),
            scripts_read=read,
            scripts_failed=failed,
            skipped=tuple(skipped),
            supabase_access=_supabase_access(set(ordered[:MAX_BACKENDS]), anon, publishable),
            table_names=tuple(sorted(tables)[:MAX_TABLES]),
        ),
        blocked_by=blocked_by,
    )
