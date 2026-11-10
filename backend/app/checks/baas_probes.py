"""Read-only checks on the Firebase and Supabase backends a site's owner has confirmed.

Security rules for this module:
- Only GET and HEAD requests through the SSRF guard, so nothing here can write to a backend.
- A backend is contacted only if the owner confirmed it and this scan found it in the site.
- Each name is checked again here, because it was read back from the database.
- Responses are reduced to a yes/no and a count on the spot, so data never leaves this module.
"""

import json
from collections.abc import Collection, Iterable
from dataclasses import replace
from time import monotonic
from urllib.parse import quote

from app.checks.active_collector import gave_no_real_answer, polite_pause
from app.checks.baas_discovery import (
    is_official_rtdb_host,
    is_official_supabase_ref,
    is_valid_bucket,
    is_valid_table_name,
)
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BaasProbes,
    DiscoveredBackend,
    RtdbProbe,
    ScanContext,
    StorageProbe,
    SupabaseAccess,
    SupabaseProbe,
    TableAccess,
    TableProbe,
)
from app.core.safe_http import SafeHttpError, SafeResponse, safe_api_request, safe_get

STORAGE_HOST = "firebasestorage.googleapis.com"
# Top-level keys only, each with the value true, so this holds thousands of them.
RTDB_MAX_BYTES = 256 * 1024
# Only the status and the start of the body are looked at, so very little is requested.
STORAGE_MAX_BYTES = 16 * 1024
# Keeps the whole scan inside the limit that expires stuck scans.
PROBE_BUDGET_SECONDS = 30.0

# A definite "no": refused, locked or not there. Anything else proves nothing either way.
_DENIED_STATUSES = frozenset({401, 403, 404, 423})

# The kinds of backend these probes can actually test.
PROBED_KINDS = frozenset({BaasKind.FIREBASE_RTDB, BaasKind.FIREBASE_STORAGE})


def _get(url: str, host: str, max_bytes: int) -> SafeResponse | None:
    polite_pause()
    try:
        # Security: allowed_hosts stops a redirect from carrying this probe off the official
        # host, so a reply can't turn it into a request to anywhere else.
        return safe_get(url, allowed_hosts=frozenset({host}), max_bytes=max_bytes)
    except SafeHttpError:
        return None


def _head_table(access: SupabaseAccess, name: str) -> tuple[TableAccess, bool]:
    """Return what one table allows, and whether Supabase asked us to stop."""
    polite_pause()
    headers = {"apikey": access.key}
    # A publishable key isn't a JWT, and Supabase rejects one sent as a bearer token.
    if access.is_jwt:
        headers["Authorization"] = f"Bearer {access.key}"
    try:
        # Security: HEAD returns headers only, so no row ever leaves Supabase. This call also
        # refuses redirects, because it carries a key.
        response = safe_api_request(
            "HEAD",
            f"https://{access.ref}.supabase.co/rest/v1/{quote(name, safe='')}?select=*&limit=1",
            headers=headers,
        )
    except SafeHttpError:
        return TableAccess.UNKNOWN, False
    if response.status_code == 429:
        return TableAccess.UNKNOWN, True
    if response.status_code == 404:
        return TableAccess.NOT_FOUND, False
    if response.status_code in (401, 403):
        return TableAccess.REFUSED, False
    if response.status_code not in (200, 206):
        return TableAccess.UNKNOWN, False
    # "0-0/*" means a row came back and "*/*" means none did.
    content_range = response.headers.get("content-range", "")
    if content_range[:1].isdigit():
        return TableAccess.READABLE, False
    return (TableAccess.NO_ROWS if content_range.startswith("*") else TableAccess.UNKNOWN), False


def _probe_supabase(baas: BaasDiscovery, ref: str, deadline: float) -> SupabaseProbe:
    access = next((item for item in baas.supabase_access if item.ref == ref), None)
    if access is None:
        return SupabaseProbe(ref, has_key=False)
    tables: list[TableProbe] = []
    stop = False
    for name in baas.table_names:
        if not is_valid_table_name(name):
            continue
        if stop or monotonic() >= deadline:
            tables.append(TableProbe(name, TableAccess.UNKNOWN))
            continue
        result, stop = _head_table(access, name)
        tables.append(TableProbe(name, result))
    return SupabaseProbe(ref, tuple(tables))


def _is_denied(response: SafeResponse) -> bool:
    return response.status_code in _DENIED_STATUSES


def _top_level_key_count(response: SafeResponse) -> int | None:
    """Count the keys and let go of the body. None means there were too many to count."""
    if response.truncated:
        return None
    document = json.loads(response.content)
    # Security: only the number leaves this function. Key names can be user ids or emails.
    if document is None:
        return 0
    return len(document) if isinstance(document, dict) else 1


def _probe_rtdb(host: str) -> RtdbProbe:
    # shallow=true replaces every value with true, so no stored data is ever sent back.
    response = _get(f"https://{host}/.json?shallow=true", host, RTDB_MAX_BYTES)
    if response is None or gave_no_real_answer(response):
        return RtdbProbe(host, readable=None)
    if _is_denied(response):
        return RtdbProbe(host, readable=False)
    if response.status_code != 200:
        return RtdbProbe(host, readable=None)
    try:
        return RtdbProbe(host, readable=True, key_count=_top_level_key_count(response))
    except ValueError:
        # Not JSON, so this wasn't the database answering.
        return RtdbProbe(host, readable=None)


def _probe_storage(bucket: str) -> StorageProbe:
    # maxResults=1 keeps the answer to one file name at most, and that name is not read.
    url = f"https://{STORAGE_HOST}/v0/b/{quote(bucket, safe='')}/o?maxResults=1"
    response = _get(url, STORAGE_HOST, STORAGE_MAX_BYTES)
    if response is None or gave_no_real_answer(response):
        return StorageProbe(bucket, listable=None)
    if _is_denied(response):
        return StorageProbe(bucket, listable=False)
    if response.status_code == 200 and response.content.lstrip().startswith(b"{"):
        return StorageProbe(bucket, listable=True)
    return StorageProbe(bucket, listable=None)


def _probe(ctx: ScanContext, backends: Iterable[DiscoveredBackend]) -> ScanContext:
    deadline = monotonic() + PROBE_BUDGET_SECONDS
    rtdb: list[RtdbProbe] = []
    storage: list[StorageProbe] = []
    supabase: list[SupabaseProbe] = []
    for backend in backends:
        out_of_time = monotonic() >= deadline
        if backend.kind is BaasKind.FIREBASE_RTDB and is_official_rtdb_host(backend.identifier):
            rtdb.append(
                RtdbProbe(backend.identifier, None)
                if out_of_time
                else _probe_rtdb(backend.identifier)
            )
        elif backend.kind is BaasKind.FIREBASE_STORAGE and is_valid_bucket(backend.identifier):
            storage.append(
                StorageProbe(backend.identifier, None)
                if out_of_time
                else _probe_storage(backend.identifier)
            )
        elif (
            backend.kind is BaasKind.SUPABASE
            and ctx.baas is not None
            and is_official_supabase_ref(backend.identifier)
        ):
            supabase.append(_probe_supabase(ctx.baas, backend.identifier, deadline))
    return replace(
        ctx,
        baas_probes=BaasProbes(rtdb=tuple(rtdb), storage=tuple(storage), supabase=tuple(supabase)),
    )


def probe_backends(ctx: ScanContext, confirmed: Collection[DiscoveredBackend]) -> ScanContext:
    """Probe what this scan found on the site, if its owner has confirmed it."""
    if ctx.baas is None:
        return ctx
    # Security: both conditions. Confirmed but gone from the site means the site no longer
    # uses it, and found but unconfirmed may be someone else's project.
    return _probe(ctx, [backend for backend in ctx.baas.backends if backend in confirmed])


def probe_confirmed_backends(
    ctx: ScanContext, confirmed: Collection[DiscoveredBackend]
) -> ScanContext:
    """Probe confirmed backends without reading the website at all.

    Security: these were found on the site by an earlier scan and vouched for by its owner.
    The owner asked for this check directly, so the site's bot protection doesn't apply.
    """
    return _probe(ctx, sorted(confirmed, key=lambda item: (item.kind.value, item.identifier)))


def mark_public_tables(ctx: ScanContext, public: Collection[tuple[str, str]]) -> ScanContext:
    """Flag the tables their owner has said are meant to be public, as (ref, name) pairs."""
    if ctx.baas_probes is None:
        return ctx
    projects = tuple(
        replace(
            project,
            tables=tuple(
                replace(table, meant_to_be_public=(project.ref, table.name) in public)
                for table in project.tables
            ),
        )
        for project in ctx.baas_probes.supabase
    )
    return replace(ctx, baas_probes=replace(ctx.baas_probes, supabase=projects))
