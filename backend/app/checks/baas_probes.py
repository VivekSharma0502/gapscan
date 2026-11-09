"""Read-only checks on the Firebase backends a verified site's owner has confirmed.

Security rules for this module:
- Only GET requests through the SSRF guard, so nothing here can write to a backend.
- A backend is contacted only if the owner confirmed it and this scan found it in the site.
- Each name is checked again here, because it was read back from the database.
- Responses are reduced to a yes/no and a count on the spot, so data never leaves this module.
"""

import json
from collections.abc import Collection
from dataclasses import replace
from time import monotonic
from urllib.parse import quote

from app.checks.active_collector import gave_no_real_answer, polite_pause
from app.checks.baas_discovery import is_official_rtdb_host, is_valid_bucket
from app.checks.base import (
    BaasKind,
    BaasProbes,
    DiscoveredBackend,
    RtdbProbe,
    ScanContext,
    StorageProbe,
)
from app.core.safe_http import SafeHttpError, SafeResponse, safe_get

STORAGE_HOST = "firebasestorage.googleapis.com"
# Top-level keys only, each with the value true, so this holds thousands of them.
RTDB_MAX_BYTES = 256 * 1024
# Only the status and the start of the body are looked at, so very little is requested.
STORAGE_MAX_BYTES = 16 * 1024
# Keeps the whole scan inside the limit that expires stuck scans.
PROBE_BUDGET_SECONDS = 30.0

# A definite "no": refused, locked or not there. Anything else proves nothing either way.
_DENIED_STATUSES = frozenset({401, 403, 404, 423})


def _get(url: str, host: str, max_bytes: int) -> SafeResponse | None:
    polite_pause()
    try:
        # Security: allowed_hosts stops a redirect from carrying this probe off the official
        # host, so a reply can't turn it into a request to anywhere else.
        return safe_get(url, allowed_hosts=frozenset({host}), max_bytes=max_bytes)
    except SafeHttpError:
        return None


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


def probe_backends(ctx: ScanContext, confirmed: Collection[DiscoveredBackend]) -> ScanContext:
    """Return the context with a result for each backend that may be tested."""
    if ctx.baas is None:
        return ctx

    deadline = monotonic() + PROBE_BUDGET_SECONDS
    rtdb: list[RtdbProbe] = []
    storage: list[StorageProbe] = []
    # Security: both conditions. Confirmed but gone from the site means the site no longer
    # uses it, and found but unconfirmed may be someone else's project.
    for backend in ctx.baas.backends:
        if backend not in confirmed:
            continue
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
    return replace(ctx, baas_probes=BaasProbes(rtdb=tuple(rtdb), storage=tuple(storage)))
