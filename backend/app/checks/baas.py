"""Active checks on the backends a verified site uses.

Security: evidence is built only from fixed masks, script paths on the verified site,
validated backend names and counts, so no key or data value can reach the database.
"""

from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BaasProbes,
    Category,
    DiscoveredBackend,
    Finding,
    Input,
    RtdbProbe,
    ScanContext,
    Severity,
    SkipCheck,
)
from app.checks.registry import check, make_finding

MAX_LOCATIONS = 5

_NO_RELIABLE_ANSWER = "This backend gave no reliable answer, so this could not be confirmed."

_KIND_LABELS = {
    BaasKind.FIREBASE_RTDB: "Firebase database",
    BaasKind.FIREBASE_STORAGE: "Firebase storage bucket",
    BaasKind.SUPABASE: "Supabase project",
}


def _discovery(ctx: ScanContext) -> BaasDiscovery:
    # The runner only calls these checks once this input has been collected.
    assert ctx.baas is not None  # noqa: S101
    return ctx.baas


def _coverage(baas: BaasDiscovery) -> str:
    summary = f"Read {baas.scripts_read} of {baas.scripts_total} scripts."
    if not baas.skipped:
        return summary
    shown = "; ".join(f"{item.path} ({item.reason})" for item in baas.skipped[:MAX_LOCATIONS])
    hidden = len(baas.skipped) - MAX_LOCATIONS
    more = f"; and {hidden} more" if hidden > 0 else ""
    return f"{summary} Skipped: {shown}{more}."


@check("baas.supabase_service_key", Category.BAAS, requires=[Input.BAAS], active=True)
def supabase_service_key(ctx: ScanContext) -> Finding | None:
    baas = _discovery(ctx)
    if not baas.exposed_keys:
        if baas.scripts_failed:
            # Security: an unread script could hold the key, so this can't be reported as clear.
            raise SkipCheck(f"Some scripts couldn't be read. {_coverage(baas)}")
        return None
    locations = [f"{item.mask} in {item.location}" for item in baas.exposed_keys[:MAX_LOCATIONS]]
    return make_finding(
        "baas.supabase_service_key",
        Severity.CRITICAL,
        f"Found a server-only key: {'; '.join(locations)}.",
    )


def _describe(backend: DiscoveredBackend) -> str:
    return f"{_KIND_LABELS[backend.kind]} {backend.identifier}"


@check("baas.backends_found", Category.BAAS, requires=[Input.BAAS], active=True)
def backends_found(ctx: ScanContext) -> Finding | None:
    baas = _discovery(ctx)
    if not baas.backends:
        return None
    names = "; ".join(_describe(item) for item in baas.backends)
    return make_finding("baas.backends_found", Severity.INFO, f"{names}. {_coverage(baas)}")


@check("baas.scripts_unread", Category.BAAS, requires=[Input.BAAS], active=True)
def scripts_unread(ctx: ScanContext) -> Finding | None:
    """Say so when nothing was found but not everything could be read."""
    baas = _discovery(ctx)
    if baas.backends or not baas.skipped:
        return None
    return make_finding("baas.scripts_unread", Severity.INFO, _coverage(baas))


def _probes(ctx: ScanContext) -> BaasProbes:
    # The runner only calls these checks once this input has been collected.
    assert ctx.baas_probes is not None  # noqa: S101
    return ctx.baas_probes


def _describe_rtdb(probe: RtdbProbe) -> str:
    if probe.key_count is None:
        return f"{probe.host} (more top-level keys than we count)"
    return f"{probe.host} ({probe.key_count} top-level keys)"


@check("baas.firebase_rtdb_public", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def firebase_rtdb_public(ctx: ScanContext) -> Finding | None:
    probes = _probes(ctx).rtdb
    readable = [probe for probe in probes if probe.readable]
    if readable:
        names = "; ".join(_describe_rtdb(probe) for probe in readable)
        return make_finding(
            "baas.firebase_rtdb_public",
            Severity.CRITICAL,
            f"Readable by anyone, without signing in: {names}.",
        )
    if any(probe.readable is None for probe in probes):
        raise SkipCheck(_NO_RELIABLE_ANSWER)
    return None


@check("baas.firebase_storage_listable", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def firebase_storage_listable(ctx: ScanContext) -> Finding | None:
    probes = _probes(ctx).storage
    listable = [probe.bucket for probe in probes if probe.listable]
    if listable:
        return make_finding(
            "baas.firebase_storage_listable",
            Severity.HIGH,
            f"Anyone can list the files in: {'; '.join(listable)}.",
        )
    if any(probe.listable is None for probe in probes):
        raise SkipCheck(_NO_RELIABLE_ANSWER)
    return None


@check("baas.firebase_rtdb_protected", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def firebase_rtdb_protected(ctx: ScanContext) -> Finding | None:
    """Say so when a database was checked and refused, so a clean result isn't just silence."""
    hosts = [probe.host for probe in _probes(ctx).rtdb if probe.readable is False]
    if not hosts:
        return None
    return make_finding(
        "baas.firebase_rtdb_protected",
        Severity.INFO,
        f"Refused a read without signing in: {'; '.join(hosts)}.",
    )


@check("baas.firebase_storage_protected", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def firebase_storage_protected(ctx: ScanContext) -> Finding | None:
    """Say so when a bucket was checked and refused, so a clean result isn't just silence."""
    buckets = [probe.bucket for probe in _probes(ctx).storage if probe.listable is False]
    if not buckets:
        return None
    return make_finding(
        "baas.firebase_storage_protected",
        Severity.INFO,
        f"Refused a file listing without signing in: {'; '.join(buckets)}.",
    )
