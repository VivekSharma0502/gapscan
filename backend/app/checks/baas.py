"""Active checks on the backends a verified site uses.

Security: evidence is built only from fixed masks, script paths on the verified site,
validated backend names and counts, so no key or data value can reach the database.
"""

from collections.abc import Callable

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
    TableAccess,
    TableProbe,
)
from app.checks.registry import check, make_finding

MAX_LOCATIONS = 5
MAX_TABLES_LISTED = 10
_ANSWERED_TABLE_STATES = (TableAccess.READABLE, TableAccess.NO_ROWS, TableAccess.REFUSED)

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


def _probe_answers(ctx: ScanContext) -> dict[DiscoveredBackend, bool]:
    """Whether each probed backend gave a real answer. Only confirmed backends get probed."""
    probes = ctx.baas_probes
    if probes is None:
        return {}
    answers = {
        DiscoveredBackend(BaasKind.FIREBASE_RTDB, probe.host): probe.readable is not None
        for probe in probes.rtdb
    }
    answers |= {
        DiscoveredBackend(BaasKind.FIREBASE_STORAGE, probe.bucket): probe.listable is not None
        for probe in probes.storage
    }
    answers |= {
        DiscoveredBackend(BaasKind.SUPABASE, project.ref): any(
            table.access in _ANSWERED_TABLE_STATES for table in project.tables
        )
        for project in probes.supabase
    }
    return answers


def _backend_card(
    ctx: ScanContext, check_id: str, belongs: Callable[[bool | None], bool]
) -> Finding | None:
    """Build one card from the backends in one state. None means not probed, so unconfirmed."""
    baas = _discovery(ctx)
    answers = _probe_answers(ctx)
    backends = [item for item in baas.backends if belongs(answers.get(item))]
    if not backends:
        return None
    names = "; ".join(_describe(item) for item in backends)
    return make_finding(check_id, Severity.INFO, f"{names}. {_coverage(baas)}")


@check("baas.backends_found", Category.BAAS, requires=[Input.BAAS], active=True)
def backends_found(ctx: ScanContext) -> Finding | None:
    return _backend_card(ctx, "baas.backends_found", lambda answered: answered is None)


@check("baas.backends_tested", Category.BAAS, requires=[Input.BAAS], active=True)
def backends_tested(ctx: ScanContext) -> Finding | None:
    return _backend_card(ctx, "baas.backends_tested", lambda answered: answered is True)


@check("baas.backends_unanswered", Category.BAAS, requires=[Input.BAAS], active=True)
def backends_unanswered(ctx: ScanContext) -> Finding | None:
    """Confirmed but without a real answer, so it can't honestly be called tested."""
    return _backend_card(ctx, "baas.backends_unanswered", lambda answered: answered is False)


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


def _tables(ctx: ScanContext) -> list[TableProbe]:
    return [table for project in _probes(ctx).supabase for table in project.tables]


def _names(tables: list[TableProbe]) -> str:
    shown = ", ".join(table.name for table in tables[:MAX_TABLES_LISTED])
    hidden = len(tables) - MAX_TABLES_LISTED
    return f"{shown} and {hidden} more" if hidden > 0 else shown


@check("baas.supabase_table_readable", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def supabase_table_readable(ctx: ScanContext) -> Finding | None:
    tables = _tables(ctx)
    readable = [
        table
        for table in tables
        if table.access is TableAccess.READABLE and not table.meant_to_be_public
    ]
    if readable:
        return make_finding(
            "baas.supabase_table_readable",
            Severity.HIGH,
            f"Returned rows to anyone using your public key: {_names(readable)}.",
        )
    projects = _probes(ctx).supabase
    if any(not project.has_key for project in projects):
        raise SkipCheck("Your site's code didn't include a public key to test with.")
    if projects and not tables:
        raise SkipCheck('No .from("table") calls were found in the scripts we could read.')
    if any(table.access is TableAccess.UNKNOWN for table in tables):
        raise SkipCheck(_NO_RELIABLE_ANSWER)
    return None


@check("baas.supabase_tables_public", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def supabase_tables_public(ctx: ScanContext) -> Finding | None:
    """Keep acknowledged tables visible without letting them affect the grade."""
    tables = [
        table
        for table in _tables(ctx)
        if table.access is TableAccess.READABLE and table.meant_to_be_public
    ]
    if not tables:
        return None
    return make_finding(
        "baas.supabase_tables_public",
        Severity.INFO,
        f"Readable, and marked by you as meant to be public: {_names(tables)}.",
    )


@check("baas.supabase_tables_checked", Category.BAAS, requires=[Input.BAAS_PROBES], active=True)
def supabase_tables_checked(ctx: ScanContext) -> Finding | None:
    """Say so when tables were checked and gave nothing, so a clean result isn't just silence."""
    tables = [
        table
        for table in _tables(ctx)
        if table.access in (TableAccess.NO_ROWS, TableAccess.REFUSED)
    ]
    if not tables:
        return None
    return make_finding(
        "baas.supabase_tables_checked",
        Severity.INFO,
        f"Returned no rows to your public key: {_names(tables)}.",
    )
