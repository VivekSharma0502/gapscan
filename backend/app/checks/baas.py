"""Active checks on the backends a verified site uses.

Security: evidence is built only from fixed masks, script paths on the verified site and
validated backend names, so no key or data value can reach the database.
"""

from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    Category,
    DiscoveredBackend,
    Finding,
    Input,
    ScanContext,
    Severity,
    SkipCheck,
)
from app.checks.registry import check, make_finding

MAX_LOCATIONS = 5

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
    return f"Read {baas.scripts_read} of {baas.scripts_total} scripts."


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
    if not baas.backends and baas.scripts_read == baas.scripts_total:
        return None
    names = "; ".join(_describe(item) for item in baas.backends)
    summary = names if names else "No Firebase or Supabase backends found."
    return make_finding("baas.backends_found", Severity.INFO, f"{summary} {_coverage(baas)}")
