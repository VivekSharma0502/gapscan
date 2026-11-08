"""Passive DNS and email authentication checks."""

from app.checks.base import Category, Finding, Input, ScanContext, Severity
from app.checks.registry import check, make_finding

# Qualifiers on "all" that let unlisted servers pass. A bare "all" means "+all".
_PERMISSIVE_ALL = {"+all", "all", "?all"}


def _spf_records(ctx: ScanContext) -> list[str]:
    return [
        record
        for record in ctx.spf_records
        if record.lower() == "v=spf1" or record.lower().startswith("v=spf1 ")
    ]


def _dmarc_tags(ctx: ScanContext) -> dict[str, str] | None:
    for record in ctx.dmarc_records:
        tags: dict[str, str] = {}
        for part in record.split(";"):
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip().lower()
        if tags.get("v") == "dmarc1":
            return tags
    return None


@check("dns.spf_missing", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_missing(ctx: ScanContext) -> Finding | None:
    if _spf_records(ctx):
        return None
    return make_finding("dns.spf_missing", Severity.MEDIUM, f"No SPF record on {ctx.email_domain}")


@check("dns.spf_weak", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_weak(ctx: ScanContext) -> Finding | None:
    records = _spf_records(ctx)
    if not records:
        return None
    # Security: more than one SPF record is a permanent error under RFC 7208, so receivers
    # treat the domain as having no working SPF at all.
    if len(records) > 1:
        return make_finding(
            "dns.spf_weak", Severity.MEDIUM, f"{len(records)} SPF records on {ctx.email_domain}"
        )
    if _PERMISSIVE_ALL.intersection(records[0].lower().split()):
        return make_finding("dns.spf_weak", Severity.MEDIUM, records[0])
    return None


@check("dns.dmarc_missing", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_missing(ctx: ScanContext) -> Finding | None:
    if _dmarc_tags(ctx) is not None:
        return None
    return make_finding(
        "dns.dmarc_missing", Severity.MEDIUM, f"No DMARC record at _dmarc.{ctx.email_domain}"
    )


@check("dns.dmarc_weak", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_weak(ctx: ScanContext) -> Finding | None:
    tags = _dmarc_tags(ctx)
    if tags is None:
        return None
    policy = tags.get("p")
    if policy in {"quarantine", "reject"}:
        return None
    return make_finding("dns.dmarc_weak", Severity.LOW, f"DMARC policy: {policy or 'not set'}")


@check("dns.caa_missing", Category.DNS_EMAIL, requires=[Input.CAA])
def caa_missing(ctx: ScanContext) -> Finding | None:
    if ctx.caa_records:
        return None
    return make_finding("dns.caa_missing", Severity.LOW, f"No CAA record for {ctx.hostname}")


@check("dns.shared_platform_domain", Category.DNS_EMAIL)
def shared_platform_domain(ctx: ScanContext) -> Finding | None:
    if ctx.shared_platform_suffix is None:
        return None
    evidence = f"{ctx.hostname} is on {ctx.shared_platform_suffix}, which many sites share"
    return make_finding("dns.shared_platform_domain", Severity.INFO, evidence)
