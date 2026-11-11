"""Passive DNS and email authentication checks."""

from app.checks.base import Category, Finding, Input, ScanContext, Severity
from app.checks.registry import check, make_finding

# DMARC policies, weakest first. Anything else in p= is invalid.
_DMARC_POLICIES = ("none", "quarantine", "reject")
_STRICT_POLICIES = {"quarantine", "reject"}


def _spf_records(ctx: ScanContext) -> list[str]:
    return [
        record
        for record in ctx.spf_records
        if record.lower() == "v=spf1" or record.lower().startswith("v=spf1 ")
    ]


def _single_spf(ctx: ScanContext) -> str | None:
    # Several records are their own finding, and judging just one of them would be a guess.
    records = _spf_records(ctx)
    return records[0] if len(records) == 1 else None


def _spf_all_qualifier(record: str) -> str | None:
    """The qualifier on the record's "all" ("+", "-", "~" or "?"), or None if it has none.

    Receivers stop at the first "all", so only that one counts. A bare "all" means "+all".
    """
    for term in record.lower().split():
        if term == "all":
            return "+"
        if len(term) == 4 and term[0] in "+-~?" and term[1:] == "all":
            return term[0]
    return None


def _dmarc_records(ctx: ScanContext) -> list[dict[str, str]]:
    records = []
    for record in ctx.dmarc_records:
        tags: dict[str, str] = {}
        for part in record.split(";"):
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip().lower()
        if tags.get("v") == "dmarc1":
            records.append(tags)
    return records


def _effective_policy(tags: dict[str, str]) -> str | None:
    """The policy receivers apply, following RFC 7489 section 6.6.3.

    With no valid p=, a record that still has a report address is treated as p=none, and one
    without is ignored, as if there were no DMARC record at all.
    """
    policy = tags.get("p")
    if policy in _DMARC_POLICIES:
        return policy
    return "none" if "mailto:" in tags.get("rua", "") else None


def _single_dmarc(ctx: ScanContext) -> tuple[dict[str, str], str] | None:
    """The one DMARC record receivers use and its effective policy, or None if none applies."""
    records = _dmarc_records(ctx)
    # Security: under RFC 7489 several DMARC records mean receivers apply none of them.
    if len(records) != 1:
        return None
    policy = _effective_policy(records[0])
    return None if policy is None else (records[0], policy)


def _dmarc_pct(tags: dict[str, str]) -> int:
    # An invalid pct falls back to the default of 100, as receivers do.
    value = tags.get("pct", "100")
    return int(value) if value.isdigit() and int(value) <= 100 else 100


@check("dns.spf_missing", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_missing(ctx: ScanContext) -> Finding | None:
    if _spf_records(ctx):
        return None
    return make_finding("dns.spf_missing", Severity.MEDIUM, f"No SPF record on {ctx.email_domain}")


@check("dns.spf_multiple_records", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_multiple_records(ctx: ScanContext) -> Finding | None:
    records = _spf_records(ctx)
    if len(records) < 2:
        return None
    # Security: more than one SPF record is a permanent error under RFC 7208, so receivers
    # treat the domain as having no working SPF at all.
    return make_finding(
        "dns.spf_multiple_records",
        Severity.MEDIUM,
        f"{len(records)} SPF records on {ctx.email_domain}",
    )


@check("dns.spf_allow_all", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_allow_all(ctx: ScanContext) -> Finding | None:
    record = _single_spf(ctx)
    if record is None or _spf_all_qualifier(record) != "+":
        return None
    # Security: +all is worse than no SPF. Forged mail passes SPF, and if the envelope
    # domain matches, that pass also satisfies DMARC, so even p=reject lets it through.
    return make_finding("dns.spf_allow_all", Severity.HIGH, record)


@check("dns.spf_weak", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_weak(ctx: ScanContext) -> Finding | None:
    record = _single_spf(ctx)
    if record is None:
        return None
    qualifier = _spf_all_qualifier(record)
    if qualifier == "?":
        return make_finding("dns.spf_weak", Severity.MEDIUM, record)
    # With no "all", unlisted servers get a neutral result, the same as ?all. A redirect hands
    # the decision to another domain's record, which a passive scan doesn't follow.
    terms = record.lower().split()
    if qualifier is None and not any(term.startswith("redirect=") for term in terms):
        return make_finding(
            "dns.spf_weak", Severity.MEDIUM, f"{record} (no all, so it acts as ?all)"
        )
    return None


@check("dns.spf_softfail", Category.DNS_EMAIL, requires=[Input.SPF])
def spf_softfail(ctx: ScanContext) -> Finding | None:
    record = _single_spf(ctx)
    if record is None or _spf_all_qualifier(record) != "~":
        return None
    # A note, not a deduction: ~all is what most email providers recommend, and DMARC
    # decides what happens to the mail.
    return make_finding("dns.spf_softfail", Severity.INFO, record)


@check("dns.dmarc_missing", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_missing(ctx: ScanContext) -> Finding | None:
    if _single_dmarc(ctx) is not None:
        return None
    location = f"_dmarc.{ctx.email_domain}"
    records = _dmarc_records(ctx)
    if not records:
        evidence = f"No DMARC record at {location}"
    elif len(records) > 1:
        evidence = f"{len(records)} DMARC records at {location}, so receivers ignore them all"
    else:
        policy = records[0].get("p") or "not set"
        evidence = f"DMARC record at {location} has no valid policy (p={policy}) and no rua"
    return make_finding("dns.dmarc_missing", Severity.MEDIUM, evidence)


@check("dns.dmarc_monitoring_only", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_monitoring_only(ctx: ScanContext) -> Finding | None:
    found = _single_dmarc(ctx)
    if found is None or found[1] != "none":
        return None
    # Security: p=none stops exactly as much spoofing as no record, so it costs the same.
    # Only the reports differ, and the fix text says it is the right first step.
    policy = found[0].get("p")
    if policy == "none":
        evidence = "DMARC policy: none"
    else:
        evidence = f"No valid DMARC policy (p={policy or 'not set'}), so it acts as p=none"
    return make_finding("dns.dmarc_monitoring_only", Severity.MEDIUM, evidence)


@check("dns.dmarc_quarantine", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_quarantine(ctx: ScanContext) -> Finding | None:
    found = _single_dmarc(ctx)
    if found is None or found[1] != "quarantine":
        return None
    # A note, not a deduction: quarantine is real enforcement, reject is just stronger.
    return make_finding("dns.dmarc_quarantine", Severity.INFO, "DMARC policy: quarantine")


@check("dns.dmarc_partial", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_partial(ctx: ScanContext) -> Finding | None:
    found = _single_dmarc(ctx)
    if found is None or found[1] not in _STRICT_POLICIES:
        return None
    tags, policy = found
    weaker = _DMARC_POLICIES[_DMARC_POLICIES.index(policy) - 1]
    # t=y is the DMARC update's replacement for pct, and means the same as pct=0.
    if tags.get("t") == "y":
        evidence = f"p={policy}; t=y (testing), so failing mail is handled as p={weaker}"
    else:
        pct = _dmarc_pct(tags)
        if pct == 100:
            return None
        evidence = (
            f"p={policy}; pct={pct}, so {100 - pct}% of failing mail is handled as p={weaker}"
        )
    return make_finding("dns.dmarc_partial", Severity.LOW, evidence)


@check("dns.dmarc_subdomain_none", Category.DNS_EMAIL, requires=[Input.DMARC])
def dmarc_subdomain_none(ctx: ScanContext) -> Finding | None:
    found = _single_dmarc(ctx)
    if found is None or found[1] not in _STRICT_POLICIES or found[0].get("sp") != "none":
        return None
    return make_finding(
        "dns.dmarc_subdomain_none", Severity.LOW, f"p={found[1]}; sp=none on {ctx.email_domain}"
    )


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
