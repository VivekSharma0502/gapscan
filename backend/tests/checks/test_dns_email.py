import pytest

from app.checks import dns_email
from app.checks.base import Category, Finding, ScanContext, Severity
from app.checks.domains import registrable_domain, shared_platform_suffix


def ctx(**kwargs: object) -> ScanContext:
    return ScanContext(hostname="example.com", email_domain="example.com", **kwargs)


SPF_CHECKS = (
    dns_email.spf_missing,
    dns_email.spf_multiple_records,
    dns_email.spf_allow_all,
    dns_email.spf_weak,
    dns_email.spf_softfail,
)

DMARC_CHECKS = (
    dns_email.dmarc_missing,
    dns_email.dmarc_monitoring_only,
    dns_email.dmarc_quarantine,
    dns_email.dmarc_partial,
    dns_email.dmarc_subdomain_none,
)


def spf_findings(*records: str) -> dict[str, Finding]:
    context = ctx(spf_records=list(records))
    return {f.check_id: f for check in SPF_CHECKS if (f := check(context)) is not None}


def dmarc_findings(*records: str) -> dict[str, Finding]:
    context = ctx(dmarc_records=list(records))
    return {f.check_id: f for check in DMARC_CHECKS if (f := check(context)) is not None}


# --- SPF ---


@pytest.mark.parametrize(
    "records", [[], ["google-site-verification=abc"], ["v=spf10 -all"], ["spf1 -all"]]
)
def test_spf_missing(records: list[str]) -> None:
    found = spf_findings(*records)
    assert list(found) == ["dns.spf_missing"]
    finding = found["dns.spf_missing"]
    assert finding.severity is Severity.MEDIUM
    assert finding.category is Category.DNS_EMAIL
    assert "example.com" in finding.evidence


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 -all",
        "V=SPF1 include:_spf.google.com -ALL",
        # A redirect hands the decision to another record, which a passive scan doesn't follow.
        "v=spf1 redirect=_spf.example.net",
    ],
)
def test_spf_strict_passes_with_no_finding(record: str) -> None:
    assert spf_findings("other", record) == {}


@pytest.mark.parametrize(
    "record", ["v=spf1 +all", "v=spf1 all", "v=spf1 include:a.com +ALL", "v=spf1 mx all -all"]
)
def test_spf_allow_all_is_high(record: str) -> None:
    found = spf_findings(record)
    assert list(found) == ["dns.spf_allow_all"]
    assert found["dns.spf_allow_all"].severity is Severity.HIGH
    assert found["dns.spf_allow_all"].evidence == record


@pytest.mark.parametrize("record", ["v=spf1 ?all", "v=spf1 include:a.com ?ALL"])
def test_spf_neutral_all_is_weak(record: str) -> None:
    found = spf_findings(record)
    assert list(found) == ["dns.spf_weak"]
    assert found["dns.spf_weak"].severity is Severity.MEDIUM
    assert found["dns.spf_weak"].evidence == record


@pytest.mark.parametrize("record", ["v=spf1", "v=spf1 include:_spf.google.com"])
def test_spf_without_all_is_weak(record: str) -> None:
    found = spf_findings(record)
    assert list(found) == ["dns.spf_weak"]
    assert found["dns.spf_weak"].evidence == f"{record} (no all, so it acts as ?all)"


def test_spf_softfail_is_a_free_note() -> None:
    record = "v=spf1 include:_spf.google.com ~all"
    found = spf_findings(record)
    assert list(found) == ["dns.spf_softfail"]
    finding = found["dns.spf_softfail"]
    assert finding.severity is Severity.INFO
    assert finding.evidence == record
    assert "-all" in finding.fix.how_to_fix


def test_spf_only_first_all_counts() -> None:
    assert list(spf_findings("v=spf1 -all +all")) == []
    assert list(spf_findings("v=spf1 ~all -all")) == ["dns.spf_softfail"]


def test_spf_multiple_records_is_its_own_finding() -> None:
    found = spf_findings("v=spf1 +all", "v=spf1 ~all")
    # Receivers ignore both, so the policy checks don't judge either record.
    assert list(found) == ["dns.spf_multiple_records"]
    assert found["dns.spf_multiple_records"].severity is Severity.MEDIUM
    assert found["dns.spf_multiple_records"].evidence == "2 SPF records on example.com"


# --- DMARC ---


@pytest.mark.parametrize(
    ("records", "evidence"),
    [
        ([], "No DMARC record at _dmarc.example.com"),
        (["not dmarc"], "No DMARC record at _dmarc.example.com"),
        (["v=DMARC2; p=reject"], "No DMARC record at _dmarc.example.com"),
        (
            ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
            "2 DMARC records at _dmarc.example.com, so receivers ignore them all",
        ),
        (
            ["v=DMARC1; p=bogus"],
            "DMARC record at _dmarc.example.com has no valid policy (p=bogus) and no rua",
        ),
        (
            ["v=DMARC1"],
            "DMARC record at _dmarc.example.com has no valid policy (p=not set) and no rua",
        ),
    ],
)
def test_dmarc_missing(records: list[str], evidence: str) -> None:
    found = dmarc_findings(*records)
    assert list(found) == ["dns.dmarc_missing"]
    assert found["dns.dmarc_missing"].severity is Severity.MEDIUM
    assert found["dns.dmarc_missing"].evidence == evidence


@pytest.mark.parametrize(
    ("record", "evidence"),
    [
        ("v=DMARC1; p=none", "DMARC policy: none"),
        ("V=DMARC1; P=None; rua=mailto:a@b.c", "DMARC policy: none"),
        # RFC 7489 6.6.3: no valid p, but a report address, is treated as p=none.
        (
            "v=DMARC1; rua=mailto:a@b.c",
            "No valid DMARC policy (p=not set), so it acts as p=none",
        ),
        (
            "v=DMARC1; p=bogus; rua=mailto:a@b.c",
            "No valid DMARC policy (p=bogus), so it acts as p=none",
        ),
        # pct and sp don't matter when nothing is enforced anyway.
        ("v=DMARC1; p=none; pct=10; sp=none", "DMARC policy: none"),
    ],
)
def test_dmarc_monitoring_only_costs_as_much_as_missing(record: str, evidence: str) -> None:
    found = dmarc_findings(record)
    assert list(found) == ["dns.dmarc_monitoring_only"]
    finding = found["dns.dmarc_monitoring_only"]
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence == evidence
    assert "good first step" in finding.fix.how_to_fix


def test_dmarc_reject_passes_with_no_finding() -> None:
    assert dmarc_findings("v=DMARC1; p=reject; rua=mailto:a@b.c") == {}
    assert dmarc_findings("V=DMARC1; P=Reject; pct=100; sp=quarantine") == {}


def test_dmarc_quarantine_passes_with_a_free_note() -> None:
    found = dmarc_findings("v=dmarc1;p=quarantine;rua=mailto:a@b.c")
    assert list(found) == ["dns.dmarc_quarantine"]
    finding = found["dns.dmarc_quarantine"]
    assert finding.severity is Severity.INFO
    assert "p=reject" in finding.fix.how_to_fix


@pytest.mark.parametrize(
    ("record", "evidence"),
    [
        (
            "v=DMARC1; p=reject; pct=25",
            "p=reject; pct=25, so 75% of failing mail is handled as p=quarantine",
        ),
        (
            "v=DMARC1; p=quarantine; pct=0",
            "p=quarantine; pct=0, so 100% of failing mail is handled as p=none",
        ),
        (
            "v=DMARC1; p=reject; t=y",
            "p=reject; t=y (testing), so failing mail is handled as p=quarantine",
        ),
    ],
)
def test_dmarc_partial(record: str, evidence: str) -> None:
    finding = dns_email.dmarc_partial(ctx(dmarc_records=[record]))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert finding.evidence == evidence


@pytest.mark.parametrize("pct", ["100", "abc", "150", "-5", ""])
def test_dmarc_full_or_invalid_pct_is_not_partial(pct: str) -> None:
    # Receivers treat an invalid pct as the default, 100.
    record = f"v=DMARC1; p=reject; pct={pct}"
    assert dns_email.dmarc_partial(ctx(dmarc_records=[record])) is None


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_dmarc_subdomain_none_when_policy_is_strict(policy: str) -> None:
    finding = dns_email.dmarc_subdomain_none(ctx(dmarc_records=[f"v=DMARC1; p={policy}; sp=none"]))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert finding.evidence == f"p={policy}; sp=none on example.com"


def test_dmarc_strict_record_can_have_several_gaps() -> None:
    found = dmarc_findings("v=DMARC1; p=quarantine; pct=50; sp=none")
    assert set(found) == {"dns.dmarc_quarantine", "dns.dmarc_partial", "dns.dmarc_subdomain_none"}


# --- CAA and shared domains ---


def test_caa_missing() -> None:
    finding = dns_email.caa_missing(ctx(caa_records=[]))
    assert finding is not None
    assert finding.severity is Severity.LOW


def test_caa_present_passes() -> None:
    assert dns_email.caa_missing(ctx(caa_records=['0 issue "letsencrypt.org"'])) is None


def test_shared_platform_note_costs_nothing_and_explains() -> None:
    context = ScanContext(hostname="foo.vercel.app", shared_platform_suffix="vercel.app")
    finding = dns_email.shared_platform_domain(context)
    assert finding is not None
    assert finding.severity is Severity.INFO
    assert "vercel.app" in finding.evidence
    assert "skipped" in finding.fix.what_it_means


def test_no_shared_platform_note_on_own_domain() -> None:
    assert dns_email.shared_platform_domain(ctx()) is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("www.example.com", "example.com"),
        ("example.com", "example.com"),
        ("shop.example.co.in", "example.co.in"),
        ("a.b.example.ac.in", "example.ac.in"),
        ("WWW.Example.COM.", "example.com"),
        ("co.in", None),
    ],
)
def test_registrable_domain(host: str, expected: str | None) -> None:
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    ("host", "suffix"),
    [
        ("foo.vercel.app", "vercel.app"),
        ("foo.netlify.app", "netlify.app"),
        ("foo.web.app", "web.app"),
        ("foo.github.io", "github.io"),
        ("foo.pages.dev", "pages.dev"),
    ],
)
def test_shared_platform_suffix(host: str, suffix: str) -> None:
    assert shared_platform_suffix(host) == suffix


@pytest.mark.parametrize("host", ["example.com", "www.example.co.in", "example.app"])
def test_own_domains_are_not_shared(host: str) -> None:
    assert shared_platform_suffix(host) is None
