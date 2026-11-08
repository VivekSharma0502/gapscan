import pytest

from app.checks import dns_email
from app.checks.base import Category, ScanContext, Severity
from app.checks.domains import registrable_domain, shared_platform_suffix


def ctx(**kwargs: object) -> ScanContext:
    return ScanContext(hostname="example.com", email_domain="example.com", **kwargs)


@pytest.mark.parametrize(
    "records", [[], ["google-site-verification=abc"], ["v=spf10 -all"], ["spf1 -all"]]
)
def test_spf_missing(records: list[str]) -> None:
    finding = dns_email.spf_missing(ctx(spf_records=records))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert finding.category is Category.DNS_EMAIL
    assert "example.com" in finding.evidence


@pytest.mark.parametrize("record", ["v=spf1 -all", "V=SPF1 include:_spf.google.com ~all"])
def test_spf_present_passes(record: str) -> None:
    assert dns_email.spf_missing(ctx(spf_records=["other", record])) is None
    assert dns_email.spf_weak(ctx(spf_records=["other", record])) is None


@pytest.mark.parametrize(
    "record", ["v=spf1 +all", "v=spf1 all", "v=spf1 ?all", "v=spf1 include:a.com +ALL"]
)
def test_spf_weak_permissive_all(record: str) -> None:
    finding = dns_email.spf_weak(ctx(spf_records=[record]))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert finding.evidence == record


def test_spf_weak_multiple_records() -> None:
    finding = dns_email.spf_weak(ctx(spf_records=["v=spf1 -all", "v=spf1 ~all"]))
    assert finding is not None
    assert finding.evidence == "2 SPF records on example.com"


def test_spf_weak_leaves_missing_to_its_own_check() -> None:
    assert dns_email.spf_weak(ctx(spf_records=[])) is None


@pytest.mark.parametrize("records", [[], ["not dmarc"], ["v=DMARC2; p=reject"]])
def test_dmarc_missing(records: list[str]) -> None:
    finding = dns_email.dmarc_missing(ctx(dmarc_records=records))
    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert "_dmarc.example.com" in finding.evidence


@pytest.mark.parametrize(
    "record", ["v=DMARC1; p=reject", "v=dmarc1;p=quarantine;rua=mailto:a@b.c", "V=DMARC1; P=Reject"]
)
def test_dmarc_enforcing_passes(record: str) -> None:
    assert dns_email.dmarc_missing(ctx(dmarc_records=[record])) is None
    assert dns_email.dmarc_weak(ctx(dmarc_records=[record])) is None


@pytest.mark.parametrize(
    ("record", "evidence"),
    [
        ("v=DMARC1; p=none", "DMARC policy: none"),
        ("v=DMARC1; rua=mailto:a@b.c", "DMARC policy: not set"),
        ("v=DMARC1; p=bogus", "DMARC policy: bogus"),
    ],
)
def test_dmarc_weak(record: str, evidence: str) -> None:
    finding = dns_email.dmarc_weak(ctx(dmarc_records=[record]))
    assert finding is not None
    assert finding.severity is Severity.LOW
    assert finding.evidence == evidence


def test_dmarc_weak_leaves_missing_to_its_own_check() -> None:
    assert dns_email.dmarc_weak(ctx(dmarc_records=[])) is None


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
