import pytest
from pydantic import ValidationError

from app.checks import registry
from app.checks.base import (
    Category,
    CheckText,
    Finding,
    Fix,
    Input,
    Platform,
    PlatformFix,
    ScanContext,
    Severity,
)
from app.checks.catalog import CATALOG
from app.checks.registry import MAX_EVIDENCE_CHARS, check, clean_evidence, make_finding


def fix_for(platforms: list[Platform]) -> Fix:
    return Fix(
        what_it_means="means",
        how_to_fix="do this",
        platforms={platform: PlatformFix(instructions="steps") for platform in platforms},
    )


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registry, "_REGISTRY", {})
    monkeypatch.setitem(CATALOG, "t.demo", CheckText(title="Demo", fix=fix_for(list(Platform))))


def noop(ctx: ScanContext) -> Finding | None:
    return None


@pytest.mark.usefixtures("isolated")
def test_check_is_registered_with_its_requirements() -> None:
    check("t.demo", Category.TLS, requires=[Input.HTTPS])(noop)
    spec = registry.all_checks()[0]
    assert (spec.check_id, spec.category) == ("t.demo", Category.TLS)
    assert spec.requires == {Input.HTTPS}
    assert spec.func is noop


@pytest.mark.usefixtures("isolated")
def test_duplicate_check_id_is_rejected() -> None:
    check("t.demo", Category.TLS)(noop)
    with pytest.raises(ValueError, match="duplicate"):
        check("t.demo", Category.TLS)(noop)


@pytest.mark.usefixtures("isolated")
def test_check_without_catalog_text_is_rejected() -> None:
    with pytest.raises(ValueError, match="no catalog text"):
        check("t.unwritten", Category.TLS)(noop)


@pytest.mark.usefixtures("isolated")
def test_make_finding_uses_catalog_and_registry() -> None:
    check("t.demo", Category.TLS)(noop)
    finding = make_finding("t.demo", Severity.LOW, "seen")
    assert finding.check_id == "t.demo"
    assert finding.category is Category.TLS
    assert finding.severity is Severity.LOW
    assert finding.title == "Demo"
    assert finding.evidence == "seen"
    assert finding.fix.what_it_means == "means"


def test_fix_must_cover_every_platform() -> None:
    with pytest.raises(ValidationError, match="missing platforms"):
        fix_for([Platform.VERCEL, Platform.NGINX])


def test_platform_without_snippet_is_allowed() -> None:
    assert fix_for(list(Platform)).platforms[Platform.NGINX].snippet is None


def test_evidence_loses_control_characters() -> None:
    assert clean_evidence("nginx\r\nX-Evil: 1\x00") == "nginx X-Evil: 1"


def test_long_evidence_is_capped() -> None:
    cleaned = clean_evidence("a" * (MAX_EVIDENCE_CHARS + 50))
    assert cleaned == "a" * MAX_EVIDENCE_CHARS + "..."
