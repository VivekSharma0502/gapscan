"""What is allowed out of a gitleaks report, and what never is."""

import hashlib
import json
from typing import Any

import pytest

from app.checks.base import Severity
from app.repos import report as report_module
from app.repos.report import UnsafeReportError, parse_report
from app.repos.rules import Provider, rule_for

COMMIT = "a" * 40
RAW = "RAW-SECRET-VALUE-do-not-store"


def entry(**overrides: Any) -> dict[str, Any]:
    fields = {
        "RuleID": "aws-access-token",
        "Description": f"contains {RAW}",
        "StartLine": 3,
        "EndLine": 3,
        "StartColumn": 1,
        "EndColumn": 20,
        "Line": f"key = {RAW}",
        "Match": RAW,
        "Secret": "REDACTED",
        "File": "config/settings.py",
        "SymlinkFile": "",
        "Commit": COMMIT,
        "Entropy": 3.5,
        "Author": "Pat Example",
        "Email": "pat@example.com",
        "Date": "2026-11-09T00:00:00Z",
        "Message": f"add {RAW}",
        "Tags": [],
        "Fingerprint": f"{COMMIT}:config/settings.py:aws-access-token:3",
    }
    return fields | overrides


def parse(*entries: dict[str, Any]) -> Any:
    return parse_report(json.dumps(list(entries)).encode())


def test_keeps_rule_file_line_commit_and_mask() -> None:
    hit = parse(entry()).hits[0]

    assert hit.rule_id == "aws-access-token"
    assert hit.file_path == "config/settings.py"
    assert hit.line == 3
    assert hit.commit_sha == COMMIT
    assert hit.masked == "AKIA****"
    assert hit.severity is Severity.CRITICAL
    assert hit.check_id == "secrets.aws"


def test_nothing_sensitive_survives_parsing() -> None:
    hit = parse(entry()).hits[0]

    kept = repr(hit)
    assert RAW not in kept
    assert "pat@example.com" not in kept
    assert "Pat Example" not in kept


def test_fingerprint_is_stored_hashed_and_fixed_length() -> None:
    fingerprint = f"{COMMIT}:{'x' * 5000}:aws-access-token:3"

    hit = parse(entry(Fingerprint=fingerprint)).hits[0]

    assert hit.fingerprint == hashlib.sha256(fingerprint.encode()).hexdigest()


@pytest.mark.parametrize("value", [RAW, "AKIA...", "", None])
def test_a_report_with_an_unredacted_secret_is_refused(value: str | None) -> None:
    with pytest.raises(UnsafeReportError) as caught:
        parse(entry(Secret=value))

    assert RAW not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_one_bad_entry_refuses_the_whole_report() -> None:
    with pytest.raises(UnsafeReportError):
        parse(entry(), entry(Secret=RAW, Fingerprint="other"))


@pytest.mark.parametrize("content", [b"not json", b"{}", b'[{"RuleID":"x"}]', b"", b"null"])
def test_unusable_reports_are_refused(content: bytes) -> None:
    with pytest.raises(UnsafeReportError):
        parse_report(content)


@pytest.mark.parametrize("commit", ["short", "A" * 40, "g" * 40, ""])
def test_malformed_commit_is_refused(commit: str) -> None:
    with pytest.raises(UnsafeReportError):
        parse(entry(Commit=commit))


def test_empty_report_has_no_hits() -> None:
    parsed = parse_report(b"[]")

    assert parsed.hits == []
    assert not parsed.truncated


def test_same_fingerprint_twice_is_one_finding() -> None:
    assert len(parse(entry(), entry()).hits) == 1


def test_service_role_rule_replaces_the_general_jwt_match() -> None:
    specific = entry(RuleID="supabase-service-role-jwt", Fingerprint="a")
    general = entry(RuleID="jwt", Fingerprint="b")

    assert [hit.rule_id for hit in parse(specific, general).hits] == ["supabase-service-role-jwt"]


def test_jwt_on_another_line_is_kept() -> None:
    specific = entry(RuleID="supabase-service-role-jwt", Fingerprint="a")
    general = entry(RuleID="jwt", Fingerprint="b", StartLine=9)

    assert len(parse(specific, general).hits) == 2


def test_most_serious_findings_survive_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(report_module, "MAX_FINDINGS", 1)
    low = entry(RuleID="generic-api-key", Fingerprint="a")
    critical = entry(RuleID="private-key", Fingerprint="b")

    parsed = parse(low, critical)

    assert [hit.rule_id for hit in parsed.hits] == ["private-key"]
    assert parsed.truncated


@pytest.mark.parametrize(
    ("rule_id", "provider", "severity", "mask"),
    [
        ("aws-access-token", Provider.AWS, Severity.CRITICAL, "AKIA****"),
        ("stripe-access-token", Provider.STRIPE, Severity.CRITICAL, "sk_****"),
        ("github-pat", Provider.GITHUB, Severity.CRITICAL, "ghp_****"),
        ("supabase-secret-key", Provider.SUPABASE, Severity.CRITICAL, "sb_secret_****"),
        ("supabase-service-role-jwt", Provider.SUPABASE, Severity.CRITICAL, "eyJ****"),
        ("private-key", Provider.GENERIC, Severity.CRITICAL, "-----BEGIN ****"),
        ("openai-api-key", Provider.OPENAI, Severity.HIGH, "sk-****"),
        # Public by design, so a loud alarm would be a false one.
        ("gcp-api-key", Provider.FIREBASE, Severity.LOW, "AIza****"),
        ("jwt", Provider.GENERIC, Severity.LOW, "eyJ****"),
        ("generic-api-key", Provider.GENERIC, Severity.MEDIUM, "****"),
        ("some-other-service", Provider.GENERIC, Severity.HIGH, "****"),
    ],
)
def test_rules(rule_id: str, provider: Provider, severity: Severity, mask: str) -> None:
    rule = rule_for(rule_id)

    assert (rule.provider, rule.severity, rule.mask) == (provider, severity, mask)
