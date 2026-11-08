import pytest

from app.checks.base import Category, Finding, Fix, Platform, PlatformFix, Severity
from app.checks.scoring import calculate_score, grade_for


def finding(severity: Severity) -> Finding:
    fix = Fix(
        what_it_means="x",
        how_to_fix="y",
        platforms={platform: PlatformFix(instructions="z") for platform in Platform},
    )
    return Finding(
        check_id="t.x",
        category=Category.TLS,
        severity=severity,
        title="t",
        evidence="e",
        fix=fix,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.CRITICAL, 75),
        (Severity.HIGH, 85),
        (Severity.MEDIUM, 93),
        (Severity.LOW, 98),
        (Severity.INFO, 100),
    ],
)
def test_each_severity_deducts_plan_amount(severity: Severity, expected: int) -> None:
    assert calculate_score([finding(severity)]) == expected


def test_no_findings_scores_100() -> None:
    assert calculate_score([]) == 100


def test_deductions_add_up() -> None:
    findings = [finding(Severity.HIGH), finding(Severity.MEDIUM), finding(Severity.LOW)]
    assert calculate_score(findings) == 76


def test_score_floors_at_zero() -> None:
    assert calculate_score([finding(Severity.CRITICAL)] * 5) == 0


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100, "A+"),
        (95, "A+"),
        (94, "A"),
        (85, "A"),
        (84, "B"),
        (70, "B"),
        (69, "C"),
        (55, "C"),
        (54, "D"),
        (40, "D"),
        (39, "F"),
        (0, "F"),
    ],
)
def test_grade_boundaries(score: int, grade: str) -> None:
    assert grade_for(score) == grade
