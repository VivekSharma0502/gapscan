"""Score and grade, as defined in PLAN.md."""

from collections.abc import Iterable

from app.checks.base import Finding, Severity

START_SCORE = 100

DEDUCTIONS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Highest first. Anything below the last threshold is an F.
GRADE_THRESHOLDS = ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"))


def calculate_score(findings: Iterable[Finding]) -> int:
    deducted = sum(DEDUCTIONS[finding.severity] for finding in findings)
    return max(START_SCORE - deducted, 0)


def grade_for(score: int) -> str:
    for minimum, grade in GRADE_THRESHOLDS:
        if score >= minimum:
            return grade
    return "F"
