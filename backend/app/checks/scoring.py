"""Score and grade, as defined in PLAN.md."""

from collections.abc import Iterable, Sequence

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

_GRADE_ORDER = ("A+", "A", "B", "C", "D", "F")

# Points alone can't express these: a site with no working HTTPS could otherwise score a B
# by getting everything else right. Listed in the order they're reported.
_F_CAPS = {
    "tls.no_https": "site doesn't offer HTTPS",
    "tls.cert_expired": "certificate has expired",
    "tls.cert_untrusted": "certificate isn't trusted",
}


def calculate_score(findings: Iterable[Finding]) -> int:
    deducted = sum(DEDUCTIONS[finding.severity] for finding in findings)
    return max(START_SCORE - deducted, 0)


def grade_for(score: int) -> str:
    for minimum, grade in GRADE_THRESHOLDS:
        if score >= minimum:
            return grade
    return "F"


def _grade_cap(findings: Sequence[Finding]) -> tuple[str, str] | None:
    """The worst grade these findings allow and why, or None if they don't limit it."""
    found = {finding.check_id for finding in findings}
    for check_id, reason in _F_CAPS.items():
        if check_id in found:
            return "F", reason
    critical = next((item for item in findings if item.severity is Severity.CRITICAL), None)
    return ("D", critical.title) if critical is not None else None


def final_grade(score: int | None, findings: Sequence[Finding]) -> tuple[str | None, str | None]:
    """The grade to show, and a line explaining the cap when one changed it."""
    cap = _grade_cap(findings)
    if score is None:
        # No score means we couldn't read the site. An F is still honest when its connection
        # is known to be broken, but any better grade would be a guess.
        if cap is None or cap[0] != "F":
            return None, None
    else:
        grade = grade_for(score)
        if cap is None or _GRADE_ORDER.index(grade) >= _GRADE_ORDER.index(cap[0]):
            return grade, None
    return cap[0], f"Capped at {cap[0]}: {cap[1]}"
