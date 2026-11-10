"""Score and grade, as defined in PLAN.md."""

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass

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


_SITE_SERVICE_KEY_CHECK = "baas.supabase_service_key"
LEAK_CAP_REASON = "a backend admin key for this site is leaked in a connected repository"


@dataclass(frozen=True)
class CorrelatedLeak:
    """A confirmed admin key for a backend this site uses, leaked in the owner's repo.

    Compared by project, so any number of commits, keys or repos counts as one.
    """

    project: str
    supabase: bool


def counted_leaks(
    leaks: Iterable[CorrelatedLeak], findings: Sequence[Finding]
) -> set[CorrelatedLeak]:
    """The leaks that still need deducting, once the site's own findings are accounted for.

    A key already found on the site has cost its 25 points. One that can't be tied to a
    project might be this same key, so it gets the benefit of the doubt and adds nothing.
    """
    unique = set(leaks)
    site_key = next((item for item in findings if item.check_id == _SITE_SERVICE_KEY_CHECK), None)
    if site_key is None:
        return unique
    project = site_key.backend_identifier
    return {leak for leak in unique if not leak.supabase or (project and leak.project != project)}


def correlation_note(
    counted: Collection[CorrelatedLeak], all_leaks: Collection[CorrelatedLeak]
) -> str | None:
    """Explain in the report what the leaks did to its score, or None if they did nothing."""
    parts: list[str] = []
    if counted:
        points = DEDUCTIONS[Severity.CRITICAL] * len(counted)
        leaked = "a leaked admin key" if len(counted) == 1 else f"{len(counted)} leaked admin keys"
        parts.append(
            f"Includes −{points} points for {leaked} in a connected repository. "
            "Each project counts once, however many commits or repositories it appears in."
        )
    if len(set(all_leaks)) > len(counted):
        parts.append("A key this scan also found on your site was only counted once.")
    return " ".join(parts) or None


def calculate_score(findings: Iterable[Finding], leaks: Collection[CorrelatedLeak] = ()) -> int:
    deducted = sum(DEDUCTIONS[finding.severity] for finding in findings)
    deducted += DEDUCTIONS[Severity.CRITICAL] * len(leaks)
    return max(START_SCORE - deducted, 0)


def grade_for(score: int) -> str:
    for minimum, grade in GRADE_THRESHOLDS:
        if score >= minimum:
            return grade
    return "F"


def _grade_cap(
    findings: Sequence[Finding], leaks: Collection[CorrelatedLeak]
) -> tuple[str, str] | None:
    """The worst grade these findings allow and why, or None if they don't limit it."""
    found = {finding.check_id for finding in findings}
    for check_id, reason in _F_CAPS.items():
        if check_id in found:
            return "F", reason
    critical = next((item for item in findings if item.severity is Severity.CRITICAL), None)
    if critical is not None:
        return "D", critical.title
    return ("D", LEAK_CAP_REASON) if leaks else None


def final_grade(
    score: int | None,
    findings: Sequence[Finding],
    leaks: Collection[CorrelatedLeak] = (),
) -> tuple[str | None, str | None]:
    """The grade to show, and a line explaining the cap when one changed it."""
    cap = _grade_cap(findings, leaks)
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
