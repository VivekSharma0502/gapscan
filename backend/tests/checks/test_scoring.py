import pytest

from app.checks.base import Category, Finding, Fix, Platform, PlatformFix, Severity
from app.checks.scoring import calculate_score, final_grade, grade_for


def finding(severity: Severity, check_id: str = "t.x", title: str = "t") -> Finding:
    fix = Fix(
        what_it_means="x",
        how_to_fix="y",
        platforms={platform: PlatformFix(instructions="z") for platform in Platform},
    )
    return Finding(
        check_id=check_id,
        category=Category.TLS,
        severity=severity,
        title=title,
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


# Grade caps


@pytest.mark.parametrize(
    ("check_id", "reason"),
    [
        ("tls.no_https", "Capped at F: site doesn't offer HTTPS"),
        ("tls.cert_expired", "Capped at F: certificate has expired"),
        ("tls.cert_untrusted", "Capped at F: certificate isn't trusted"),
    ],
)
def test_broken_connection_caps_the_grade_at_f(check_id: str, reason: str) -> None:
    assert final_grade(75, [finding(Severity.CRITICAL, check_id)]) == ("F", reason)


def test_any_other_critical_finding_caps_the_grade_at_d() -> None:
    findings = [finding(Severity.CRITICAL, "t.other", "Admin panel is public")]
    assert final_grade(75, findings) == ("D", "Capped at D: Admin panel is public")


def test_f_cap_wins_over_d_cap() -> None:
    findings = [finding(Severity.CRITICAL, "a.other"), finding(Severity.CRITICAL, "tls.no_https")]
    assert final_grade(50, findings)[0] == "F"


def test_first_listed_f_cap_is_the_one_reported() -> None:
    findings = [
        finding(Severity.CRITICAL, "tls.cert_untrusted"),
        finding(Severity.CRITICAL, "tls.cert_expired"),
    ]
    assert final_grade(50, findings) == ("F", "Capped at F: certificate has expired")


@pytest.mark.parametrize(
    ("score", "check_id", "grade"),
    [
        (30, "tls.no_https", "F"),  # the score already earned an F
        (30, "t.other", "F"),  # a D cap must never raise a grade
        (45, "t.other", "D"),  # the score already earned a D
    ],
)
def test_no_explanation_when_the_cap_changes_nothing(score: int, check_id: str, grade: str) -> None:
    assert final_grade(score, [finding(Severity.CRITICAL, check_id)]) == (grade, None)


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])
def test_lower_severities_do_not_cap_the_grade(severity: Severity) -> None:
    assert final_grade(90, [finding(severity)]) == ("A", None)


def test_no_findings_means_no_cap() -> None:
    assert final_grade(100, []) == ("A+", None)


def test_unscored_scan_with_a_broken_connection_is_still_an_f() -> None:
    findings = [finding(Severity.CRITICAL, "tls.cert_expired")]
    assert final_grade(None, findings) == ("F", "Capped at F: certificate has expired")


@pytest.mark.parametrize(
    "findings",
    [[], [finding(Severity.CRITICAL, "t.other")], [finding(Severity.LOW)]],
)
def test_unscored_scan_gets_no_guessed_grade(findings: list[Finding]) -> None:
    assert final_grade(None, findings) == (None, None)
