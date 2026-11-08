"""Runs every registered check against a ScanContext and builds the report."""

import logging
from enum import StrEnum

from pydantic import BaseModel

# Imported for their side effect: each module registers its checks with the registry.
from app.checks import cms, cookies, dns_email, headers, tls  # noqa: F401
from app.checks.base import Finding, Input, ScanContext, Severity, SkipCheck, StepCallback
from app.checks.registry import CheckSpec, all_checks
from app.checks.scoring import calculate_score, grade_for

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = list(Severity)
_NOT_COLLECTED_REASON = "This information could not be collected."
_CHECK_FAILED_REASON = "This check could not be completed."
_NO_HOMEPAGE_REASON = "We could not read the site's homepage."


class ScanStatus(StrEnum):
    COMPLETE = "complete"
    # Scored, but some checks that should have run could not, so the grade may be generous.
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"


class SkippedCheck(BaseModel):
    check_id: str
    reason: str
    # True when the check can't apply to this site, as opposed to having failed.
    not_applicable: bool = False


class ScanReport(BaseModel):
    hostname: str
    status: ScanStatus
    incomplete_reason: str | None
    # None when the scan is incomplete. A partial score would flatter a broken site.
    score: int | None
    grade: str | None
    # Shown next to a partial score, so nobody mistakes it for a full result.
    score_label: str | None
    findings: list[Finding]
    skipped: list[SkippedCheck]


def _missing_input(spec: CheckSpec, ctx: ScanContext) -> Input | None:
    for needed in sorted(spec.requires):
        if getattr(ctx, needed.value) is None:
            return needed
    return None


def _partial_label(count: int) -> str:
    return f"Partial — {count} check{'' if count == 1 else 's'} skipped"


def selected_checks(allow_active: bool = False) -> list[CheckSpec]:
    return [spec for spec in all_checks() if allow_active or not spec.active]


def run_checks(
    ctx: ScanContext, *, on_step: StepCallback | None = None, allow_active: bool = False
) -> ScanReport:
    """Run the checks. Security: active checks are opt-in, so none run by accident."""
    findings: list[Finding] = []
    skipped: list[SkippedCheck] = []

    for spec in selected_checks(allow_active):
        if on_step is not None:
            on_step(spec.check_id)
        missing = _missing_input(spec, ctx)
        if missing is not None:
            skipped.append(
                SkippedCheck(
                    check_id=spec.check_id,
                    reason=ctx.skip_reasons.get(missing, _NOT_COLLECTED_REASON),
                    not_applicable=missing in ctx.not_applicable,
                )
            )
            continue
        try:
            finding = spec.func(ctx)
        except SkipCheck as exc:
            skipped.append(SkippedCheck(check_id=spec.check_id, reason=str(exc)))
            continue
        except Exception as exc:
            # A site's odd response must not lose the whole report. Security: only the
            # error type is logged, since the message could echo the site's content.
            logger.error("check %s failed: %s", spec.check_id, type(exc).__name__)
            skipped.append(SkippedCheck(check_id=spec.check_id, reason=_CHECK_FAILED_REASON))
            continue
        if finding is not None:
            findings.append(finding)

    findings.sort(key=lambda item: (_SEVERITY_ORDER.index(item.severity), item.check_id))

    if ctx.homepage is None:
        reason = ctx.skip_reasons.get(Input.HOMEPAGE, _NO_HOMEPAGE_REASON)
        return ScanReport(
            hostname=ctx.hostname,
            status=ScanStatus.INCOMPLETE,
            incomplete_reason=reason,
            score=None,
            grade=None,
            score_label=None,
            findings=findings,
            skipped=skipped,
        )

    score = calculate_score(findings)
    failed_count = sum(1 for item in skipped if not item.not_applicable)
    return ScanReport(
        hostname=ctx.hostname,
        status=ScanStatus.PARTIAL if failed_count else ScanStatus.COMPLETE,
        incomplete_reason=None,
        score=score,
        grade=grade_for(score),
        score_label=_partial_label(failed_count) if failed_count else None,
        findings=findings,
        skipped=skipped,
    )
