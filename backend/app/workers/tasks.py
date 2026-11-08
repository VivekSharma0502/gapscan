"""Background scan jobs."""

import logging
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlmodel import update

from app.checks.collector import COLLECT_STEPS, collect_context
from app.checks.runner import ScanReport, run_checks, selected_checks
from app.core.db import new_session
from app.models.scan import FindingRecord, Scan, ScanJobStatus, utc_now
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


def _progress(
    completed: int, total: int, current: str | None, finished: Sequence[str] = ()
) -> dict[str, Any]:
    # Security: counts, step names and done/running only. "done" means the step ran, not
    # that it passed. A pass/fail or severity here would reveal the findings that anonymous
    # viewers don't get to see.
    steps = [{"name": name, "status": "done"} for name in finished]
    if current is not None:
        steps.append({"name": current, "status": "running"})
    return {"completed": completed, "total": total, "current": current, "steps": steps}


def initial_quick_progress() -> dict[str, Any]:
    return _progress(0, len(COLLECT_STEPS) + len(selected_checks()), None)


def _claim_scan(scan_id: UUID) -> str | None:
    """Move a queued scan to running and return its target, or None if it isn't queued.

    One atomic update, so a redelivered task or an expired scan can't start a second run.
    """
    with new_session() as session:
        result = session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanJobStatus.QUEUED)
            .values(status=ScanJobStatus.RUNNING, started_at=utc_now())
        )
        session.commit()
        if result.rowcount == 0:
            return None
        return session.get_one(Scan, scan_id).target


def _update_running(scan_id: UUID, **values: Any) -> None:
    # Only touches a running scan, so a late worker can't revive one already expired.
    with new_session() as session:
        session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanJobStatus.RUNNING)
            .values(**values)
        )
        session.commit()


def _save_report(scan_id: UUID, report: ScanReport, total: int, steps: Sequence[str]) -> None:
    # Findings and the final status commit together, so nobody can read a half-saved report.
    with new_session() as session:
        result = session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanJobStatus.RUNNING)
            .values(
                status=ScanJobStatus.DONE,
                result_status=report.status,
                score=report.score,
                grade=report.grade,
                score_label=report.score_label,
                incomplete_reason=report.incomplete_reason,
                skipped_json=[item.model_dump() for item in report.skipped],
                progress_json=_progress(total, total, None, steps),
                finished_at=utc_now(),
            )
        )
        if result.rowcount == 0:
            session.rollback()
            return
        session.add_all(
            FindingRecord(
                scan_id=scan_id,
                check_id=finding.check_id,
                category=finding.category,
                severity=finding.severity,
                title=finding.title,
                evidence_masked=finding.evidence,
            )
            for finding in report.findings
        )
        session.commit()


@celery_app.task(name="scans.run_quick")
def run_quick_scan(scan_id: str) -> None:
    """Run a passive scan. The target is read from the database, never taken from the queue."""
    job_id = UUID(scan_id)
    target = _claim_scan(job_id)
    if target is None:
        return

    total = initial_quick_progress()["total"]
    # Sent whole on every update, because checks finish faster than the page polls.
    finished: list[str] = []

    def on_step(step: str) -> None:
        _update_running(job_id, progress_json=_progress(len(finished), total, step, finished))
        finished.append(step)

    try:
        # Security: allow_active stays off. Quick scans run on domains nobody has verified.
        context = collect_context(target, on_step=on_step)
        report = run_checks(context, on_step=on_step)
        _save_report(job_id, report, total, finished)
    except Exception as exc:
        # Security: only the error type is logged, since the message could echo site content.
        logger.error("scan %s failed: %s", scan_id, type(exc).__name__)
        _update_running(job_id, status=ScanJobStatus.FAILED, finished_at=utc_now())
