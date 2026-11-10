"""Background scan jobs."""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete
from sqlmodel import Session, select, update

from app.checks.active_collector import attach_probes, without_probes
from app.checks.baas_collector import discover_backends
from app.checks.baas_probes import (
    mark_public_tables,
    probe_backends,
    probe_confirmed_backends,
)
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BaasProbes,
    BotProtection,
    Category,
    DiscoveredBackend,
    Input,
    ScanContext,
    TableAccess,
    bot_protection_label,
)
from app.checks.collector import COLLECT_STEPS, collect_context
from app.checks.ownership import VerificationMethod, prove_ownership
from app.checks.runner import (
    ScanReport,
    ScanStatus,
    run_backend_checks,
    run_checks,
    selected_checks,
)
from app.core.db import new_session
from app.models.correlation import RepoIdentifier
from app.models.domain import Domain, DomainBackend, DomainBackendTable
from app.models.github import GithubInstallation, Repo
from app.models.scan import FindingRecord, IdentifierBasis, Scan, ScanJobStatus, utc_now
from app.repos.scanner import REPO_STEPS, RepoScanLimitError, RepoScanResult, scan_repository
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

OWNERSHIP_STEP = "ownership_check"
PROBE_STEP = "active_probes"
BAAS_STEP = "baas_discovery"
BAAS_PROBE_STEP = "baas_probes"

# Security: how long a past verification can stand in when bot protection blocks a new
# one, and only for backend checks. Short, because a domain can change hands.
RECENT_PROOF_LIMIT = timedelta(hours=24)
BACKEND_CHECK_IDS = (
    "baas.firebase_rtdb_public",
    "baas.firebase_storage_listable",
    "baas.firebase_rtdb_protected",
    "baas.firebase_storage_protected",
)

_NOT_VERIFIED_REASON = "This domain isn't verified, so these checks did not run."
_PROOF_GONE_REASON = (
    "We could no longer find your verification record or file, so the domain was marked "
    "unverified and these checks did not run."
)
_PROOF_UNKNOWN_REASON = (
    "We couldn't re-confirm that you own this domain, so these checks did not run."
)

# Enforced on Linux. Kept under REPO_SCAN_STALE_AFTER, and over the scanner's own caps.
REPO_TASK_TIME_LIMIT_SECONDS = 840
_REPO_NOT_LINKED = "This repository is no longer connected to your account."
_REPO_SCAN_FAILED = "We couldn't finish scanning this repository. Please try again."
_TOO_MANY_FINDINGS = (
    "This repository has more findings than we can list, so only the most serious are shown."
)


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


def initial_full_progress() -> dict[str, Any]:
    total = len(COLLECT_STEPS) + 4 + len(selected_checks(allow_active=True))
    return _progress(0, total, None)


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
                grade_cap_reason=report.grade_cap_reason,
                score_label=report.score_label,
                incomplete_reason=report.incomplete_reason,
                blocked_by=report.blocked_by,
                verification_note=report.verification_note,
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


@dataclass(frozen=True)
class _OwnershipProblem:
    reason: str
    blocked_by: BotProtection | None = None
    # How long ago ownership was last proven. Set only when bot protection is all that
    # stopped a fresh proof, so a wrong or missing token can never use it.
    proof_age: timedelta | None = None


def _age_since(moment: datetime) -> timedelta:
    # SQLite, used in tests, hands back timestamps without their timezone.
    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    return max(utc_now() - aware, timedelta(0))


def _ownership_problem(scan_id: UUID) -> _OwnershipProblem | None:
    """Return why active checks must not run, or None once ownership is confirmed.

    Security: asked here as well as in the API, and re-proven on every scan, because a domain
    can change hands long after it was verified.
    """
    with new_session() as session:
        scan = session.get_one(Scan, scan_id)
        domain = session.get(Domain, scan.domain_id) if scan.domain_id is not None else None
        if (
            domain is None
            or domain.verified_at is None
            or domain.owner_id != scan.owner_id
            or domain.hostname != scan.target
        ):
            return _OwnershipProblem(_NOT_VERIFIED_REASON)
        domain_id, hostname, token = domain.id, domain.hostname, domain.verify_token
        accept_legacy = domain.accepts_legacy_verify_names
        last_proven_at, proven_by = domain.verified_at, domain.verified_method

    result = prove_ownership(hostname, token, accept_legacy=accept_legacy)
    if result.proven:
        # This is the last successful verification that the 24-hour rule relies on.
        with new_session() as session:
            session.exec(
                update(Domain)
                .where(Domain.id == domain_id)
                .values(verified_at=utc_now(), verified_method=result.method)
            )
            session.commit()
        return None
    if result.blocked_by is not None:
        # Security: a domain proven by DNS can't lean on a blocked file. Its own proof gave a
        # real answer, and the file says nothing about it.
        inconclusive = proven_by == VerificationMethod.FILE and result.file_proof_only_blocked
        return _OwnershipProblem(
            f"{bot_protection_label(result.blocked_by)} blocked our request for your "
            "verification file, so these checks did not run. Your domain is still verified.",
            result.blocked_by,
            _age_since(last_proven_at) if inconclusive else None,
        )
    if not result.definitely_gone:
        return _OwnershipProblem(_PROOF_UNKNOWN_REASON)
    with new_session() as session:
        session.exec(
            update(Domain)
            .where(Domain.id == domain_id)
            .values(verified_at=None, verified_method=None)
        )
        session.commit()
    return _OwnershipProblem(_PROOF_GONE_REASON)


def initial_repo_progress() -> dict[str, Any]:
    return _progress(0, len(REPO_STEPS), None)


@dataclass(frozen=True)
class _RepoTarget:
    repo_id: UUID
    installation_id: int
    github_repo_id: int
    before_sha: str | None
    after_sha: str | None


def _repo_target(scan_id: UUID) -> _RepoTarget | None:
    """Return what to scan, or None if the scan's owner no longer has this repo.

    Security: checked again here, because the app can be uninstalled while a scan is queued.
    """
    with new_session() as session:
        scan = session.get_one(Scan, scan_id)
        repo = session.get(Repo, scan.repo_id) if scan.repo_id is not None else None
        if repo is None or repo.owner_id != scan.owner_id:
            return None
        installation = session.get(GithubInstallation, repo.installation_id)
        if installation is None or installation.suspended_at is not None:
            return None
        return _RepoTarget(
            repo_id=repo.id,
            installation_id=installation.installation_id,
            github_repo_id=repo.github_repo_id,
            before_sha=scan.before_sha,
            after_sha=scan.after_sha,
        )


def _save_repo_identifiers(session: Session, repo_id: UUID, result: RepoScanResult) -> None:
    # A failed read says nothing about the repo, so what's saved must not be cleared by it.
    if result.identifiers is None:
        return
    now = utc_now()
    known = {
        (row.kind, row.value): row
        for row in session.exec(select(RepoIdentifier).where(RepoIdentifier.repo_id == repo_id))
    }
    for kind, value in result.identifiers:
        row = known.get((kind, value))
        if row is None:
            session.add(RepoIdentifier(repo_id=repo_id, kind=kind, value=value))
        else:
            row.last_seen_at = now
    # A push only looks at new commits, so only a complete scan can show one has gone.
    if result.full_history and not result.truncated:
        for pair, row in known.items():
            if pair not in result.identifiers:
                session.delete(row)


def _save_repo_report(
    scan_id: UUID, repo_id: UUID, result: RepoScanResult, steps: Sequence[str]
) -> None:
    total = len(REPO_STEPS)
    with new_session() as session:
        # Held until commit, so two scans of one repo can't save the same secret at once.
        repo = session.get(Repo, repo_id, with_for_update=True)
        if repo is None:
            session.rollback()
            _update_running(scan_id, status=ScanJobStatus.FAILED, finished_at=utc_now())
            return

        updated = session.exec(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanJobStatus.RUNNING)
            .values(
                status=ScanJobStatus.DONE,
                result_status=ScanStatus.PARTIAL if result.truncated else ScanStatus.COMPLETE,
                incomplete_reason=_TOO_MANY_FINDINGS if result.truncated else None,
                progress_json=_progress(total, total, None, steps),
                finished_at=utc_now(),
            )
        )
        if updated.rowcount == 0:
            session.rollback()
            return

        # A secret already on file keeps its row, and so its first-seen date.
        known = {
            row.fingerprint: row
            for row in session.exec(select(FindingRecord).where(FindingRecord.repo_id == repo_id))
        }
        # Findings from before identifiers existed get theirs the next time they're seen.
        for hit in result.hits:
            existing = known.get(hit.fingerprint)
            if existing is None or hit.backend_identifier is None:
                continue
            # A guess never replaces a project worked out from the key or its file.
            if hit.identifier_basis is IdentifierBasis.ONLY_PROJECT and (
                existing.identifier_basis not in (None, IdentifierBasis.ONLY_PROJECT)
            ):
                continue
            existing.backend_identifier = hit.backend_identifier
            existing.identifier_basis = hit.identifier_basis
        session.add_all(
            FindingRecord(
                scan_id=scan_id,
                repo_id=repo_id,
                check_id=hit.check_id,
                category=Category.SECRETS,
                severity=hit.severity,
                title=hit.title,
                evidence_masked=hit.masked,
                location=f"{hit.file_path}:{hit.line}",
                rule_id=hit.rule_id,
                file_path=hit.file_path,
                line=hit.line,
                commit_sha=hit.commit_sha,
                fingerprint=hit.fingerprint,
                backend_identifier=hit.backend_identifier,
                identifier_basis=hit.identifier_basis,
            )
            for hit in result.hits
            if hit.fingerprint not in known
        )
        if result.full_history:
            repo.first_full_scan_at = repo.first_full_scan_at or utc_now()
            repo.needs_full_scan = False
            # A complete view of the history, so anything missing was rewritten out of it. A
            # truncated list proves nothing about what it left out.
            if not result.truncated:
                session.exec(
                    delete(FindingRecord).where(
                        FindingRecord.repo_id == repo_id,
                        FindingRecord.fingerprint.not_in({hit.fingerprint for hit in result.hits}),
                    )
                )
        repo.full_name = result.full_name
        _save_repo_identifiers(session, repo_id, result)
        session.commit()


@celery_app.task(name="scans.run_repo", time_limit=REPO_TASK_TIME_LIMIT_SECONDS)
def run_repo_scan(scan_id: str) -> None:
    """Search a linked repo's git history for secrets. Stores masked results only."""
    job_id = UUID(scan_id)
    if _claim_scan(job_id) is None:
        return

    total = len(REPO_STEPS)
    finished: list[str] = []

    def on_step(step: str) -> None:
        _update_running(job_id, progress_json=_progress(len(finished), total, step, finished))
        finished.append(step)

    try:
        target = _repo_target(job_id)
        if target is None:
            _update_running(
                job_id,
                status=ScanJobStatus.FAILED,
                incomplete_reason=_REPO_NOT_LINKED,
                finished_at=utc_now(),
            )
            return
        result = scan_repository(
            target.installation_id,
            target.github_repo_id,
            before_sha=target.before_sha,
            after_sha=target.after_sha,
            on_step=on_step,
        )
        _save_repo_report(job_id, target.repo_id, result, finished)
    except RepoScanLimitError as exc:
        _update_running(
            job_id,
            status=ScanJobStatus.DONE,
            result_status=ScanStatus.INCOMPLETE,
            incomplete_reason=str(exc),
            finished_at=utc_now(),
        )
    except Exception as exc:
        # Security: only the error type is logged, since a message could echo repo content.
        logger.error("repo scan %s failed: %s", scan_id, type(exc).__name__)
        _update_running(
            job_id,
            status=ScanJobStatus.FAILED,
            incomplete_reason=_REPO_SCAN_FAILED,
            finished_at=utc_now(),
        )


def _remember_backends(scan_id: UUID, baas: BaasDiscovery | None) -> None:
    """Record what the site's code names, so its owner can say which are theirs."""
    if baas is None or not baas.backends:
        return
    with new_session() as session:
        domain_id = session.get_one(Scan, scan_id).domain_id
        if domain_id is None:
            return
        known = {
            (row.kind, row.identifier): row
            for row in session.exec(
                select(DomainBackend).where(DomainBackend.domain_id == domain_id)
            )
        }
        now = utc_now()
        for backend in baas.backends:
            row = known.get((backend.kind, backend.identifier))
            if row is not None:
                # An existing row keeps its confirmation, and only the time it was seen moves.
                row.last_seen_at = now
            else:
                session.add(
                    DomainBackend(
                        domain_id=domain_id, kind=backend.kind, identifier=backend.identifier
                    )
                )
        session.commit()


def _confirmed_backends(scan_id: UUID) -> set[DiscoveredBackend]:
    with new_session() as session:
        domain_id = session.get_one(Scan, scan_id).domain_id
        if domain_id is None:
            return set()
        rows = session.exec(
            select(DomainBackend).where(
                DomainBackend.domain_id == domain_id, DomainBackend.confirmed_at.is_not(None)
            )
        )
        return {DiscoveredBackend(row.kind, row.identifier) for row in rows}


def _public_tables(scan_id: UUID) -> set[tuple[str, str]]:
    with new_session() as session:
        domain_id = session.get_one(Scan, scan_id).domain_id
        if domain_id is None:
            return set()
        rows = session.exec(
            select(DomainBackend.identifier, DomainBackendTable.name)
            .join(DomainBackendTable, DomainBackendTable.backend_id == DomainBackend.id)
            .where(
                DomainBackend.domain_id == domain_id,
                DomainBackendTable.meant_to_be_public_at.is_not(None),
            )
        )
        return {(ref, name) for ref, name in rows}


def _remember_tables(scan_id: UUID, probes: BaasProbes | None) -> None:
    """Record each table's state, so its owner can mark the public ones. Names only."""
    if probes is None or not probes.supabase:
        return
    with new_session() as session:
        domain_id = session.get_one(Scan, scan_id).domain_id
        if domain_id is None:
            return
        now = utc_now()
        for project in probes.supabase:
            backend = session.exec(
                select(DomainBackend).where(
                    DomainBackend.domain_id == domain_id,
                    DomainBackend.kind == BaasKind.SUPABASE,
                    DomainBackend.identifier == project.ref,
                )
            ).first()
            if backend is None:
                continue
            known = {
                row.name: row
                for row in session.exec(
                    select(DomainBackendTable).where(DomainBackendTable.backend_id == backend.id)
                )
            }
            for table in project.tables:
                # A name that isn't a table, or a table that gave no answer, tells us nothing.
                if table.access in (TableAccess.NOT_FOUND, TableAccess.UNKNOWN):
                    continue
                row = known.get(table.name)
                if row is None:
                    session.add(
                        DomainBackendTable(
                            backend_id=backend.id, name=table.name, access=table.access
                        )
                    )
                else:
                    # An existing row keeps its "meant to be public" choice.
                    row.access = table.access
                    row.last_seen_at = now
        session.commit()


def initial_backend_progress() -> dict[str, Any]:
    return _progress(0, 2 + len(BACKEND_CHECK_IDS), None)


def _hours_ago(age: timedelta) -> str:
    hours = int(age.total_seconds() // 3600)
    if hours < 1:
        return "less than an hour ago"
    return "1 hour ago" if hours == 1 else f"{hours} hours ago"


def _may_use_recent_proof(problem: _OwnershipProblem) -> bool:
    return problem.proof_age is not None and problem.proof_age < RECENT_PROOF_LIMIT


def _recent_proof_note(problem: _OwnershipProblem) -> str:
    assert problem.blocked_by is not None and problem.proof_age is not None  # noqa: S101
    return (
        f"{bot_protection_label(problem.blocked_by)} blocked our request for your verification "
        f"file, so we couldn't check it again. Your last successful verification was "
        f"{_hours_ago(problem.proof_age)}, within the 24-hour limit, so only the backend checks "
        "ran."
    )


def _refused_backend_check(target: str, problem: _OwnershipProblem) -> ScanReport:
    reason = problem.reason
    if problem.proof_age is not None:
        assert problem.blocked_by is not None  # noqa: S101
        reason = (
            f"{bot_protection_label(problem.blocked_by)} blocked our request for your "
            "verification file, and your last successful verification is more than 24 hours "
            "old, so the backend checks did not run. Your domain is still verified."
        )
    return ScanReport(
        hostname=target,
        status=ScanStatus.INCOMPLETE,
        incomplete_reason=reason,
        score=None,
        grade=None,
        grade_cap_reason=None,
        score_label=None,
        findings=[],
        skipped=[],
        blocked_by=problem.blocked_by,
    )


@celery_app.task(name="scans.run_backends")
def run_backend_check(scan_id: str) -> None:
    """Check confirmed backends only. Apart from re-proving ownership, the site isn't contacted."""
    job_id = UUID(scan_id)
    target = _claim_scan(job_id)
    if target is None:
        return

    total = initial_backend_progress()["total"]
    finished: list[str] = []

    def on_step(step: str) -> None:
        _update_running(job_id, progress_json=_progress(len(finished), total, step, finished))
        finished.append(step)

    try:
        on_step(OWNERSHIP_STEP)
        problem = _ownership_problem(job_id)
        if problem is not None and not _may_use_recent_proof(problem):
            report = _refused_backend_check(target, problem)
        else:
            on_step(BAAS_PROBE_STEP)
            context = probe_confirmed_backends(
                ScanContext(hostname=target), _confirmed_backends(job_id)
            )
            report = run_backend_checks(
                context,
                BACKEND_CHECK_IDS,
                on_step=on_step,
                verification_note=_recent_proof_note(problem) if problem else None,
            )
        _save_report(job_id, report, total, finished)
    except Exception as exc:
        # Security: only the error type is logged, since the message could echo a response.
        logger.error("backend check %s failed: %s", scan_id, type(exc).__name__)
        _update_running(job_id, status=ScanJobStatus.FAILED, finished_at=utc_now())


@celery_app.task(name="scans.run_full")
def run_full_scan(scan_id: str) -> None:
    """Run the passive and active checks on a verified domain the scan's owner controls."""
    job_id = UUID(scan_id)
    target = _claim_scan(job_id)
    if target is None:
        return

    total = initial_full_progress()["total"]
    finished: list[str] = []

    def on_step(step: str) -> None:
        _update_running(job_id, progress_json=_progress(len(finished), total, step, finished))
        finished.append(step)

    try:
        on_step(OWNERSHIP_STEP)
        problem = _ownership_problem(job_id)
        if problem is not None and problem.blocked_by is not None:
            # Security: the verification file was challenged, so the scan ends here and
            # sends this site nothing more.
            context = ScanContext(
                hostname=target,
                skip_reasons=dict.fromkeys(Input, problem.reason),
                blocked_by=problem.blocked_by,
            )
        else:
            context = collect_context(target, on_step=on_step)
        # Scripts come first. A burst of requests for sensitive paths can set off a site's
        # bot protection, which would then block the ordinary script requests too.
        on_step(BAAS_STEP)
        if not problem:
            context = discover_backends(context)
            _remember_backends(job_id, context.baas)
        on_step(PROBE_STEP)
        context = without_probes(context, problem.reason) if problem else attach_probes(context)
        on_step(BAAS_PROBE_STEP)
        if not problem:
            context = probe_backends(context, _confirmed_backends(job_id))
            context = mark_public_tables(context, _public_tables(job_id))
            _remember_tables(job_id, context.baas_probes)
        # After a problem there are no probes, so the active checks report skipped, not passed.
        report = run_checks(context, on_step=on_step, allow_active=True)
        _save_report(job_id, report, total, finished)
    except Exception as exc:
        # Security: only the error type is logged, since the message could echo site content.
        logger.error("scan %s failed: %s", scan_id, type(exc).__name__)
        _update_running(job_id, status=ScanJobStatus.FAILED, finished_at=utc_now())


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
