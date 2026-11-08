from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks import runner
from app.checks.base import Category, Finding, ScanContext, Severity
from app.checks.catalog import CATALOG
from app.checks.collector import COLLECT_STEPS
from app.checks.registry import CheckSpec
from app.checks.runner import ScanStatus, selected_checks
from app.models.scan import FindingRecord, Scan, ScanJobStatus, ScanMode, TargetType
from app.workers import celery_app as celery_module
from app.workers import tasks
from app.workers.tasks import initial_quick_progress, run_quick_scan
from tests.checks.helpers import response


def add_scan(engine: Engine, **overrides: Any) -> UUID:
    fields: dict[str, Any] = {
        "target_type": TargetType.WEB,
        "target": "example.com",
        "mode": ScanMode.QUICK,
        "progress_json": initial_quick_progress(),
    }
    with Session(engine) as session:
        scan = Scan(**(fields | overrides))
        session.add(scan)
        session.commit()
        return scan.id


def load(engine: Engine, scan_id: UUID) -> Scan:
    with Session(engine) as session:
        return session.get_one(Scan, scan_id)


def fake_collect(hostname: str, *, on_step: Any = None) -> ScanContext:
    for step in COLLECT_STEPS:
        on_step(step)
    return ScanContext(hostname=hostname, https=response(), homepage_via_http=False)


@pytest.fixture
def collected(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    hosts: list[str] = []

    def collect(hostname: str, *, on_step: Any = None) -> ScanContext:
        hosts.append(hostname)
        return fake_collect(hostname, on_step=on_step)

    monkeypatch.setattr(tasks, "collect_context", collect)
    return hosts


def findings_of(engine: Engine, scan_id: UUID) -> list[FindingRecord]:
    with Session(engine) as session:
        return list(session.exec(select(FindingRecord).where(FindingRecord.scan_id == scan_id)))


def test_scan_saves_report_and_findings(db_engine: Engine, collected: list[str]) -> None:
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    scan = load(db_engine, scan_id)
    assert collected == ["example.com"]
    assert scan.status is ScanJobStatus.DONE
    assert scan.result_status in {ScanStatus.COMPLETE, ScanStatus.PARTIAL}
    assert scan.score is not None
    assert scan.grade is not None
    assert scan.started_at is not None
    assert scan.finished_at is not None
    assert findings_of(db_engine, scan_id)


def test_progress_is_written_for_every_step(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = add_scan(db_engine)
    writes: list[dict[str, Any]] = []
    real_update = tasks._update_running

    def spy(job_id: UUID, **values: Any) -> None:
        writes.append(values["progress_json"])
        real_update(job_id, **values)

    monkeypatch.setattr(tasks, "_update_running", spy)

    run_quick_scan(str(scan_id))

    total = len(COLLECT_STEPS) + len(selected_checks())
    assert [write["completed"] for write in writes] == list(range(total))
    assert {write["total"] for write in writes} == {total}
    assert [write["current"] for write in writes[:4]] == list(COLLECT_STEPS)
    final = load(db_engine, scan_id).progress_json
    assert (final["completed"], final["total"], final["current"]) == (total, total, None)
    assert [step["name"] for step in final["steps"]] == [
        *COLLECT_STEPS,
        *(spec.check_id for spec in selected_checks()),
    ]
    assert {step["status"] for step in final["steps"]} == {"done"}


def test_step_log_keeps_earlier_steps_and_marks_only_the_current_one_running(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = add_scan(db_engine)
    writes: list[dict[str, Any]] = []
    real_update = tasks._update_running

    def spy(job_id: UUID, **values: Any) -> None:
        writes.append(values["progress_json"])
        real_update(job_id, **values)

    monkeypatch.setattr(tasks, "_update_running", spy)

    run_quick_scan(str(scan_id))

    for index, write in enumerate(writes):
        assert len(write["steps"]) == index + 1
        assert write["steps"][-1] == {"name": write["current"], "status": "running"}
        assert all(step["status"] == "done" for step in write["steps"][:-1])


def test_progress_never_contains_results(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = add_scan(db_engine)
    writes: list[dict[str, Any]] = []
    real_update = tasks._update_running

    def spy(job_id: UUID, **values: Any) -> None:
        writes.append(values["progress_json"])
        real_update(job_id, **values)

    monkeypatch.setattr(tasks, "_update_running", spy)

    run_quick_scan(str(scan_id))

    writes.append(load(db_engine, scan_id).progress_json)
    assert all(set(write) == {"completed", "total", "current", "steps"} for write in writes)
    # Security: each step says only that it ran. Checks that did and didn't produce a
    # finding must look identical here, or the log would reveal hidden findings.
    for write in writes:
        for step in write["steps"]:
            assert set(step) == {"name", "status"}
            assert step["status"] in {"done", "running"}


def test_step_log_is_the_same_whether_or_not_a_check_found_something(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    check_id = next(iter(CATALOG))
    finding = Finding(
        check_id=check_id,
        category=Category.TLS,
        severity=Severity.CRITICAL,
        title=CATALOG[check_id].title,
        evidence="evidence text",
        fix=CATALOG[check_id].fix,
    )

    def run_with(result: Finding | None) -> list[dict[str, str]]:
        spec = CheckSpec(check_id, Category.TLS, lambda _ctx: result, frozenset())
        monkeypatch.setattr(runner, "all_checks", lambda: [spec])
        scan_id = add_scan(db_engine)
        run_quick_scan(str(scan_id))
        return load(db_engine, scan_id).progress_json["steps"]

    assert run_with(finding) == run_with(None)


def test_scan_that_is_not_queued_does_not_run(db_engine: Engine, collected: list[str]) -> None:
    scan_id = add_scan(db_engine, status=ScanJobStatus.RUNNING)

    run_quick_scan(str(scan_id))

    assert collected == []
    assert load(db_engine, scan_id).status is ScanJobStatus.RUNNING


def test_redelivered_task_does_not_scan_twice(db_engine: Engine, collected: list[str]) -> None:
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))
    run_quick_scan(str(scan_id))

    assert collected == ["example.com"]


def test_crash_marks_scan_failed_and_logs_only_the_error_type(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(_hostname: str, *, on_step: Any = None) -> ScanContext:
        raise RuntimeError("secret-from-site")

    monkeypatch.setattr(tasks, "collect_context", boom)
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    assert load(db_engine, scan_id).status is ScanJobStatus.FAILED
    assert "RuntimeError" in caplog.text
    assert "secret-from-site" not in caplog.text


def test_expired_scan_is_not_overwritten_by_a_late_worker(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_id = add_scan(db_engine)

    def expire_midway(hostname: str, *, on_step: Any = None) -> ScanContext:
        with Session(db_engine) as session:
            scan = session.get_one(Scan, scan_id)
            scan.status = ScanJobStatus.FAILED
            session.add(scan)
            session.commit()
        return fake_collect(hostname, on_step=on_step)

    monkeypatch.setattr(tasks, "collect_context", expire_midway)

    run_quick_scan(str(scan_id))

    assert load(db_engine, scan_id).status is ScanJobStatus.FAILED
    assert findings_of(db_engine, scan_id) == []


def test_quick_scan_never_runs_active_checks(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[str] = []

    def active_check(_ctx: ScanContext) -> Finding | None:
        ran.append("active")
        return None

    check_id = next(iter(CATALOG))
    spec = CheckSpec(check_id, Category.TLS, active_check, frozenset(), active=True)
    monkeypatch.setattr(runner, "all_checks", lambda: [spec])
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    assert ran == []
    assert load(db_engine, scan_id).status is ScanJobStatus.DONE


def test_findings_keep_severity_from_the_report(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    check_id = next(iter(CATALOG))
    finding = Finding(
        check_id=check_id,
        category=Category.TLS,
        severity=Severity.HIGH,
        title=CATALOG[check_id].title,
        evidence="evidence text",
        fix=CATALOG[check_id].fix,
    )
    spec = CheckSpec(check_id, Category.TLS, lambda _ctx: finding, frozenset())
    monkeypatch.setattr(runner, "all_checks", lambda: [spec])
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    [record] = findings_of(db_engine, scan_id)
    assert record.severity is Severity.HIGH
    assert record.evidence_masked == "evidence text"


def test_celery_only_accepts_json() -> None:
    conf = celery_module.celery_app.conf
    assert conf.task_serializer == "json"
    assert list(conf.accept_content) == ["json"]
