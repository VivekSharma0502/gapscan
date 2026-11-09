from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks import active_collector, runner
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BotProtection,
    Category,
    DiscoveredBackend,
    Finding,
    ScanContext,
    Severity,
)
from app.checks.catalog import CATALOG
from app.checks.collector import COLLECT_STEPS
from app.checks.ownership import (
    FailureCode,
    MethodFailure,
    OwnershipResult,
    VerificationMethod,
)
from app.checks.registry import CheckSpec
from app.checks.runner import ScanStatus, selected_checks
from app.models.domain import Domain, DomainBackend
from app.models.profile import Profile
from app.models.scan import FindingRecord, Scan, ScanJobStatus, ScanMode, TargetType, utc_now
from app.workers import celery_app as celery_module
from app.workers import tasks
from app.workers.tasks import (
    initial_full_progress,
    initial_quick_progress,
    run_full_scan,
    run_quick_scan,
)
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


# Full scans: active checks run only after ownership is confirmed


SECRET_VALUE = "sk_live_super_secret"  # noqa: S105


class ProbeNet:
    """Stands in for the probing client, and records every path requested."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    def __call__(self, url: str, **_kwargs: Any) -> Any:
        self.urls.append(url)
        if url.endswith("/.env"):
            return response(body=f"API_KEY={SECRET_VALUE}\n".encode())
        return response(status=404)


@pytest.fixture
def probe_net(monkeypatch: pytest.MonkeyPatch) -> ProbeNet:
    fake = ProbeNet()
    monkeypatch.setattr(active_collector, "safe_get", fake)
    return fake


def add_domain(engine: Engine, owner: UUID, *, verified: bool = True, hostname: str = "") -> UUID:
    with Session(engine) as session:
        session.add(Profile(id=owner))
        domain = Domain(
            owner_id=owner,
            hostname=hostname or "example.com",
            verify_token="tok",  # noqa: S106
            verified_at=utc_now() if verified else None,
        )
        session.add(domain)
        session.commit()
        return domain.id


def add_full(engine: Engine, owner: UUID, domain_id: UUID | None) -> UUID:
    return add_scan(
        engine,
        owner_id=owner,
        domain_id=domain_id,
        mode=ScanMode.FULL,
        progress_json=initial_full_progress(),
    )


def proof(monkeypatch: pytest.MonkeyPatch, result: OwnershipResult) -> list[str]:
    calls: list[str] = []

    def prove(hostname: str, _token: str, **_kwargs: Any) -> OwnershipResult:
        calls.append(hostname)
        return result

    monkeypatch.setattr(tasks, "prove_ownership", prove)
    return calls


GONE = OwnershipResult(
    None,
    (
        MethodFailure(VerificationMethod.DNS, FailureCode.TXT_NOT_FOUND, "no", True),
        MethodFailure(VerificationMethod.FILE, FailureCode.FILE_MISSING, "no", True),
    ),
)
UNKNOWN = OwnershipResult(
    None,
    (
        MethodFailure(VerificationMethod.DNS, FailureCode.TXT_NOT_FOUND, "no", True),
        MethodFailure(VerificationMethod.FILE, FailureCode.FILE_UNREACHABLE, "down", False),
    ),
)
PROVEN = OwnershipResult(VerificationMethod.DNS)


def active_skips(engine: Engine, scan_id: UUID) -> list[dict[str, Any]]:
    return [
        item
        for item in load(engine, scan_id).skipped_json
        if item["check_id"].startswith("exposure.")
    ]


@pytest.mark.usefixtures("collected")
def test_full_scan_probes_and_saves_masked_findings(
    db_engine: Engine, probe_net: ProbeNet, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = proof(monkeypatch, PROVEN)
    owner = uuid4()
    scan_id = add_full(db_engine, owner, add_domain(db_engine, owner))

    run_full_scan(str(scan_id))

    scan = load(db_engine, scan_id)
    assert scan.status is ScanJobStatus.DONE
    assert calls == ["example.com"]
    assert "https://example.com/.env" in probe_net.urls
    finding = next(
        item for item in findings_of(db_engine, scan_id) if item.check_id == "exposure.env_file"
    )
    assert "API_KEY" in finding.evidence_masked
    # Security: the value must not survive anywhere in what was saved.
    saved = " ".join(item.evidence_masked for item in findings_of(db_engine, scan_id))
    assert SECRET_VALUE not in saved
    assert SECRET_VALUE not in str(scan.progress_json)
    assert SECRET_VALUE not in str(scan.skipped_json)


@pytest.mark.usefixtures("collected")
def test_full_scan_progress_reaches_its_total(
    db_engine: Engine, probe_net: ProbeNet, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    owner = uuid4()
    scan_id = add_full(db_engine, owner, add_domain(db_engine, owner))

    run_full_scan(str(scan_id))

    progress = load(db_engine, scan_id).progress_json
    assert progress["completed"] == progress["total"]
    assert len(progress["steps"]) == progress["total"]
    assert progress["steps"][0]["name"] == tasks.OWNERSHIP_STEP


@pytest.mark.usefixtures("collected")
def test_proof_gone_means_no_probes_and_unverifies(
    db_engine: Engine, probe_net: ProbeNet, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, GONE)
    owner = uuid4()
    domain_id = add_domain(db_engine, owner)
    scan_id = add_full(db_engine, owner, domain_id)

    run_full_scan(str(scan_id))

    assert probe_net.urls == []
    with Session(db_engine) as session:
        assert session.get_one(Domain, domain_id).verified_at is None
    skips = active_skips(db_engine, scan_id)
    assert len(skips) == 6
    assert "marked unverified" in skips[0]["reason"]
    assert load(db_engine, scan_id).score_label is not None


@pytest.mark.usefixtures("collected")
def test_temporary_proof_failure_skips_probes_but_stays_verified(
    db_engine: Engine, probe_net: ProbeNet, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, UNKNOWN)
    owner = uuid4()
    domain_id = add_domain(db_engine, owner)
    scan_id = add_full(db_engine, owner, domain_id)

    run_full_scan(str(scan_id))

    assert probe_net.urls == []
    with Session(db_engine) as session:
        assert session.get_one(Domain, domain_id).verified_at is not None
    assert "re-confirm" in active_skips(db_engine, scan_id)[0]["reason"]


@pytest.mark.usefixtures("collected")
@pytest.mark.parametrize("problem", ["unverified", "other_owner", "wrong_host", "no_domain"])
def test_worker_refuses_to_probe_without_a_matching_verified_domain(
    db_engine: Engine, probe_net: ProbeNet, monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    # Security: the worker doesn't rely on the API having checked.
    calls = proof(monkeypatch, PROVEN)
    owner = uuid4()
    domain_id: UUID | None = add_domain(
        db_engine,
        owner if problem != "other_owner" else uuid4(),
        verified=problem != "unverified",
        hostname="other.com" if problem == "wrong_host" else "",
    )
    if problem == "other_owner":
        with Session(db_engine) as session:
            session.add(Profile(id=owner))
            session.commit()
    if problem == "no_domain":
        domain_id = None
    scan_id = add_full(db_engine, owner, domain_id)

    run_full_scan(str(scan_id))

    assert probe_net.urls == []
    assert calls == []
    assert "isn't verified" in active_skips(db_engine, scan_id)[0]["reason"]


@pytest.mark.usefixtures("collected")
def test_quick_scan_sends_no_probes(db_engine: Engine, probe_net: ProbeNet) -> None:
    # Security: the hard rule. Quick scans run on domains nobody has verified.
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    assert probe_net.urls == []
    assert active_skips(db_engine, scan_id) == []


@pytest.mark.usefixtures("collected")
def test_full_scan_failure_is_recorded(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, probe_net: ProbeNet
) -> None:
    def boom(_hostname: str, _token: str, **_kwargs: Any) -> OwnershipResult:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(tasks, "prove_ownership", boom)
    owner = uuid4()
    scan_id = add_full(db_engine, owner, add_domain(db_engine, owner))

    run_full_scan(str(scan_id))

    assert load(db_engine, scan_id).status is ScanJobStatus.FAILED
    assert probe_net.urls == []


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


def test_capped_grade_and_reason_are_saved_with_the_uncapped_score(
    db_engine: Engine, collected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    check_id = "tls.no_https"
    finding = Finding(
        check_id=check_id,
        category=Category.TLS,
        severity=Severity.CRITICAL,
        title=CATALOG[check_id].title,
        evidence="evidence text",
        fix=CATALOG[check_id].fix,
    )
    spec = CheckSpec(check_id, Category.TLS, lambda _ctx: finding, frozenset())
    monkeypatch.setattr(runner, "all_checks", lambda: [spec])
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    scan = load(db_engine, scan_id)
    assert (scan.score, scan.grade) == (75, "F")
    assert scan.grade_cap_reason == "Capped at F: site doesn't offer HTTPS"


@pytest.mark.usefixtures("collected", "probe_net")
@pytest.mark.parametrize("legacy", [True, False])
def test_recheck_accepts_old_names_only_for_existing_domains(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, legacy: bool
) -> None:
    # Otherwise the rename would unverify every older domain at its next full scan.
    seen: list[bool] = []

    def prove(_hostname: str, _token: str, *, accept_legacy: bool = False) -> OwnershipResult:
        seen.append(accept_legacy)
        return PROVEN

    monkeypatch.setattr(tasks, "prove_ownership", prove)
    owner = uuid4()
    domain_id = add_domain(db_engine, owner)
    with Session(db_engine) as session:
        session.get_one(Domain, domain_id).accepts_legacy_verify_names = legacy
        session.commit()

    run_full_scan(str(add_full(db_engine, owner, domain_id)))

    assert seen == [legacy]


def test_celery_only_accepts_json() -> None:
    conf = celery_module.celery_app.conf
    assert conf.task_serializer == "json"
    assert list(conf.accept_content) == ["json"]


# --- backends named in a site's code ---

RTDB = DiscoveredBackend(BaasKind.FIREBASE_RTDB, "my-app.firebaseio.com")
SUPABASE = DiscoveredBackend(BaasKind.SUPABASE, "abcdefghijklmnopqrst")


def discovery(*backends: DiscoveredBackend) -> Any:
    def discover(ctx: ScanContext) -> ScanContext:
        return replace(ctx, baas=BaasDiscovery(backends, (), 1, 1, 0))

    return discover


def saved_backends(engine: Engine) -> list[DomainBackend]:
    with Session(engine) as session:
        return list(session.exec(select(DomainBackend)))


@pytest.mark.usefixtures("collected", "probe_net")
def test_full_scan_remembers_backends_as_unconfirmed(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    monkeypatch.setattr(tasks, "discover_backends", discovery(RTDB, SUPABASE))
    owner = uuid4()
    domain = add_domain(db_engine, owner)

    run_full_scan(str(add_full(db_engine, owner, domain)))

    rows = saved_backends(db_engine)
    assert {(row.kind, row.identifier) for row in rows} == {
        (RTDB.kind, RTDB.identifier),
        (SUPABASE.kind, SUPABASE.identifier),
    }
    assert all(row.domain_id == domain and row.confirmed_at is None for row in rows)


@pytest.mark.usefixtures("collected", "probe_net")
def test_rescan_keeps_a_confirmation_and_first_seen(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    monkeypatch.setattr(tasks, "discover_backends", discovery(SUPABASE))
    owner = uuid4()
    domain = add_domain(db_engine, owner)
    run_full_scan(str(add_full(db_engine, owner, domain)))
    with Session(db_engine) as session:
        row = session.exec(select(DomainBackend)).one()
        row.confirmed_at = utc_now()
        session.add(row)
        session.commit()
        confirmed_at, first_seen = row.confirmed_at, row.first_seen_at

    run_full_scan(str(add_full(db_engine, owner, domain)))

    rows = saved_backends(db_engine)
    assert len(rows) == 1
    assert rows[0].confirmed_at == confirmed_at
    assert rows[0].first_seen_at == first_seen


@pytest.mark.usefixtures("collected", "probe_net")
@pytest.mark.parametrize("result", [GONE, UNKNOWN])
def test_no_discovery_without_proven_ownership(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, result: OwnershipResult
) -> None:
    proof(monkeypatch, result)

    def must_not_run(_ctx: ScanContext) -> ScanContext:
        raise AssertionError("discovery ran without proven ownership")

    monkeypatch.setattr(tasks, "discover_backends", must_not_run)
    owner = uuid4()
    scan_id = add_full(db_engine, owner, add_domain(db_engine, owner))

    run_full_scan(str(scan_id))

    assert load(db_engine, scan_id).status is ScanJobStatus.DONE
    assert saved_backends(db_engine) == []


@pytest.mark.usefixtures("collected")
def test_quick_scan_never_discovers(db_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_run(_ctx: ScanContext) -> ScanContext:
        raise AssertionError("discovery ran in a quick scan")

    monkeypatch.setattr(tasks, "discover_backends", must_not_run)
    scan_id = add_scan(db_engine)

    run_quick_scan(str(scan_id))

    assert load(db_engine, scan_id).status is ScanJobStatus.DONE


# --- probing confirmed backends ---


class RecordingProbe:
    def __init__(self) -> None:
        self.confirmed: list[set[DiscoveredBackend]] = []

    def __call__(self, ctx: ScanContext, confirmed: Any) -> ScanContext:
        self.confirmed.append(set(confirmed))
        return ctx


def set_confirmed(engine: Engine, identifier: str) -> None:
    with Session(engine) as session:
        row = session.exec(
            select(DomainBackend).where(DomainBackend.identifier == identifier)
        ).one()
        row.confirmed_at = utc_now()
        session.add(row)
        session.commit()


@pytest.mark.usefixtures("collected", "probe_net")
def test_only_confirmed_backends_are_passed_to_the_probes(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, PROVEN)
    monkeypatch.setattr(tasks, "discover_backends", discovery(RTDB, SUPABASE))
    recorder = RecordingProbe()
    monkeypatch.setattr(tasks, "probe_backends", recorder)
    owner = uuid4()
    domain = add_domain(db_engine, owner)
    run_full_scan(str(add_full(db_engine, owner, domain)))
    assert recorder.confirmed == [set()]

    set_confirmed(db_engine, RTDB.identifier)
    run_full_scan(str(add_full(db_engine, owner, domain)))

    assert recorder.confirmed[1] == {RTDB}


@pytest.mark.usefixtures("collected", "probe_net")
@pytest.mark.parametrize("result", [GONE, UNKNOWN])
def test_no_probes_without_proven_ownership(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch, result: OwnershipResult
) -> None:
    proof(monkeypatch, result)

    def must_not_run(_ctx: ScanContext, _confirmed: Any) -> ScanContext:
        raise AssertionError("probes ran without proven ownership")

    monkeypatch.setattr(tasks, "probe_backends", must_not_run)
    owner = uuid4()
    scan_id = add_full(db_engine, owner, add_domain(db_engine, owner))

    run_full_scan(str(scan_id))

    assert load(db_engine, scan_id).status is ScanJobStatus.DONE


@pytest.mark.usefixtures("collected")
def test_scripts_are_read_before_any_sensitive_path_is_requested(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression: the burst of probes set off Vercel's checkpoint, which then blocked app.js.
    proof(monkeypatch, PROVEN)
    calls: list[str] = []

    def discover(ctx: ScanContext) -> ScanContext:
        calls.append("scripts")
        return ctx

    def attach(ctx: ScanContext) -> ScanContext:
        calls.append("probes")
        return ctx

    monkeypatch.setattr(tasks, "discover_backends", discover)
    monkeypatch.setattr(tasks, "attach_probes", attach)
    owner = uuid4()

    run_full_scan(str(add_full(db_engine, owner, add_domain(db_engine, owner))))

    assert calls == ["scripts", "probes"]


# --- naming the platform in a report ---

BLOCKED_FILE = OwnershipResult(
    None,
    (
        MethodFailure(VerificationMethod.DNS, FailureCode.TXT_NOT_FOUND, "no", True),
        MethodFailure(
            VerificationMethod.FILE,
            FailureCode.FILE_BLOCKED,
            "blocked",
            False,
            BotProtection.VERCEL,
        ),
    ),
)


@pytest.mark.usefixtures("collected", "probe_net")
def test_blocked_verification_file_says_so_and_keeps_the_domain_verified(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, BLOCKED_FILE)
    owner = uuid4()
    domain_id = add_domain(db_engine, owner)
    scan_id = add_full(db_engine, owner, domain_id)

    run_full_scan(str(scan_id))

    scan = load(db_engine, scan_id)
    reasons = {item["reason"] for item in active_skips(db_engine, scan_id)}
    assert len(reasons) == 1
    reason = reasons.pop()
    assert "Vercel's bot protection blocked our request for your verification file" in reason
    assert "couldn't re-confirm" not in reason
    assert scan.blocked_by is BotProtection.VERCEL
    with Session(db_engine) as session:
        assert session.get_one(Domain, domain_id).verified_at is not None


@pytest.mark.usefixtures("collected", "probe_net")
def test_ordinary_failure_to_reconfirm_keeps_its_wording(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    proof(monkeypatch, UNKNOWN)
    owner = uuid4()
    scan_id = add_full(db_engine, owner, add_domain(db_engine, owner))

    run_full_scan(str(scan_id))

    assert load(db_engine, scan_id).blocked_by is None
    assert all("couldn't re-confirm" in i["reason"] for i in active_skips(db_engine, scan_id))
