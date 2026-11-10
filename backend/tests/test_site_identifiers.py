"""What a site scan saves so its backends can be matched to a repo's."""

from uuid import UUID

from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks.baas import supabase_service_key
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    DiscoveredBackend,
    ExposedServiceKey,
    ScanContext,
)
from app.checks.runner import ScanReport, ScanStatus
from app.models import DomainBackend, DomainFirebaseProject, FindingRecord, Scan
from app.models.scan import ScanJobStatus, ScanMode, TargetType, utc_now
from app.workers.tasks import _remember_backends, _save_report
from tests.test_correlation_models import REF, World, seed

HOST = "my-app-default-rtdb.firebaseio.com"


def add_site_scan(engine: Engine, world: World) -> UUID:
    with Session(engine) as session:
        scan = Scan(
            owner_id=world.owner,
            domain_id=world.domain,
            target_type=TargetType.WEB,
            target="example.com",
            mode=ScanMode.FULL,
            status=ScanJobStatus.RUNNING,
        )
        session.add(scan)
        session.commit()
        return scan.id


def discovery(*backends: DiscoveredBackend, **overrides: object) -> BaasDiscovery:
    fields: dict[str, object] = {
        "backends": backends,
        "exposed_keys": (),
        "scripts_total": 1,
        "scripts_read": 1,
        "scripts_failed": 0,
    }
    return BaasDiscovery(**(fields | overrides))


def rtdb(project: str | None) -> DiscoveredBackend:
    return DiscoveredBackend(BaasKind.FIREBASE_RTDB, HOST, project)


def saved_backend(engine: Engine) -> DomainBackend:
    with Session(engine) as session:
        return session.exec(select(DomainBackend)).one()


def test_a_new_backend_keeps_its_project_id(db_engine: Engine) -> None:
    scan_id = add_site_scan(db_engine, seed(db_engine))

    _remember_backends(scan_id, discovery(rtdb("my-app")))

    assert saved_backend(db_engine).firebase_project_id == "my-app"


def test_a_known_backend_gets_its_project_id_and_stays_confirmed(db_engine: Engine) -> None:
    world = seed(db_engine)
    confirmed = utc_now()
    with Session(db_engine) as session:
        session.add(
            DomainBackend(
                domain_id=world.domain,
                kind=BaasKind.FIREBASE_RTDB,
                identifier=HOST,
                confirmed_at=confirmed,
            )
        )
        session.commit()

    _remember_backends(add_site_scan(db_engine, world), discovery(rtdb("my-app")))

    saved = saved_backend(db_engine)
    assert saved.firebase_project_id == "my-app"
    assert saved.confirmed_at is not None


def test_a_scan_that_could_not_read_the_project_does_not_clear_it(db_engine: Engine) -> None:
    world = seed(db_engine)
    _remember_backends(add_site_scan(db_engine, world), discovery(rtdb("my-app")))

    _remember_backends(add_site_scan(db_engine, world), discovery(rtdb(None)))

    assert saved_backend(db_engine).firebase_project_id == "my-app"


def test_a_service_key_finding_is_saved_with_its_project(db_engine: Engine) -> None:
    scan_id = add_site_scan(db_engine, seed(db_engine))
    key = ExposedServiceKey("eyJ****", "/app.js", REF)
    finding = supabase_service_key(
        ScanContext(hostname="example.com", baas=discovery(exposed_keys=(key,)))
    )
    assert finding is not None
    report = ScanReport(
        hostname="example.com",
        status=ScanStatus.COMPLETE,
        incomplete_reason=None,
        score=75,
        grade="D",
        grade_cap_reason=None,
        score_label=None,
        findings=[finding],
        skipped=[],
    )

    _save_report(scan_id, report, 1, [])

    with Session(db_engine) as session:
        saved = session.exec(select(FindingRecord)).one()
    assert saved.backend_identifier == REF
    assert saved.evidence_masked.count("eyJ****") == 1


def saved_projects(engine: Engine) -> list[DomainFirebaseProject]:
    with Session(engine) as session:
        return list(session.exec(select(DomainFirebaseProject)))


def test_a_site_with_only_a_project_id_saves_it(db_engine: Engine) -> None:
    scan_id = add_site_scan(db_engine, seed(db_engine))

    _remember_backends(scan_id, discovery(firebase_project_ids=("my-app",)))

    assert [row.project_id for row in saved_projects(db_engine)] == ["my-app"]
    with Session(db_engine) as session:
        # Nothing the owner could confirm, so nothing that could be probed.
        assert list(session.exec(select(DomainBackend))) == []


def test_seeing_a_project_id_again_keeps_one_row_and_its_first_seen(db_engine: Engine) -> None:
    world = seed(db_engine)
    found = discovery(firebase_project_ids=("my-app",))
    _remember_backends(add_site_scan(db_engine, world), found)
    first = saved_projects(db_engine)[0].first_seen_at

    _remember_backends(add_site_scan(db_engine, world), found)

    rows = saved_projects(db_engine)
    assert len(rows) == 1
    assert rows[0].first_seen_at == first
