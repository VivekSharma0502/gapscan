"""Supabase discovery and read-only probes. Offline: requests are faked."""

import base64
import inspect
import json
import os
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks import baas_collector, baas_probes
from app.checks.baas import (
    supabase_table_readable,
    supabase_tables_checked,
    supabase_tables_public,
)
from app.checks.baas_collector import MAX_TABLES, discover_backends
from app.checks.baas_discovery import find_anon_keys, find_publishable_keys, find_table_names
from app.checks.baas_probes import mark_public_tables, probe_backends, probe_confirmed_backends
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BaasProbes,
    DiscoveredBackend,
    ScanContext,
    Severity,
    SkipCheck,
    SupabaseAccess,
    SupabaseProbe,
    TableAccess,
    TableProbe,
)
from app.checks.catalog import CATALOG
from app.checks.ownership import OwnershipResult, VerificationMethod
from app.checks.runner import run_checks
from app.core.safe_http import RequestFailedError, SafeResponse
from app.models.domain import Domain, DomainBackend, DomainBackendTable
from app.models.profile import Profile
from app.models.scan import FindingRecord, Scan, ScanMode, TargetType, utc_now
from app.workers import tasks
from app.workers.tasks import initial_full_progress, run_full_scan
from tests.checks.helpers import response

REF = "abcdefghijklmnopqrst"
OTHER_REF = "tsrqponmlkjihgfedcba"
PROJECT = DiscoveredBackend(BaasKind.SUPABASE, REF)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# Built at run time, so nothing secret-shaped is ever committed to this repo.
def make_jwt(**claims: Any) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.{b64url(os.urandom(32))}"


def anon_key(ref: str = REF) -> str:
    return make_jwt(iss="supabase", ref=ref, role="anon")


def service_key(ref: str = REF) -> str:
    return make_jwt(iss="supabase", ref=ref, role="service_role")


def publishable_key() -> str:
    return "sb_" + "publishable_" + "y" * 32


def script(key: str, *tables: str, ref: str = REF) -> bytes:
    calls = ";".join(f'db.from("{name}").select("*")' for name in tables)
    return f'const db=createClient("https://{ref}.supabase.co","{key}");{calls};'.encode()


# --- finding table names and keys ---


@pytest.mark.parametrize(
    "code",
    [
        'supabase.from("todos")',
        "e.from('todos')",
        "client.from(`todos`)",
        'x.from( "todos" )',
        '\\"x.from(\\"todos\\")\\"',
    ],
)
def test_table_names_are_found(code: str) -> None:
    assert find_table_names(code) == {"todos"}


@pytest.mark.parametrize(
    "code",
    [
        'Array.from("abc")',
        'Buffer.from("abc")',
        'Uint8Array.from("abc")',
        'Object.from("abc")',
        'supabase.storage.from("avatars")',
        'x.from("bad name")',
        'x.from("1starts_with_digit")',
        'x.from("a;drop")',
        "x.from(variable)",
    ],
)
def test_things_that_are_not_tables_are_ignored(code: str) -> None:
    assert find_table_names(code) == set()


def test_anon_key_is_tied_to_its_project() -> None:
    key = anon_key()

    assert find_anon_keys(f'"{key}"') == {REF: key}


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "supabase", "ref": REF, "role": "service_role"},
        {"iss": "supabase", "ref": REF, "role": "authenticated"},
        {"iss": "someone-else", "ref": REF, "role": "anon"},
        {"iss": "supabase", "role": "anon"},
    ],
)
def test_only_a_supabase_anon_key_counts(claims: dict[str, str]) -> None:
    assert find_anon_keys(make_jwt(**claims)) == {}


def test_publishable_key_is_found() -> None:
    assert find_publishable_keys(publishable_key()) == {publishable_key()}


def test_a_secret_key_is_not_a_publishable_key() -> None:
    assert find_publishable_keys("sb_" + "secret_" + "y" * 32) == set()


class FakeGet:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __call__(self, _url: str, **_kwargs: Any) -> SafeResponse:
        return response(body=self.body)


def discovered(monkeypatch: pytest.MonkeyPatch, body: bytes, *extra_refs: str) -> ScanContext:
    monkeypatch.setattr(baas_collector, "safe_get", FakeGet(body))
    inline = "".join(f'"https://{ref}.supabase.co"' for ref in extra_refs)
    html = f'<html><script>{inline}</script><script src="app.js"></script></html>'
    return discover_backends(
        ScanContext(
            hostname="example.com",
            https=response(url="https://example.com/", body=html.encode()),
        )
    )


def test_discovery_collects_access_and_table_names(monkeypatch: pytest.MonkeyPatch) -> None:
    key = anon_key()

    baas = discovered(monkeypatch, script(key, "todos", "notes")).baas

    assert baas is not None
    assert baas.table_names == ("notes", "todos")
    assert baas.supabase_access == (SupabaseAccess(REF, key, is_jwt=True),)


def test_keys_stay_out_of_the_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    key = anon_key()

    assert key not in repr(discovered(monkeypatch, script(key, "todos")).baas)


def test_a_service_key_is_never_available_to_the_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_value = service_key()

    baas = discovered(monkeypatch, script(secret_value, "todos")).baas

    assert baas is not None
    assert baas.supabase_access == ()
    assert len(baas.exposed_keys) == 1


def test_anon_key_is_chosen_over_a_service_key_on_the_same_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anon = anon_key()
    body = script(anon, "todos") + f'var s="{service_key()}";'.encode()

    baas = discovered(monkeypatch, body).baas

    assert baas is not None
    assert baas.supabase_access == (SupabaseAccess(REF, anon, is_jwt=True),)


def test_an_anon_key_for_another_project_is_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    baas = discovered(monkeypatch, script(anon_key(OTHER_REF), "todos")).baas

    assert baas is not None
    assert baas.supabase_access == ()


def test_publishable_key_is_used_for_a_single_project(monkeypatch: pytest.MonkeyPatch) -> None:
    baas = discovered(monkeypatch, script(publishable_key(), "todos")).baas

    assert baas is not None
    assert baas.supabase_access == (SupabaseAccess(REF, publishable_key(), is_jwt=False),)


def test_publishable_key_is_not_guessed_between_projects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baas = discovered(monkeypatch, script(publishable_key(), "todos"), OTHER_REF).baas

    assert baas is not None
    assert baas.supabase_access == ()


def test_table_names_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    names = [f"t{index}" for index in range(MAX_TABLES + 5)]

    baas = discovered(monkeypatch, script(anon_key(), *names)).baas

    assert baas is not None
    assert len(baas.table_names) == MAX_TABLES


# --- the probes ---

ROWS = {"content-range": "0-0/*"}
NO_ROWS = {"content-range": "*/*"}
ACCESS = SupabaseAccess(REF, "the-public-key", is_jwt=True)
PUBLISHABLE = SupabaseAccess(REF, "the-publishable-key", is_jwt=False)


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.answer: SafeResponse | Exception = response(headers=ROWS)

    def __call__(
        self, method: str, url: str, *, headers: dict[str, str], json_body: Any = None
    ) -> SafeResponse:
        self.calls.append({"method": method, "url": url, "headers": headers, "body": json_body})
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    fake = FakeApi()
    monkeypatch.setattr(baas_probes, "safe_api_request", fake)
    return fake


def found(
    *tables: str, access: tuple[SupabaseAccess, ...] = (ACCESS,), backend: Any = PROJECT
) -> ScanContext:
    return ScanContext(
        hostname="example.com",
        baas=BaasDiscovery((backend,), (), 1, 1, 0, supabase_access=access, table_names=tables),
    )


def probed(ctx: ScanContext, *confirmed: DiscoveredBackend) -> tuple[SupabaseProbe, ...]:
    result = probe_backends(ctx, set(confirmed)).baas_probes
    assert result is not None
    return result.supabase


def test_probe_is_a_head_request_for_at_most_one_row(api: FakeApi) -> None:
    probed(found("todos"), PROJECT)

    call = api.calls[0]
    assert call["method"] == "HEAD"
    assert call["url"] == f"https://{REF}.supabase.co/rest/v1/todos?select=*&limit=1"
    assert call["body"] is None


def test_anon_key_goes_in_both_headers(api: FakeApi) -> None:
    probed(found("todos"), PROJECT)

    assert api.calls[0]["headers"] == {
        "apikey": "the-public-key",
        "Authorization": "Bearer the-public-key",
    }


def test_publishable_key_is_not_sent_as_a_bearer_token(api: FakeApi) -> None:
    probed(found("todos", access=(PUBLISHABLE,)), PROJECT)

    assert api.calls[0]["headers"] == {"apikey": "the-publishable-key"}


def test_unconfirmed_project_is_never_contacted(api: FakeApi) -> None:
    assert probed(found("todos")) == ()
    assert api.calls == []


def test_the_module_never_writes() -> None:
    source = inspect.getsource(baas_probes)

    assert 'safe_api_request(\n            "HEAD"' in source
    for method in ('"POST"', '"PUT"', '"PATCH"', '"DELETE"'):
        assert method not in source


@pytest.mark.parametrize("ref", ["evil.example/x", "short", "UPPERCASEUPPERCASEUP", REF + "x"])
def test_a_tampered_project_ref_is_never_contacted(api: FakeApi, ref: str) -> None:
    backend = DiscoveredBackend(BaasKind.SUPABASE, ref)

    probed(found("todos", access=(SupabaseAccess(ref, "k", True),), backend=backend), backend)

    assert api.calls == []


@pytest.mark.parametrize("name", ["a/b", "../x", "a b", "a;b", ""])
def test_a_tampered_table_name_is_never_requested(api: FakeApi, name: str) -> None:
    probed(found(name), PROJECT)

    assert api.calls == []


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (200, ROWS, TableAccess.READABLE),
        (206, ROWS, TableAccess.READABLE),
        (200, NO_ROWS, TableAccess.NO_ROWS),
        (401, {}, TableAccess.REFUSED),
        (403, {}, TableAccess.REFUSED),
        (404, {}, TableAccess.NOT_FOUND),
        (200, {}, TableAccess.UNKNOWN),
        (500, {}, TableAccess.UNKNOWN),
        (300, {}, TableAccess.UNKNOWN),
    ],
)
def test_answers_are_read_correctly(
    api: FakeApi, status: int, headers: dict[str, str], expected: TableAccess
) -> None:
    api.answer = response(status=status, headers=headers)

    assert probed(found("todos"), PROJECT)[0].tables == (TableProbe("todos", expected),)


def test_network_failure_is_unknown(api: FakeApi) -> None:
    api.answer = RequestFailedError("down")

    assert probed(found("todos"), PROJECT)[0].tables[0].access is TableAccess.UNKNOWN


def test_rate_limiting_stops_the_rest(api: FakeApi) -> None:
    api.answer = response(status=429)

    tables = probed(found("a", "b", "c"), PROJECT)[0].tables

    assert len(api.calls) == 1
    assert all(table.access is TableAccess.UNKNOWN for table in tables)


def test_no_key_means_no_requests(api: FakeApi) -> None:
    project = probed(found("todos", access=()), PROJECT)[0]

    assert api.calls == []
    assert project.has_key is False


def test_check_backends_never_probes_supabase(api: FakeApi) -> None:
    # It doesn't read the site, so it has no key and no table names to work with.
    ctx = probe_confirmed_backends(ScanContext(hostname="example.com"), {PROJECT})

    assert api.calls == []
    assert ctx.baas_probes == BaasProbes()


def test_owner_choices_are_applied_per_project_and_table() -> None:
    ctx = ScanContext(
        hostname="example.com",
        baas_probes=BaasProbes(
            supabase=(
                SupabaseProbe(
                    REF,
                    (
                        TableProbe("products", TableAccess.READABLE),
                        TableProbe("users", TableAccess.READABLE),
                    ),
                ),
            )
        ),
    )

    marked = mark_public_tables(ctx, {(REF, "products"), (OTHER_REF, "users")})

    assert marked.baas_probes is not None
    tables = marked.baas_probes.supabase[0].tables
    assert [table.meant_to_be_public for table in tables] == [True, False]


# --- the checks ---


def with_tables(*tables: TableProbe, has_key: bool = True) -> ScanContext:
    return ScanContext(
        hostname="example.com",
        baas_probes=BaasProbes(supabase=(SupabaseProbe(REF, tables, has_key),)),
    )


READABLE = TableProbe("todos", TableAccess.READABLE)
ACKNOWLEDGED = TableProbe("products", TableAccess.READABLE, meant_to_be_public=True)


def test_readable_table_is_high_and_names_only_the_table() -> None:
    finding = supabase_table_readable(with_tables(READABLE))

    assert finding is not None
    assert finding.severity is Severity.HIGH
    assert "todos" in finding.evidence


def test_acknowledged_table_is_info_and_not_high() -> None:
    ctx = with_tables(ACKNOWLEDGED)

    assert supabase_table_readable(ctx) is None
    finding = supabase_tables_public(ctx)
    assert finding is not None
    assert finding.severity is Severity.INFO
    assert "products" in finding.evidence


def test_only_unacknowledged_tables_are_reported_high() -> None:
    finding = supabase_table_readable(with_tables(READABLE, ACKNOWLEDGED))

    assert finding is not None
    assert "products" not in finding.evidence


def test_acknowledging_every_table_leaves_the_score_alone() -> None:
    report = run_checks(with_tables(ACKNOWLEDGED), allow_active=True)

    assert all(
        item.severity is Severity.INFO
        for item in report.findings
        if item.check_id.startswith("baas.supabase")
    )


@pytest.mark.parametrize("access", [TableAccess.NO_ROWS, TableAccess.REFUSED])
def test_no_rows_or_refused_says_it_was_checked(access: TableAccess) -> None:
    ctx = with_tables(TableProbe("notes", access))

    assert supabase_table_readable(ctx) is None
    finding = supabase_tables_checked(ctx)
    assert finding is not None
    assert finding.title == "Checked: tables returned no rows to the public"
    assert "notes" in finding.evidence


def test_checked_text_admits_empty_tables_look_the_same() -> None:
    assert "empty" in CATALOG["baas.supabase_tables_checked"].fix.what_it_means


def test_not_found_names_are_not_reported_as_checked() -> None:
    assert supabase_tables_checked(with_tables(TableProbe("x", TableAccess.NOT_FOUND))) is None


def test_no_key_can_not_be_reported_clear() -> None:
    with pytest.raises(SkipCheck, match="public key"):
        supabase_table_readable(with_tables(has_key=False))


def test_no_table_names_can_not_be_reported_clear() -> None:
    with pytest.raises(SkipCheck, match="from"):
        supabase_table_readable(with_tables())


def test_no_answer_can_not_be_reported_clear() -> None:
    with pytest.raises(SkipCheck):
        supabase_table_readable(with_tables(TableProbe("a", TableAccess.UNKNOWN)))


def test_a_readable_table_is_reported_even_if_another_gave_no_answer() -> None:
    ctx = with_tables(TableProbe("a", TableAccess.UNKNOWN), READABLE)

    assert supabase_table_readable(ctx) is not None


def test_nothing_confirmed_means_no_finding() -> None:
    ctx = ScanContext(hostname="example.com", baas_probes=BaasProbes())

    assert supabase_table_readable(ctx) is None


def test_long_lists_are_shortened() -> None:
    tables = tuple(TableProbe(f"t{i}", TableAccess.READABLE) for i in range(14))

    finding = supabase_table_readable(with_tables(*tables))

    assert finding is not None
    assert "and 4 more" in finding.evidence


def test_fix_has_the_rls_and_policy_sql() -> None:
    backend = CATALOG["baas.supabase_table_readable"].fix.backend

    assert backend is not None
    assert backend.snippet is not None
    assert "enable row level security" in backend.snippet
    assert "(select auth.uid())" in backend.snippet
    assert backend.docs_url is not None


# --- the whole scan ---

SITE = "example.com"


def seed(engine: Engine, *, confirmed: bool = True) -> tuple[UUID, UUID, UUID]:
    owner = uuid4()
    with Session(engine) as session:
        session.add(Profile(id=owner))
        session.flush()
        domain = Domain(
            owner_id=owner,
            hostname=SITE,
            verify_token="tok",  # noqa: S106
            verified_at=utc_now(),
            verified_method="dns",
        )
        session.add(domain)
        session.flush()
        backend = DomainBackend(
            domain_id=domain.id,
            kind=BaasKind.SUPABASE,
            identifier=REF,
            confirmed_at=utc_now() if confirmed else None,
        )
        session.add(backend)
        session.commit()
        return owner, domain.id, backend.id


def full_scan(engine: Engine, owner: UUID, domain: UUID) -> UUID:
    with Session(engine) as session:
        scan = Scan(
            owner_id=owner,
            domain_id=domain,
            target_type=TargetType.WEB,
            target=SITE,
            mode=ScanMode.FULL,
            progress_json=initial_full_progress(),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    run_full_scan(str(scan_id))
    return scan_id


@pytest.fixture
def scanning(monkeypatch: pytest.MonkeyPatch, api: FakeApi) -> dict[str, str]:
    key = anon_key()
    monkeypatch.setattr(
        tasks,
        "prove_ownership",
        lambda *_args, **_kwargs: OwnershipResult(VerificationMethod.DNS),
    )
    monkeypatch.setattr(
        tasks,
        "collect_context",
        lambda host, on_step=None: ScanContext(
            hostname=host,
            https=response(
                url=f"https://{host}/", body=b'<html><script src="app.js"></script></html>'
            ),
        ),
    )
    monkeypatch.setattr(tasks, "attach_probes", lambda ctx: ctx)
    monkeypatch.setattr(baas_collector, "safe_get", FakeGet(script(key, "todos")))
    return {"key": key}


def saved_tables(engine: Engine) -> list[DomainBackendTable]:
    with Session(engine) as session:
        return list(session.exec(select(DomainBackendTable)))


def saved_findings(engine: Engine, scan_id: UUID) -> dict[str, FindingRecord]:
    with Session(engine) as session:
        rows = session.exec(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
        return {row.check_id: row for row in rows}


def test_confirmed_project_is_probed_and_its_tables_remembered(
    db_engine: Engine, scanning: dict[str, str], api: FakeApi
) -> None:
    owner, domain, _ = seed(db_engine)

    scan_id = full_scan(db_engine, owner, domain)

    assert [call["method"] for call in api.calls] == ["HEAD"]
    found_ = saved_findings(db_engine, scan_id)
    assert found_["baas.supabase_table_readable"].severity is Severity.HIGH
    assert [(row.name, row.access) for row in saved_tables(db_engine)] == [
        ("todos", TableAccess.READABLE)
    ]


def test_unconfirmed_project_gets_no_request(
    db_engine: Engine, scanning: dict[str, str], api: FakeApi
) -> None:
    owner, domain, _ = seed(db_engine, confirmed=False)

    full_scan(db_engine, owner, domain)

    assert api.calls == []
    assert saved_tables(db_engine) == []


def test_the_key_is_never_stored(db_engine: Engine, scanning: dict[str, str]) -> None:
    owner, domain, _ = seed(db_engine)

    scan_id = full_scan(db_engine, owner, domain)

    with Session(db_engine) as session:
        scan = session.get_one(Scan, scan_id)
        stored = scan.model_dump_json() + "".join(
            row.model_dump_json() for row in session.exec(select(FindingRecord))
        )
        stored += "".join(row.model_dump_json() for row in session.exec(select(DomainBackend)))
        stored += "".join(row.model_dump_json() for row in session.exec(select(DomainBackendTable)))
    assert scanning["key"] not in stored


def test_marking_a_table_public_takes_effect_on_the_next_scan(
    db_engine: Engine, scanning: dict[str, str]
) -> None:
    owner, domain, _ = seed(db_engine)
    full_scan(db_engine, owner, domain)
    with Session(db_engine) as session:
        row = session.exec(select(DomainBackendTable)).one()
        row.meant_to_be_public_at = utc_now()
        session.add(row)
        session.commit()

    scan_id = full_scan(db_engine, owner, domain)

    found_ = saved_findings(db_engine, scan_id)
    assert "baas.supabase_table_readable" not in found_
    assert found_["baas.supabase_tables_public"].severity is Severity.INFO
    assert saved_tables(db_engine)[0].meant_to_be_public_at is not None


def test_state_updates_when_a_table_gets_locked(
    db_engine: Engine, scanning: dict[str, str], api: FakeApi
) -> None:
    owner, domain, _ = seed(db_engine)
    full_scan(db_engine, owner, domain)
    api.answer = response(headers=NO_ROWS)

    full_scan(db_engine, owner, domain)

    assert saved_tables(db_engine)[0].access is TableAccess.NO_ROWS


@pytest.mark.parametrize("status", [404, 500])
def test_tables_that_gave_no_useful_answer_are_not_saved(
    db_engine: Engine, scanning: dict[str, str], api: FakeApi, status: int
) -> None:
    owner, domain, _ = seed(db_engine)
    api.answer = response(status=status)

    full_scan(db_engine, owner, domain)

    assert saved_tables(db_engine) == []
