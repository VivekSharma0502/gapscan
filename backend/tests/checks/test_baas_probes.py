"""Read-only Firebase probes. Offline: the guarded request function is faked."""

import inspect
import json
from typing import Any

import pytest

from app.checks import baas_collector, baas_probes
from app.checks.active_collector import without_probes
from app.checks.baas import firebase_rtdb_public, firebase_storage_listable
from app.checks.baas_collector import discover_backends
from app.checks.baas_probes import (
    RTDB_MAX_BYTES,
    STORAGE_HOST,
    STORAGE_MAX_BYTES,
    probe_backends,
)
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BaasProbes,
    DiscoveredBackend,
    Input,
    RtdbProbe,
    ScanContext,
    Severity,
    SkipCheck,
    StorageProbe,
)
from app.checks.catalog import CATALOG
from app.checks.runner import run_checks, selected_checks
from app.core.safe_http import OffHostRedirectError, RequestFailedError, SafeResponse
from tests.checks.helpers import response

HOST = "my-app-default-rtdb.firebaseio.com"
BUCKET = "my-app.appspot.com"
RTDB = DiscoveredBackend(BaasKind.FIREBASE_RTDB, HOST)
STORAGE = DiscoveredBackend(BaasKind.FIREBASE_STORAGE, BUCKET)
SUPABASE = DiscoveredBackend(BaasKind.SUPABASE, "abcdefghijklmnopqrst")
RTDB_URL = f"https://{HOST}/.json?shallow=true"
STORAGE_URL = f"https://{STORAGE_HOST}/v0/b/{BUCKET}/o?maxResults=1"


class FakeGet:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.kwargs: list[dict[str, Any]] = []
        self.answer: SafeResponse | Exception = response(body=b"null")

    def __call__(self, url: str, **kwargs: Any) -> SafeResponse:
        self.urls.append(url)
        self.kwargs.append(kwargs)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def fake_get(monkeypatch: pytest.MonkeyPatch) -> FakeGet:
    fake = FakeGet()
    monkeypatch.setattr(baas_probes, "safe_get", fake)
    return fake


def found(*backends: DiscoveredBackend) -> ScanContext:
    return ScanContext(
        hostname="example.com",
        baas=BaasDiscovery(backends, (), 1, 1, 0),
    )


def probed(ctx: ScanContext, *confirmed: DiscoveredBackend) -> BaasProbes:
    result = probe_backends(ctx, set(confirmed)).baas_probes
    assert result is not None
    return result


# --- what may be contacted ---


def test_unconfirmed_backends_are_never_contacted(fake_get: FakeGet) -> None:
    result = probed(found(RTDB, STORAGE))

    assert fake_get.urls == []
    assert result == BaasProbes()


def test_confirmed_backend_no_longer_on_the_site_is_not_contacted(fake_get: FakeGet) -> None:
    probed(found(STORAGE), RTDB)

    assert RTDB_URL not in fake_get.urls
    assert fake_get.urls == []


def test_only_the_confirmed_one_is_contacted(fake_get: FakeGet) -> None:
    probed(found(RTDB, STORAGE), RTDB)

    assert fake_get.urls == [RTDB_URL]


def test_supabase_is_not_contacted_by_these_probes(fake_get: FakeGet) -> None:
    probed(found(SUPABASE), SUPABASE)

    assert fake_get.urls == []


def test_nothing_is_probed_without_discovery(fake_get: FakeGet) -> None:
    ctx = ScanContext(hostname="example.com")

    assert probe_backends(ctx, {RTDB}).baas_probes is None
    assert fake_get.urls == []


@pytest.mark.parametrize(
    "backend",
    [
        DiscoveredBackend(BaasKind.FIREBASE_RTDB, "evil.example"),
        DiscoveredBackend(BaasKind.FIREBASE_RTDB, "169.254.169.254"),
        DiscoveredBackend(BaasKind.FIREBASE_RTDB, "my-app.firebaseio.com.evil.example"),
        DiscoveredBackend(BaasKind.FIREBASE_STORAGE, "../../other"),
        DiscoveredBackend(BaasKind.FIREBASE_STORAGE, "a/b"),
    ],
)
def test_a_tampered_stored_name_is_never_contacted(
    fake_get: FakeGet, backend: DiscoveredBackend
) -> None:
    # Security: names are checked at discovery and again when read back from the database.
    probed(found(backend), backend)

    assert fake_get.urls == []


def test_rtdb_probe_cannot_redirect_off_its_host(fake_get: FakeGet) -> None:
    probed(found(RTDB), RTDB)

    assert fake_get.kwargs[0]["allowed_hosts"] == frozenset({HOST})
    assert fake_get.kwargs[0]["max_bytes"] == RTDB_MAX_BYTES


def test_storage_probe_cannot_redirect_off_its_host(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b"{}")

    probed(found(STORAGE), STORAGE)

    assert fake_get.urls == [STORAGE_URL]
    assert fake_get.kwargs[0]["allowed_hosts"] == frozenset({STORAGE_HOST})
    assert fake_get.kwargs[0]["max_bytes"] == STORAGE_MAX_BYTES


def test_the_module_can_only_make_get_requests() -> None:
    source = inspect.getsource(baas_probes)

    assert "safe_api_request" not in source
    assert "httpx" not in source


def test_time_budget_leaves_the_rest_unanswered(
    fake_get: FakeGet, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(baas_probes, "PROBE_BUDGET_SECONDS", 0.0)

    result = probed(found(RTDB, STORAGE), RTDB, STORAGE)

    assert fake_get.urls == []
    assert result.rtdb == (RtdbProbe(HOST, None),)
    assert result.storage == (StorageProbe(BUCKET, None),)


# --- reading the database's answer ---


def test_open_database_keeps_only_the_key_count(fake_get: FakeGet) -> None:
    fake_get.answer = response(
        body=json.dumps({"alice@example.com": True, "user-secret-id": True}).encode()
    )

    result = probed(found(RTDB), RTDB)

    assert result.rtdb == (RtdbProbe(HOST, readable=True, key_count=2),)
    assert "alice@example.com" not in repr(result)
    assert "user-secret-id" not in repr(result)


def test_empty_open_database_is_still_readable(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b"null")

    assert probed(found(RTDB), RTDB).rtdb == (RtdbProbe(HOST, readable=True, key_count=0),)


def test_primitive_at_the_root_counts_as_one_and_is_not_kept(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b'"a stored value"')

    result = probed(found(RTDB), RTDB)

    assert result.rtdb == (RtdbProbe(HOST, readable=True, key_count=1),)
    assert "a stored value" not in repr(result)


def test_too_many_keys_is_readable_without_a_count(fake_get: FakeGet) -> None:
    fake_get.answer = SafeResponse(
        RTDB_URL, 200, response().headers, b'{"a":true,"b"', truncated=True, redirects=()
    )

    assert probed(found(RTDB), RTDB).rtdb == (RtdbProbe(HOST, readable=True, key_count=None),)


@pytest.mark.parametrize("status", [401, 403, 404, 423])
def test_refused_database_is_not_readable(fake_get: FakeGet, status: int) -> None:
    fake_get.answer = response(status=status, body=b'{"error":"Permission denied"}')

    assert probed(found(RTDB), RTDB).rtdb == (RtdbProbe(HOST, readable=False),)


@pytest.mark.parametrize("status", [400, 429, 500, 503])
def test_unclear_status_is_unknown(fake_get: FakeGet, status: int) -> None:
    fake_get.answer = response(status=status)

    assert probed(found(RTDB), RTDB).rtdb == (RtdbProbe(HOST, readable=None),)


def test_a_non_json_answer_is_unknown(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b"<html>not a database</html>")

    assert probed(found(RTDB), RTDB).rtdb == (RtdbProbe(HOST, readable=None),)


@pytest.mark.parametrize(
    "error", [RequestFailedError("down"), OffHostRedirectError("left the host")]
)
def test_network_failure_is_unknown(fake_get: FakeGet, error: Exception) -> None:
    fake_get.answer = error

    assert probed(found(RTDB), RTDB).rtdb == (RtdbProbe(HOST, readable=None),)


# --- reading the bucket's answer ---


def test_listable_bucket_keeps_no_file_names(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b'{"items":[{"name":"private/passport.pdf"}]}')

    result = probed(found(STORAGE), STORAGE)

    assert result.storage == (StorageProbe(BUCKET, listable=True),)
    assert "passport" not in repr(result)


def test_empty_listable_bucket_is_still_listable(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b"{}")

    assert probed(found(STORAGE), STORAGE).storage == (StorageProbe(BUCKET, listable=True),)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_refused_bucket_is_not_listable(fake_get: FakeGet, status: int) -> None:
    fake_get.answer = response(status=status, body=b'{"error":{"code":403}}')

    assert probed(found(STORAGE), STORAGE).storage == (StorageProbe(BUCKET, listable=False),)


@pytest.mark.parametrize("status", [400, 412, 429, 500])
def test_unclear_bucket_status_is_unknown(fake_get: FakeGet, status: int) -> None:
    fake_get.answer = response(status=status)

    assert probed(found(STORAGE), STORAGE).storage == (StorageProbe(BUCKET, listable=None),)


def test_html_at_200_is_not_a_listing(fake_get: FakeGet) -> None:
    fake_get.answer = response(body=b"<html></html>")

    assert probed(found(STORAGE), STORAGE).storage == (StorageProbe(BUCKET, listable=None),)


# --- the checks ---


def checked(**probes: Any) -> ScanContext:
    return ScanContext(hostname="example.com", baas_probes=BaasProbes(**probes))


def test_readable_database_is_critical_with_a_count_only() -> None:
    finding = firebase_rtdb_public(checked(rtdb=(RtdbProbe(HOST, True, 3),)))

    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert HOST in finding.evidence
    assert "3 top-level keys" in finding.evidence


def test_uncounted_database_says_so() -> None:
    finding = firebase_rtdb_public(checked(rtdb=(RtdbProbe(HOST, True, None),)))

    assert finding is not None
    assert "more top-level keys" in finding.evidence


def test_protected_database_is_clear() -> None:
    assert firebase_rtdb_public(checked(rtdb=(RtdbProbe(HOST, False),))) is None


def test_no_answer_from_a_database_is_not_clear() -> None:
    with pytest.raises(SkipCheck):
        firebase_rtdb_public(checked(rtdb=(RtdbProbe(HOST, None),)))


def test_a_readable_database_is_reported_even_if_another_gave_no_answer() -> None:
    probes = (RtdbProbe(HOST, None), RtdbProbe("other.firebaseio.com", True, 1))

    assert firebase_rtdb_public(checked(rtdb=probes)) is not None


def test_nothing_confirmed_means_no_finding() -> None:
    assert firebase_rtdb_public(checked()) is None
    assert firebase_storage_listable(checked()) is None


def test_listable_bucket_is_high() -> None:
    finding = firebase_storage_listable(checked(storage=(StorageProbe(BUCKET, True),)))

    assert finding is not None
    assert finding.severity is Severity.HIGH
    assert BUCKET in finding.evidence


def test_protected_bucket_is_clear() -> None:
    assert firebase_storage_listable(checked(storage=(StorageProbe(BUCKET, False),))) is None


def test_no_answer_from_a_bucket_is_not_clear() -> None:
    with pytest.raises(SkipCheck):
        firebase_storage_listable(checked(storage=(StorageProbe(BUCKET, None),)))


# --- the gate and the fixes ---


def test_probe_checks_never_run_in_a_quick_scan() -> None:
    ids = {spec.check_id for spec in selected_checks()}

    assert "baas.firebase_rtdb_public" not in ids
    assert "baas.firebase_storage_listable" not in ids


def test_scan_without_ownership_skips_them_with_the_reason() -> None:
    ctx = without_probes(ScanContext(hostname="example.com"), "Not verified.")

    assert ctx.skip_reasons[Input.BAAS_PROBES] == "Not verified."
    reasons = {item.check_id: item.reason for item in run_checks(ctx, allow_active=True).skipped}
    assert reasons["baas.firebase_rtdb_public"] == "Not verified."


@pytest.mark.parametrize(
    ("check_id", "needle"),
    [
        ("baas.firebase_rtdb_public", "auth.uid === $uid"),
        ("baas.firebase_storage_listable", "rules_version = '2'"),
    ],
)
def test_fixes_carry_a_per_user_rule_and_the_official_docs(check_id: str, needle: str) -> None:
    backend = CATALOG[check_id].fix.backend

    assert backend is not None
    assert backend.snippet is not None
    assert needle in backend.snippet
    assert backend.docs_url == "https://firebase.google.com/docs/rules/basics"


def test_rtdb_fix_is_valid_json() -> None:
    backend = CATALOG["baas.firebase_rtdb_public"].fix.backend

    assert backend is not None
    assert backend.snippet is not None
    assert "rules" in json.loads(backend.snippet)


# --- the whole path, from a site's script to a finding ---

KEY_NAME = "alice-private-user-id"
SITE_SCRIPT = f"""const firebaseConfig = {{
  apiKey:        "{"AIza" + "x" * 35}",
  databaseURL:   "https://{HOST}",
  projectId:     "my-app",
  storageBucket: "{BUCKET}",
}};""".encode()


def _site() -> ScanContext:
    return ScanContext(
        hostname="example.com",
        https=response(
            url="https://example.com/", body=b'<html><script src="app.js"></script></html>'
        ),
    )


def _report(
    monkeypatch: pytest.MonkeyPatch, answer: SafeResponse, *confirmed: DiscoveredBackend
) -> tuple[Any, FakeGet]:
    def script(_url: str, **_kwargs: Any) -> SafeResponse:
        return response(body=SITE_SCRIPT)

    monkeypatch.setattr(baas_collector, "safe_get", script)
    backend_get = FakeGet()
    backend_get.answer = answer
    monkeypatch.setattr(baas_probes, "safe_get", backend_get)
    ctx = probe_backends(discover_backends(_site()), set(confirmed))
    return run_checks(ctx, allow_active=True), backend_get


def _baas_findings(report: Any) -> dict[str, Any]:
    return {item.check_id: item for item in report.findings if item.check_id.startswith("baas.")}


def test_open_database_from_script_to_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = response(body=json.dumps({KEY_NAME: True, "second": True}).encode())

    report, backend_get = _report(monkeypatch, answer, RTDB)

    assert backend_get.urls == [RTDB_URL]
    found = _baas_findings(report)
    assert found["baas.firebase_rtdb_public"].severity is Severity.CRITICAL
    assert "2 top-level keys" in found["baas.firebase_rtdb_public"].evidence
    assert KEY_NAME not in report.model_dump_json()


def test_locked_database_from_script_to_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = response(status=401, body=b'{"error":"Permission denied"}')

    report, _ = _report(monkeypatch, answer, RTDB)

    assert "baas.firebase_rtdb_public" not in _baas_findings(report)


def test_found_but_unconfirmed_backends_get_no_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    report, backend_get = _report(monkeypatch, response(body=b"{}"))

    assert backend_get.urls == []
    found = _baas_findings(report)
    assert HOST in found["baas.backends_found"].evidence
    assert "baas.firebase_rtdb_public" not in found
