"""Finding backends and server-only keys in a site's code. Offline, with fixtures."""

import base64
import json
import os
from typing import Any

import pytest

from app.checks import baas_collector
from app.checks.active_collector import allowed_probe_hosts, without_probes
from app.checks.baas import backends_found, supabase_service_key
from app.checks.baas_collector import (
    BUNDLE_MAX_BYTES,
    MAX_BACKENDS,
    MAX_BUNDLE_SCRIPTS,
    discover_backends,
)
from app.checks.baas_discovery import (
    SECRET_KEY_MASK,
    SERVICE_ROLE_MASK,
    find_backends,
    find_exposed_keys,
)
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    Category,
    DiscoveredBackend,
    ExposedServiceKey,
    Fix,
    Input,
    ScanContext,
    Severity,
    SkipCheck,
)
from app.checks.catalog import CATALOG
from app.checks.runner import run_checks, selected_checks
from app.core.safe_http import OffHostRedirectError, RequestFailedError, SafeResponse
from tests.checks.helpers import response

REF = "abcdefghijklmnopqrst"
RTDB = DiscoveredBackend(BaasKind.FIREBASE_RTDB, "my-app-default-rtdb.firebaseio.com")
BUCKET = DiscoveredBackend(BaasKind.FIREBASE_STORAGE, "my-app.appspot.com")
SUPABASE = DiscoveredBackend(BaasKind.SUPABASE, REF)

# Built at run time, so nothing secret-shaped is ever committed to this repo.
API_KEY = "AIza" + "x" * 35


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(**claims: Any) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.{b64url(os.urandom(32))}"


def service_jwt() -> str:
    return make_jwt(iss="supabase", ref=REF, role="service_role")


def secret_key() -> str:
    return "sb_" + "secret_" + "y" * 32


def firebase_config(**overrides: str) -> str:
    fields = {
        "apiKey": API_KEY,
        "authDomain": "my-app.firebaseapp.com",
        "databaseURL": "https://my-app-default-rtdb.firebaseio.com",
        "projectId": "my-app",
        "storageBucket": "my-app.appspot.com",
    } | overrides
    return "{" + ",".join(f'{key}:"{value}"' for key, value in fields.items()) + "}"


# --- finding backends ---


def test_finds_every_part_of_a_minified_firebase_config() -> None:
    assert find_backends(f"init({firebase_config()})") == {RTDB, BUCKET}


def test_finds_a_firebase_config_written_as_json() -> None:
    assert find_backends(json.dumps(json.loads(_as_json()))) == {RTDB, BUCKET}


def _as_json() -> str:
    return json.dumps(
        {
            "apiKey": API_KEY,
            "projectId": "my-app",
            "databaseURL": "https://my-app-default-rtdb.firebaseio.com",
            "storageBucket": "my-app.appspot.com",
        }
    )


def test_finds_a_firebase_config_escaped_inside_a_json_string() -> None:
    assert find_backends(json.dumps(_as_json())) == {RTDB, BUCKET}


def test_finds_a_regional_database() -> None:
    url = "https://my-app.europe-west1.firebasedatabase.app"

    assert DiscoveredBackend(
        BaasKind.FIREBASE_RTDB, "my-app.europe-west1.firebasedatabase.app"
    ) in find_backends(firebase_config(databaseURL=url))


def test_finds_a_new_style_bucket() -> None:
    backends = find_backends(firebase_config(storageBucket="my-app.firebasestorage.app"))

    assert DiscoveredBackend(BaasKind.FIREBASE_STORAGE, "my-app.firebasestorage.app") in backends


def test_config_without_a_project_id_is_not_a_firebase_config() -> None:
    text = f'{{apiKey:"{API_KEY}",databaseURL:"https://x.firebaseio.com"}}'

    assert find_backends(text) == set()


def test_fields_without_an_api_key_are_ignored() -> None:
    assert find_backends('{projectId:"a",databaseURL:"https://x.firebaseio.com"}') == set()


@pytest.mark.parametrize(
    "url",
    [
        "http://my-app.firebaseio.com",  # not HTTPS
        "https://evil.example/.firebaseio.com",
        "https://my-app.firebaseio.com.evil.example",
        "https://my-app.firebaseio.com@evil.example",
        "https://user@my-app.firebaseio.com",
        "https://my-app.firebaseio.com:8443",
        "https://my-app.firebaseio.com/some/path",
        "https://a.b.firebaseio.com",  # one label only
        "https://evil.firebasedatabase.app",  # missing the region label
        "https://a.b.c.firebasedatabase.app",
        "https://169.254.169.254",
        "https://localhost",
        "https://[::1]",
        "not a url",
    ],
)
def test_database_urls_off_the_official_hosts_are_refused(url: str) -> None:
    backends = find_backends(firebase_config(databaseURL=url))

    assert not any(item.kind is BaasKind.FIREBASE_RTDB for item in backends)


@pytest.mark.parametrize("bucket", ["../other", "a/b", "a", "my..bucket", "-bad", "UP%2fPER"])
def test_unsafe_bucket_names_are_refused(bucket: str) -> None:
    backends = find_backends(firebase_config(storageBucket=bucket))

    assert not any(item.kind is BaasKind.FIREBASE_STORAGE for item in backends)


def test_gs_prefix_is_removed_from_a_bucket() -> None:
    assert BUCKET in find_backends(firebase_config(storageBucket="gs://my-app.appspot.com"))


def test_finds_a_supabase_project() -> None:
    assert find_backends(f'createClient("https://{REF}.supabase.co","k")') == {SUPABASE}


def test_finds_a_supabase_project_with_escaped_slashes() -> None:
    assert find_backends(f'"https:\\/\\/{REF}.supabase.co"') == {SUPABASE}


@pytest.mark.parametrize(
    "url",
    [
        "https://your-project-ref.supabase.co",  # a docs placeholder
        "https://short.supabase.co",
        f"http://{REF}.supabase.co",
        f"https://{REF}.supabase.co.evil.example",
        f"https://{REF}.supabase.co-evil.example",
        f"https://{REF}x.supabase.co",
        f"https://evil.example/{REF}.supabase.co",
    ],
)
def test_supabase_urls_off_the_official_host_are_refused(url: str) -> None:
    assert find_backends(f'"{url}"') == set()


# --- server-only keys ---


def test_service_role_key_is_reported_masked() -> None:
    token = service_jwt()

    found = find_exposed_keys(f'key="{token}"', "/app.js")

    assert found == [ExposedServiceKey(SERVICE_ROLE_MASK, "/app.js")]
    assert token not in repr(found)


def test_secret_key_is_reported_masked() -> None:
    key = secret_key()

    found = find_exposed_keys(f'key="{key}"', "/app.js")

    assert found == [ExposedServiceKey(SECRET_KEY_MASK, "/app.js")]
    assert key not in repr(found)


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "supabase", "ref": REF, "role": "anon"},  # public by design
        {"iss": "supabase", "ref": REF, "role": "authenticated"},
        {"iss": "someone-else", "role": "service_role"},  # not a Supabase key
        {"role": "service_role"},
    ],
)
def test_other_tokens_are_not_reported(claims: dict[str, str]) -> None:
    assert find_exposed_keys(make_jwt(**claims), "/app.js") == []


def test_publishable_key_is_not_reported() -> None:
    assert find_exposed_keys("sb_" + "publishable_" + "y" * 32, "/app.js") == []


def test_broken_token_is_ignored() -> None:
    assert find_exposed_keys("eyJaaaaaaaaaaaaa.eyJbbbbbbbbbbbbb.cccccccccccccc", "/a.js") == []


# --- reading the site's scripts ---


class FakeGet:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.kwargs: list[dict[str, Any]] = []
        self.answers: dict[str, SafeResponse | Exception] = {}
        self.default: SafeResponse | Exception = response(body=b"var a=1;")

    def __call__(self, url: str, **kwargs: Any) -> SafeResponse:
        self.urls.append(url)
        self.kwargs.append(kwargs)
        answer = self.answers.get(url, self.default)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def fake_get(monkeypatch: pytest.MonkeyPatch) -> FakeGet:
    fake = FakeGet()
    monkeypatch.setattr(baas_collector, "safe_get", fake)
    return fake


def page(*scripts: str, inline: str = "") -> ScanContext:
    tags = "".join(f'<script src="{src}"></script>' for src in scripts)
    return ScanContext(
        hostname="example.com",
        https=response(body=f"<html>{tags}<script>{inline}</script></html>".encode()),
    )


def discovered(ctx: ScanContext) -> BaasDiscovery:
    result = discover_backends(ctx).baas
    assert result is not None
    return result


def test_reads_scripts_on_the_verified_host_only(fake_get: FakeGet) -> None:
    discovered(page("/a.js", "https://cdn.example.net/b.js", "https://www.example.com/c.js"))

    assert fake_get.urls == ["https://example.com/a.js", "https://example.com/c.js"]


def test_contacts_no_backend_during_discovery(fake_get: FakeGet) -> None:
    fake_get.default = response(body=f'"https://{REF}.supabase.co"'.encode())

    discovered(page("/a.js"))

    assert all(url.startswith("https://example.com/") for url in fake_get.urls)


def test_scripts_cannot_redirect_off_the_verified_site(fake_get: FakeGet) -> None:
    discovered(page("/a.js"))

    assert fake_get.kwargs[0]["allowed_hosts"] == allowed_probe_hosts("example.com")
    assert fake_get.kwargs[0]["max_bytes"] == BUNDLE_MAX_BYTES


def test_finds_backends_in_a_script(fake_get: FakeGet) -> None:
    fake_get.default = response(body=firebase_config().encode())

    assert set(discovered(page("/a.js")).backends) == {RTDB, BUCKET}


def test_finds_backends_inline_in_the_homepage(fake_get: FakeGet) -> None:
    assert discovered(page(inline=f'"https://{REF}.supabase.co"')).backends == (SUPABASE,)


def test_finds_a_service_key_and_where_it_is(fake_get: FakeGet) -> None:
    fake_get.default = response(body=service_jwt().encode())

    assert discovered(page("/app.js")).exposed_keys == (
        ExposedServiceKey(SERVICE_ROLE_MASK, "/app.js"),
    )


def test_a_key_repeated_in_one_file_is_reported_once(fake_get: FakeGet) -> None:
    fake_get.default = response(body=f"{service_jwt()} {service_jwt()}".encode())

    assert len(discovered(page("/app.js")).exposed_keys) == 1


def test_script_contents_are_not_kept(fake_get: FakeGet) -> None:
    token = service_jwt()
    fake_get.default = response(body=f'var a="{token}";'.encode())

    assert token not in repr(discovered(page("/app.js")))


def test_number_of_scripts_is_capped(fake_get: FakeGet) -> None:
    scripts = [f"/{index}.js" for index in range(MAX_BUNDLE_SCRIPTS + 5)]

    result = discovered(page(*scripts))

    assert len(fake_get.urls) == MAX_BUNDLE_SCRIPTS
    assert result.scripts_total == MAX_BUNDLE_SCRIPTS + 5
    assert result.scripts_read == MAX_BUNDLE_SCRIPTS


def test_total_bytes_are_capped(fake_get: FakeGet, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baas_collector, "MAX_BUNDLE_TOTAL_BYTES", 10)
    fake_get.default = response(body=b"x" * 10)

    assert discovered(page("/a.js", "/b.js", "/c.js")).scripts_read == 1


def test_time_budget_stops_reading(fake_get: FakeGet, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baas_collector, "DISCOVERY_BUDGET_SECONDS", 0.0)

    assert discovered(page("/a.js")).scripts_read == 0
    assert fake_get.urls == []


def test_number_of_backends_remembered_is_capped(fake_get: FakeGet) -> None:
    refs = [f"{index:020d}" for index in range(MAX_BACKENDS + 5)]
    inline = " ".join(f'"https://{ref}.supabase.co"' for ref in refs)

    assert len(discovered(page(inline=inline)).backends) == MAX_BACKENDS


def test_unreadable_scripts_are_counted(fake_get: FakeGet) -> None:
    fake_get.answers["https://example.com/a.js"] = RequestFailedError("down")
    fake_get.answers["https://example.com/b.js"] = OffHostRedirectError("left")
    fake_get.answers["https://example.com/c.js"] = response(status=503)

    result = discovered(page("/a.js", "/b.js", "/c.js", "/d.js"))

    assert (result.scripts_read, result.scripts_failed) == (1, 3)


def test_html_answer_for_a_script_is_not_read(fake_get: FakeGet) -> None:
    fake_get.default = response(body=f'<!doctype html>"{service_jwt()}"'.encode())

    result = discovered(page("/missing.js"))

    assert result.scripts_read == 0
    assert result.exposed_keys == ()


def test_missing_homepage_collects_nothing(fake_get: FakeGet) -> None:
    ctx = ScanContext(hostname="example.com")

    assert discover_backends(ctx).baas is None
    assert fake_get.urls == []


# --- the checks ---


def baas(**overrides: Any) -> ScanContext:
    fields: dict[str, Any] = {
        "backends": (),
        "exposed_keys": (),
        "scripts_total": 2,
        "scripts_read": 2,
        "scripts_failed": 0,
    }
    return ScanContext(hostname="example.com", baas=BaasDiscovery(**(fields | overrides)))


def test_service_key_is_critical_with_a_masked_location() -> None:
    finding = supabase_service_key(
        baas(exposed_keys=(ExposedServiceKey(SERVICE_ROLE_MASK, "/_next/app.js"),))
    )

    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert finding.category is Category.BAAS
    assert "eyJ****" in finding.evidence
    assert "/_next/app.js" in finding.evidence


def test_no_service_key_with_every_script_read_is_clear() -> None:
    assert supabase_service_key(baas()) is None


def test_unread_scripts_can_not_be_reported_clear() -> None:
    with pytest.raises(SkipCheck, match="Read 1 of 2"):
        supabase_service_key(baas(scripts_read=1, scripts_failed=1))


def test_key_is_reported_even_if_some_scripts_failed() -> None:
    finding = supabase_service_key(
        baas(exposed_keys=(ExposedServiceKey(SECRET_KEY_MASK, "/a.js"),), scripts_failed=1)
    )

    assert finding is not None


def test_backends_found_is_info_and_names_them() -> None:
    finding = backends_found(baas(backends=(RTDB, SUPABASE)))

    assert finding is not None
    assert finding.severity is Severity.INFO
    assert RTDB.identifier in finding.evidence
    assert REF in finding.evidence
    assert "Read 2 of 2 scripts." in finding.evidence


def test_nothing_found_with_every_script_read_says_nothing() -> None:
    assert backends_found(baas()) is None


def test_partial_coverage_is_reported_even_with_no_backends() -> None:
    finding = backends_found(baas(scripts_total=30, scripts_read=20))

    assert finding is not None
    assert "Read 20 of 30" in finding.evidence


# --- the gate ---


def test_baas_checks_never_run_in_a_quick_scan() -> None:
    ids = {spec.check_id for spec in selected_checks()}

    assert not any(check_id.startswith("baas.") for check_id in ids)


def test_baas_checks_are_active() -> None:
    specs = [s for s in selected_checks(allow_active=True) if s.check_id.startswith("baas.")]

    assert specs
    assert all(spec.active for spec in specs)


def test_scan_without_ownership_skips_them_with_the_reason() -> None:
    ctx = without_probes(ScanContext(hostname="example.com"), "Not verified.")

    assert ctx.skip_reasons[Input.BAAS] == "Not verified."
    report = run_checks(ctx, allow_active=True)
    assert "Not verified." in {
        item.reason for item in report.skipped if item.check_id.startswith("baas.")
    }


# --- fixes that don't depend on hosting ---


@pytest.mark.parametrize("check_id", ["baas.supabase_service_key", "baas.backends_found"])
def test_backend_fixes_need_no_hosting_tabs(check_id: str) -> None:
    fix = CATALOG[check_id].fix

    assert isinstance(fix, Fix)
    assert fix.platforms == {}
    assert fix.backend is not None


def test_service_key_fix_links_the_official_docs() -> None:
    backend = CATALOG["baas.supabase_service_key"].fix.backend

    assert backend is not None
    assert backend.docs_url == "https://supabase.com/docs/guides/security/rotate-leaked-api-keys"
