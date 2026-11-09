from typing import Any

import pytest

from app.checks import active_collector
from app.checks.active_collector import (
    MAX_SCRIPTS,
    PROBE_MAX_BYTES,
    allowed_probe_hosts,
    attach_probes,
    source_map_paths,
    without_probes,
)
from app.checks.base import Input, ScanContext
from app.checks.exposure import FIXED_PROBE_PATHS
from app.core.safe_http import OffHostRedirectError, RequestFailedError, SafeResponse
from tests.checks.helpers import response

ALLOWED = allowed_probe_hosts("example.com")


class FakeGet:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.kwargs: list[dict[str, Any]] = []
        self.answers: dict[str, SafeResponse | Exception] = {}
        self.default: SafeResponse | Exception = response(status=404)

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
    monkeypatch.setattr(active_collector, "safe_get", fake)
    return fake


def site(body: bytes = b"", **overrides: Any) -> ScanContext:
    fields: dict[str, Any] = {"hostname": "example.com", "https": response(body=body)}
    return ScanContext(**(fields | overrides))


def test_every_fixed_path_is_requested_on_the_verified_host(fake_get: FakeGet) -> None:
    attach_probes(site())

    assert fake_get.urls == [f"https://example.com{path}" for path in FIXED_PROBE_PATHS]


def test_probes_cannot_redirect_off_the_verified_site(fake_get: FakeGet) -> None:
    # Security: the guard that keeps active probes on verified domains.
    attach_probes(site())

    assert all(item["allowed_hosts"] == ALLOWED for item in fake_get.kwargs)
    assert ALLOWED == {"example.com", "www.example.com"}


def test_probes_read_only_a_small_amount(fake_get: FakeGet) -> None:
    attach_probes(site())

    assert all(item["max_bytes"] == PROBE_MAX_BYTES for item in fake_get.kwargs)


def test_answers_are_recorded(fake_get: FakeGet) -> None:
    fake_get.answers["https://example.com/.env"] = response(body=b"A=1", status=200)

    probes = attach_probes(site()).probes

    assert probes is not None
    assert (probes["/.env"].status_code, probes["/.env"].content) == (200, b"A=1")
    assert probes["/.git/HEAD"].status_code == 404


def test_403_is_an_answer(fake_get: FakeGet) -> None:
    fake_get.default = response(status=403)

    probes = attach_probes(site()).probes

    assert probes is not None
    assert probes["/.env"].status_code == 403


@pytest.mark.parametrize("status", [500, 502, 503])
def test_server_errors_are_not_answers(fake_get: FakeGet, status: int) -> None:
    fake_get.default = response(status=status)

    probes = attach_probes(site()).probes

    assert probes is not None
    assert probes["/.env"].status_code is None


def test_bot_challenge_is_not_an_answer(fake_get: FakeGet) -> None:
    fake_get.default = response(status=403, headers={"cf-mitigated": "challenge"})

    probes = attach_probes(site()).probes

    assert probes is not None
    assert probes["/.env"].status_code is None


@pytest.mark.parametrize("error", [RequestFailedError("x"), OffHostRedirectError("x")])
def test_failed_requests_stay_unanswered(fake_get: FakeGet, error: Exception) -> None:
    fake_get.default = error

    probes = attach_probes(site()).probes

    assert probes is not None
    assert all(probe.status_code is None for probe in probes.values())


def test_rate_limiting_stops_the_remaining_requests(fake_get: FakeGet) -> None:
    fake_get.answers["https://example.com/.env.local"] = response(status=429)

    probes = attach_probes(site()).probes

    assert len(fake_get.urls) == 2
    assert probes is not None
    assert set(probes) == set(FIXED_PROBE_PATHS)
    assert probes["/.git/HEAD"].status_code is None


def test_time_budget_leaves_the_rest_unanswered(
    fake_get: FakeGet, monkeypatch: pytest.MonkeyPatch
) -> None:
    times = iter([0.0, 1.0, 999.0])
    monkeypatch.setattr(active_collector, "monotonic", lambda: next(times, 999.0))

    probes = attach_probes(site()).probes

    assert len(fake_get.urls) == 1
    assert probes is not None
    assert probes[FIXED_PROBE_PATHS[1]].status_code is None


def test_unreadable_site_gets_no_requests(fake_get: FakeGet) -> None:
    blocked = ScanContext(hostname="example.com", skip_reasons={Input.HOMEPAGE: "Blocked by WAF"})

    result = attach_probes(blocked)

    assert fake_get.urls == []
    assert result.probes is None
    assert result.skip_reasons[Input.PROBES] == "Blocked by WAF"


def test_http_only_site_is_probed_over_http(fake_get: FakeGet) -> None:
    http_site = ScanContext(
        hostname="example.com", http=response(url="http://example.com/"), homepage_via_http=True
    )

    attach_probes(http_site)

    assert fake_get.urls[0] == "http://example.com/.env"


def test_without_probes_records_the_reason() -> None:
    result = without_probes(site(), "not verified")

    assert result.probes is None
    assert result.skip_reasons[Input.PROBES] == "not verified"


# Which scripts get a source map request


def maps(html: str, url: str = "https://example.com/") -> list[str]:
    return source_map_paths(response(body=html.encode(), url=url), ALLOWED)


def test_own_scripts_get_a_map_path() -> None:
    assert maps('<script src="/js/app.abc.js"></script>') == ["/js/app.abc.js.map"]


def test_relative_scripts_resolve_against_the_page() -> None:
    assert maps('<script src="app.js"></script>', "https://example.com/a/") == ["/a/app.js.map"]


def test_query_strings_are_dropped() -> None:
    assert maps('<script src="/app.js?v=3"></script>') == ["/app.js.map"]


def test_www_scripts_count_as_the_site() -> None:
    assert maps('<script src="https://www.example.com/app.js"></script>') == ["/app.js.map"]


def test_other_hosts_are_never_probed() -> None:
    # Security: a CDN or third party isn't covered by this domain's verification.
    html = '<script src="https://cdn.other.com/app.js"></script><script src="//x.io/a.js"></script>'

    assert maps(html) == []


def test_non_javascript_sources_and_inline_scripts_are_ignored() -> None:
    assert maps('<script>var a;</script><script src="/widget"></script>') == []


def test_duplicates_are_removed_and_the_list_is_capped() -> None:
    html = '<script src="/a.js"></script>' * 2 + "".join(
        f'<script src="/s{index}.js"></script>' for index in range(MAX_SCRIPTS + 3)
    )

    found = maps(html)

    assert found[0] == "/a.js.map"
    assert len(found) == MAX_SCRIPTS
    assert len(set(found)) == MAX_SCRIPTS


def test_source_map_probes_are_added_to_the_fixed_ones(fake_get: FakeGet) -> None:
    attach_probes(site(b'<script src="/app.js"></script>'))

    assert "https://example.com/app.js.map" in fake_get.urls


@pytest.mark.parametrize("header", ["cf-mitigated", "x-vercel-mitigated"])
def test_bot_challenge_stops_the_remaining_requests(fake_get: FakeGet, header: str) -> None:
    fake_get.default = response(status=403, headers={header: "challenge"})

    probes = attach_probes(site()).probes

    assert len(fake_get.urls) == 1
    assert probes is not None
    assert set(probes) == set(FIXED_PROBE_PATHS)
    assert all(probe.status_code is None for probe in probes.values())


def test_a_vercel_challenge_never_counts_as_file_not_found(fake_get: FakeGet) -> None:
    fake_get.default = response(status=403, headers={"x-vercel-mitigated": "challenge"})

    probes = attach_probes(site()).probes

    assert probes is not None
    assert probes["/.env"].status_code is None
