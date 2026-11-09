"""Pauses between active checks, and stopping at the first bot-protection challenge."""

from typing import Any

import pytest

from app.checks import active_collector, baas_collector, baas_probes, collector
from app.checks.active_collector import ACTIVE_PAUSE_RANGE_SECONDS, attach_probes, polite_pause
from app.checks.baas_collector import discover_backends
from app.checks.baas_probes import probe_backends
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BotProtection,
    DiscoveredBackend,
    ScanContext,
)
from app.checks.collector import collect_context
from app.checks.exposure import FIXED_PROBE_PATHS
from app.core.safe_http import MIN_SECONDS_BETWEEN_REQUESTS, SafeResponse, TlsProbe, TlsStatus
from tests.checks.helpers import response

CHALLENGE = response(status=403, headers={"x-vercel-mitigated": "challenge"})
RTDB = DiscoveredBackend(BaasKind.FIREBASE_RTDB, "my-app.firebaseio.com")


class FakeGet:
    def __init__(self, answer: SafeResponse | None = None) -> None:
        self.urls: list[str] = []
        self.answer = answer or response(status=404)

    def __call__(self, url: str, **_kwargs: Any) -> SafeResponse:
        self.urls.append(url)
        return self.answer


@pytest.fixture
def pauses(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr(active_collector, "sleep", recorded.append)
    return recorded


def site(*scripts: str, **overrides: Any) -> ScanContext:
    tags = "".join(f'<script src="{src}"></script>' for src in scripts)
    return ScanContext(
        hostname="example.com",
        https=response(url="https://example.com/", body=f"<html>{tags}</html>".encode()),
        **overrides,
    )


# --- pauses ---


def test_a_pause_is_within_its_range(pauses: list[float]) -> None:
    for _ in range(200):
        polite_pause()

    low, high = ACTIVE_PAUSE_RANGE_SECONDS
    assert all(low <= value <= high for value in pauses)
    assert len(set(pauses)) > 1


def test_pauses_are_long_enough_to_vary_the_gaps() -> None:
    # A shorter pause would be swallowed by the per-host limit, leaving an even beat.
    assert ACTIVE_PAUSE_RANGE_SECONDS[0] >= MIN_SECONDS_BETWEEN_REQUESTS


def test_each_sensitive_path_request_is_preceded_by_a_pause(
    monkeypatch: pytest.MonkeyPatch, pauses: list[float]
) -> None:
    fake = FakeGet()
    monkeypatch.setattr(active_collector, "safe_get", fake)

    attach_probes(site())

    assert len(fake.urls) == len(FIXED_PROBE_PATHS)
    assert len(pauses) == len(FIXED_PROBE_PATHS)


def test_each_script_request_is_preceded_by_a_pause(
    monkeypatch: pytest.MonkeyPatch, pauses: list[float]
) -> None:
    monkeypatch.setattr(baas_collector, "safe_get", FakeGet())

    discover_backends(site("/a.js", "/b.js"))

    assert len(pauses) == 2


def test_each_backend_probe_is_preceded_by_a_pause(
    monkeypatch: pytest.MonkeyPatch, pauses: list[float]
) -> None:
    monkeypatch.setattr(baas_probes, "safe_get", FakeGet(response(body=b"null")))
    ctx = ScanContext(hostname="example.com", baas=BaasDiscovery((RTDB,), (), 1, 1, 0))

    probe_backends(ctx, {RTDB})

    assert len(pauses) == 1


def test_no_pause_for_a_request_that_is_not_sent(
    monkeypatch: pytest.MonkeyPatch, pauses: list[float]
) -> None:
    monkeypatch.setattr(active_collector, "safe_get", FakeGet(CHALLENGE))

    attach_probes(site())

    assert len(pauses) == 1


# --- stopping at the first challenge ---


@pytest.fixture
def quiet_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        collector, "safe_tls_probe", lambda _host: TlsProbe(TlsStatus.OK, protocol="TLSv1.3")
    )
    monkeypatch.setattr(collector, "safe_dns_records", lambda _name, _type: [])


@pytest.mark.usefixtures("quiet_dns")
def test_challenge_on_https_means_no_http_request(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGet(CHALLENGE)
    monkeypatch.setattr(collector, "safe_get", fake)

    ctx = collect_context("example.com")

    assert fake.urls == ["https://example.com/"]
    assert ctx.blocked_by is BotProtection.VERCEL
    assert ctx.http is None


@pytest.mark.usefixtures("quiet_dns")
def test_challenge_on_http_is_remembered(monkeypatch: pytest.MonkeyPatch) -> None:
    def answer(url: str) -> SafeResponse:
        return CHALLENGE if url.startswith("http://") else response(url=url)

    monkeypatch.setattr(collector, "safe_get", answer)

    assert collect_context("example.com").blocked_by is BotProtection.VERCEL


def test_earlier_challenge_means_no_sensitive_path_requests(
    monkeypatch: pytest.MonkeyPatch, pauses: list[float]
) -> None:
    fake = FakeGet()
    monkeypatch.setattr(active_collector, "safe_get", fake)

    probes = attach_probes(site(blocked_by=BotProtection.VERCEL)).probes

    assert fake.urls == []
    assert pauses == []
    assert probes is not None
    assert all(probe.status_code is None for probe in probes.values())


def test_earlier_challenge_means_no_script_requests(
    monkeypatch: pytest.MonkeyPatch, pauses: list[float]
) -> None:
    fake = FakeGet()
    monkeypatch.setattr(baas_collector, "safe_get", fake)

    result = discover_backends(site("/a.js", blocked_by=BotProtection.VERCEL)).baas

    assert fake.urls == []
    assert pauses == []
    assert result is not None
    assert result.scripts_failed == 1
    assert "not requested" in result.skipped[0].reason


def test_challenge_during_scripts_stops_the_sensitive_paths_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scripts = FakeGet(CHALLENGE)
    paths = FakeGet()
    monkeypatch.setattr(baas_collector, "safe_get", scripts)
    monkeypatch.setattr(active_collector, "safe_get", paths)

    ctx = attach_probes(discover_backends(site("/a.js", "/b.js")))

    assert scripts.urls == ["https://example.com/a.js"]
    assert paths.urls == []
    assert ctx.blocked_by is BotProtection.VERCEL
