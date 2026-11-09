"""The per-host request limit. Offline, with a fake clock."""

import ipaddress
import threading
from typing import Any

import httpx
import pytest

from app.core import safe_http
from app.core.config import Settings
from app.core.safe_http import (
    MIN_SECONDS_BETWEEN_REQUESTS,
    RequestFailedError,
    _HostThrottle,
    safe_get,
)

FAR_AWAY = 1_000_000.0


class FakeTime:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture
def fake_time() -> FakeTime:
    return FakeTime()


@pytest.fixture
def throttle(fake_time: FakeTime) -> _HostThrottle:
    return _HostThrottle(clock=fake_time.clock, sleep=fake_time.sleep)


def test_limit_is_about_two_requests_a_second() -> None:
    assert MIN_SECONDS_BETWEEN_REQUESTS == 0.5


def test_first_request_does_not_wait(throttle: _HostThrottle, fake_time: FakeTime) -> None:
    throttle.wait_for_turn("example.com", FAR_AWAY)

    assert fake_time.sleeps == []


def test_requests_to_one_host_are_spaced(throttle: _HostThrottle, fake_time: FakeTime) -> None:
    started = fake_time.now

    for _ in range(5):
        throttle.wait_for_turn("example.com", FAR_AWAY)

    assert fake_time.now - started == pytest.approx(2.0)


def test_no_wait_once_enough_time_has_passed(throttle: _HostThrottle, fake_time: FakeTime) -> None:
    throttle.wait_for_turn("example.com", FAR_AWAY)
    fake_time.now += 10

    throttle.wait_for_turn("example.com", FAR_AWAY)

    assert fake_time.sleeps == []


def test_hosts_are_limited_separately(throttle: _HostThrottle, fake_time: FakeTime) -> None:
    throttle.wait_for_turn("a.example.com", FAR_AWAY)
    throttle.wait_for_turn("b.example.com", FAR_AWAY)

    assert fake_time.sleeps == []


@pytest.mark.parametrize("variant", ["EXAMPLE.com", "example.com."])
def test_spellings_of_one_host_share_a_limit(
    throttle: _HostThrottle, fake_time: FakeTime, variant: str
) -> None:
    throttle.wait_for_turn("example.com", FAR_AWAY)
    throttle.wait_for_turn(variant, FAR_AWAY)

    assert fake_time.sleeps == [pytest.approx(0.5)]


def test_a_turn_past_the_deadline_fails_instead_of_waiting(
    throttle: _HostThrottle, fake_time: FakeTime
) -> None:
    throttle.wait_for_turn("example.com", FAR_AWAY)

    with pytest.raises(RequestFailedError):
        throttle.wait_for_turn("example.com", fake_time.now + 0.1)

    assert fake_time.sleeps == []


def test_a_refused_turn_does_not_push_back_the_next_one(
    throttle: _HostThrottle, fake_time: FakeTime
) -> None:
    throttle.wait_for_turn("example.com", FAR_AWAY)
    with pytest.raises(RequestFailedError):
        throttle.wait_for_turn("example.com", fake_time.now)

    throttle.wait_for_turn("example.com", FAR_AWAY)

    assert fake_time.sleeps == [pytest.approx(0.5)]


def test_concurrent_requests_get_separate_slots() -> None:
    delays: list[float] = []
    lock = threading.Lock()

    def record(seconds: float) -> None:
        with lock:
            delays.append(seconds)

    throttle = _HostThrottle(clock=lambda: 100.0, sleep=record)
    threads = [
        threading.Thread(target=throttle.wait_for_turn, args=("example.com", FAR_AWAY))
        for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(delays) == pytest.approx([0.5, 1.0, 1.5])


def test_finished_hosts_are_forgotten(fake_time: FakeTime, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(safe_http, "_MAX_THROTTLED_HOSTS", 3)
    throttle = _HostThrottle(clock=fake_time.clock, sleep=fake_time.sleep)
    for name in ("a.com", "b.com", "c.com"):
        throttle.wait_for_turn(name, FAR_AWAY)
    fake_time.now += 10

    throttle.wait_for_turn("d.com", FAR_AWAY)

    assert set(throttle._next_slot) == {"d.com"}


# --- every request goes through it ---


class RecordingThrottle:
    def __init__(self) -> None:
        self.hosts: list[str] = []

    def wait_for_turn(self, host: str, deadline: float) -> None:
        self.hosts.append(host)


@pytest.fixture
def recording(monkeypatch: pytest.MonkeyPatch) -> RecordingThrottle:
    fake = RecordingThrottle()
    monkeypatch.setattr(safe_http, "_throttle", fake)

    def resolve(_host: str, _deadline: float) -> list[Any]:
        return [ipaddress.ip_address("93.184.216.34")]

    monkeypatch.setattr(safe_http, "_resolve", resolve)
    return fake


def transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    monkeypatch.setattr(safe_http, "_make_transport", lambda: httpx.MockTransport(handler))


def test_a_request_takes_a_turn(
    recording: RecordingThrottle, monkeypatch: pytest.MonkeyPatch
) -> None:
    transport(monkeypatch, lambda _request: httpx.Response(200))

    safe_get("https://example.com/")

    assert recording.hosts == ["example.com"]


def test_each_redirect_takes_its_own_turn(
    recording: RecordingThrottle, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "https://other.com/next"})
        return httpx.Response(200)

    transport(monkeypatch, handler)

    safe_get("https://example.com/")

    assert recording.hosts == ["example.com", "other.com"]


def test_a_blocked_address_takes_no_turn(
    recording: RecordingThrottle, monkeypatch: pytest.MonkeyPatch
) -> None:
    def private(_host: str, _deadline: float) -> list[Any]:
        return [ipaddress.ip_address("10.0.0.1")]

    monkeypatch.setattr(safe_http, "_resolve", private)
    transport(monkeypatch, lambda _request: httpx.Response(200))

    with pytest.raises(safe_http.BlockedTargetError):
        safe_get("https://example.com/")

    assert recording.hosts == []


# --- identifying ourselves ---


def test_default_user_agent_is_clear_and_links_to_an_explanation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SCANNER_USER_AGENT", raising=False)

    agent = Settings(_env_file=None).scanner_user_agent

    assert agent == "GapScanBot/1.0 (+https://viivek.xyz/bot)"


def test_requests_carry_the_user_agent(
    recording: RecordingThrottle, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["user-agent"])
        return httpx.Response(200)

    transport(monkeypatch, handler)
    monkeypatch.setattr(safe_http.settings, "scanner_user_agent", "GapScanBot/1.0 (+x)")

    safe_get("https://example.com/")

    assert seen == ["GapScanBot/1.0 (+x)"]
