"""Step reporting for scan progress, and the gate that keeps active checks out of quick scans."""

import pytest

from app.checks import collector, runner
from app.checks.base import Category, ScanContext
from app.checks.collector import COLLECT_STEPS, collect_context
from app.checks.registry import CheckSpec
from app.checks.runner import run_checks, selected_checks
from app.core.safe_http import BlockedTargetError, TlsProbe, TlsStatus
from tests.checks.helpers import response


@pytest.fixture
def fake_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        collector, "safe_tls_probe", lambda _host: TlsProbe(TlsStatus.OK, protocol="TLSv1.3")
    )
    monkeypatch.setattr(collector, "safe_get", lambda _url: response())
    monkeypatch.setattr(collector, "safe_dns_records", lambda _name, _type: [])


@pytest.mark.usefixtures("fake_network")
def test_collector_reports_each_step_in_order() -> None:
    steps: list[str] = []
    collect_context("example.com", on_step=steps.append)
    assert steps == list(COLLECT_STEPS)


def test_collector_stops_reporting_after_a_blocked_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked(_host: str) -> TlsProbe:
        raise BlockedTargetError("address not allowed")

    monkeypatch.setattr(collector, "safe_tls_probe", blocked)
    steps: list[str] = []
    collect_context("internal.example.com", on_step=steps.append)
    assert steps == ["tls_probe"]


def _specs(calls: list[str]) -> list[CheckSpec]:
    def recorder(name: str):
        def run(_ctx: ScanContext) -> None:
            calls.append(name)

        return run

    return [
        CheckSpec("passive.one", Category.TLS, recorder("passive.one"), frozenset()),
        CheckSpec("active.one", Category.TLS, recorder("active.one"), frozenset(), active=True),
    ]


def test_active_checks_do_not_run_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(runner, "all_checks", lambda: _specs(calls))

    report = run_checks(ScanContext(hostname="example.com"))

    assert calls == ["passive.one"]
    assert "active.one" not in {item.check_id for item in report.skipped}
    assert [spec.check_id for spec in selected_checks()] == ["passive.one"]


def test_active_checks_run_only_when_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(runner, "all_checks", lambda: _specs(calls))

    run_checks(ScanContext(hostname="example.com"), allow_active=True)

    assert calls == ["passive.one", "active.one"]


def test_runner_reports_only_the_checks_it_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "all_checks", lambda: _specs([]))
    steps: list[str] = []

    run_checks(ScanContext(hostname="example.com"), on_step=steps.append)

    assert steps == ["passive.one"]
