from typing import Any

import pytest

from app.checks import ownership
from app.checks.ownership import (
    FailureCode,
    VerificationMethod,
    prove_ownership,
    txt_record_name,
    txt_record_value,
    verification_file_url,
)
from app.core.safe_http import (
    BlockedTargetError,
    OffHostRedirectError,
    RequestFailedError,
    SafeResponse,
)
from tests.checks.helpers import response

HOST = "app.example.com"
TOKEN = "tok_abc123"  # noqa: S105
TXT_NAME = "_scankit-verify.app.example.com"
FILE_URL = "https://app.example.com/.well-known/scankit-verify.txt"


class FakeNet:
    def __init__(self) -> None:
        self.txt: list[str] | Exception = []
        self.file: SafeResponse | Exception = response(status=404)
        self.txt_names: list[str] = []
        self.file_calls: list[tuple[str, dict[str, Any]]] = []

    def dns(self, name: str, record_type: str) -> list[str]:
        assert record_type == "TXT"
        self.txt_names.append(name)
        if isinstance(self.txt, Exception):
            raise self.txt
        return self.txt

    def get(self, url: str, **kwargs: Any) -> SafeResponse:
        self.file_calls.append((url, kwargs))
        if isinstance(self.file, Exception):
            raise self.file
        return self.file


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch) -> FakeNet:
    fake = FakeNet()
    monkeypatch.setattr(ownership, "safe_dns_records", fake.dns)
    monkeypatch.setattr(ownership, "safe_get", fake.get)
    return fake


def failure_for(net: FakeNet, method: VerificationMethod) -> Any:
    result = prove_ownership(HOST, TOKEN)
    return next(item for item in result.failures if item.method is method)


def test_instructions_use_the_prefixed_name_and_exact_url() -> None:
    assert txt_record_name(HOST) == TXT_NAME
    assert txt_record_value(TOKEN) == f"scankit-verify={TOKEN}"
    assert verification_file_url(HOST) == FILE_URL


# DNS


def test_matching_txt_record_proves_ownership(net: FakeNet) -> None:
    net.txt = ["v=spf1 -all", f"scankit-verify={TOKEN}"]

    result = prove_ownership(HOST, TOKEN)

    assert result.proven
    assert result.method is VerificationMethod.DNS
    assert net.txt_names == [TXT_NAME]


def test_missing_txt_mentions_dns_delay(net: FakeNet) -> None:
    failure = failure_for(net, VerificationMethod.DNS)

    assert failure.code is FailureCode.TXT_NOT_FOUND
    assert "few minutes" in failure.message
    assert TXT_NAME in failure.message
    assert failure.definite


def test_wrong_txt_token_is_a_mismatch(net: FakeNet) -> None:
    net.txt = ["scankit-verify=someone-elses"]

    failure = failure_for(net, VerificationMethod.DNS)

    assert failure.code is FailureCode.TXT_MISMATCH
    assert failure.definite


def test_bare_token_without_the_prefix_does_not_count(net: FakeNet) -> None:
    net.txt = [TOKEN]

    assert not prove_ownership(HOST, TOKEN).proven


def test_dns_failure_is_not_definite(net: FakeNet) -> None:
    net.txt = RequestFailedError("down")

    failure = failure_for(net, VerificationMethod.DNS)

    assert failure.code is FailureCode.DNS_LOOKUP_FAILED
    assert not failure.definite


# File


@pytest.mark.parametrize(
    "body", [TOKEN.encode(), f"\n {TOKEN}\r\n".encode(), f"﻿{TOKEN}\n".encode()]
)
def test_file_with_only_the_token_proves_ownership(net: FakeNet, body: bytes) -> None:
    net.file = response(body=body)

    assert prove_ownership(HOST, TOKEN).method is VerificationMethod.FILE


def test_file_request_stays_on_exactly_this_host(net: FakeNet) -> None:
    # Security: www is not allowed here, unlike probes. Proof must come from this host.
    prove_ownership(HOST, TOKEN)

    url, kwargs = net.file_calls[0]
    assert url == FILE_URL
    assert kwargs["allowed_hosts"] == {HOST}


def test_token_inside_a_longer_file_does_not_count(net: FakeNet) -> None:
    # Security: a site that echoes visitors' text must not be able to verify for them.
    net.file = response(body=f"latest comment: {TOKEN}".encode())

    failure = failure_for(net, VerificationMethod.FILE)

    assert failure.code is FailureCode.FILE_MISMATCH
    assert failure.definite


def test_spa_catch_all_is_reported_as_a_web_page(net: FakeNet) -> None:
    net.file = response(body=f"<!doctype html><html>{TOKEN}</html>".encode())

    failure = failure_for(net, VerificationMethod.FILE)

    assert failure.code is FailureCode.FILE_IS_WEB_PAGE
    assert failure.definite


def test_404_is_file_missing(net: FakeNet) -> None:
    failure = failure_for(net, VerificationMethod.FILE)

    assert failure.code is FailureCode.FILE_MISSING
    assert FILE_URL in failure.message
    assert failure.definite


def test_off_host_redirect_cannot_supply_the_token(net: FakeNet) -> None:
    net.file = OffHostRedirectError("left")

    failure = failure_for(net, VerificationMethod.FILE)

    assert failure.code is FailureCode.FILE_REDIRECTED
    assert failure.definite


@pytest.mark.parametrize(
    "file",
    [
        RequestFailedError("down"),
        BlockedTargetError("no"),
        response(status=500),
        response(status=403),
        response(status=429),
        response(status=503),
    ],
    ids=str,
)
def test_unreachable_file_is_not_definite(net: FakeNet, file: Any) -> None:
    net.file = file

    failure = failure_for(net, VerificationMethod.FILE)

    assert failure.code is FailureCode.FILE_UNREACHABLE
    assert not failure.definite


# Overall


def test_either_method_is_enough_and_reports_no_failures(net: FakeNet) -> None:
    net.txt = [f"scankit-verify={TOKEN}"]
    net.file = RequestFailedError("down")

    result = prove_ownership(HOST, TOKEN)

    assert result.proven
    assert result.failures == ()


def test_both_definite_failures_mean_the_proof_is_gone(net: FakeNet) -> None:
    result = prove_ownership(HOST, TOKEN)

    assert not result.proven
    assert result.definitely_gone


@pytest.mark.parametrize("which", ["dns", "file"])
def test_one_temporary_failure_means_we_dont_know(net: FakeNet, which: str) -> None:
    # Security for users: a blip must not strip a domain's verification.
    if which == "dns":
        net.txt = RequestFailedError("down")
    else:
        net.file = RequestFailedError("down")

    result = prove_ownership(HOST, TOKEN)

    assert not result.proven
    assert not result.definitely_gone
