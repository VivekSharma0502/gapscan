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
TXT_NAME = "_gapscan-verify.app.example.com"
FILE_URL = "https://app.example.com/.well-known/gapscan-verify.txt"
LEGACY_TXT_NAME = "_scankit-verify.app.example.com"
LEGACY_FILE_URL = "https://app.example.com/.well-known/scankit-verify.txt"


class FakeNet:
    def __init__(self) -> None:
        self.txt: list[str] | Exception = []
        self.file: SafeResponse | Exception = response(status=404)
        self.txt_names: list[str] = []
        self.file_calls: list[tuple[str, dict[str, Any]]] = []
        # Answers for one specific name or URL, overriding the two defaults above.
        self.txt_at: dict[str, list[str] | Exception] = {}
        self.file_at: dict[str, SafeResponse | Exception] = {}

    def dns(self, name: str, record_type: str) -> list[str]:
        assert record_type == "TXT"
        self.txt_names.append(name)
        answer = self.txt_at.get(name, self.txt)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get(self, url: str, **kwargs: Any) -> SafeResponse:
        self.file_calls.append((url, kwargs))
        answer = self.file_at.get(url, self.file)
        if isinstance(answer, Exception):
            raise answer
        return answer


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
    assert txt_record_value(TOKEN) == f"gapscan-verify={TOKEN}"
    assert verification_file_url(HOST) == FILE_URL


# DNS


def test_matching_txt_record_proves_ownership(net: FakeNet) -> None:
    net.txt = ["v=spf1 -all", f"gapscan-verify={TOKEN}"]

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
    net.txt = ["gapscan-verify=someone-elses"]

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
    net.txt = [f"gapscan-verify={TOKEN}"]
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


# Names from before the rename


def test_old_names_do_not_count_for_a_new_domain(net: FakeNet) -> None:
    net.txt_at[LEGACY_TXT_NAME] = [f"scankit-verify={TOKEN}"]
    net.file_at[LEGACY_FILE_URL] = response(body=TOKEN.encode())

    assert not prove_ownership(HOST, TOKEN).proven


def test_new_domain_never_looks_up_the_old_names(net: FakeNet) -> None:
    prove_ownership(HOST, TOKEN)

    assert net.txt_names == [TXT_NAME]
    assert [url for url, _ in net.file_calls] == [FILE_URL]


def test_old_txt_record_proves_an_existing_domain(net: FakeNet) -> None:
    net.txt_at[LEGACY_TXT_NAME] = [f"scankit-verify={TOKEN}"]

    assert prove_ownership(HOST, TOKEN, accept_legacy=True).method is VerificationMethod.DNS


def test_old_file_proves_an_existing_domain(net: FakeNet) -> None:
    net.file_at[LEGACY_FILE_URL] = response(body=TOKEN.encode())

    assert prove_ownership(HOST, TOKEN, accept_legacy=True).method is VerificationMethod.FILE


def test_new_names_also_work_for_an_existing_domain(net: FakeNet) -> None:
    net.txt_at[TXT_NAME] = [f"gapscan-verify={TOKEN}"]

    assert prove_ownership(HOST, TOKEN, accept_legacy=True).proven


def test_old_file_request_stays_on_exactly_this_host(net: FakeNet) -> None:
    # Security: the older path gets the same no-other-host rule as the current one.
    prove_ownership(HOST, TOKEN, accept_legacy=True)

    assert {url for url, _ in net.file_calls} == {FILE_URL, LEGACY_FILE_URL}
    assert all(kwargs["allowed_hosts"] == {HOST} for _, kwargs in net.file_calls)


def test_wrong_token_at_the_old_name_does_not_count(net: FakeNet) -> None:
    net.txt_at[LEGACY_TXT_NAME] = ["scankit-verify=someone-elses"]

    assert not prove_ownership(HOST, TOKEN, accept_legacy=True).proven


def test_failures_shown_are_for_the_current_names_only(net: FakeNet) -> None:
    result = prove_ownership(HOST, TOKEN, accept_legacy=True)

    assert len(result.failures) == 2
    assert all(LEGACY_TXT_NAME not in item.message for item in result.failures)
    assert all(LEGACY_FILE_URL not in item.message for item in result.failures)


def test_all_names_definitely_absent_means_the_proof_is_gone(net: FakeNet) -> None:
    assert prove_ownership(HOST, TOKEN, accept_legacy=True).definitely_gone


@pytest.mark.parametrize("which", ["dns", "file"])
def test_temporary_failure_on_an_old_name_means_we_dont_know(net: FakeNet, which: str) -> None:
    # Security for users: the old record may still be there, so this must not unverify.
    if which == "dns":
        net.txt_at[LEGACY_TXT_NAME] = RequestFailedError("down")
    else:
        net.file_at[LEGACY_FILE_URL] = RequestFailedError("down")

    result = prove_ownership(HOST, TOKEN, accept_legacy=True)

    assert not result.proven
    assert not result.definitely_gone
