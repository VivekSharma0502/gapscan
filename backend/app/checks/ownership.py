"""Proving that someone controls a domain, by DNS record or by a file on the site."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum

from app.checks.base import BLOCKED_STATUSES
from app.checks.exposure import looks_like_html
from app.core.safe_http import (
    OffHostRedirectError,
    SafeHttpError,
    safe_dns_records,
    safe_get,
)

TXT_PREFIX = "_scankit-verify"
TXT_VALUE_PREFIX = "scankit-verify="
FILE_PATH = "/.well-known/scankit-verify.txt"
_MAX_FILE_BYTES = 4096


class VerificationMethod(StrEnum):
    DNS = "dns"
    FILE = "file"


class FailureCode(StrEnum):
    TXT_NOT_FOUND = "txt_not_found"
    TXT_MISMATCH = "txt_mismatch"
    DNS_LOOKUP_FAILED = "dns_lookup_failed"
    FILE_MISSING = "file_missing"
    FILE_IS_WEB_PAGE = "file_is_web_page"
    FILE_MISMATCH = "file_mismatch"
    FILE_REDIRECTED = "file_redirected"
    FILE_UNREACHABLE = "file_unreachable"


@dataclass(frozen=True)
class MethodFailure:
    method: VerificationMethod
    code: FailureCode
    message: str
    # True when the proof is really absent, False when we just couldn't find out.
    definite: bool


@dataclass(frozen=True)
class OwnershipResult:
    method: VerificationMethod | None
    failures: tuple[MethodFailure, ...] = ()

    @property
    def proven(self) -> bool:
        return self.method is not None

    @property
    def definitely_gone(self) -> bool:
        return not self.proven and all(failure.definite for failure in self.failures)


def txt_record_name(hostname: str) -> str:
    # A prefix, because a hostname with a CNAME, usual for hosted apps, can't also have a TXT.
    return f"{TXT_PREFIX}.{hostname}"


def txt_record_value(token: str) -> str:
    return f"{TXT_VALUE_PREFIX}{token}"


def verification_file_url(hostname: str) -> str:
    return f"https://{hostname}{FILE_PATH}"


def _check_dns(hostname: str, token: str) -> MethodFailure | None:
    name = txt_record_name(hostname)

    def failed(code: FailureCode, message: str, *, definite: bool = True) -> MethodFailure:
        return MethodFailure(VerificationMethod.DNS, code, message, definite)

    try:
        records = [record.strip() for record in safe_dns_records(name, "TXT")]
    except SafeHttpError:
        return failed(
            FailureCode.DNS_LOOKUP_FAILED,
            "The DNS lookup didn't complete. Please try again in a moment.",
            definite=False,
        )
    if txt_record_value(token) in records:
        return None
    if any(record.startswith(TXT_VALUE_PREFIX) for record in records):
        return failed(
            FailureCode.TXT_MISMATCH,
            f"The TXT record at {name} has a different token. Copy the value shown here.",
        )
    return failed(
        FailureCode.TXT_NOT_FOUND,
        f"No TXT record found at {name} yet. New DNS records can take a few minutes to appear.",
    )


def _check_file(hostname: str, token: str) -> MethodFailure | None:
    url = verification_file_url(hostname)

    def failed(code: FailureCode, message: str, *, definite: bool = True) -> MethodFailure:
        return MethodFailure(VerificationMethod.FILE, code, message, definite)

    unreachable = failed(
        FailureCode.FILE_UNREACHABLE,
        f"We couldn't reach {url}. Check the site is online and try again.",
        definite=False,
    )
    try:
        # Security: no other host may answer. Otherwise a redirect could let a server the
        # requester controls supply the token for a domain they don't.
        response = safe_get(url, allowed_hosts=frozenset({hostname}), max_bytes=_MAX_FILE_BYTES)
    except OffHostRedirectError:
        return failed(
            FailureCode.FILE_REDIRECTED,
            f"{url} redirects to a different site. Put the file on {hostname} itself, or "
            "use the DNS method.",
        )
    except SafeHttpError:
        return unreachable

    if response.status_code in BLOCKED_STATUSES or response.status_code >= 500:
        return unreachable
    if response.status_code != 200:
        return failed(
            FailureCode.FILE_MISSING,
            f"The file wasn't found at {url}. Upload it and redeploy your site if needed.",
        )
    if looks_like_html(response.content):
        return failed(
            FailureCode.FILE_IS_WEB_PAGE,
            f"{url} returned a web page instead of the file, so the file isn't being served.",
        )
    # Security: the whole file must be the token. Searching inside it could be satisfied by
    # a site that shows visitors' text on every page. utf-8-sig drops the mark Notepad adds.
    if response.content.decode("utf-8-sig", "replace").strip() != token:
        return failed(
            FailureCode.FILE_MISMATCH,
            f"The file at {url} doesn't match. It must contain only the token shown here.",
        )
    return None


def prove_ownership(hostname: str, token: str) -> OwnershipResult:
    """Try both methods at once, so a slow one doesn't add to the other's wait."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        dns_check = pool.submit(_check_dns, hostname, token)
        file_check = pool.submit(_check_file, hostname, token)
        dns_failure, file_failure = dns_check.result(), file_check.result()

    if dns_failure is None:
        return OwnershipResult(VerificationMethod.DNS)
    if file_failure is None:
        return OwnershipResult(VerificationMethod.FILE)
    return OwnershipResult(None, (dns_failure, file_failure))
