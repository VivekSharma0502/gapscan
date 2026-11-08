"""Gathers everything the passive checks need, using only the SSRF-safe client.

One failed input never stops the scan. It is left as None with a reason, so the checks
that needed it are reported as skipped instead of passed.
"""

import ipaddress

from app.checks.base import Input, ScanContext
from app.checks.domains import registrable_domain, shared_platform_suffix
from app.core.safe_http import (
    BlockedTargetError,
    SafeHttpError,
    SafeResponse,
    TlsProbe,
    TlsStatus,
    TooManyRedirectsError,
    safe_dns_records,
    safe_get,
    safe_tls_probe,
)

BLOCKED_REASON = "This address can't be scanned."
_DNS_FAILED_REASON = "The DNS lookup did not complete."
_ALL_INPUTS = tuple(Input)
_DNS_INPUTS = (Input.SPF, Input.DMARC, Input.CAA)


def _unreachable_reason(tls: TlsProbe | None, error: SafeHttpError) -> str:
    # The TLS result comes first because it explains why the HTTPS request failed.
    if tls is not None and tls.status is TlsStatus.EXPIRED:
        return "The certificate has expired, so the site can't be reached securely."
    if tls is not None and tls.status is TlsStatus.UNTRUSTED:
        return f"Certificate problem: {tls.detail}, so the site can't be reached securely."
    if tls is not None and tls.status is TlsStatus.NO_HTTPS:
        if tls.legacy_accepted:
            return "The site only supports outdated TLS, so it can't be reached securely."
        return "The site doesn't offer HTTPS, so its homepage can't be read securely."
    if isinstance(error, BlockedTargetError):
        return "The site redirected to an address that can't be scanned."
    if isinstance(error, TooManyRedirectsError):
        return "The site redirected too many times."
    return "We could not reach the site over HTTPS."


def _fetch_homepage(hostname: str, tls: TlsProbe | None) -> tuple[SafeResponse | None, str | None]:
    try:
        response = safe_get(f"https://{hostname}/")
    except SafeHttpError as exc:
        return None, _unreachable_reason(tls, exc)
    # An error or bot-block page doesn't show the site's real headers and cookies.
    if response.status_code >= 400:
        return None, (
            f"The homepage returned HTTP {response.status_code}, so its security settings "
            "could not be read."
        )
    return response, None


def _caa_lookup(hostname: str, domain: str) -> list[str]:
    # RFC 8659: a CAA record on a parent domain applies to every name below it.
    labels = hostname.split(".")
    for start in range(len(labels) - len(domain.split(".")) + 1):
        records = safe_dns_records(".".join(labels[start:]), "CAA")
        if records:
            return records
    return []


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _collect_dns(hostname: str) -> tuple[dict[str, object], dict[Input, str]]:
    def skip_all(reason: str) -> dict[Input, str]:
        return dict.fromkeys(_DNS_INPUTS, reason)

    if _is_ip_literal(hostname):
        return {}, skip_all("DNS checks don't apply to a bare IP address.")

    suffix = shared_platform_suffix(hostname)
    if suffix is not None:
        reason = f"{suffix} is a shared domain, so these records belong to the platform."
        return {"shared_platform_suffix": suffix}, skip_all(reason)

    domain = registrable_domain(hostname)
    if domain is None:
        return {}, skip_all("This hostname has no registered domain to check.")

    fields: dict[str, object] = {"email_domain": domain}
    reasons: dict[Input, str] = {}
    lookups = {
        Input.SPF: lambda: safe_dns_records(domain, "TXT"),
        Input.DMARC: lambda: safe_dns_records(f"_dmarc.{domain}", "TXT"),
        Input.CAA: lambda: _caa_lookup(hostname, domain),
    }
    for input_name, lookup in lookups.items():
        try:
            fields[input_name.value] = lookup()
        except SafeHttpError:
            reasons[input_name] = _DNS_FAILED_REASON
    return fields, reasons


def collect_context(hostname: str) -> ScanContext:
    name = hostname.lower().rstrip(".")
    reasons: dict[Input, str] = {}

    try:
        tls = safe_tls_probe(name)
    except BlockedTargetError:
        # Security: stop here, so a disallowed target gets no further requests or lookups.
        return ScanContext(hostname=name, skip_reasons=dict.fromkeys(_ALL_INPUTS, BLOCKED_REASON))
    except SafeHttpError:
        tls = None
        reasons[Input.TLS] = "We could not complete a TLS connection."

    https, https_reason = _fetch_homepage(name, tls)
    if https_reason is not None:
        reasons[Input.HTTPS] = https_reason

    try:
        http = safe_get(f"http://{name}/")
    except SafeHttpError:
        http = None
        reasons[Input.HTTP] = "We could not load the site over HTTP."

    dns_fields, dns_reasons = _collect_dns(name)
    reasons.update(dns_reasons)

    return ScanContext(
        hostname=name, https=https, http=http, tls=tls, skip_reasons=reasons, **dns_fields
    )
