"""SSRF-safe HTTP client. Every outbound request from the backend must go through here.

The scanner fetches URLs chosen by anonymous users, so without this guard a scan could be
pointed at internal services or cloud metadata endpoints such as 169.254.169.254.

Each hop of a request is validated, resolved, and then connected to by IP, so the address
that was checked is the address that gets used.
"""

import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import warnings
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, TypeVar

import dns.exception
import dns.resolver
import httpx

from app.core.config import settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
DEFAULT_PORTS = {"http": 80, "https": 443}

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# At most about two requests a second to any one host, redirects included. A scanner that
# arrives in a burst looks like an attack, and can get a real site's protection switched on.
MIN_SECONDS_BETWEEN_REQUESTS = 0.5
_MAX_THROTTLED_HOSTS = 4096

CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 10.0
WRITE_TIMEOUT_SECONDS = 5.0
# A read timeout resets on every chunk, so a server dripping one byte at a time could
# otherwise hold a worker forever. This bounds the whole request, redirects included.
TOTAL_DEADLINE_SECONDS = 20.0

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# DNS-over-HTTPS fallbacks. These are IP literals on purpose: looking up a DoH server's
# name would need the DNS that just failed. Their certificates cover these IPs.
_DOH_ENDPOINTS = ("https://1.1.1.1/dns-query", "https://8.8.8.8/resolve")
_DOH_RECORD_TYPES = {"A": 1, "AAAA": 28}
_DOH_TEXT_RECORD_TYPES = {"TXT": 16, "CAA": 257}
_DOH_STATUS_OK = 0
_DOH_STATUS_NXDOMAIN = 3
# TXT data arrives quoted from some DoH servers, split into chunks of at most 255 bytes.
_DOH_TXT_CHUNK_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

TextRecordType = Literal["TXT", "CAA"]

_TLS_PORT = 443
# OpenSSL verification codes, translated so reports don't show OpenSSL's wording.
_X509_CERT_HAS_EXPIRED = 10
_X509_FAILURE_DETAILS = {
    9: "the certificate is not valid yet",
    18: "the certificate is self-signed",
    19: "the certificate chain ends in a self-signed certificate",
    20: "the certificate was issued by an authority browsers do not trust",
    21: "the server did not send its full certificate chain",
    62: "the certificate was issued for a different domain",
}
# Failures that mean this machine's OpenSSL could not offer the old versions at all.
_LOCAL_TLS_LIMITS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"}

# Names that only ever mean something on a private network.
_MAX_HOSTNAME_LENGTH = 253
_BLOCKED_HOSTNAMES = {"localhost"}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal")

_HOSTNAME_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")
# Security: a host whose last label is a number is not a domain name. Resolvers may read
# forms like 2130706433, 0x7f.1 or 127.1 as 127.0.0.1, so they are refused before DNS.
_NUMERIC_LAST_LABEL_RE = re.compile(r"^(\d+|0x[0-9a-f]*)$")

# Security: ipaddress.is_global returns True for these, but each one can carry or relay
# traffic to an address that was never validated (translation and tunnelling ranges).
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.88.99.0/24",  # 6to4 relay anycast
        "::/96",  # IPv4-compatible IPv6
        "64:ff9b::/96",  # NAT64
        "64:ff9b:1::/48",  # local-use NAT64
        "2001::/32",  # Teredo
        "2002::/16",  # 6to4
        "fec0::/10",  # deprecated site-local
    )
)


class SafeHttpError(Exception):
    """Base error. Messages stay generic so they never reveal internal addresses."""


class BlockedTargetError(SafeHttpError):
    """The URL or the address it resolves to is not allowed."""


class TooManyRedirectsError(SafeHttpError):
    """The redirect chain was longer than MAX_REDIRECTS."""


class OffHostRedirectError(SafeHttpError):
    """A redirect pointed outside the hosts this request is allowed to visit."""


class RedirectRefusedError(SafeHttpError):
    """A request carrying credentials was redirected. The redirect was not followed."""


class RequestFailedError(SafeHttpError):
    """DNS, network, TLS or deadline failure."""


class _DnsTierFailed(Exception):
    """One resolver could not give a complete answer, so the next one should be tried."""


@dataclass(frozen=True)
class SafeResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    content: bytes
    truncated: bool
    # Each URL redirected to, in order. Scanner checks need this for HTTP -> HTTPS.
    redirects: tuple[str, ...]


class TlsStatus(StrEnum):
    OK = "ok"
    EXPIRED = "expired"
    UNTRUSTED = "untrusted"
    NO_HTTPS = "no_https"


@dataclass(frozen=True)
class TlsProbe:
    status: TlsStatus
    # Plain-language reason when status is not OK.
    detail: str | None = None
    protocol: str | None = None
    not_after: datetime | None = None
    # None means we could not tell, which is different from the server refusing.
    legacy_accepted: bool | None = None


@dataclass(frozen=True)
class _Hop:
    status_code: int
    headers: httpx.Headers
    content: bytes
    truncated: bool
    location: str | None


_T = TypeVar("_T")


class _HostThrottle:
    """Spaces requests to each host, so a scan never arrives as a burst.

    Every request reserves its own slot under the lock and then waits outside it, so
    concurrent requests to one host queue up without blocking requests to other hosts.
    """

    def __init__(
        self,
        interval: float = MIN_SECONDS_BETWEEN_REQUESTS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._interval = interval
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_slot: dict[str, float] = {}

    def wait_for_turn(self, host: str, deadline: float) -> None:
        name = host.rstrip(".").lower()
        with self._lock:
            now = self._clock()
            if len(self._next_slot) >= _MAX_THROTTLED_HOSTS:
                self._next_slot = {key: slot for key, slot in self._next_slot.items() if slot > now}
            slot = max(now, self._next_slot.get(name, now))
            if slot > deadline:
                raise RequestFailedError("deadline exceeded")
            self._next_slot[name] = slot + self._interval
        if slot > now:
            self._sleep(slot - now)


_throttle = _HostThrottle()


def is_public_ip(ip: IPAddress) -> bool:
    # Security: is_global alone is not enough. It is True for multicast and for
    # IPv4-mapped IPv6 such as ::ffff:8.8.8.8, so those are excluded explicitly.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return False
    if any(ip in network for network in _BLOCKED_NETWORKS):
        return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def _parse_url(url: str | httpx.URL) -> httpx.URL:
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError) as exc:
        raise BlockedTargetError("invalid URL") from exc

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise BlockedTargetError("scheme not allowed")
    if parsed.userinfo:
        raise BlockedTargetError("credentials in URL not allowed")
    port = DEFAULT_PORTS[parsed.scheme] if parsed.port is None else parsed.port
    if port not in ALLOWED_PORTS:
        raise BlockedTargetError("port not allowed")
    return parsed


def _query_dns_servers(host: str, servers: list[str], tcp: bool, budget: float) -> list[IPAddress]:
    """Ask the given servers, or the system's configured ones if servers is empty."""
    tier_deadline = time.monotonic() + budget
    addresses: list[IPAddress] = []
    try:
        resolver = dns.resolver.Resolver(configure=not servers)
        if servers:
            resolver.nameservers = servers
        for record_type in ("A", "AAAA"):
            resolver.lifetime = tier_deadline - time.monotonic()
            try:
                answer = resolver.resolve(host, record_type, tcp=tcp)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            addresses.extend(ipaddress.ip_address(record.address) for record in answer)
    except dns.exception.DNSException as exc:
        raise _DnsTierFailed from exc
    return addresses


def _doh_answer_data(payload: Any, type_code: int) -> list[str]:
    status = payload["Status"]
    if status == _DOH_STATUS_NXDOMAIN:
        return []
    if status != _DOH_STATUS_OK:
        raise _DnsTierFailed
    # Answers can include CNAME records, which are not the type that was asked for.
    return [record["data"] for record in payload.get("Answer", []) if record["type"] == type_code]


def _parse_doh_answer(payload: Any, type_code: int) -> list[IPAddress]:
    return [ipaddress.ip_address(data) for data in _doh_answer_data(payload, type_code)]


def _unquote_txt(data: str) -> str:
    chunks = _DOH_TXT_CHUNK_RE.findall(data)
    if not data.startswith('"') or not chunks:
        return data
    return "".join(re.sub(r"\\(.)", r"\1", chunk) for chunk in chunks)


def _parse_doh_text_answer(payload: Any, type_code: int) -> list[str]:
    data = _doh_answer_data(payload, type_code)
    if type_code == _DOH_TEXT_RECORD_TYPES["TXT"]:
        return [_unquote_txt(item) for item in data]
    return data


def _doh_lookup(
    endpoint: str,
    host: str,
    record_types: dict[str, int],
    budget: float,
    parse: Callable[[Any, int], list[_T]],
) -> list[_T]:
    # Security: a hardcoded endpoint, with the same TLS checks and size cap as scan traffic.
    tier_deadline = time.monotonic() + budget
    headers = {"Accept": "application/dns-json", "User-Agent": settings.scanner_user_agent}
    results: list[_T] = []
    try:
        with httpx.Client(
            transport=_make_transport(), trust_env=False, follow_redirects=False
        ) as client:
            for record_type, type_code in record_types.items():
                with client.stream(
                    "GET",
                    endpoint,
                    params={"name": host, "type": record_type},
                    headers=headers,
                    timeout=_timeouts(tier_deadline),
                ) as response:
                    if response.status_code != httpx.codes.OK:
                        raise _DnsTierFailed
                    body, truncated = _read_capped(response, tier_deadline)
                if truncated:
                    raise _DnsTierFailed
                results.extend(parse(json.loads(body), type_code))
    except (
        httpx.HTTPError,
        RequestFailedError,
        ValueError,  # invalid JSON or IP address
        KeyError,  # missing field
        TypeError,  # JSON of the wrong shape
        AttributeError,
    ) as exc:
        raise _DnsTierFailed from exc
    return results


def _query_doh(endpoint: str, host: str, budget: float) -> list[IPAddress]:
    return _doh_lookup(endpoint, host, _DOH_RECORD_TYPES, budget, _parse_doh_answer)


def _query_system(host: str, budget: float) -> list[IPAddress]:
    # getaddrinfo has no timeout of its own, so it runs in a thread we can stop waiting for.
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
        results = future.result(timeout=budget)
    except (OSError, UnicodeError) as exc:  # TimeoutError and gaierror are OSErrors
        raise _DnsTierFailed from exc
    finally:
        executor.shutdown(wait=False)
    unique = dict.fromkeys(ipaddress.ip_address(result[4][0]) for result in results)
    return sorted(unique, key=lambda address: address.version)


def _first_working_tier(tiers: list[Callable[[float], list[_T]]], deadline: float) -> list[_T]:
    for tier in tiers:
        budget = min(settings.scanner_dns_timeout_seconds, deadline - time.monotonic())
        if budget <= 0:
            break
        try:
            # Security: answers are never merged across resolvers. A resolver that returned
            # only some records could otherwise hide a private address. Whatever comes back
            # still goes through the IP checks in _validated_ip, and a private answer
            # blocks the request instead of moving on to ask another resolver.
            return tier(budget)
        except _DnsTierFailed:
            continue
    raise RequestFailedError("DNS lookup failed")


def _resolve(host: str, deadline: float) -> list[IPAddress]:
    """Return every A and AAAA record for host, IPv4 first, using the first working resolver.

    Some networks block plain DNS, so this falls back from UDP to TCP to DNS-over-HTTPS
    to the operating system. Only failures move on to the next resolver. A definite answer,
    including "no such host", ends the chain. Each resolver gets its own timeout.
    """
    servers = [str(server) for server in settings.scanner_dns_servers]
    tiers: list[Callable[[float], list[IPAddress]]] = [
        lambda budget: _query_dns_servers(host, servers, False, budget),
        lambda budget: _query_dns_servers(host, servers, True, budget),
        lambda budget: _query_doh(_DOH_ENDPOINTS[0], host, budget),
        lambda budget: _query_doh(_DOH_ENDPOINTS[1], host, budget),
        lambda budget: _query_system(host, budget),
    ]
    return _first_working_tier(tiers, deadline)


def _validated_name(host: str) -> str:
    """Return host without a trailing dot, or raise if it is not an allowed domain name."""
    name = host.rstrip(".")
    if not _HOSTNAME_RE.fullmatch(name):
        raise BlockedTargetError("invalid host")
    if _NUMERIC_LAST_LABEL_RE.fullmatch(name.rsplit(".", 1)[-1]):
        raise BlockedTargetError("address not allowed")
    if name in _BLOCKED_HOSTNAMES or name.endswith(_BLOCKED_SUFFIXES):
        raise BlockedTargetError("host not allowed")
    return name


def normalize_scan_target(value: str) -> str:
    """Return the lowercase domain from a user's domain or http(s) URL, or raise.

    Security: runs the guard's own URL and name rules when the request arrives, so a bad
    target never reaches the queue. DNS is still checked by the worker, on every request.
    IP addresses are refused because scans are for named sites, not for walking IP ranges.
    """
    text = value.strip()
    parsed = _parse_url(text if "://" in text else f"https://{text}")
    # raw_host is the ASCII form, so a look-alike Unicode name can't dodge the checks.
    name = _validated_name(parsed.raw_host.decode("ascii"))
    if "." not in name or len(name) > _MAX_HOSTNAME_LENGTH:
        raise BlockedTargetError("invalid host")
    return name


def _validated_ip(host: str, deadline: float) -> IPAddress:
    """Return the IP to connect to for host, or raise if the host is not allowed."""
    if not host:
        raise BlockedTargetError("missing host")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not is_public_ip(literal):
            raise BlockedTargetError("address not allowed")
        return literal

    addresses = _resolve(_validated_name(host), deadline)
    if not addresses:
        raise RequestFailedError("host did not resolve")
    # Security: refuse if any record is private. Picking only the public ones would let
    # an attacker mix records and rely on behaviour we do not control.
    if not all(is_public_ip(address) for address in addresses):
        raise BlockedTargetError("address not allowed")
    return addresses[0]


def _make_transport() -> httpx.BaseTransport:
    # trust_env=False: certificates come from certifi, not environment overrides.
    return httpx.HTTPTransport(retries=0, trust_env=False)


def _timeouts(deadline: float) -> httpx.Timeout:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RequestFailedError("deadline exceeded")
    return httpx.Timeout(
        connect=min(CONNECT_TIMEOUT_SECONDS, remaining),
        read=min(READ_TIMEOUT_SECONDS, remaining),
        write=min(WRITE_TIMEOUT_SECONDS, remaining),
        pool=min(CONNECT_TIMEOUT_SECONDS, remaining),
    )


def _read_capped(
    response: httpx.Response, deadline: float, max_bytes: int = MAX_RESPONSE_BYTES
) -> tuple[bytes, bool]:
    # Security: counts decompressed bytes and stops at the cap, so a compressed response
    # cannot expand into an unbounded body.
    body = bytearray()
    for chunk in response.iter_bytes():
        if time.monotonic() > deadline:
            raise RequestFailedError("deadline exceeded")
        space_left = max_bytes - len(body)
        if len(chunk) > space_left:
            body += chunk[:space_left]
            return bytes(body), True
        body += chunk
    return bytes(body), False


def _send_pinned(
    method: str,
    url: httpx.URL,
    deadline: float,
    max_bytes: int,
    extra_headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
) -> _Hop:
    host = url.raw_host.decode("ascii")
    ip = _validated_ip(host, deadline)
    _throttle.wait_for_turn(host, deadline)
    timeouts = _timeouts(deadline)

    # Security: connect to the IP we just validated, not the hostname. If the HTTP
    # library resolved the name again, DNS could answer differently the second time
    # (DNS rebinding) and send us to an internal address.
    pinned_url = url.copy_with(host=str(ip))
    headers = httpx.Headers({"Accept": "*/*"})
    headers.update(extra_headers or {})
    # Security: applied last, so a caller can't redirect the request with its own Host header
    # or send traffic that hides who is making it.
    headers.update(
        {
            "Host": url.netloc.decode("ascii"),
            "User-Agent": settings.scanner_user_agent,
            "Accept-Encoding": "gzip, deflate",
        }
    )
    # Security: SNI carries the real hostname, so the certificate is still verified
    # against that name even though the connection is made to an IP.
    extensions = {"sni_hostname": host.rstrip(".")} if url.scheme == "https" else {}

    # Security: a fresh client per hop. A shared pool is keyed by IP, so two sites on one
    # CDN address could reuse a TLS connection whose certificate was checked for the other.
    # An explicit transport already makes httpx ignore HTTP_PROXY-style variables, which
    # could route around this guard. trust_env=False states that intent directly.
    try:
        with httpx.Client(
            transport=_make_transport(), trust_env=False, follow_redirects=False
        ) as client:
            request = client.build_request(
                method,
                pinned_url,
                headers=headers,
                content=body,
                extensions=extensions,
                timeout=timeouts,
            )
            response = client.send(request, stream=True)
            try:
                location = None
                if response.status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("location")
                content, truncated = b"", False
                if location is None and method != "HEAD":
                    content, truncated = _read_capped(response, deadline, max_bytes)
                return _Hop(response.status_code, response.headers, content, truncated, location)
            finally:
                response.close()
    except httpx.HTTPError as exc:
        raise RequestFailedError("request failed") from exc


def _fetch(
    method: str,
    url: str,
    allowed_hosts: frozenset[str] | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> SafeResponse:
    deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    current = _parse_url(url)
    redirects: list[str] = []

    # One initial request plus at most MAX_REDIRECTS followed redirects.
    for _ in range(MAX_REDIRECTS + 1):
        hop = _send_pinned(method, current, deadline, max_bytes)
        if hop.location is None:
            return SafeResponse(
                url=str(current),
                status_code=hop.status_code,
                headers=hop.headers,
                content=hop.content,
                truncated=hop.truncated,
                redirects=tuple(redirects),
            )
        # Security: every redirect target gets the full URL, DNS and IP checks again,
        # because a public site can redirect to an internal address.
        try:
            target = current.join(hop.location)
        except httpx.InvalidURL as exc:
            raise BlockedTargetError("invalid URL") from exc
        current = _parse_url(target)
        # Security: refused before the next request is sent. Active probes are only allowed
        # on verified domains, so merely following this redirect would break that rule.
        if allowed_hosts is not None:
            if current.raw_host.decode("ascii").rstrip(".") not in allowed_hosts:
                raise OffHostRedirectError("redirect left the allowed hosts")
        redirects.append(str(current))

    raise TooManyRedirectsError("too many redirects")


def safe_get(
    url: str,
    *,
    allowed_hosts: frozenset[str] | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> SafeResponse:
    """GET a URL. With allowed_hosts, a redirect to any other host raises instead of being sent."""
    return _fetch("GET", url, allowed_hosts, min(max_bytes, MAX_RESPONSE_BYTES))


def safe_head(url: str) -> SafeResponse:
    return _fetch("HEAD", url)


def safe_api_request(
    method: Literal["GET", "POST", "DELETE"],
    url: str,
    *,
    headers: Mapping[str, str],
    json_body: Any = None,
) -> SafeResponse:
    """Call an HTTPS API with credentials, under the same SSRF checks as any other request."""
    deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    target = _parse_url(url)
    # Security: credentials never travel over plain HTTP.
    if target.scheme != "https":
        raise BlockedTargetError("scheme not allowed")

    extra_headers = dict(headers)
    body = None
    if json_body is not None:
        body = json.dumps(json_body).encode()
        extra_headers["Content-Type"] = "application/json"

    hop = _send_pinned(method, target, deadline, MAX_RESPONSE_BYTES, extra_headers, body)
    # Security: never followed. Repeating the request elsewhere would hand over the token.
    if hop.location is not None:
        raise RedirectRefusedError("redirect refused for a request with credentials")
    return SafeResponse(
        url=str(target),
        status_code=hop.status_code,
        headers=hop.headers,
        content=hop.content,
        truncated=hop.truncated,
        redirects=(),
    )


def _make_tls_context() -> ssl.SSLContext:
    # The same trust store as scan traffic, so this probe and safe_get agree on validity.
    return httpx.create_ssl_context(trust_env=False)


def _make_legacy_tls_context() -> ssl.SSLContext | None:
    """Return a context offering only TLS 1.0/1.1, or None if this OpenSSL cannot do that."""
    if not (ssl.HAS_TLSv1 or ssl.HAS_TLSv1_1):
        return None
    # Security: verification is off because this connection only asks "would you agree to an
    # old protocol?". Nothing is sent over it and no data is read from it.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_1
        # Modern OpenSSL hides the old ciphers unless the security level is lowered.
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return context


def _tls_handshake(
    ip: IPAddress, name: str, context: ssl.SSLContext, deadline: float
) -> ssl.SSLSocket:
    _throttle.wait_for_turn(name, deadline)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RequestFailedError("deadline exceeded")
    # Security: connects to the validated IP on 443 only, for the same reason as _send_pinned.
    raw = socket.create_connection(
        (str(ip), _TLS_PORT), timeout=min(CONNECT_TIMEOUT_SECONDS, remaining)
    )
    try:
        raw.settimeout(min(READ_TIMEOUT_SECONDS, remaining))
        return context.wrap_socket(raw, server_hostname=name)
    except BaseException:
        raw.close()
        raise


def _accepts_legacy_tls(ip: IPAddress, name: str, deadline: float) -> bool | None:
    context = _make_legacy_tls_context()
    if context is None:
        return None
    try:
        with _tls_handshake(ip, name, context, deadline):
            return True
    except ssl.SSLError as exc:
        return None if getattr(exc, "reason", None) in _LOCAL_TLS_LIMITS else False
    except ConnectionError:
        return False  # many servers just drop a client offering only old protocols
    except (OSError, RequestFailedError):
        return None


def _cert_expiry(cert: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
    except (KeyError, TypeError, ValueError):
        return None


def _failed_verification(exc: ssl.SSLCertVerificationError) -> tuple[TlsStatus, str]:
    if exc.verify_code == _X509_CERT_HAS_EXPIRED:
        return TlsStatus.EXPIRED, "the certificate has expired"
    detail = _X509_FAILURE_DETAILS.get(exc.verify_code, "the certificate could not be verified")
    return TlsStatus.UNTRUSTED, detail


def safe_tls_probe(host: str) -> TlsProbe:
    """Inspect a host's TLS setup with handshakes only. No HTTP request is sent.

    Raises BlockedTargetError for a disallowed host, and RequestFailedError when the
    result is unknown, such as a timeout. A definite problem is returned as a status.
    """
    deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    # Security: the same URL, DNS and IP validation as an HTTP request.
    name = _parse_url(f"https://{host}/").raw_host.decode("ascii").rstrip(".")
    ip = _validated_ip(name, deadline)

    try:
        with _tls_handshake(ip, name, _make_tls_context(), deadline) as connection:
            protocol, cert = connection.version(), connection.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        status, detail = _failed_verification(exc)
        return TlsProbe(status, detail, legacy_accepted=_accepts_legacy_tls(ip, name, deadline))
    except ConnectionRefusedError:
        return TlsProbe(TlsStatus.NO_HTTPS, "port 443 refused the connection")
    except ssl.SSLEOFError as exc:
        raise RequestFailedError("TLS probe failed") from exc  # dropped, which proves nothing
    except ssl.SSLError:
        detail = "the server did not complete a modern TLS handshake"
        return TlsProbe(
            TlsStatus.NO_HTTPS, detail, legacy_accepted=_accepts_legacy_tls(ip, name, deadline)
        )
    except OSError as exc:
        raise RequestFailedError("TLS probe failed") from exc

    return TlsProbe(
        TlsStatus.OK,
        protocol=protocol,
        not_after=_cert_expiry(cert),
        legacy_accepted=_accepts_legacy_tls(ip, name, deadline),
    )


def _text_record_data(record: Any, record_type: TextRecordType) -> str:
    if record_type == "TXT":
        return b"".join(record.strings).decode("utf-8", "replace")
    return record.to_text()


def _query_text_records(
    name: str, record_type: TextRecordType, servers: list[str], tcp: bool, budget: float
) -> list[str]:
    try:
        resolver = dns.resolver.Resolver(configure=not servers)
        if servers:
            resolver.nameservers = servers
        resolver.lifetime = budget
        try:
            answer = resolver.resolve(name, record_type, tcp=tcp)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        return [_text_record_data(record, record_type) for record in answer]
    except dns.exception.DNSException as exc:
        raise _DnsTierFailed from exc


def safe_dns_records(name: str, record_type: TextRecordType) -> list[str]:
    """Return a name's TXT or CAA records. An empty list means there are none.

    Uses the same fallback chain as address lookups, minus the operating system, which
    can only answer for addresses. Raises RequestFailedError if every resolver fails.
    """
    deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    # Security: names are validated like hostnames so scan input can't probe internal zones.
    validated = _validated_name(name)
    servers = [str(server) for server in settings.scanner_dns_servers]
    types = {record_type: _DOH_TEXT_RECORD_TYPES[record_type]}

    def doh_tier(endpoint: str) -> Callable[[float], list[str]]:
        return lambda budget: _doh_lookup(
            endpoint, validated, types, budget, _parse_doh_text_answer
        )

    tiers: list[Callable[[float], list[str]]] = [
        lambda budget: _query_text_records(validated, record_type, servers, False, budget),
        lambda budget: _query_text_records(validated, record_type, servers, True, budget),
        doh_tier(_DOH_ENDPOINTS[0]),
        doh_tier(_DOH_ENDPOINTS[1]),
    ]
    return _first_working_tier(tiers, deadline)
