"""SSRF-safe HTTP client. Every outbound request from the backend must go through here.

ScanKit fetches URLs chosen by anonymous users, so without this guard a scan could be
pointed at internal services or cloud metadata endpoints such as 169.254.169.254.

Each hop of a request is validated, resolved, and then connected to by IP, so the address
that was checked is the address that gets used.
"""

import ipaddress
import re
import time
from dataclasses import dataclass

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

DNS_TIMEOUT_SECONDS = 3.0
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 10.0
WRITE_TIMEOUT_SECONDS = 5.0
# A read timeout resets on every chunk, so a server dripping one byte at a time could
# otherwise hold a worker forever. This bounds the whole request, redirects included.
TOTAL_DEADLINE_SECONDS = 20.0

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Names that only ever mean something on a private network.
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


class RequestFailedError(SafeHttpError):
    """DNS, network, TLS or deadline failure."""


@dataclass(frozen=True)
class SafeResponse:
    url: str
    status_code: int
    headers: httpx.Headers
    content: bytes
    truncated: bool
    # Each URL redirected to, in order. Scanner checks need this for HTTP -> HTTPS.
    redirects: tuple[str, ...]


@dataclass(frozen=True)
class _Hop:
    status_code: int
    headers: httpx.Headers
    content: bytes
    truncated: bool
    location: str | None


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


def _resolve(host: str) -> list[IPAddress]:
    """Return every A and AAAA record for host, IPv4 first."""
    addresses: list[IPAddress] = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT_SECONDS
        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(host, record_type)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            addresses.extend(ipaddress.ip_address(record.address) for record in answer)
    except dns.exception.DNSException as exc:
        # Security: fail closed. A partial answer could hide a private record.
        raise RequestFailedError("DNS lookup failed") from exc
    return addresses


def _validated_ip(host: str) -> IPAddress:
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

    name = host.rstrip(".")
    if not _HOSTNAME_RE.fullmatch(name):
        raise BlockedTargetError("invalid host")
    if _NUMERIC_LAST_LABEL_RE.fullmatch(name.rsplit(".", 1)[-1]):
        raise BlockedTargetError("address not allowed")
    if name in _BLOCKED_HOSTNAMES or name.endswith(_BLOCKED_SUFFIXES):
        raise BlockedTargetError("host not allowed")

    addresses = _resolve(name)
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


def _read_capped(response: httpx.Response, deadline: float) -> tuple[bytes, bool]:
    # Security: counts decompressed bytes and stops at the cap, so a compressed response
    # cannot expand into an unbounded body.
    body = bytearray()
    for chunk in response.iter_bytes():
        if time.monotonic() > deadline:
            raise RequestFailedError("deadline exceeded")
        space_left = MAX_RESPONSE_BYTES - len(body)
        if len(chunk) > space_left:
            body += chunk[:space_left]
            return bytes(body), True
        body += chunk
    return bytes(body), False


def _send_pinned(method: str, url: httpx.URL, deadline: float) -> _Hop:
    host = url.raw_host.decode("ascii")
    ip = _validated_ip(host)
    timeouts = _timeouts(deadline)

    # Security: connect to the IP we just validated, not the hostname. If the HTTP
    # library resolved the name again, DNS could answer differently the second time
    # (DNS rebinding) and send us to an internal address.
    pinned_url = url.copy_with(host=str(ip))
    headers = {
        "Host": url.netloc.decode("ascii"),
        "User-Agent": settings.scanner_user_agent,
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate",
    }
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
                method, pinned_url, headers=headers, extensions=extensions, timeout=timeouts
            )
            response = client.send(request, stream=True)
            try:
                location = None
                if response.status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("location")
                content, truncated = b"", False
                if location is None and method != "HEAD":
                    content, truncated = _read_capped(response, deadline)
                return _Hop(response.status_code, response.headers, content, truncated, location)
            finally:
                response.close()
    except httpx.HTTPError as exc:
        raise RequestFailedError("request failed") from exc


def _fetch(method: str, url: str) -> SafeResponse:
    deadline = time.monotonic() + TOTAL_DEADLINE_SECONDS
    current = _parse_url(url)
    redirects: list[str] = []

    # One initial request plus at most MAX_REDIRECTS followed redirects.
    for _ in range(MAX_REDIRECTS + 1):
        hop = _send_pinned(method, current, deadline)
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
        redirects.append(str(current))

    raise TooManyRedirectsError("too many redirects")


def safe_get(url: str) -> SafeResponse:
    return _fetch("GET", url)


def safe_head(url: str) -> SafeResponse:
    return _fetch("HEAD", url)
