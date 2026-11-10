"""Finds Firebase and Supabase backends, and server-only keys, in a site's own code.

Pure text matching, with no network access. Everything matched comes from a page the scanned
site controls, so each value must fit the exact shape of an official host or bucket before it
counts, and later steps can only ever contact what passes here.
"""

import re
from typing import Any
from urllib.parse import urlsplit

import jwt

from app.checks.base import BaasKind, DiscoveredBackend, ExposedServiceKey

SERVICE_ROLE_MASK = "eyJ****"
SECRET_KEY_MASK = "sb_secret_****"  # noqa: S105

# A Firebase config object is written on a few lines, so its fields sit close together.
_CONFIG_WINDOW_CHARS = 1500
_JWT_PART = r"[A-Za-z0-9_-]{10,4096}"

# Security: fully anchored, one label per wildcard. "evil.com/.firebaseio.com" or
# "x.firebaseio.com.evil.com" can never match.
_RTDB_HOST_RES = (
    re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.firebaseio\.com"),
    re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9-]{1,30}\.firebasedatabase\.app"),
)
_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")
_SUPABASE_URL_RE = re.compile(r"https:\\?/\\?/([a-z0-9]{20})\.supabase\.co(?![a-z0-9.-])")

# Quotes may be escaped, because frameworks embed these objects inside JSON strings.
_Q = r"""\\?["'`]"""
_OPTIONAL_Q = r"""\\?["'`]?"""
_API_KEY_RE = re.compile(rf"apiKey{_OPTIONAL_Q}\s*:\s*{_Q}AIza[0-9A-Za-z_-]{{35}}")
_JWT_RE = re.compile(rf"\beyJ{_JWT_PART}\.eyJ{_JWT_PART}\.{_JWT_PART}")
_SECRET_KEY_RE = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")
_PUBLISHABLE_KEY_RE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{20,}")
_SUPABASE_REF_RE = re.compile(r"[a-z0-9]{20}")
_FIREBASE_PROJECT_ID_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_TABLE_NAME = r"[A-Za-z_][A-Za-z0-9_]{0,62}"
_TABLE_NAME_RE = re.compile(_TABLE_NAME)
_FROM_CALL_RE = re.compile(rf"([A-Za-z0-9_$]*)\.from\(\s*{_Q}({_TABLE_NAME}){_Q}\s*\)")
# Array.from("x") and storage.from("bucket") look the same as a table query.
_NOT_TABLE_CLIENTS = frozenset({"Buffer", "Object", "Set", "Map", "storage"})


def _config_field(window: str, name: str) -> str | None:
    match = re.search(rf"""{name}{_OPTIONAL_Q}\s*:\s*{_Q}([^"'`\s]{{1,300}}?){_Q}""", window)
    return match.group(1).replace("\\", "") if match else None


def _rtdb_host(database_url: str) -> str | None:
    """Return the host of an official database URL, or None for anything else."""
    try:
        parts = urlsplit(database_url)
        port = parts.port
    except ValueError:
        return None
    # Security: a username, port or path would mean this isn't a plain database address.
    if parts.scheme != "https" or parts.username or port or parts.path not in ("", "/"):
        return None
    host = (parts.hostname or "").lower()
    return host if is_official_rtdb_host(host) else None


def is_official_rtdb_host(host: str) -> bool:
    return any(pattern.fullmatch(host) for pattern in _RTDB_HOST_RES)


def is_valid_bucket(name: str) -> bool:
    return _BUCKET_RE.fullmatch(name) is not None and ".." not in name


def _bucket_name(value: str) -> str | None:
    name = value.removeprefix("gs://").lower()
    return name if is_valid_bucket(name) else None


def is_valid_firebase_project_id(value: str) -> bool:
    return _FIREBASE_PROJECT_ID_RE.fullmatch(value) is not None


def _config_window(text: str, api_key: re.Match[str]) -> str:
    return text[
        max(0, api_key.start() - _CONFIG_WINDOW_CHARS) : api_key.end() + _CONFIG_WINDOW_CHARS
    ]


def find_firebase_project_ids(text: str) -> set[str]:
    """Return the project IDs in Firebase configs, including those with no database or bucket."""
    found: set[str] = set()
    for match in _API_KEY_RE.finditer(text):
        project = _config_field(_config_window(text, match), "projectId")
        # Security: the site controls this text, so a value of the wrong shape is dropped.
        if project is not None and is_valid_firebase_project_id(project):
            found.add(project)
    return found


def _firebase_backends(text: str) -> set[DiscoveredBackend]:
    found: set[DiscoveredBackend] = set()
    for match in _API_KEY_RE.finditer(text):
        window = _config_window(text, match)
        # An API key and a project id together mean this really is a Firebase config.
        project_value = _config_field(window, "projectId")
        if project_value is None:
            continue
        # Security: the site controls this text, so a value of the wrong shape is dropped.
        project = project_value if is_valid_firebase_project_id(project_value) else None
        database_url = _config_field(window, "databaseURL")
        host = _rtdb_host(database_url) if database_url else None
        if host:
            found.add(DiscoveredBackend(BaasKind.FIREBASE_RTDB, host, project))
        bucket_value = _config_field(window, "storageBucket")
        bucket = _bucket_name(bucket_value) if bucket_value else None
        if bucket:
            found.add(DiscoveredBackend(BaasKind.FIREBASE_STORAGE, bucket, project))
    return found


def find_backends(text: str) -> set[DiscoveredBackend]:
    supabase = {
        DiscoveredBackend(BaasKind.SUPABASE, match.group(1))
        for match in _SUPABASE_URL_RE.finditer(text)
    }
    return _firebase_backends(text) | supabase


def _supabase_claims(token: str) -> dict[str, Any]:
    try:
        # Security: the signature isn't checked because nothing here trusts this token. Only
        # its stated role and project are read, to tell which kind of key was published.
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}
    return claims if claims.get("iss") == "supabase" else {}


def _is_supabase_service_role(token: str) -> bool:
    return _supabase_claims(token).get("role") == "service_role"


def is_official_supabase_ref(ref: str) -> bool:
    return _SUPABASE_REF_RE.fullmatch(ref) is not None


def is_valid_table_name(name: str) -> bool:
    return _TABLE_NAME_RE.fullmatch(name) is not None


def find_anon_keys(text: str) -> dict[str, str]:
    """Return public anon keys by project. Security: any other role is never returned."""
    keys: dict[str, str] = {}
    for match in _JWT_RE.finditer(text):
        claims = _supabase_claims(match.group(0))
        ref = claims.get("ref")
        if claims.get("role") == "anon" and isinstance(ref, str):
            keys[ref] = match.group(0)
    return keys


def find_publishable_keys(text: str) -> set[str]:
    return set(_PUBLISHABLE_KEY_RE.findall(text))


def find_table_names(text: str) -> set[str]:
    """Return the names passed to supabase-js .from() calls."""
    return {
        match.group(2)
        for match in _FROM_CALL_RE.finditer(text)
        if match.group(1) not in _NOT_TABLE_CLIENTS and not match.group(1).endswith("Array")
    }


def find_service_role_refs(text: str) -> set[str]:
    """Return the projects that service_role keys in this text belong to, not the keys."""
    refs: set[str] = set()
    for match in _JWT_RE.finditer(text):
        claims = _supabase_claims(match.group(0))
        ref = claims.get("ref")
        if claims.get("role") == "service_role" and isinstance(ref, str):
            if is_official_supabase_ref(ref):
                refs.add(ref)
    return refs


def _only_one(values: set[str]) -> str | None:
    # With several projects in view, picking one would be a guess.
    return next(iter(values)) if len(values) == 1 else None


def find_exposed_keys(text: str, location: str) -> list[ExposedServiceKey]:
    """Report server-only Supabase keys. The keys themselves are not kept or returned."""
    found: list[ExposedServiceKey] = []
    if any(_is_supabase_service_role(match.group(0)) for match in _JWT_RE.finditer(text)):
        found.append(
            ExposedServiceKey(SERVICE_ROLE_MASK, location, _only_one(find_service_role_refs(text)))
        )
    if _SECRET_KEY_RE.search(text):
        # An sb_secret_ key doesn't name its project, so the URL beside it has to.
        urls = {match.group(1) for match in _SUPABASE_URL_RE.finditer(text)}
        found.append(ExposedServiceKey(SECRET_KEY_MASK, location, _only_one(urls)))
    return found
