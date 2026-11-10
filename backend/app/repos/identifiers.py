"""Works out which backend project a repo, and each secret in it, points at.

Pure text handling, with no network and no git. The scanner passes in text from the temporary
clone that a scan already holds, so correlation needs no new outbound requests.

Security: file text is only searched here and is never stored or returned. What comes out is
a project identifier, which the project's own code already exposes, and never a key. Every
value must fit the exact shape of an official identifier before it counts.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import replace
from urllib.parse import urlsplit

from app.checks.baas_discovery import (
    find_backends,
    find_service_role_refs,
    is_official_rtdb_host,
    is_official_supabase_ref,
    is_valid_bucket,
    is_valid_firebase_project_id,
)
from app.checks.base import BaasKind
from app.models.correlation import RepoIdentifierKind
from app.models.scan import IdentifierBasis
from app.repos.report import SecretHit

IdentifierPair = tuple[RepoIdentifierKind, str]

MAX_IDENTIFIERS = 200
MAX_FILES_READ = 200

_SERVICE_ROLE_RULE = "supabase-service-role-jwt"
_SECRET_KEY_RULE = "supabase-secret-key"  # noqa: S105
PRIVATE_KEY_RULE = "private-key"
SUPABASE_RULES = frozenset({_SERVICE_ROLE_RULE, _SECRET_KEY_RULE})
_RULES_TO_ATTRIBUTE = SUPABASE_RULES | {PRIVATE_KEY_RULE}

# For git grep -o, so only these short matches ever leave git, not the lines around them.
_QUOTE = "[\"']?"
_ASSIGN = f"{_QUOTE}[[:space:]]*[:=][[:space:]]*{_QUOTE}"
GREP_PATTERNS = (
    r"https://[a-z0-9]{20}\.supabase\.co",
    r"https://[a-z0-9-]+(\.[a-z0-9-]+)?\.(firebaseio\.com|firebasedatabase\.app)",
    f"(projectId|project_id|FIREBASE_PROJECT_ID){_ASSIGN}[a-z0-9-]+",
    f"(storageBucket|STORAGE_BUCKET){_ASSIGN}(gs://)?[a-z0-9._-]+",
)

_SUPABASE_LINE_RE = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
_PROJECT_LINE_RE = re.compile(
    r"(?:projectId|project_id|FIREBASE_PROJECT_ID)[\"']?\s*[:=]\s*[\"']?([a-z0-9-]+)"
)
_BUCKET_LINE_RE = re.compile(
    r"(?:storageBucket|STORAGE_BUCKET)[\"']?\s*[:=]\s*[\"']?(?:gs://)?([a-z0-9._-]+)"
)
_SERVICE_ACCOUNT_RE = re.compile(r'"type"\s*:\s*"service_account"')
_FILE_PROJECT_RE = re.compile(r'"project_id"\s*:\s*"([a-z0-9-]+)"')


def parse_grep_output(output: str) -> set[IdentifierPair]:
    """Turn git grep matches into the identifiers that pass validation."""
    found: set[IdentifierPair] = set()
    for line in output.splitlines():
        if match := _SUPABASE_LINE_RE.search(line):
            if is_official_supabase_ref(match.group(1)):
                found.add((RepoIdentifierKind.SUPABASE_REF, match.group(1)))
        elif match := _PROJECT_LINE_RE.search(line):
            if is_valid_firebase_project_id(match.group(1)):
                found.add((RepoIdentifierKind.FIREBASE_PROJECT, match.group(1)))
        elif match := _BUCKET_LINE_RE.search(line):
            if is_valid_bucket(match.group(1)):
                found.add((RepoIdentifierKind.FIREBASE_BUCKET, match.group(1)))
        elif line.startswith("https://"):
            host = urlsplit(line.strip()).hostname or ""
            if is_official_rtdb_host(host):
                found.add((RepoIdentifierKind.FIREBASE_RTDB, host))
    return found


def _only(values: Iterable[str]) -> str | None:
    distinct = set(values)
    return distinct.pop() if len(distinct) == 1 else None


def _supabase_refs_in(text: str) -> set[str]:
    return {item.identifier for item in find_backends(text) if item.kind is BaasKind.SUPABASE}


def _supabase_project_of(hit: SecretHit, text: str) -> tuple[str, IdentifierBasis] | None:
    if hit.rule_id == _SERVICE_ROLE_RULE:
        # Lines around the reported one too, in case a tool counts them differently.
        window = "\n".join(text.splitlines()[max(0, hit.line - 2) : hit.line + 1])
        ref = _only(find_service_role_refs(window))
        if ref is not None:
            return ref, IdentifierBasis.KEY_CLAIM
    ref = _only(_supabase_refs_in(text))
    return (ref, IdentifierBasis.SAME_FILE) if ref is not None else None


def _firebase_project_of(text: str) -> tuple[str, IdentifierBasis] | None:
    # A private key alone could be anything, such as an SSH key. Only a service account file
    # says which project it unlocks.
    if _SERVICE_ACCOUNT_RE.search(text) is None:
        return None
    project = _only(_FILE_PROJECT_RE.findall(text))
    if project is None or not is_valid_firebase_project_id(project):
        return None
    return project, IdentifierBasis.SAME_FILE


def attach_project_identifiers(
    hits: list[SecretHit],
    head_identifiers: set[IdentifierPair],
    read_file: Callable[[SecretHit], str | None],
) -> tuple[list[SecretHit], frozenset[IdentifierPair]]:
    """Tie each attributable secret to a project, and return all the repo's identifiers."""
    found = set(head_identifiers)
    resolved: dict[str, tuple[str, IdentifierBasis]] = {}
    files_read = 0
    for hit in hits:
        if hit.rule_id not in _RULES_TO_ATTRIBUTE or files_read >= MAX_FILES_READ:
            continue
        files_read += 1
        text = read_file(hit)
        if text is None:
            continue
        is_supabase = hit.rule_id in SUPABASE_RULES
        project = _supabase_project_of(hit, text) if is_supabase else _firebase_project_of(text)
        if project is None:
            continue
        resolved[hit.fingerprint] = project
        kind = (
            RepoIdentifierKind.SUPABASE_REF if is_supabase else RepoIdentifierKind.FIREBASE_PROJECT
        )
        found.add((kind, project[0]))

    only_ref = _only(value for kind, value in found if kind is RepoIdentifierKind.SUPABASE_REF)
    attributed: list[SecretHit] = []
    for hit in hits:
        project = resolved.get(hit.fingerprint)
        if project is None and hit.rule_id in SUPABASE_RULES and only_ref is not None:
            # A guess: the repo names just one project, so the key probably belongs to it.
            project = (only_ref, IdentifierBasis.ONLY_PROJECT)
        if project is None:
            attributed.append(hit)
        else:
            attributed.append(
                replace(hit, backend_identifier=project[0], identifier_basis=project[1])
            )
    return attributed, frozenset(sorted(found)[:MAX_IDENTIFIERS])
