"""Turns a gitleaks report into what GapScan is willing to keep."""

import hashlib
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError

from app.checks.base import Severity
from app.repos.rules import rule_for

MAX_FINDINGS = 1000

_SEVERITY_ORDER = list(Severity)
# Both match the same token, and the specific rule says more than the general one.
_MORE_SPECIFIC_THAN_JWT = "supabase-service-role-jwt"
_JWT_RULE = "jwt"


class UnsafeReportError(Exception):
    """The report can't be used. Raised without any of its content."""


class _ReportEntry(BaseModel):
    # Security: an allowlist. A report also has Author, Email, Message, Line and Match. They
    # aren't declared, so they are never read and can't reach the database or a log.
    model_config = ConfigDict(hide_input_in_errors=True)

    rule_id: str = Field(alias="RuleID", min_length=1, max_length=128)
    file_path: str = Field(alias="File", min_length=1)
    line: int = Field(alias="StartLine", ge=0)
    commit_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")] = Field(alias="Commit")
    fingerprint: str = Field(alias="Fingerprint", min_length=1)
    # Security: fails closed. If gitleaks ever hands back a real value, because of a changed
    # flag or a new version, the whole report is refused rather than risk storing it.
    secret: Literal["REDACTED"] = Field(alias="Secret")


_REPORT = TypeAdapter(list[_ReportEntry])


@dataclass(frozen=True)
class SecretHit:
    check_id: str
    severity: Severity
    title: str
    masked: str
    rule_id: str
    file_path: str
    line: int
    commit_sha: str
    fingerprint: str


@dataclass(frozen=True)
class ParsedReport:
    hits: list[SecretHit]
    # True when more were found than MAX_FINDINGS. The most serious ones are kept.
    truncated: bool


def _hit(entry: _ReportEntry) -> SecretHit:
    rule = rule_for(entry.rule_id)
    return SecretHit(
        check_id=f"secrets.{rule.provider.value}",
        severity=rule.severity,
        title=rule.title,
        masked=rule.mask,
        rule_id=entry.rule_id,
        file_path=entry.file_path,
        line=entry.line,
        commit_sha=entry.commit_sha,
        fingerprint=hashlib.sha256(entry.fingerprint.encode()).hexdigest(),
    )


def _without_shadowed_jwts(entries: list[_ReportEntry]) -> list[_ReportEntry]:
    specific = {
        (entry.commit_sha, entry.file_path, entry.line)
        for entry in entries
        if entry.rule_id == _MORE_SPECIFIC_THAN_JWT
    }
    return [
        entry
        for entry in entries
        if entry.rule_id != _JWT_RULE
        or (entry.commit_sha, entry.file_path, entry.line) not in specific
    ]


def parse_report(content: bytes) -> ParsedReport:
    try:
        entries = _REPORT.validate_json(content)
    except ValidationError:
        # Security: "from None", so the traceback doesn't carry the report's content.
        raise UnsafeReportError("the gitleaks report could not be used") from None

    unique = {entry.fingerprint: entry for entry in _without_shadowed_jwts(entries)}
    hits = sorted(
        (_hit(entry) for entry in unique.values()),
        key=lambda hit: (_SEVERITY_ORDER.index(hit.severity), hit.file_path, hit.line),
    )
    return ParsedReport(hits=hits[:MAX_FINDINGS], truncated=len(hits) > MAX_FINDINGS)
