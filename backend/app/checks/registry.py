"""Check registry. Group modules register their checks with the @check decorator."""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from app.checks.base import Category, Finding, Input, ScanContext, Severity
from app.checks.catalog import CATALOG

CheckFunc = Callable[[ScanContext], Finding | None]

MAX_EVIDENCE_CHARS = 500

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    category: Category
    func: CheckFunc
    requires: frozenset[Input]


_REGISTRY: dict[str, CheckSpec] = {}


def check(
    check_id: str, category: Category, requires: Iterable[Input] = ()
) -> Callable[[CheckFunc], CheckFunc]:
    """Register a check. Fails at import if its text is missing, so it can never ship blank."""

    def register(func: CheckFunc) -> CheckFunc:
        if check_id in _REGISTRY:
            raise ValueError(f"duplicate check id: {check_id}")
        if check_id not in CATALOG:
            raise ValueError(f"no catalog text for check: {check_id}")
        _REGISTRY[check_id] = CheckSpec(check_id, category, func, frozenset(requires))
        return func

    return register


def all_checks() -> list[CheckSpec]:
    return list(_REGISTRY.values())


def clean_evidence(value: str) -> str:
    # Security: evidence is copied from responses the scanned site controls, so control
    # characters are removed and the length is capped before it can reach a log or report.
    cleaned = _CONTROL_CHARS_RE.sub(" ", value).strip()
    if len(cleaned) > MAX_EVIDENCE_CHARS:
        return f"{cleaned[:MAX_EVIDENCE_CHARS]}..."
    return cleaned


def make_finding(check_id: str, severity: Severity, evidence: str) -> Finding:
    text = CATALOG[check_id]
    return Finding(
        check_id=check_id,
        category=_REGISTRY[check_id].category,
        severity=severity,
        title=text.title,
        evidence=clean_evidence(evidence),
        fix=text.fix,
    )
