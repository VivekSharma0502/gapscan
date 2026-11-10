"""Working out which backend project a repo and its secrets point at."""

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, select

from app.checks.base import Severity
from app.models.correlation import RepoIdentifier, RepoIdentifierKind
from app.models.scan import FindingRecord, IdentifierBasis
from app.repos import scanner
from app.repos.identifiers import (
    MAX_FILES_READ,
    attach_project_identifiers,
    parse_grep_output,
)
from app.repos.report import SecretHit, parse_report
from app.repos.scanner import read_identifiers, run_gitleaks, scan_workspace
from app.workers import tasks
from app.workers.tasks import run_repo_scan
from tests.test_repo_scan_flow import FakeScanner, add_scan, hit, result, seed
from tests.test_repo_scanner import (
    b64url,
    bare_copy,
    commit_file,
    git,
    requires_tools,
    supabase_key,
)

REF = "abcdefghijklmnopqrst"
OTHER_REF = "tsrqponmlkjihgfedcba"
SB = RepoIdentifierKind.SUPABASE_REF
PROJECT = RepoIdentifierKind.FIREBASE_PROJECT
RTDB = RepoIdentifierKind.FIREBASE_RTDB
BUCKET = RepoIdentifierKind.FIREBASE_BUCKET


# Built at run time, so nothing secret-shaped is ever committed to this repo.
def make_jwt(role: str = "service_role", ref: str = REF, iss: str = "supabase") -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"iss": iss, "ref": ref, "role": role}).encode())
    return f"{header}.{payload}.{b64url(os.urandom(32))}"


def secret_hit(rule_id: str, *, line: int = 1, name: str = "a") -> SecretHit:
    return SecretHit(
        check_id="secrets.supabase",
        severity=Severity.CRITICAL,
        title="t",
        masked="****",
        rule_id=rule_id,
        file_path=f"{name}.js",
        line=line,
        commit_sha="c" * 40,
        fingerprint=name,
    )


SERVICE = "supabase-service-role-jwt"
SECRET = "supabase-secret-key"  # noqa: S105


def attach(
    hits: list[SecretHit], text: str | None, head: set[Any] | None = None
) -> tuple[list[SecretHit], frozenset[Any]]:
    return attach_project_identifiers(hits, head or set(), lambda _hit: text)


# --- reading grep output ---


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (f"https://{REF}.supabase.co", (SB, REF)),
        (
            "https://my-app-default-rtdb.firebaseio.com",
            (RTDB, "my-app-default-rtdb.firebaseio.com"),
        ),
        (
            "https://my-app.europe-west1.firebasedatabase.app",
            (RTDB, "my-app.europe-west1.firebasedatabase.app"),
        ),
        ('projectId: "my-app-1"', (PROJECT, "my-app-1")),
        ('"project_id": "my-app-1"', (PROJECT, "my-app-1")),
        ("FIREBASE_PROJECT_ID=my-app-1", (PROJECT, "my-app-1")),
        ('storageBucket: "my-app.appspot.com"', (BUCKET, "my-app.appspot.com")),
        ("STORAGE_BUCKET=gs://my-app.appspot.com", (BUCKET, "my-app.appspot.com")),
    ],
)
def test_identifiers_are_recognised(line: str, expected: tuple[Any, str]) -> None:
    assert parse_grep_output(line) == {expected}


@pytest.mark.parametrize(
    "line",
    [
        "https://short.supabase.co",
        "https://a.b.firebaseio.com",
        'projectId: "x"',
        'projectId: "-bad-start"',
        "storageBucket: a",
        "https://evil.example",
        "",
    ],
)
def test_anything_else_is_dropped(line: str) -> None:
    assert parse_grep_output(line) == set()


# --- tying secrets to projects ---


def test_service_role_key_is_tied_to_its_project_by_its_claim() -> None:
    hits, found = attach([secret_hit(SERVICE)], f'key = "{make_jwt()}"')

    assert hits[0].backend_identifier == REF
    assert hits[0].identifier_basis is IdentifierBasis.KEY_CLAIM
    assert (SB, REF) in found


def test_the_key_itself_is_never_returned() -> None:
    token = make_jwt()

    hits, found = attach([secret_hit(SERVICE)], f'key = "{token}"')

    assert token not in repr(hits)
    assert token not in repr(found)


@pytest.mark.parametrize("line", [1, 2, 3])
def test_claim_is_found_when_the_line_number_is_off_by_one(line: int) -> None:
    text = f"\n{make_jwt()}\n"

    hits, _ = attach([secret_hit(SERVICE, line=line)], text)

    assert hits[0].identifier_basis is IdentifierBasis.KEY_CLAIM


@pytest.mark.parametrize(
    "token",
    [make_jwt(role="anon"), make_jwt(iss="someone-else"), make_jwt(ref="not-a-valid-ref")],
)
def test_other_tokens_give_no_claim(token: str) -> None:
    hits, _ = attach([secret_hit(SERVICE)], token)

    assert hits[0].identifier_basis is None


def test_two_projects_on_the_line_are_not_guessed_between() -> None:
    text = f"{make_jwt()} {make_jwt(ref=OTHER_REF)}"

    hits, _ = attach([secret_hit(SERVICE)], text)

    assert hits[0].backend_identifier is None


def test_secret_key_uses_a_supabase_url_in_the_same_file() -> None:
    hits, found = attach([secret_hit(SECRET)], f'url = "https://{REF}.supabase.co"')

    assert hits[0].backend_identifier == REF
    assert hits[0].identifier_basis is IdentifierBasis.SAME_FILE
    assert (SB, REF) in found


def test_two_urls_in_one_file_are_not_guessed_between() -> None:
    text = f'"https://{REF}.supabase.co" "https://{OTHER_REF}.supabase.co"'

    hits, _ = attach([secret_hit(SECRET)], text)

    assert hits[0].backend_identifier is None


def test_the_only_project_in_a_repo_is_a_labelled_guess() -> None:
    hits, _ = attach([secret_hit(SECRET)], "no url here", {(SB, REF)})

    assert hits[0].backend_identifier == REF
    assert hits[0].identifier_basis is IdentifierBasis.ONLY_PROJECT


def test_several_projects_in_a_repo_means_no_guess() -> None:
    hits, _ = attach([secret_hit(SECRET)], "no url here", {(SB, REF), (SB, OTHER_REF)})

    assert hits[0].backend_identifier is None


def test_an_unreadable_file_can_still_be_a_labelled_guess() -> None:
    hits, _ = attach([secret_hit(SECRET)], None, {(SB, REF)})

    assert hits[0].identifier_basis is IdentifierBasis.ONLY_PROJECT


def service_account(project: str = "my-app-1") -> str:
    return json.dumps(
        {"type": "service_account", "project_id": project, "private_key": "REDACTED-IN-TEST"}
    )


def test_firebase_service_account_is_tied_to_its_project() -> None:
    hits, found = attach([secret_hit("private-key")], service_account())

    assert hits[0].backend_identifier == "my-app-1"
    assert hits[0].identifier_basis is IdentifierBasis.SAME_FILE
    assert (PROJECT, "my-app-1") in found


def test_a_private_key_that_is_not_a_service_account_stays_unlinked() -> None:
    text = '{"project_id": "my-app-1"}\n-----BEGIN PRIVATE KEY-----'

    assert attach([secret_hit("private-key")], text)[0][0].backend_identifier is None


def test_a_private_key_is_never_guessed_from_the_repo() -> None:
    hits, _ = attach([secret_hit("private-key")], "plain", {(PROJECT, "my-app-1"), (SB, REF)})

    assert hits[0].backend_identifier is None


def test_other_rules_are_not_read_or_attributed() -> None:
    def must_not_read(_hit: SecretHit) -> str | None:
        raise AssertionError("read a file for a rule that can't be attributed")

    hits, _ = attach_project_identifiers([secret_hit("aws-access-token")], set(), must_not_read)

    assert hits[0].backend_identifier is None


def test_file_reads_are_capped() -> None:
    reads: list[str] = []

    def read(item: SecretHit) -> str | None:
        reads.append(item.fingerprint)
        return None

    hits = [secret_hit(SERVICE, name=str(i)) for i in range(MAX_FILES_READ + 5)]
    attach_project_identifiers(hits, set(), read)

    assert len(reads) == MAX_FILES_READ


# --- the real tools ---


@pytest.fixture
def source(tmp_path: Path) -> Path:
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    return repo


def real_hit(commit: str, path: str, rule: str, line: int = 1) -> SecretHit:
    return replace(secret_hit(rule, line=line), commit_sha=commit, file_path=path)


def read_real(source_repo: Path, hits: list[SecretHit]) -> tuple[list[SecretHit], frozenset[Any]]:
    with scan_workspace() as workspace:
        bare_copy(source_repo, workspace.repo)
        return read_identifiers(workspace.repo, hits)


@requires_tools
def test_config_on_the_default_branch_is_found(source: Path) -> None:
    commit_file(
        source,
        "config.js",
        f"""const url = "https://{REF}.supabase.co";
const firebaseConfig = {{
  databaseURL: "https://my-app-default-rtdb.firebaseio.com",
  projectId: "my-app-1",
  storageBucket: "my-app.appspot.com",
}};
""",
    )

    _, found = read_real(source, [])

    assert found == {
        (SB, REF),
        (RTDB, "my-app-default-rtdb.firebaseio.com"),
        (PROJECT, "my-app-1"),
        (BUCKET, "my-app.appspot.com"),
    }


@requires_tools
def test_a_key_deleted_from_the_latest_code_is_still_tied_to_its_project(source: Path) -> None:
    commit = commit_file(source, "env.js", f'KEY = "{make_jwt()}"\n')
    git(source, "rm", "env.js")
    git(source, "commit", "-m", "remove it")

    hits, found = read_real(source, [real_hit(commit, "env.js", SERVICE)])

    assert hits[0].backend_identifier == REF
    assert hits[0].identifier_basis is IdentifierBasis.KEY_CLAIM
    assert (SB, REF) in found


@requires_tools
def test_secret_key_with_a_url_beside_it(source: Path) -> None:
    text = f'URL="https://{REF}.supabase.co"\nKEY="{supabase_key()}"\n'
    commit = commit_file(source, "env.txt", text)

    hits, _ = read_real(source, [real_hit(commit, "env.txt", SECRET, line=2)])

    assert hits[0].identifier_basis is IdentifierBasis.SAME_FILE


@requires_tools
def test_a_missing_file_is_handled(source: Path) -> None:
    commit = commit_file(source, "readme.txt", "hello\n")

    hits, _ = read_real(source, [real_hit(commit, "gone.js", SERVICE)])

    assert hits[0].backend_identifier is None


@requires_tools
def test_repo_with_no_identifiers(source: Path) -> None:
    commit_file(source, "readme.txt", "hello\n")

    assert read_real(source, [])[1] == frozenset()


@requires_tools
def test_a_real_scan_links_a_key_without_keeping_it(source: Path) -> None:
    token = make_jwt()
    commit_file(source, "env.txt", f'KEY = "{token}"\n')

    with scan_workspace() as workspace:
        bare_copy(source, workspace.repo)
        report = parse_report(run_gitleaks(workspace, None))
        hits, found = read_identifiers(workspace.repo, report.hits)

    linked = [item for item in hits if item.rule_id == SERVICE]
    assert linked[0].backend_identifier == REF
    assert linked[0].identifier_basis is IdentifierBasis.KEY_CLAIM
    assert (SB, REF) in found
    assert token not in repr(hits) + repr(found)


def test_a_failure_returns_the_hits_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise subprocess.TimeoutExpired("git", 30)

    monkeypatch.setattr(scanner, "_git_bytes", boom)
    hits = [secret_hit(SERVICE)]

    assert read_identifiers(tmp_path, hits) == (hits, None)


def test_only_local_git_commands_are_used(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    commands: list[str] = []

    def record(_repo: Path, *args: str, **_kwargs: Any) -> bytes | None:
        commands.append(args[0])
        return b"1"

    monkeypatch.setattr(scanner, "_git_bytes", record)

    read_identifiers(tmp_path, [secret_hit(SERVICE)])

    assert set(commands) == {"grep", "cat-file"}


# --- saving ---


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeScanner:
    scanner_fake = FakeScanner()
    monkeypatch.setattr(tasks, "scan_repository", scanner_fake)
    return scanner_fake


def saved_identifiers(engine: Engine) -> dict[tuple[Any, str], RepoIdentifier]:
    with Session(engine) as session:
        return {(row.kind, row.value): row for row in session.exec(select(RepoIdentifier))}


def saved_findings(engine: Engine) -> list[FindingRecord]:
    with Session(engine) as session:
        return list(session.exec(select(FindingRecord)))


def run(engine: Engine, seeded: Any, **overrides: Any) -> UUID:
    scan_id = add_scan(engine, seeded, **overrides)
    run_repo_scan(str(scan_id))
    return scan_id


def linked_hit() -> SecretHit:
    return replace(hit(), backend_identifier=REF, identifier_basis=IdentifierBasis.KEY_CLAIM)


def test_identifiers_and_finding_links_are_saved(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = seed(db_engine)
    fake.result = replace(result(linked_hit()), identifiers=frozenset({(SB, REF)}))

    run(db_engine, seeded)

    assert (SB, REF) in saved_identifiers(db_engine)
    row = saved_findings(db_engine)[0]
    assert row.backend_identifier == REF
    assert row.identifier_basis is IdentifierBasis.KEY_CLAIM


def test_an_existing_finding_gets_its_link_and_keeps_its_first_seen(
    db_engine: Engine, fake: FakeScanner
) -> None:
    seeded = seed(db_engine)
    fake.result = result(hit())
    run(db_engine, seeded)
    original = saved_findings(db_engine)[0]
    assert original.backend_identifier is None

    fake.result = result(linked_hit())
    run(db_engine, seeded)

    rows = saved_findings(db_engine)
    assert len(rows) == 1
    assert rows[0].id == original.id
    assert rows[0].created_at == original.created_at
    assert rows[0].backend_identifier == REF


def test_rescan_keeps_an_identifiers_first_seen(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = seed(db_engine)
    fake.result = replace(result(), identifiers=frozenset({(SB, REF)}))
    run(db_engine, seeded)
    first = saved_identifiers(db_engine)[(SB, REF)].first_seen_at

    run(db_engine, seeded)

    rows = saved_identifiers(db_engine)
    assert len(rows) == 1
    assert rows[(SB, REF)].first_seen_at == first


def test_a_complete_scan_removes_identifiers_no_longer_present(
    db_engine: Engine, fake: FakeScanner
) -> None:
    seeded = seed(db_engine)
    fake.result = replace(result(), identifiers=frozenset({(SB, REF)}))
    run(db_engine, seeded)

    fake.result = replace(result(), identifiers=frozenset({(SB, OTHER_REF)}))
    run(db_engine, seeded)

    assert set(saved_identifiers(db_engine)) == {(SB, OTHER_REF)}


def test_a_push_scan_never_removes_identifiers(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = seed(db_engine)
    fake.result = replace(result(), identifiers=frozenset({(SB, REF)}))
    run(db_engine, seeded)

    fake.result = replace(result(full_history=False), identifiers=frozenset())
    run(db_engine, seeded, before_sha="a" * 40, after_sha="b" * 40)

    assert (SB, REF) in saved_identifiers(db_engine)


def test_a_truncated_scan_never_removes_identifiers(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = seed(db_engine)
    fake.result = replace(result(), identifiers=frozenset({(SB, REF)}))
    run(db_engine, seeded)

    fake.result = replace(result(truncated=True), identifiers=frozenset())
    run(db_engine, seeded)

    assert (SB, REF) in saved_identifiers(db_engine)


def test_git_grep_failing_is_not_the_same_as_finding_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def failed(_repo: Path, *_args: str, **_kwargs: Any) -> bytes | None:
        return None

    monkeypatch.setattr(scanner, "_git_bytes", failed)
    hits = [secret_hit(SERVICE)]

    assert read_identifiers(tmp_path, hits) == (hits, None)


def test_a_failed_read_keeps_saved_identifiers(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = seed(db_engine)
    fake.result = replace(result(), identifiers=frozenset({(SB, REF)}))
    run(db_engine, seeded)

    # A complete scan, the only kind allowed to remove identifiers.
    fake.result = replace(result(), identifiers=None)
    run(db_engine, seeded)

    assert (SB, REF) in saved_identifiers(db_engine)


def test_a_guess_does_not_replace_a_project_from_the_key(
    db_engine: Engine, fake: FakeScanner
) -> None:
    seeded = seed(db_engine)
    fake.result = result(linked_hit())
    run(db_engine, seeded)

    guessed = replace(
        hit(), backend_identifier=OTHER_REF, identifier_basis=IdentifierBasis.ONLY_PROJECT
    )
    fake.result = result(guessed)
    run(db_engine, seeded)

    saved = saved_findings(db_engine)[0]
    assert saved.backend_identifier == REF
    assert saved.identifier_basis is IdentifierBasis.KEY_CLAIM


def test_a_better_answer_replaces_a_guess(db_engine: Engine, fake: FakeScanner) -> None:
    seeded = seed(db_engine)
    guessed = replace(
        hit(), backend_identifier=OTHER_REF, identifier_basis=IdentifierBasis.ONLY_PROJECT
    )
    fake.result = result(guessed)
    run(db_engine, seeded)

    fake.result = result(linked_hit())
    run(db_engine, seeded)

    saved = saved_findings(db_engine)[0]
    assert saved.backend_identifier == REF
    assert saved.identifier_basis is IdentifierBasis.KEY_CLAIM
