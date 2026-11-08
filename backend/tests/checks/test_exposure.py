from collections.abc import Callable

import pytest

from app.checks import exposure
from app.checks.base import Finding, Input, Probe, ScanContext, Severity, SkipCheck
from app.checks.catalog import CATALOG
from app.checks.exposure import (
    BACKUP_FILES,
    DS_STORE_PATH,
    ENV_PATHS,
    FIXED_PROBE_PATHS,
    GIT_HEAD_PATH,
    LISTING_PATHS,
    MAX_KEY_NAMES,
    env_key_names,
    looks_like_html,
)
from app.checks.registry import all_checks
from app.checks.runner import selected_checks

SPA_PAGE = (
    b'<!DOCTYPE html><html><head><title>My App</title></head><body><div id="root"></div>'
    b'<script src="/app.js"></script></body></html>'
)
SECRET = "sk_live_51Hsuper_secret_value"  # noqa: S105
ENV_FILE = f"# production\nDATABASE_URL=postgres://u:{SECRET}@db/x\nexport STRIPE_KEY={SECRET}\n"

Check = Callable[[ScanContext], Finding | None]
ACTIVE_CHECKS: list[Check] = [
    exposure.env_file,
    exposure.git_directory,
    exposure.ds_store,
    exposure.backup_file,
    exposure.source_maps,
    exposure.directory_listing,
]
MAP_PATH = "/app.js.map"
ALL_PATHS = (*FIXED_PROBE_PATHS, MAP_PATH)


def context(default: Probe | None = None, **_: object) -> ScanContext:
    return ScanContext(hostname="example.com", probes=probes_with({}, default))


def probes_with(answers: dict[str, Probe], default: Probe | None = None) -> dict[str, Probe]:
    base = {
        path: Probe(path, default.status_code, default.content) if default else Probe(path, 404)
        for path in ALL_PATHS
    }
    return base | answers


def ctx(path: str, body: bytes, status: int = 200) -> ScanContext:
    return ScanContext(
        hostname="example.com", probes=probes_with({path: Probe(path, status, body)})
    )


# The gate


def test_every_exposure_check_is_active_only() -> None:
    exposure_specs = [spec for spec in all_checks() if spec.check_id.startswith("exposure.")]

    assert len(exposure_specs) == len(ACTIVE_CHECKS)
    assert all(spec.active and Input.PROBES in spec.requires for spec in exposure_specs)


def test_quick_scans_never_select_an_exposure_check() -> None:
    assert not [spec for spec in selected_checks() if spec.check_id.startswith("exposure.")]


# False positives


@pytest.mark.parametrize("check_func", ACTIVE_CHECKS, ids=lambda func: func.__name__)
def test_spa_catch_all_is_not_a_finding(check_func: Check) -> None:
    # Security rule from the brief: a 200 with the app's HTML for every path proves nothing.
    spa = Probe("", 200, SPA_PAGE)

    assert check_func(context(spa)) is None


@pytest.mark.parametrize("check_func", ACTIVE_CHECKS, ids=lambda func: func.__name__)
def test_all_404s_are_clear(check_func: Check) -> None:
    assert check_func(context()) is None


@pytest.mark.parametrize("check_func", ACTIVE_CHECKS, ids=lambda func: func.__name__)
def test_403_counts_as_not_exposed(check_func: Check) -> None:
    assert check_func(context(Probe("", 403, b"Forbidden"))) is None


@pytest.mark.parametrize("check_func", ACTIVE_CHECKS, ids=lambda func: func.__name__)
def test_no_answers_means_skipped_not_clear(check_func: Check) -> None:
    with pytest.raises(SkipCheck):
        check_func(context(Probe("", None)))


def test_a_real_finding_wins_over_unanswered_paths() -> None:
    answers = {"/.env.local": Probe("/.env.local"), "/.env": Probe("/.env", 200, ENV_FILE.encode())}
    probes = ScanContext(hostname="example.com", probes=probes_with(answers))

    assert exposure.env_file(probes) is not None


@pytest.mark.parametrize(
    "body",
    [
        b"<!doctype html><p>A=1</p>",
        b"  \n<HTML>A=1\nB=2</HTML>",
        b"\xef\xbb\xbf<html>",
        b"<!-- comment --><div>",
    ],
)
def test_html_is_recognised(body: bytes) -> None:
    assert looks_like_html(body)


@pytest.mark.parametrize("body", [b"A=1\nB=2", b"", b"<?php echo 1;", b'{"version":3}'])
def test_other_content_is_not_html(body: bytes) -> None:
    assert not looks_like_html(body)


# .env


def test_env_file_is_critical_and_lists_key_names() -> None:
    finding = exposure.env_file(ctx("/.env", ENV_FILE.encode()))

    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert "DATABASE_URL" in finding.evidence
    assert "STRIPE_KEY" in finding.evidence


def test_env_values_are_never_in_the_evidence() -> None:
    # Security: never store file contents, only key names.
    finding = exposure.env_file(ctx("/.env", ENV_FILE.encode()))

    assert finding is not None
    assert SECRET not in finding.evidence
    assert "postgres" not in finding.evidence


def test_env_key_list_is_capped() -> None:
    body = "\n".join(f"KEY_{index}=x" for index in range(MAX_KEY_NAMES + 5)).encode()

    finding = exposure.env_file(ctx("/.env", body))

    assert finding is not None
    assert "KEY_0" in finding.evidence
    assert f"KEY_{MAX_KEY_NAMES}" not in finding.evidence
    assert "and 5 more" in finding.evidence


@pytest.mark.parametrize("path", ENV_PATHS)
def test_every_env_path_is_checked(path: str) -> None:
    assert exposure.env_file(ctx(path, b"API_KEY=abc")) is not None


@pytest.mark.parametrize(
    "body",
    [
        b"Welcome to our site.\nThis page is about pricing.\nprice=10 for most people\nThanks",
        b"",
        b"# only a comment\n",
        b'{"key": "value"}',
    ],
)
def test_text_that_is_not_an_env_file_is_ignored(body: bytes) -> None:
    assert env_key_names(body) is None


# .git


@pytest.mark.parametrize("body", [b"ref: refs/heads/main\n", b"a" * 40 + b"\n", b"f" * 64])
def test_git_head_is_critical(body: bytes) -> None:
    finding = exposure.git_directory(ctx(GIT_HEAD_PATH, body))

    assert finding is not None
    assert finding.severity is Severity.CRITICAL


def test_git_branch_name_is_not_stored() -> None:
    finding = exposure.git_directory(ctx(GIT_HEAD_PATH, b"ref: refs/heads/client-acme-secret"))

    assert finding is not None
    assert "client-acme" not in finding.evidence


@pytest.mark.parametrize("body", [b"ref: nope", b"abc123", b"reference: refs/heads/main"])
def test_text_that_is_not_git_head_is_ignored(body: bytes) -> None:
    assert exposure.git_directory(ctx(GIT_HEAD_PATH, body)) is None


# .DS_Store


def test_ds_store_needs_its_magic_bytes() -> None:
    finding = exposure.ds_store(ctx(DS_STORE_PATH, b"\x00\x00\x00\x01Bud1\x00\x00secret.txt"))

    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert "secret.txt" not in finding.evidence
    assert exposure.ds_store(ctx(DS_STORE_PATH, b"just some text")) is None


# Backups


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/backup.zip", b"PK\x03\x04rest"),
        ("/site.zip", b"PK\x03\x04rest"),
        ("/backup.tar.gz", b"\x1f\x8brest"),
        ("/backup.sql", b"-- MySQL dump 10.13\n"),
        ("/dump.sql", b"-- PostgreSQL database dump\n"),
        ("/database.sql", b"\n\nCREATE TABLE users (id int);"),
        ("/db.sql", b"INSERT INTO users VALUES (1, 'alice@example.com');"),
        ("/wp-config.php.bak", b"<?php\ndefine('DB_PASSWORD', 'hunter2');"),
    ],
)
def test_backup_signature_is_critical(path: str, body: bytes) -> None:
    finding = exposure.backup_file(ctx(path, body))

    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert path in finding.evidence
    assert b"alice" not in finding.evidence.encode()
    assert b"hunter2" not in finding.evidence.encode()


def test_every_backup_path_has_a_signature() -> None:
    assert all(path in FIXED_PROBE_PATHS for path in BACKUP_FILES)


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/backup.zip", b"not an archive"),
        ("/backup.tar.gz", b"PK\x03\x04 wrong type"),
        ("/backup.sql", b"Hello, this page mentions nothing"),
        ("/wp-config.php.bak", b"plain text"),
    ],
)
def test_wrong_content_for_a_backup_path_is_ignored(path: str, body: bytes) -> None:
    assert exposure.backup_file(ctx(path, body)) is None


# Source maps


def test_source_map_is_found_even_when_cut_off() -> None:
    body = b'{"version":3,"file":"app.js","sources":["src/secret-plan.ts"],"mappings":"AAAA'

    finding = exposure.source_maps(ctx(MAP_PATH, body))

    assert finding is not None
    assert finding.severity is Severity.MEDIUM
    assert MAP_PATH in finding.evidence
    assert "secret-plan" not in finding.evidence


@pytest.mark.parametrize("body", [b'{"version":2,"sources":[]}', b'{"version":3}', b"not json"])
def test_other_files_at_a_map_path_are_ignored(body: bytes) -> None:
    assert exposure.source_maps(ctx(MAP_PATH, body)) is None


def test_no_scripts_means_nothing_to_report() -> None:
    assert exposure.source_maps(ScanContext(hostname="example.com", probes={})) is None


# Directory listing


@pytest.mark.parametrize(
    "body",
    [
        b"<html><head><title>Index of /uploads</title></head>",
        b"<html><body><h1>Index of /uploads/</h1>",
        b"<title>Directory listing for /uploads/</title>",
        b"<pre>[To Parent Directory]</pre>",
    ],
)
def test_directory_listing_is_recognised(body: bytes) -> None:
    finding = exposure.directory_listing(ctx(LISTING_PATHS[0], body))

    assert finding is not None
    assert finding.severity is Severity.MEDIUM


def test_a_page_that_mentions_an_index_is_not_a_listing() -> None:
    body = b"<html><title>Uploads</title><p>See the Index of /uploads in the docs</p>"

    assert exposure.directory_listing(ctx(LISTING_PATHS[0], body)) is None


def test_every_exposure_check_has_catalog_text() -> None:
    assert {key for key in CATALOG if key.startswith("exposure.")} == {
        spec.check_id for spec in all_checks() if spec.check_id.startswith("exposure.")
    }
