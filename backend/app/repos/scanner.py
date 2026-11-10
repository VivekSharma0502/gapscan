"""Downloads a repo into a temporary folder and runs gitleaks over its history.

The repo's contents are untrusted input and may hold live secrets. So git runs with every
way of executing repo-supplied code turned off, the clone is bare so no file is ever written
out from the repo, and the folder is removed afterwards whatever happened.
"""

import base64
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.core.github_app import (
    GithubRepository,
    InstallationToken,
    create_installation_token,
    get_repository,
    revoke_installation_token,
)
from app.repos.identifiers import (
    GREP_PATTERNS,
    IdentifierPair,
    attach_project_identifiers,
    parse_grep_output,
)
from app.repos.report import SecretHit, parse_report

logger = logging.getLogger(__name__)

STEP_CLONE = "repo_clone"
STEP_SECRETS = "repo_secrets"
REPO_STEPS = (STEP_CLONE, STEP_SECRETS)

MAX_REPO_SIZE_KB = 500 * 1024
# GitHub's reported size is only an estimate, so the real download is measured as well.
MAX_CLONE_DISK_BYTES = 1024 * 1024 * 1024
MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_SCANNED_FILE_MB = 5
CLONE_TIMEOUT_SECONDS = 180.0
GITLEAKS_TIMEOUT_SECONDS = 300.0
GIT_READ_TIMEOUT_SECONDS = 30.0
# Config files and service account files are small, so anything larger is neither.
MAX_IDENTIFIER_FILE_BYTES = 2 * 1024 * 1024
POLL_SECONDS = 1.0
KILL_WAIT_SECONDS = 15.0

WORKSPACE_PREFIX = "gapscan-repo-"
# Longer than any scan can run, so a sweep never removes a folder that is still in use.
WORKSPACE_ABANDONED_AFTER_SECONDS = 3600.0
_REMOVE_ATTEMPTS = 5

GITLEAKS_CONFIG = Path(__file__).with_name("gitleaks.toml")

_TOO_LARGE = "This repository is over the 500 MB limit, so it wasn't scanned."
_CLONE_TOO_SLOW = "This repository took too long to download, so it wasn't scanned."
_CLONE_TOO_BIG = "This repository grew past the size limit while downloading, so it wasn't scanned."
_SCAN_TOO_SLOW = "Scanning this repository's history took too long, so it didn't finish."

_SHA_RE = re.compile(r"[0-9a-f]{40}")

# Security: child processes get only what they need to start. The worker's own environment
# holds the GitHub App key and database credentials, none of which git or gitleaks should see.
_INHERITED_ENV = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")

# Security: passed on every git command. A clone runs against content an attacker may control.
_GIT_HARDENING = (
    # Only HTTPS. Others, like file:// and ext::, could read the disk or run commands.
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.file.allow=never",
    # Hooks are the classic way for a repo to run code on the machine cloning it.
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.symlinks=false",
    # An empty value clears any configured helper, so no stored login can be used or saved.
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    # A redirect could carry the request to another host.
    "-c",
    "http.followRedirects=false",
    "-c",
    "fetch.recurseSubmodules=false",
)


class RepoScanError(Exception):
    """The scan could not be completed. Messages never include tool output."""


class RepoScanLimitError(Exception):
    """A size or time cap was reached. The message is written for the user."""


@dataclass(frozen=True)
class RepoScanResult:
    full_name: str
    hits: list[SecretHit]
    truncated: bool
    # False when only some commits were scanned.
    full_history: bool
    # The backend projects this repo points at. Identifiers only, never a key.
    # None means they couldn't be read, which is different from there being none.
    identifiers: frozenset[IdentifierPair] | None = frozenset()


@dataclass(frozen=True)
class _Watch:
    path: Path
    max_bytes: int
    reason: str


def _tool(path: str) -> str:
    found = shutil.which(path)
    if found is None:
        raise RepoScanError(f"{path} is not installed")
    return found


def _child_env() -> dict[str, str]:
    env = {name: os.environ[name] for name in _INHERITED_ENV if name in os.environ}
    # Security: no git settings from this machine or user can apply, and nothing can prompt.
    env |= {
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    return env


def _clone_env(token: InstallationToken) -> dict[str, str]:
    # Security: through the environment, because a process's arguments are visible to other
    # users of the machine and a token in the URL would be saved in the clone's config. The
    # setting is scoped to github.com, so it can't be sent anywhere else.
    credentials = base64.b64encode(f"x-access-token:{token.value}".encode()).decode()
    return _child_env() | {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {credentials}",
    }


def clone_url(repository: GithubRepository) -> str:
    # Security: takes a GithubRepository, which only exists once a GitHub API response has
    # passed its strict owner/name check. No user input can reach this URL.
    return f"https://github.com/{repository.full_name}.git"


def _directory_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.stat(os.path.join(root, name)).st_size
            except OSError:
                continue  # git renames its temporary files while working
    return total


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    # git starts helpers of its own, and one left running would hold files open on Windows.
    if sys.platform == "win32":
        subprocess.run(  # noqa: S603
            [_tool("taskkill"), "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()


def run_supervised(
    args: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout: float,
    timeout_reason: str,
    watch: _Watch | None = None,
) -> int:
    """Run a command under time and disk caps, and return its exit code.

    Security: output is discarded, not captured. git and gitleaks can echo URLs, paths or
    matched text, and what's never read can't end up in a log.
    """
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(  # noqa: S603
        args,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=sys.platform != "win32",
    )
    try:
        while True:
            try:
                return process.wait(timeout=POLL_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() > deadline:
                raise RepoScanLimitError(timeout_reason)
            if watch is not None and _directory_size(watch.path) > watch.max_bytes:
                raise RepoScanLimitError(watch.reason)
    except BaseException:
        _kill_tree(process)
        raise


def _remove_tree(path: Path) -> bool:
    # git marks its pack files read-only, and Windows refuses to delete those. A just-killed
    # process can also hold a file open for a moment, so this retries.
    for attempt in range(_REMOVE_ATTEMPTS):
        try:
            for root, dirs, files in os.walk(path):
                for name in [*dirs, *files]:
                    os.chmod(os.path.join(root, name), stat.S_IRWXU)
            shutil.rmtree(path)
        except FileNotFoundError:
            return True
        except OSError:
            time.sleep(0.5 * (attempt + 1))
        else:
            return True
    return not path.exists()


@dataclass(frozen=True)
class _Workspace:
    repo: Path
    # An empty folder to run gitleaks in, so it finds no ignore file in its working directory.
    empty: Path
    report: Path


@contextmanager
def scan_workspace() -> Iterator[_Workspace]:
    # Security: mkdtemp makes a folder only this user can read. The clone may hold live keys.
    root = Path(tempfile.mkdtemp(prefix=WORKSPACE_PREFIX))
    try:
        empty = root / "empty"
        empty.mkdir()
        yield _Workspace(repo=root / "repo.git", empty=empty, report=root / "report.json")
    finally:
        if not _remove_tree(root):
            # The sweep at the next worker start removes it.
            logger.error("could not remove a scan workspace: %s", root.name)


def sweep_abandoned_workspaces() -> None:
    """Remove folders left by a worker that died mid-scan, where no cleanup code could run."""
    now = time.time()
    for path in Path(tempfile.gettempdir()).glob(f"{WORKSPACE_PREFIX}*"):
        try:
            abandoned = now - path.stat().st_mtime > WORKSPACE_ABANDONED_AFTER_SECONDS
        except OSError:
            continue
        if abandoned and path.is_dir():
            _remove_tree(path)


def clone_command(url: str, destination: Path) -> list[str]:
    # A bare clone writes git's object database only, so a crafted path or symlink in the
    # repo is never created on disk. --template= stops git copying in any default hooks.
    return [
        _tool("git"),
        *_GIT_HARDENING,
        "clone",
        "--bare",
        "--template=",
        "--",
        url,
        str(destination),
    ]


def _git_read(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [_tool("git"), *_GIT_HARDENING, "-C", str(repo), *args],
        env=_child_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=GIT_READ_TIMEOUT_SECONDS,
        check=False,
    )


def _git_bytes(repo: Path, *args: str, empty_on: tuple[int, ...] = ()) -> bytes | None:
    """Run a local git read. Returns None if git reports failure."""
    result = subprocess.run(  # noqa: S603
        [_tool("git"), *_GIT_HARDENING, "-C", str(repo), *args],
        env=_child_env(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=GIT_READ_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode in empty_on:
        return b""
    return result.stdout if result.returncode == 0 else None


def _file_at_commit(repo: Path, hit: SecretHit) -> str | None:
    # Read from the object database, because the secret may be long gone from the latest code.
    spec = f"{hit.commit_sha}:{hit.file_path}"
    size = _git_bytes(repo, "cat-file", "-s", spec)
    if size is None or int(size) > MAX_IDENTIFIER_FILE_BYTES:
        return None
    blob = _git_bytes(repo, "cat-file", "blob", spec)
    return blob.decode("utf-8", "replace") if blob is not None else None


def read_identifiers(
    repo: Path, hits: list[SecretHit]
) -> tuple[list[SecretHit], frozenset[IdentifierPair] | None]:
    """Find which projects this repo and its secrets point at, using only the local clone.

    Security: runs after the token is revoked, with no network involved. A failure here costs
    only the links between repo and site, so it never fails the scan.
    """
    try:
        pattern_args = [arg for pattern in GREP_PATTERNS for arg in ("-e", pattern)]
        # git grep exits with 1 when nothing matched, and higher when it actually failed.
        output = _git_bytes(
            repo, "grep", "-I", "-h", "-o", "-E", *pattern_args, "HEAD", empty_on=(1,)
        )
        if output is None:
            raise RepoScanError("git grep failed")
        head = parse_grep_output(output.decode("utf-8", "replace"))
        return attach_project_identifiers(hits, head, lambda hit: _file_at_commit(repo, hit))
    except (subprocess.SubprocessError, OSError, ValueError, RepoScanError) as exc:
        # Security: only the error type is logged, since a message could echo repo content.
        logger.warning("could not read project identifiers: %s", type(exc).__name__)
        return hits, None


def _has_commit(repo: Path, sha: str) -> bool:
    return _git_read(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def _default_branch_head(repo: Path) -> str | None:
    result = _git_read(repo, "rev-parse", "--verify", "HEAD")
    head = result.stdout.strip()
    return head if result.returncode == 0 and _SHA_RE.fullmatch(head) else None


def _is_empty(repo: Path) -> bool:
    return _git_read(repo, "for-each-ref", "--count=1").stdout.strip() == ""


def log_range(repo: Path, before_sha: str | None, after_sha: str | None) -> str | None:
    """Return the git log range to scan, or None for the whole history.

    Security: each commit id is checked again here, since this string becomes a git argument.
    Anything that can't be resolved falls back to scanning everything, never to less.
    """
    if after_sha is None or not _SHA_RE.fullmatch(after_sha) or not _has_commit(repo, after_sha):
        return None
    if before_sha is None:
        head = _default_branch_head(repo)
        return f"{after_sha} ^{head}" if head is not None else None
    if not _SHA_RE.fullmatch(before_sha) or not _has_commit(repo, before_sha):
        return None
    return f"{before_sha}..{after_sha}"


def gitleaks_command(workspace: _Workspace, commit_range: str | None) -> list[str]:
    command = [
        _tool(settings.gitleaks_path),
        "git",
        str(workspace.repo),
        f"--config={GITLEAKS_CONFIG}",
        f"--gitleaks-ignore-path={workspace.empty}",
        "--report-format=json",
        f"--report-path={workspace.report}",
        # Security: 100 replaces each secret entirely. A lower percentage would keep part of
        # it, which for a long private key is hundreds of characters on disk.
        "--redact=100",
        # Findings are the expected outcome here, not a failure.
        "--exit-code=0",
        f"--max-target-megabytes={MAX_SCANNED_FILE_MB}",
        "--no-banner",
        "--no-color",
        "--log-level=error",
    ]
    if commit_range is not None:
        command.append(f"--log-opts={commit_range}")
    return command


def run_gitleaks(workspace: _Workspace, commit_range: str | None) -> bytes:
    exit_code = run_supervised(
        gitleaks_command(workspace, commit_range),
        # Security: no token, and none of gitleaks' GITLEAKS_CONFIG override variables.
        env=_child_env(),
        cwd=workspace.empty,
        timeout=GITLEAKS_TIMEOUT_SECONDS,
        timeout_reason=_SCAN_TOO_SLOW,
    )
    if exit_code != 0:
        raise RepoScanError(f"gitleaks exited with {exit_code}")
    if workspace.report.stat().st_size > MAX_REPORT_BYTES:
        raise RepoScanLimitError(_SCAN_TOO_SLOW)
    return workspace.report.read_bytes()


def _download(installation_id: int, github_repo_id: int, workspace: _Workspace) -> GithubRepository:
    token = create_installation_token(installation_id, [github_repo_id])
    try:
        # Looked up fresh by id, so the clone uses GitHub's current name, not a stored one.
        repository = get_repository(token, github_repo_id)
        if repository is None:
            raise RepoScanError("the repository is no longer available")
        if repository.size > MAX_REPO_SIZE_KB:
            raise RepoScanLimitError(_TOO_LARGE)
        exit_code = run_supervised(
            clone_command(clone_url(repository), workspace.repo),
            env=_clone_env(token),
            cwd=workspace.empty,
            timeout=CLONE_TIMEOUT_SECONDS,
            timeout_reason=_CLONE_TOO_SLOW,
            watch=_Watch(workspace.repo, MAX_CLONE_DISK_BYTES, _CLONE_TOO_BIG),
        )
        if exit_code != 0:
            raise RepoScanError(f"git clone exited with {exit_code}")
        return repository
    finally:
        # Security: revoked as soon as the download ends. Nothing after this needs GitHub.
        revoke_installation_token(token)


def scan_repository(
    installation_id: int,
    github_repo_id: int,
    *,
    before_sha: str | None,
    after_sha: str | None,
    on_step: Callable[[str], None],
) -> RepoScanResult:
    with scan_workspace() as workspace:
        on_step(STEP_CLONE)
        repository = _download(installation_id, github_repo_id, workspace)

        on_step(STEP_SECRETS)
        if _is_empty(workspace.repo):
            return RepoScanResult(repository.full_name, [], truncated=False, full_history=True)
        commit_range = log_range(workspace.repo, before_sha, after_sha)
        report = parse_report(run_gitleaks(workspace, commit_range))
        hits, identifiers = read_identifiers(workspace.repo, report.hits)
        return RepoScanResult(
            repository.full_name,
            hits,
            truncated=report.truncated,
            full_history=commit_range is None,
            identifiers=identifiers,
        )
