"""The git and gitleaks runner. Integration tests use the real tools on synthetic repos."""

import base64
import json
import os
import random
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from app.core.config import settings
from app.core.github_app import GithubRepository, InstallationToken
from app.repos import scanner
from app.repos.report import parse_report
from app.repos.scanner import (
    RepoScanError,
    RepoScanLimitError,
    clone_command,
    clone_url,
    gitleaks_command,
    log_range,
    run_gitleaks,
    run_supervised,
    scan_repository,
    scan_workspace,
    sweep_abandoned_workspaces,
)

TOKEN = InstallationToken("ghs_scan_token_value")
REPOSITORY = GithubRepository(id=9, full_name="me/project", private=True, size=100)

requires_tools = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which(settings.gitleaks_path) is None,
    reason="needs git and gitleaks installed",
)


def random_chars(alphabet: str, length: int) -> str:
    return "".join(random.choices(alphabet, k=length))  # noqa: S311


# Built at run time, so no secret-shaped string is ever committed to this repo.
def aws_key() -> str:
    return "AKIA" + random_chars(string.ascii_uppercase + "234567", 16)


def supabase_key() -> str:
    return "sb_" + "secret_" + random_chars(string.ascii_letters + string.digits, 32)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def supabase_jwt(role: str, padding: int = 0) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = {"iss": "supabase", "ref": "a" * (20 + padding), "role": role, "iat": 1700000000}
    return f"{header}.{b64url(json.dumps(payload).encode())}.{b64url(os.urandom(32))}"


def git(cwd: Path, *args: str) -> str:
    env = os.environ | {
        "GIT_AUTHOR_NAME": "Pat Example",
        "GIT_AUTHOR_EMAIL": "pat@example.com",
        "GIT_COMMITTER_NAME": "Pat Example",
        "GIT_COMMITTER_EMAIL": "pat@example.com",
    }
    result = subprocess.run(  # noqa: S603
        ["git", "-c", "commit.gpgsign=false", *args],  # noqa: S607
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit_file(repo: Path, name: str, content: str) -> str:
    (repo / name).write_text(content)
    git(repo, "add", name)
    git(repo, "commit", "-m", f"add {name}")
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def source(tmp_path: Path) -> Path:
    repo = tmp_path / "source"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    return repo


def bare_copy(source_repo: Path, destination: Path) -> None:
    git(source_repo.parent, "clone", "--bare", str(source_repo), str(destination))


def scan(source_repo: Path, commit_range: str | None = None) -> tuple[Any, bytes]:
    with scan_workspace() as workspace:
        bare_copy(source_repo, workspace.repo)
        content = run_gitleaks(workspace, commit_range)
    return parse_report(content), content


# --- what git and gitleaks are told ---


def test_clone_url_is_github_only() -> None:
    assert clone_url(REPOSITORY) == "https://github.com/me/project.git"


@requires_tools
def test_clone_has_every_hardening_flag(tmp_path: Path) -> None:
    command = clone_command("https://github.com/me/project.git", tmp_path / "dest")

    settings_passed = [command[i + 1] for i, arg in enumerate(command) if arg == "-c"]
    for setting in [
        "protocol.allow=never",
        "protocol.https.allow=always",
        "protocol.file.allow=never",
        f"core.hooksPath={os.devnull}",
        "core.fsmonitor=false",
        "core.symlinks=false",
        "credential.helper=",
        "core.askPass=",
        "http.followRedirects=false",
        "fetch.recurseSubmodules=false",
    ]:
        assert setting in settings_passed
    assert "--bare" in command
    assert "--template=" in command
    assert command.index("--") == command.index("https://github.com/me/project.git") - 1


def test_child_processes_cannot_prompt_or_read_machine_git_settings() -> None:
    env = scanner._child_env()

    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GCM_INTERACTIVE"] == "never"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_child_processes_do_not_inherit_the_workers_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ["GITHUB_APP_PRIVATE_KEY_B64", "DATABASE_URL", "GITLEAKS_CONFIG"]:
        monkeypatch.setenv(name, "should-not-be-passed")

    assert "should-not-be-passed" not in scanner._child_env().values()


def test_token_goes_in_a_github_scoped_setting() -> None:
    env = scanner._clone_env(TOKEN)

    assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"].startswith("Authorization: Basic ")


def test_gitleaks_never_receives_the_token() -> None:
    assert all(not key.startswith("GIT_CONFIG_KEY") for key in scanner._child_env())


@requires_tools
def test_gitleaks_uses_our_config_and_full_redaction(tmp_path: Path) -> None:
    with scan_workspace() as workspace:
        command = gitleaks_command(workspace, None)

    assert f"--config={scanner.GITLEAKS_CONFIG}" in command
    assert "--redact=100" in command
    assert not any(arg.startswith("--log-opts") for arg in command)


# --- running a scan, with the tools faked ---


class FakeGithub:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.repository: GithubRepository | None = REPOSITORY
        self.exit_code = 0
        self.error: Exception | None = None
        self.commands: list[list[str]] = []
        self.envs: list[dict[str, str]] = []
        self.revoked: list[InstallationToken] = []
        self.token_args: list[Any] = []
        self.root = tmp_path
        monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
        monkeypatch.setattr(scanner, "create_installation_token", self.create)
        monkeypatch.setattr(scanner, "get_repository", lambda _t, _id: self.repository)
        monkeypatch.setattr(scanner, "revoke_installation_token", self.revoked.append)
        monkeypatch.setattr(scanner, "run_supervised", self.run)

    def create(self, installation_id: int, repository_ids: list[int]) -> InstallationToken:
        self.token_args.append((installation_id, repository_ids))
        return TOKEN

    def run(self, args: list[str], *, env: dict[str, str], **_kwargs: Any) -> int:
        self.commands.append(args)
        self.envs.append(env)
        if self.error is not None:
            raise self.error
        return self.exit_code

    def workspaces(self) -> list[Path]:
        return list(self.root.glob(f"{scanner.WORKSPACE_PREFIX}*"))


@pytest.fixture
def faked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeGithub:
    return FakeGithub(monkeypatch, tmp_path)


def run_scan(steps: list[str] | None = None) -> Any:
    return scan_repository(7, 9, before_sha=None, after_sha=None, on_step=(steps or []).append)


@requires_tools
def test_token_is_limited_to_this_repo_and_stays_out_of_the_command(faked: FakeGithub) -> None:
    run_scan()

    assert faked.token_args == [(7, [9])]
    joined = " ".join(faked.commands[0])
    assert TOKEN.value not in joined
    assert base64.b64encode(f"x-access-token:{TOKEN.value}".encode()).decode() not in joined
    assert "https://github.com/me/project.git" in faked.commands[0]
    assert "GIT_CONFIG_VALUE_0" in faked.envs[0]


@requires_tools
def test_token_is_revoked_and_workspace_removed_after_success(faked: FakeGithub) -> None:
    run_scan()

    assert faked.revoked == [TOKEN]
    assert faked.workspaces() == []


@requires_tools
def test_failed_clone_cleans_up(faked: FakeGithub) -> None:
    faked.exit_code = 128

    with pytest.raises(RepoScanError):
        run_scan()

    assert faked.revoked == [TOKEN]
    assert faked.workspaces() == []


@requires_tools
def test_time_limit_cleans_up(faked: FakeGithub) -> None:
    faked.error = RepoScanLimitError("too slow")

    with pytest.raises(RepoScanLimitError):
        run_scan()

    assert faked.revoked == [TOKEN]
    assert faked.workspaces() == []


def test_repo_over_the_size_cap_is_never_cloned(faked: FakeGithub) -> None:
    faked.repository = GithubRepository(
        id=9, full_name="me/project", private=True, size=scanner.MAX_REPO_SIZE_KB + 1
    )

    with pytest.raises(RepoScanLimitError):
        run_scan()

    assert faked.commands == []
    assert faked.revoked == [TOKEN]


def test_repo_that_disappeared_is_an_error(faked: FakeGithub) -> None:
    faked.repository = None

    with pytest.raises(RepoScanError):
        run_scan()

    assert faked.commands == []
    assert faked.revoked == [TOKEN]


# --- caps and cleanup, for real ---


def sleeper() -> list[str]:
    return [sys.executable, "-c", "import time; time.sleep(60)"]


def test_time_cap_kills_the_process(tmp_path: Path) -> None:
    started = time.monotonic()

    with pytest.raises(RepoScanLimitError, match="too slow"):
        run_supervised(
            sleeper(), env=dict(os.environ), cwd=tmp_path, timeout=0.2, timeout_reason="too slow"
        )

    assert time.monotonic() - started < 30


def test_disk_cap_kills_the_process(tmp_path: Path) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "big").write_bytes(b"x" * 2048)

    with pytest.raises(RepoScanLimitError, match="too big"):
        run_supervised(
            sleeper(),
            env=dict(os.environ),
            cwd=tmp_path,
            timeout=30,
            timeout_reason="too slow",
            watch=scanner._Watch(watched, 1024, "too big"),
        )


def test_exit_code_is_returned(tmp_path: Path) -> None:
    code = run_supervised(
        [sys.executable, "-c", "raise SystemExit(3)"],
        env=dict(os.environ),
        cwd=tmp_path,
        timeout=30,
        timeout_reason="x",
    )

    assert code == 3


def test_workspace_is_removed_after_an_exception_even_with_read_only_files() -> None:
    with pytest.raises(ValueError, match="boom"):
        with scan_workspace() as workspace:
            root = workspace.empty.parent
            locked = root / "pack.idx"
            locked.write_text("x")
            os.chmod(locked, stat.S_IREAD)
            raise ValueError("boom")

    assert not root.exists()


def test_sweep_removes_only_abandoned_workspaces(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    old = tmp_path / f"{scanner.WORKSPACE_PREFIX}old"
    fresh = tmp_path / f"{scanner.WORKSPACE_PREFIX}fresh"
    unrelated = tmp_path / "unrelated"
    for path in (old, fresh, unrelated):
        path.mkdir()
    long_ago = time.time() - scanner.WORKSPACE_ABANDONED_AFTER_SECONDS - 60
    os.utime(old, (long_ago, long_ago))
    os.utime(unrelated, (long_ago, long_ago))

    sweep_abandoned_workspaces()

    assert not old.exists()
    assert fresh.exists()
    assert unrelated.exists()


# --- the real tools ---


@requires_tools
@pytest.mark.parametrize("use_file_scheme", [False, True])
def test_hardened_clone_refuses_a_local_repo(
    source: Path, tmp_path: Path, use_file_scheme: bool
) -> None:
    commit_file(source, "readme.txt", "hello")
    url = source.as_uri() if use_file_scheme else str(source)
    destination = tmp_path / "stolen.git"

    result = subprocess.run(  # noqa: S603
        clone_command(url, destination), env=scanner._child_env(), capture_output=True, check=False
    )

    assert result.returncode != 0
    assert not (destination / "HEAD").exists()


@requires_tools
def test_finds_a_secret_and_the_report_never_holds_it(source: Path) -> None:
    key = aws_key()
    commit_file(source, "settings.py", f'AWS_KEY = "{key}"\n')

    parsed, content = scan(source)

    assert [hit.rule_id for hit in parsed.hits] == ["aws-access-token"]
    hit = parsed.hits[0]
    assert hit.masked == "AKIA****"
    assert hit.file_path == "settings.py"
    assert hit.line == 1
    assert key.encode() not in content
    assert key not in repr(hit)


@requires_tools
def test_finds_a_secret_that_was_later_deleted(source: Path) -> None:
    commit_file(source, "settings.py", f'AWS_KEY = "{aws_key()}"\n')
    git(source, "rm", "settings.py")
    git(source, "commit", "-m", "remove it")

    parsed, _ = scan(source)

    assert [hit.rule_id for hit in parsed.hits] == ["aws-access-token"]


@requires_tools
def test_clean_repo_has_no_findings(source: Path) -> None:
    commit_file(source, "readme.txt", "nothing to see\n")

    assert scan(source)[0].hits == []


@requires_tools
def test_repo_cannot_switch_off_its_own_scan(source: Path) -> None:
    commit_file(source, ".gitleaks.toml", "[allowlist]\npaths = ['''.*''']\n")
    commit_file(source, "settings.py", f'AWS_KEY = "{aws_key()}"\n')

    assert "aws-access-token" in {hit.rule_id for hit in scan(source)[0].hits}


@requires_tools
@pytest.mark.parametrize("padding", [0, 1, 2])
def test_supabase_service_role_key_is_found_at_every_alignment(source: Path, padding: int) -> None:
    commit_file(source, "env.txt", f'KEY = "{supabase_jwt("service_role", padding)}"\n')

    hits = scan(source)[0].hits

    assert "supabase-service-role-jwt" in {hit.rule_id for hit in hits}
    assert "jwt" not in {hit.rule_id for hit in hits}


@requires_tools
def test_supabase_anon_key_is_not_called_a_service_key(source: Path) -> None:
    commit_file(source, "env.txt", f'KEY = "{supabase_jwt("anon")}"\n')

    assert "supabase-service-role-jwt" not in {hit.rule_id for hit in scan(source)[0].hits}


@requires_tools
def test_new_format_supabase_secret_is_found(source: Path) -> None:
    commit_file(source, "env.txt", f"KEY={supabase_key()}\n")

    assert "supabase-secret-key" in {hit.rule_id for hit in scan(source)[0].hits}


@requires_tools
def test_push_range_scans_only_the_new_commits(source: Path) -> None:
    first = commit_file(source, "old.py", f'KEY = "{aws_key()}"\n')
    second = commit_file(source, "new.py", f'KEY = "{aws_key()}"\n')

    with scan_workspace() as workspace:
        bare_copy(source, workspace.repo)
        commit_range = log_range(workspace.repo, first, second)
        parsed = parse_report(run_gitleaks(workspace, commit_range))

    assert commit_range == f"{first}..{second}"
    assert [hit.file_path for hit in parsed.hits] == ["new.py"]


@requires_tools
def test_new_branch_scans_only_what_is_not_on_the_default_branch(source: Path) -> None:
    head = commit_file(source, "old.py", f'KEY = "{aws_key()}"\n')
    git(source, "checkout", "-b", "feature")
    tip = commit_file(source, "new.py", f'KEY = "{aws_key()}"\n')
    git(source, "checkout", "main")

    with scan_workspace() as workspace:
        bare_copy(source, workspace.repo)
        commit_range = log_range(workspace.repo, None, tip)
        parsed = parse_report(run_gitleaks(workspace, commit_range))

    assert commit_range == f"{tip} ^{head}"
    assert [hit.file_path for hit in parsed.hits] == ["new.py"]


@requires_tools
def test_empty_commit_range_is_clean_not_an_error(source: Path) -> None:
    tip = commit_file(source, "readme.txt", "hello\n")

    assert scan(source, f"{tip}..{tip}")[0].hits == []


@requires_tools
def test_commit_missing_from_the_clone_falls_back_to_everything(source: Path) -> None:
    tip = commit_file(source, "readme.txt", "hello\n")

    with scan_workspace() as workspace:
        bare_copy(source, workspace.repo)
        assert log_range(workspace.repo, "f" * 40, tip) is None
        assert log_range(workspace.repo, tip, "f" * 40) is None
        assert log_range(workspace.repo, None, None) is None


@requires_tools
@pytest.mark.parametrize("bad", ["--output=x", "HEAD", "a" * 39, "a" * 40 + " --all"])
def test_unsafe_commit_id_is_never_used_in_a_range(source: Path, bad: str) -> None:
    tip = commit_file(source, "readme.txt", "hello\n")

    with scan_workspace() as workspace:
        bare_copy(source, workspace.repo)
        assert log_range(workspace.repo, bad, tip) is None
        assert log_range(workspace.repo, tip, bad) is None


@requires_tools
def test_empty_repository_is_detected(tmp_path: Path) -> None:
    bare = tmp_path / "empty.git"
    git(tmp_path, "init", "--bare", str(bare))

    assert scanner._is_empty(bare)
