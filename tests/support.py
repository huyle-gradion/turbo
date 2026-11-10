"""Synthetic git repositories and CLI drivers for the private factory tests."""

from __future__ import annotations

import atexit
import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 120


def env(extra_path: str | None = None) -> dict[str, str]:
    values = dict(
        os.environ,
        PYTHONPATH=str(ROOT),
        PYTHONDONTWRITEBYTECODE="1",
        GIT_TERMINAL_PROMPT="0",
    )
    if extra_path:
        values["PATH"] = extra_path + os.pathsep + values["PATH"]
    return values


def cli(
    repo: Path,
    home: Path,
    *args: str,
    extra_path: str | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-P", "-m", "factory", "--repo", str(repo), "--home", str(home), *args],
        cwd=str(cwd or repo),
        capture_output=True,
        text=True,
        env=env(extra_path),
        timeout=TIMEOUT,
    )


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env=dict(os.environ, GIT_TERMINAL_PROMPT="0"),
        timeout=TIMEOUT,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


def make_repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "factory@example.test")
    git(repo, "config", "user.name", "Factory Test")
    git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("# probe\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-q", "-m", "base")
    return repo


def commit(repo: Path, path: str, text: str, message: str) -> str:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    git(repo, "add", path)
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


PROBE_IMPL = "def answer():\n    return {value}\n"
PROBE_TEST = (
    "import unittest\n\n"
    "from probe_impl import answer\n\n\n"
    "class ProbeTest(unittest.TestCase):\n"
    "    def test_answer(self):\n"
    "        self.assertEqual(answer(), 42)\n"
)
RED_COMMAND = "python3 -m unittest discover -s tests -p test_probe.py -v"


def commit_probe(repo: Path, value: int, message: str) -> str:
    commit(repo, "probe_impl.py", PROBE_IMPL.format(value=value), message)
    commit(repo, "tests/__init__.py", "", message + " init")
    return commit(repo, "tests/test_probe.py", PROBE_TEST, message + " test")


_HOME_TEMPLATES: dict[tuple[object, ...], tuple[Path, str, str, bool]] = {}


def _bound(path: Path, resolved: bool) -> str:
    return str(path.resolve() if resolved else path)


def _reused_home(build):
    """Configure a home through the real CLI once per argument set, then copy it.

    The first call in a test process runs the CLI. A later call with the same
    arguments in the same ISO week copies that home and rebinds its recorded
    repo and home paths, which are the only path-bound fields. Only the
    timestamps differ from a fresh run. Configuration behaviour itself is
    covered by the tests that drive `init` and `configure` directly.
    """
    @functools.wraps(build)
    def wrapper(repo: Path, home: Path, **kwargs: object) -> None:
        try:
            week = datetime.now(ZoneInfo(str(kwargs.get("timezone", "UTC")))).isocalendar()[:2]
        except (KeyError, ValueError):
            build(repo, home, **kwargs)
            return
        key = (build.__name__, repr(sorted(kwargs.items())), week)
        cached = _HOME_TEMPLATES.get(key)
        if cached is None or home.exists():
            fresh = not home.exists()
            build(repo, home, **kwargs)
            if cached is None and fresh:
                payload = json.loads((home / "config.json").read_text(encoding="utf-8"))
                template = Path(tempfile.mkdtemp(prefix="turbo-home-template-")) / "home"
                atexit.register(shutil.rmtree, template.parent, True)
                shutil.copytree(home, template, symlinks=True)
                resolved = payload["repo"] != str(repo)
                assert (payload["repo"], payload["home"]) == (_bound(repo, resolved), _bound(home, resolved)), payload
                _HOME_TEMPLATES[key] = (template, payload["repo"], payload["home"], resolved)
            return
        template, old_repo, old_home, resolved = cached
        new_repo, new_home = _bound(repo, resolved), _bound(home, resolved)
        shutil.copytree(template, home, symlinks=True)
        target = home / "config.json"
        text = target.read_text(encoding="utf-8")
        text = text.replace(json.dumps(old_repo), json.dumps(new_repo)).replace(json.dumps(old_home), json.dumps(new_home))
        target.write_text(text, encoding="utf-8")
        payload = json.loads(text)
        assert (payload["repo"], payload["home"]) == (new_repo, new_home), payload

    return wrapper


@_reused_home
def config(repo: Path, home: Path, *, gate1: list[str] | None = None, gate2: list[str] | None = None,
           protected: list[str] | None = None, timezone: str = "UTC", spend: float | None = 12.5,
           source: str = "test export") -> None:
    assert cli(repo, home, "init").returncode == 0
    assert cli(repo, home, "configure", "--timezone", timezone).returncode == 0
    one = gate1 or [sys.executable, "-c", "import sys; sys.exit(0)"]
    assert cli(repo, home, "configure", "--gate", "1", "--declare-host-deny", "--", *one).returncode == 0
    two = gate2 or [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-q"]
    assert cli(repo, home, "configure", "--gate", "2", "--", *two).returncode == 0
    paths = protected or ["AGENTS.md", "docs/spec.md", "guards"]
    args = ["configure", "--gate", "3"]
    for path in paths:
        args += ["--protected", path]
    assert cli(repo, home, *args).returncode == 0
    if spend is not None:
        spend_record(repo, home, spend, source)


def spend_record(repo: Path, home: Path, usd: float | None, source: str = "test export") -> subprocess.CompletedProcess[str]:
    if usd is None:
        return cli(repo, home, "spend", "record", "--unknown", "--source", source)
    return cli(repo, home, "spend", "record", "--usd", str(usd), "--source", source)


def prepare(
    repo: Path,
    home: Path,
    *,
    issue: int = 7,
    kind: str = "feature",
    feature: str = "S-1",
    model: str = "test-model",
    time_limit: str = "60m",
    operations: int = 20,
    attest: bool = True,
) -> subprocess.CompletedProcess[str]:
    args = [
        "prepare",
        "--issue", str(issue),
        "--feature", feature,
        "--kind", kind,
        "--model", model,
        "--time-limit", time_limit,
        "--operation-limit", str(operations),
    ]
    if attest:
        args.append("--attest-model-account")
    return cli(repo, home, *args)


def to_ready(repo: Path, home: Path, **kwargs: object) -> None:
    config(repo, home, **kwargs)
    result = prepare(repo, home)
    assert result.returncode == 0, result.stdout + result.stderr


@_reused_home
def configure_turbo(
    repo: Path,
    home: Path,
    *,
    gate1: list[str] | None = None,
    gate2: list[str] | None = None,
    protected: list[str] | None = None,
    timezone: str = "UTC",
    spend: float | None = 12.5,
    source: str = "test export",
    host: str = "antigravity-native",
) -> None:
    assert cli(repo, home, "init").returncode == 0
    assert cli(repo, home, "configure", "--timezone", timezone).returncode == 0
    profile = cli(repo, home, "configure", "--profile", "native-turbo", "--attest-native-turbo", host)
    assert profile.returncode == 0, profile.stdout + profile.stderr
    one = gate1 or [sys.executable, "-c", "import sys; sys.exit(0)"]
    assert cli(repo, home, "configure", "--gate", "1", "--declare-host-probed", "--", *one).returncode == 0
    two = gate2 or [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-q"]
    assert cli(repo, home, "configure", "--gate", "2", "--", *two).returncode == 0
    paths = protected or ["AGENTS.md", "docs/spec.md", "guards"]
    args = ["configure", "--gate", "3"]
    for path in paths:
        args += ["--protected", path]
    assert cli(repo, home, *args).returncode == 0
    if spend is not None:
        spend_record(repo, home, spend, source)


def staged_turbo(repo: Path, home: Path, *, operations: int = 5, issue: int = 7, **kwargs: object) -> str:
    configure_turbo(repo, home, **kwargs)
    result = prepare(repo, home, issue=issue, operations=operations)
    assert result.returncode == 0, result.stdout + result.stderr
    git(repo, "switch", "-q", "-c", f"run-issue-{issue}")
    commit_probe(repo, 0, "failing test")
    assert red(repo, home, issue=issue).returncode == 0
    sha = commit_probe(repo, 42, "implementation")
    assert cli(repo, home, "stage", "--issue", str(issue), "--commit", sha).returncode == 0
    return sha


def config_json(home: Path) -> dict[str, object]:
    return json.loads((home / "config.json").read_text(encoding="utf-8"))


def evidence_files(home: Path, issue: int = 7) -> list[Path]:
    directory = home / "evidence" / str(issue)
    return sorted(directory.glob("*.txt")) if directory.is_dir() else []


def marker_gate(marker: Path) -> list[str]:
    return [
        sys.executable,
        "-c",
        "import pathlib, sys; pathlib.Path(sys.argv[1]).write_text('ran')",
        str(marker),
    ]


def to_red(repo: Path, home: Path, issue: int = 7) -> None:
    to_ready(repo, home)
    git(repo, "switch", "-q", "-c", f"run-issue-{issue}")
    commit_probe(repo, 0, "failing test")
    result = cli(
        repo, home, "red", "--issue", str(issue),
        "--test", "tests/test_probe.py",
        "--selector", "ProbeTest.test_answer",
        "--command", RED_COMMAND,
        "--expect", "AssertionError",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def to_staged(repo: Path, home: Path, issue: int = 7) -> str:
    to_red(repo, home, issue)
    sha = commit_probe(repo, 42, "implementation")
    result = cli(repo, home, "stage", "--issue", str(issue), "--commit", sha)
    assert result.returncode == 0, result.stdout + result.stderr
    return sha


def to_green(repo: Path, home: Path, issue: int = 7) -> str:
    sha = to_staged(repo, home, issue)
    for gate in ("1", "2", "3"):
        result = cli(repo, home, "gate", "--issue", str(issue), "--gate", gate)
        assert result.returncode == 0, result.stdout + result.stderr
    result = cli(repo, home, "replay", "--issue", str(issue))
    assert result.returncode == 0, result.stdout + result.stderr
    result = cli(repo, home, "green", "--issue", str(issue))
    assert result.returncode == 0, result.stdout + result.stderr
    return sha


def red(
    repo: Path,
    home: Path,
    *,
    issue: int = 7,
    expect: str = "AssertionError",
    command: str | None = None,
    test: str = "tests/test_probe.py",
) -> subprocess.CompletedProcess[str]:
    return cli(
        repo, home, "red", "--issue", str(issue),
        "--test", test,
        "--selector", "ProbeTest.test_answer",
        "--command", command or RED_COMMAND,
        "--expect", expect,
    )


def staged(repo: Path, home: Path, *, issue: int = 7, **config_kwargs: object) -> str:
    config(repo, home, **config_kwargs)
    assert prepare(repo, home, issue=issue).returncode == 0
    git(repo, "switch", "-q", "-c", f"run-issue-{issue}")
    commit_probe(repo, 0, "failing test")
    assert red(repo, home, issue=issue).returncode == 0
    sha = commit_probe(repo, 42, "implementation")
    assert cli(repo, home, "stage", "--issue", str(issue), "--commit", sha).returncode == 0
    return sha


def run_state(home: Path, issue: int = 7) -> dict[str, object]:
    return json.loads((home / "runs" / f"{issue}.json").read_text(encoding="utf-8"))


def home_dir(tmp: Path) -> Path:
    return tmp / "factory-home"


def private_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
