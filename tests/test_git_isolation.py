"""Host git calls ignore repository config a builder can plant in its working copy (#125)."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import tempfile
import time
import unittest

from support import ROOT, git
from factory import gitio
from test_deliver import (
    GOOD_BUILDER_SCRIPT, PARENT_TASK, READY_CHILD, _DisposableAsanaServer, _DisposableGitHubServer,
    _make_disposable_product_workspace, _make_fake_agy, _run_deliver,
)


def _hostile(root: Path) -> tuple[Path, Path, Path]:
    """A program that records its first argument in `marker`; filters and textconv still pass content through."""
    marker, hooks = root / "host ran.log", root / "hooks dir"
    prog = root / "bin dir" / "hostile"
    prog.parent.mkdir()
    prog.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{marker}'\n"
        'case "$1" in clean|smudge) exec cat ;; textconv) exec cat "$2" ;; esac\nexit 0\n', encoding="utf-8",
    )
    hooks.mkdir()
    for hook in ("post-checkout", "pre-commit", "post-commit", "reference-transaction"):
        (hooks / hook).write_text(f"#!/bin/sh\nexec '{prog}' hook-{hook}\n", encoding="utf-8")
        (hooks / hook).chmod(0o755)
    prog.chmod(0o755)
    return prog, hooks, marker


def _repo(root: Path) -> Path:
    """`f.txt` is "one" at HEAD~1 and "two" at HEAD, with a configured origin URL."""
    repo = root / "work copy"
    repo.mkdir()
    for args in (("init", "-q", "-b", "main"), ("config", "user.email", "t@example.test"), ("config", "user.name", "T"),
                 ("config", "commit.gpgsign", "false"), ("remote", "add", "origin", "https://example.invalid/o.git")):
        git(repo, *args)
    for text, msg in (("one", "first"), ("two", "second")):
        (repo / "f.txt").write_text(text + "\n", encoding="utf-8")
        git(repo, "add", "f.txt")
        git(repo, "commit", "-q", "-m", msg)
    return repo


def _plant(repo: Path, prog: Path, hooks: Path, vector: str) -> None:
    cmd = lambda tag: f"'{prog}' {tag}"  # noqa: E731
    attrs = repo / ".git" / "info" / "attributes"
    if vector in ("filter.clean", "filter.smudge", "diff.textconv", "diff.driver.command"):
        attrs.parent.mkdir(exist_ok=True)
        attrs.write_text("* filter=evil diff=evil\n", encoding="utf-8")
    if vector.startswith("include"):
        (repo.parent / "inc.cfg").write_text(f"[core]\n\tfsmonitor = {cmd('fsmonitor')}\n", encoding="utf-8")
    if vector == ".git/hooks":
        (repo / ".git" / "hooks").mkdir(exist_ok=True)
        (repo / ".git" / "hooks" / "post-checkout").write_text((hooks / "post-checkout").read_text(), encoding="utf-8")
        (repo / ".git" / "hooks" / "post-checkout").chmod(0o755)
    entries = {
        "core.fsmonitor": ("core.fsmonitor", cmd("fsmonitor")),
        "include.path": ("include.path", str(repo.parent / "inc.cfg")),
        "includeIf.gitdir": (f"includeIf.gitdir:{repo}/.git.path", str(repo.parent / "inc.cfg")),
        "core.hooksPath": ("core.hooksPath", str(hooks)),
        "filter.clean": ("filter.evil.clean", cmd("clean")),
        "filter.smudge": ("filter.evil.smudge", cmd("smudge")),
        "diff.external": ("diff.external", cmd("external")),
        "diff.textconv": ("diff.evil.textconv", cmd("textconv")),
        "diff.driver.command": ("diff.evil.command", cmd("driver-command")),
    }
    if vector in entries:
        git(repo, "config", *entries[vector])
    future = time.time() + 100  # a stat mismatch forces git to re-read (and clean-filter) f.txt
    os.utime(repo / "f.txt", (future, future))


STATUS, WT_DIFF = ("status", "--porcelain", "--untracked-files=all"), ("diff",)
PATCHES = (("diff", "HEAD~1", "HEAD"), ("diff", "--binary", "HEAD~1", "HEAD"), ("show", "HEAD"), ("log", "-p", "-1"))
CHECKOUTS = (("checkout", "-q", "--detach", "HEAD~1"), ("reset", "-q", "--hard", "HEAD~1"))
# vector planted in the working copy's .git/config (or .git/hooks, .git/info/attributes) -> factory git calls it reaches.
# core.pager is not listed: git only pages to a terminal, and the factory always captures output.
# External diff drivers only run for `git diff` (show/log need --ext-diff); textconv runs for all four.
CASES = (
    ("core.fsmonitor", (STATUS, WT_DIFF)),
    ("include.path", (STATUS,)),
    ("includeIf.gitdir", (STATUS,)),
    ("core.hooksPath", CHECKOUTS),
    (".git/hooks", CHECKOUTS[:1]),
    ("filter.clean", (STATUS, WT_DIFF)),
    ("filter.smudge", CHECKOUTS),
    ("diff.external", PATCHES[:2]),
    ("diff.textconv", PATCHES),
    ("diff.driver.command", PATCHES[:2]),
)
HELPERS = (("git", lambda repo, *a: gitio.git(repo, *a).exit), ("_git_bytes", lambda repo, *a: gitio._git_bytes(repo, *a)[0]))


class HostGitIgnoresPlantedConfigTest(unittest.TestCase):
    def test_planted_config_never_runs_a_program(self) -> None:
        for vector, commands in CASES:
            for argv in commands:
                for helper, call in HELPERS:
                    with self.subTest(vector=vector, argv=" ".join(argv), helper=helper), tempfile.TemporaryDirectory(prefix="iso ") as tmp:
                        root = Path(tmp)
                        prog, hooks, marker = _hostile(root)
                        repo = _repo(root)
                        _plant(repo, prog, hooks, vector)
                        self.assertEqual(call(repo, *argv), 0)
                        self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")

    def test_replace_refs_do_not_change_what_the_factory_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iso ") as tmp:
            repo = _repo(Path(tmp))
            forged = git(repo, "commit-tree", git(repo, "rev-parse", "HEAD~1^{tree}"), "-m", "forged")
            git(repo, "replace", "HEAD", forged)
            for argv, true in ((("cat-file", "blob", "HEAD:f.txt"), "two"), (("show", "HEAD:f.txt"), "two"),
                               (("log", "-1", "--format=%s", "HEAD"), "second"),
                               (("ls-tree", "HEAD", "f.txt"), git(repo, "--no-replace-objects", "ls-tree", "HEAD", "f.txt"))):
                with self.subTest(argv=" ".join(argv)):
                    self.assertEqual(gitio.git(repo, *argv).output, true)
                    self.assertEqual(gitio._git_bytes(repo, *argv)[1].decode().strip(), true)

    def test_a_plain_repository_reads_as_before(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iso ") as tmp:
            repo = _repo(Path(tmp))
            (repo / "f.txt").write_text("three\n", encoding="utf-8")
            head = git(repo, "rev-parse", "HEAD")
            for argv, expected in (
                (("rev-parse", "HEAD"), head), (("status", "--porcelain"), "M f.txt"),
                (("cat-file", "blob", "HEAD:f.txt"), "two"), (("show", "HEAD:f.txt"), "two"),
                (("log", "-1", "--format=%s"), "second"), (("ls-tree", "--name-only", "HEAD"), "f.txt"),
                (("diff", "--name-only", "HEAD~1", "HEAD"), "f.txt"), (("remote", "get-url", "origin"), "https://example.invalid/o.git"),
            ):
                with self.subTest(argv=" ".join(argv)):
                    self.assertEqual(gitio.git(repo, *argv).output, expected)
            self.assertIn("-one\n+two", gitio.git(repo, "diff", "HEAD~1", "HEAD").output)
            self.assertEqual(gitio.status_entries(repo), ((" M", "f.txt", None),))


class DeliverIgnoresPlantedConfigTest(unittest.TestCase):
    def test_builder_planted_fsmonitor_hook_and_filter_do_not_run_on_the_host(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iso ") as tmp:
            root = Path(tmp)
            prog, hooks, marker = _hostile(root)
            repo, home, bare = _make_disposable_product_workspace(root)
            planted = {"core.fsmonitor": f"'{prog}' fsmonitor", "core.hooksPath": str(hooks),
                       "filter.evil.clean": f"'{prog}' clean", "filter.evil.smudge": f"'{prog}' smudge"}
            plant = (  # after its good commit, the builder plants config, an attribute and a stale stat in its copy
                "import os, pathlib, time\n"
                f"for k, v in {planted!r}.items():\n    subprocess.run(['git', 'config', k, v], check=True)\n"
                "pathlib.Path('.git/info').mkdir(exist_ok=True)\n"
                "pathlib.Path('.git/info/attributes').write_text('* filter=evil\\n', encoding='utf-8')\n"
                "os.utime('src/chat_bridge/auth.py', (time.time() + 100, time.time() + 100))\n"
            )
            wrapper = _make_fake_agy(root, "fake-agy", GOOD_BUILDER_SCRIPT + plant)
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                res, payload = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(wrapper), time_limit="60s")
            self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")
            self.assertEqual((res.returncode, payload.get("status"), payload.get("pr_opened")), (1, "qa-missing", True), res.stdout + res.stderr)
            child = payload["child"]
            self.assertEqual(git(bare, "rev-parse", f"refs/heads/{child['head_branch']}"), child["candidate_sha"])
            self.assertIn("expired:", git(bare, "show", f"{child['candidate_sha']}:src/chat_bridge/auth.py"))


# qualification.py is left out for now: #123 is rewriting it and its git calls move with that change.
SCAN_EXEMPT = {"gitio.py", "qualification.py"}


class GitCallsGoThroughGitioTest(unittest.TestCase):
    def test_no_direct_git_argv_outside_gitio(self) -> None:
        offenders = []
        for path in sorted((ROOT / "factory").rglob("*.py")):
            if path.relative_to(ROOT / "factory").as_posix() in SCAN_EXEMPT:
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, (ast.List, ast.Tuple)) and node.elts and isinstance(node.elts[0], ast.Constant) and node.elts[0].value == "git":
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [], "run host git through factory.gitio")


if __name__ == "__main__":
    unittest.main()
