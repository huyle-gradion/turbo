"""Host git calls ignore repository config a builder can plant in its working copy (#125)."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

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


def _plant(repo: Path, prog: Path, hooks: Path, vector: str) -> Path:
    """Plant `vector` and return the working copy to run git in (a linked worktree for "config.worktree linked")."""
    cmd = lambda tag: f"'{prog}' {tag}"  # noqa: E731
    attrs = repo / ".git" / "info" / "attributes"
    here = repo.parent / "linked copy" if vector == "config.worktree linked" else repo
    if vector.startswith("config.worktree"):  # extensions.worktreeConfig puts these keys in worktree scope
        if here != repo:
            git(repo, "worktree", "add", "-q", "--detach", str(here))
        for pair in (("core.repositoryformatversion", "1"), ("extensions.worktreeConfig", "true")):
            git(repo, "config", *pair)
        for key, tag in (("filter.evil.clean", "clean"), ("filter.evil.smudge", "smudge"), ("filter.evil.process", "process")):
            git(here, "config", "--worktree", key, cmd(tag))
    if vector in ("filter.clean", "filter.smudge", "filter.process", "diff.textconv", "diff.driver.command") or vector.startswith("config.worktree"):
        attrs.parent.mkdir(exist_ok=True)
        attrs.write_text("* filter=evil diff=evil\n", encoding="utf-8")
    if vector.startswith("include"):
        (repo.parent / "inc.cfg").write_text(f"[core]\n\tfsmonitor = {cmd('fsmonitor')}\n", encoding="utf-8")
    if vector == ".git/hooks":
        (repo / ".git" / "hooks").mkdir(exist_ok=True)
        (repo / ".git" / "hooks" / "post-checkout").write_text((hooks / "post-checkout").read_text(), encoding="utf-8")
        (repo / ".git" / "hooks" / "post-checkout").chmod(0o755)
    if vector == "promisor":  # branch `ghost` adds a blob the copy does not have
        tree = subprocess.run(["git", "mktree", "--missing"], cwd=repo, input=f"100644 blob {MISSING}\tghost.txt\n",
                              capture_output=True, text=True, check=True).stdout.strip()
        git(repo, "update-ref", "refs/heads/ghost", git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "ghost"))
    if vector in ("submodule", "core.alternateRefsCommand"):
        (repo.parent / "other").mkdir()
        other = _repo(repo.parent / "other")
    if vector == "core.alternateRefsCommand":
        (repo / ".git" / "objects" / "info" / "alternates").write_text(f"{other}/.git/objects\n", encoding="utf-8")
    if vector == "submodule":  # HEAD bumps `sub`, whose own config and attributes carry a filter and an external diff
        git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(other), "sub")
        git(repo, "commit", "-q", "-m", "add sub")
        (repo / "sub" / "f.txt").write_text("three\n", encoding="utf-8")
        git(repo / "sub", "-c", "user.name=T", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "commit", "-q", "-am", "three")
        git(repo, "commit", "-q", "-am", "bump sub")
        (repo / ".git" / "modules" / "sub" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "modules" / "sub" / "info" / "attributes").write_text("* filter=evil\n", encoding="utf-8")
        for key, value in (("filter.evil.clean", cmd("clean")), ("diff.external", cmd("external"))):
            git(repo / "sub", "config", key, value)
        future = time.time() + 100
        os.utime(repo / "sub" / "f.txt", (future, future))
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
    lazy = f"ext::{str(prog).replace(' ', '% ')} lazy"  # the ext:: transport runs the program
    pairs = {
        "promisor": (("core.repositoryformatversion", "1"), ("extensions.partialClone", "evil"), ("remote.evil.url", lazy),
                     ("remote.evil.promisor", "true"), ("protocol.ext.allow", "always")),
        "filter.process": (("filter.evil.process", cmd("process")), ("filter.evil.required", "true")),
        "submodule": (("diff.submodule", "diff"),),
        "core.alternateRefsCommand": (("core.alternateRefsCommand", cmd("alternate-refs")),),
    }
    for pair in (entries[vector],) if vector in entries else pairs.get(vector, ()):
        git(repo, "config", *pair)
    future = time.time() + 100  # a stat mismatch forces git to re-read (and clean-filter) f.txt
    os.utime(here / "f.txt", (future, future))
    return here


MISSING = "3" * 40
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
    # `diff REV PATH` without `--` compares against the working tree, so it is not tree-to-tree.
    ("filter.clean", (STATUS, WT_DIFF, ("diff", "HEAD~1", "f.txt"))),
    ("filter.smudge", CHECKOUTS),
    ("filter.process", (STATUS, WT_DIFF, *CHECKOUTS)),
    ("config.worktree", (STATUS, WT_DIFF, *CHECKOUTS)),
    ("config.worktree linked", (STATUS, WT_DIFF, *CHECKOUTS)),
    ("diff.external", PATCHES[:2]),
    ("diff.textconv", PATCHES),
    ("diff.driver.command", PATCHES[:2]),
    # A read of an object the copy lacks would lazily fetch it from the planted promisor; the read itself may fail.
    ("promisor", (("cat-file", "-t", MISSING), ("rev-parse", "--verify", f"{MISSING}^{{commit}}"), ("diff", "--binary", "HEAD", "ghost"))),
    # status recurses into the submodule; diff.submodule=diff starts a child diff there.
    ("submodule", (STATUS, ("diff", "--binary", "HEAD~1", "HEAD"))),
    # Not reachable today: the factory fetches inside a copy only before any builder runs there.
    ("core.alternateRefsCommand", (("fetch", "-q", "--no-tags", "../other/work copy", "HEAD"),)),
)
MAY_FAIL = {"promisor"}
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
                        repo = _plant(repo, prog, hooks, vector)
                        exit_code = call(repo, *argv)
                        if vector not in MAY_FAIL:
                            self.assertEqual(exit_code, 0)
                        self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")

    def test_dirt_inside_a_nested_repository_is_reported_without_running_its_filters(self) -> None:
        # The factory never populates submodules, so a nested repository in a builder copy is the builder's.
        for declared in (True, False):  # in .gitmodules, or a bare gitlink
            for dirt in ("owt\n", None):  # a same-size edit, or an untracked file
                with self.subTest(gitmodules=declared, dirt=dirt), tempfile.TemporaryDirectory(prefix="iso ") as tmp:
                    root = Path(tmp)
                    prog, _, marker = _hostile(root)
                    repo = _repo(root)
                    (root / "other").mkdir()
                    other = _repo(root / "other")
                    if declared:
                        git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(other), "sub")
                    else:
                        git(repo, "clone", "-q", str(other), "sub")
                        git(repo, "add", "sub")
                    git(repo, "commit", "-q", "-m", "add sub")
                    sub = repo / "sub"
                    git(sub, "config", "filter.evil.clean", f"'{prog}' clean")
                    (Path(git(sub, "rev-parse", "--absolute-git-dir")) / "info").mkdir(exist_ok=True)
                    (Path(git(sub, "rev-parse", "--absolute-git-dir")) / "info" / "attributes").write_text("* filter=evil\n", encoding="utf-8")
                    (sub / ("f.txt" if dirt else "new.txt")).write_text(dirt or "new\n", encoding="utf-8")
                    future = time.time() + 100
                    os.utime(sub / "f.txt", (future, future))
                    self.assertIn("sub", [line.split()[-1] for line in gitio.status_porcelain(repo).splitlines()])
                    self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")

    def test_operator_global_filters_still_apply_and_local_ones_do_not(self) -> None:
        for local, attribute, expected in ((None, "op", "ONE"), ("filter.op.smudge", "op", "one"), ("filter.evil.smudge", "evil", "one")):
            with self.subTest(local=local), tempfile.TemporaryDirectory(prefix="iso ") as tmp:
                root = Path(tmp)
                prog, _, marker = _hostile(root)
                repo = _repo(root)
                (root / "global.cfg").write_text('[filter "op"]\n\tsmudge = tr a-z A-Z\n\tclean = tr A-Z a-z\n', encoding="utf-8")
                (repo / ".git" / "info").mkdir(exist_ok=True)
                (repo / ".git" / "info" / "attributes").write_text(f"f.txt filter={attribute}\n", encoding="utf-8")
                if local:
                    git(repo, "config", local, f"'{prog}' smudge")
                with mock.patch.dict(os.environ, GIT_CONFIG_GLOBAL=str(root / "global.cfg")):
                    self.assertEqual(gitio.git(repo, "checkout", "-q", "--detach", "HEAD~1").exit, 0)
                self.assertEqual((repo / "f.txt").read_text(encoding="utf-8").strip(), expected)
                self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")

    @unittest.skipIf(subprocess.run(["git", "lfs", "version"], capture_output=True, timeout=30).returncode, "git-lfs is not installed")
    def test_operator_lfs_filter_ignores_repository_local_lfs_programs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iso ") as tmp:
            root = Path(tmp)
            prog, _, marker = _hostile(root)
            repo = _repo(root)
            (root / "global.cfg").write_text('[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n'
                                             '\tprocess = git-lfs filter-process\n\trequired = true\n', encoding="utf-8")
            (repo / ".git" / "info").mkdir(exist_ok=True)
            (repo / ".git" / "info" / "attributes").write_text("* filter=lfs\n", encoding="utf-8")
            for key, value in (("lfs.extension.evil.clean", f"'{prog}' clean"), ("lfs.extension.evil.smudge", f"'{prog}' smudge"),
                               ("lfs.extension.evil.priority", "0"), ("lfs.customtransfer.evil.path", str(prog)),
                               ("lfs.standalonetransferagent", "evil")):
                git(repo, "config", key, value)
            future = time.time() + 100
            os.utime(repo / "f.txt", (future, future))
            with mock.patch.dict(os.environ, GIT_CONFIG_GLOBAL=str(root / "global.cfg")):
                for argv in (STATUS, *CHECKOUTS):
                    gitio.git(repo, *argv)
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


def _deliver(root: Path, repo: Path, home: Path, bare: Path, plant: str):
    wrapper = _make_fake_agy(root, "fake-agy", GOOD_BUILDER_SCRIPT + plant)
    with (
        _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
        _DisposableGitHubServer(bare_repo=bare) as gh,
    ):
        return _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(wrapper), time_limit="60s")


class DeliverIgnoresPlantedConfigTest(unittest.TestCase):
    def test_a_planted_promisor_is_not_lazily_fetched_by_the_host(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iso ") as tmp:
            root = Path(tmp)
            prog, _, marker = _hostile(root)
            repo, home, bare = _make_disposable_product_workspace(root)
            plant = (  # the builder's candidate adds a blob its copy lacks, and its config names a promisor for it
                f"for k, v in (('core.repositoryformatversion', '1'), ('extensions.partialClone', 'evil'), ('remote.evil.promisor', 'true'),\n"
                f"             ('remote.evil.url', {'ext::' + str(prog).replace(' ', '% ') + ' lazy'!r}), ('protocol.ext.allow', 'always')):\n"
                "    subprocess.run(['git', 'config', k, v], check=True)\n"
                "listing = subprocess.run(['git', 'ls-tree', 'HEAD'], capture_output=True, text=True, check=True).stdout\n"
                f"tree = subprocess.run(['git', 'mktree', '--missing'], input=listing + '100644 blob {MISSING}\\tghost.txt\\n',\n"
                "                      capture_output=True, text=True, check=True).stdout.strip()\n"
                "ghost = subprocess.run(['git', 'commit-tree', tree, '-p', 'HEAD', '-m', 'ghost'], capture_output=True, text=True, check=True)\n"
                "subprocess.run(['git', 'reset', '-q', '--soft', ghost.stdout.strip()], check=True)\n"
                "subprocess.run(['git', 'read-tree', '--reset', ghost.stdout.strip()])\n"
            )
            _deliver(root, repo, home, bare, plant)
            self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")

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
            res, payload = _deliver(root, repo, home, bare, plant)
            self.assertFalse(marker.exists(), f"host git ran {marker.read_text().split() if marker.exists() else ''}")
            self.assertEqual((res.returncode, payload.get("status"), payload.get("pr_opened")), (1, "qa-missing", True), res.stdout + res.stderr)
            child = payload["child"]
            self.assertEqual(git(bare, "rev-parse", f"refs/heads/{child['head_branch']}"), child["candidate_sha"])
            self.assertIn("expired:", git(bare, "show", f"{child['candidate_sha']}:src/chat_bridge/auth.py"))


    def test_dirt_inside_a_committed_nested_repository_stops_delivery(self) -> None:
        with tempfile.TemporaryDirectory(prefix="iso ") as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            plant = (  # after its good commit, the builder commits a nested repository as a gitlink and leaves dirt inside it
                "subprocess.run(['git', 'init', '-q', 'nest'], check=True)\n"
                "subprocess.run(['git', '-C', 'nest', '-c', 'user.name=B', '-c', 'user.email=b@example.test', '-c', 'commit.gpgsign=false',\n"
                "                'commit', '-q', '--allow-empty', '-m', 'nest'], check=True)\n"
                "subprocess.run(['git', 'add', 'nest'], check=True)\n"
                "subprocess.run(['git', 'commit', '-q', '-m', 'nest'], check=True)\n"
                "pathlib.Path('nest/hidden.txt').write_text('hidden\\n', encoding='utf-8')\n"
            )
            res, payload = _deliver(root, repo, home, bare, plant)
            self.assertEqual(payload.get("status"), "uncommitted-changes", res.stdout + res.stderr)
            self.assertIn("nest", " ".join(payload["blockers"]), payload["blockers"])


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
