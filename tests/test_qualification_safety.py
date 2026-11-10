"""Credential and merge-path safety for hosted qualification (issue #95).

Offline only: every git subprocess and GitHub request is replaced by a recorder.
"""

from __future__ import annotations

import ast
import contextlib
import io
import logging
import subprocess
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest import mock

from factory import qualification

TOKEN = "ghp_FAKE_SECRET_TOKEN_95"
SLUG = "example-org/example-repo"
API = "https://api.github.com"
SOURCE = Path(qualification.__file__)


class _GitRecorder:
    """Stand-in for subprocess.run/Popen: records argv and env, fakes git."""

    def __init__(self, fail: bool) -> None:
        self.fail = fail
        self.calls: list[tuple[list[str], dict | None]] = []

    def _record(self, args, kwargs) -> list[str]:
        argv = [str(a) for a in (args if isinstance(args, (list, tuple)) else [args])]
        self.calls.append((argv, kwargs.get("env")))
        return argv

    def _stderr(self, argv: list[str]) -> bytes:
        # Real git echoes the remote URL it was given when it fails.
        return ("fatal: unable to access '" + " ".join(argv) + "': Could not resolve host\n").encode()

    def run(self, args, *a, **kwargs):
        argv = self._record(args, kwargs)
        if self.fail and argv and Path(argv[0]).name == "git":
            err = self._stderr(argv)
            if kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding"):
                err = err.decode()
            if kwargs.get("check"):
                raise subprocess.CalledProcessError(128, argv, output=err[:0], stderr=err)
            return subprocess.CompletedProcess(argv, 128, err[:0], err)
        out = "" if (kwargs.get("text") or kwargs.get("encoding")) else b""
        return subprocess.CompletedProcess(argv, 0, out, out)

    def popen(self, args, *a, **kwargs):
        argv = self._record(args, kwargs)
        code = 128 if self.fail else 0
        err = self._stderr(argv) if self.fail else b""
        proc = mock.MagicMock()
        proc.args, proc.returncode, proc.pid = argv, code, 4242
        proc.communicate.return_value = (b"", err)
        proc.wait.return_value = proc.poll.return_value = code
        proc.__enter__.return_value = proc
        proc.stdout = io.BytesIO(b"")
        proc.stderr = io.BytesIO(err)
        return proc


def _exception_text(exc: BaseException) -> str:
    parts = ["".join(traceback.format_exception(type(exc), exc, exc.__traceback__))]
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        parts += [str(cur), repr(cur), repr(cur.args)]
        for attr in ("cmd", "stderr", "output", "stdout"):
            parts.append(repr(getattr(cur, attr, None)))
        cur = cur.__cause__ or cur.__context__
    return "\n".join(parts)


class QualificationCredentialSafetyTests(unittest.TestCase):
    def _git_ops(self, dest: Path):
        """(name, callable) for each hosted git entry point; clone_remote_repo resolved lazily."""
        yield "fetch_remote_repo", lambda: qualification.fetch_remote_repo(dest, SLUG, TOKEN)
        yield "clone_remote_repo", lambda: qualification.clone_remote_repo(dest / "clone", SLUG, TOKEN)

    def _run_recorded(self, op, fail: bool):
        rec = _GitRecorder(fail=fail)
        stderr, log_buf = io.StringIO(), io.StringIO()
        handler = logging.StreamHandler(log_buf)
        handler.setLevel(logging.DEBUG)
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        raised: BaseException | None = None
        try:
            with mock.patch.object(qualification.subprocess, "run", rec.run), \
                 mock.patch.object(qualification.subprocess, "Popen", rec.popen), \
                 mock.patch.object(qualification.time, "sleep", lambda _s: None), \
                 contextlib.redirect_stderr(stderr):
                try:
                    op()
                except Exception as exc:  # noqa: BLE001 - inspected below
                    raised = exc
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        return rec, raised, stderr.getvalue(), log_buf.getvalue()

    def test_hosted_git_never_puts_token_in_argv(self) -> None:
        """AC1 (argv): fetch and clone keep the token off every git command line."""
        with tempfile.TemporaryDirectory() as tmp:
            for name, op in self._git_ops(Path(tmp)):
                with self.subTest(function=name):
                    rec, raised, _, _ = self._run_recorded(op, fail=False)
                    self.assertIsNone(raised, f"{name} raised on a successful git run: {raised!r}")
                    self.assertTrue(rec.calls, f"{name} started no git subprocess")
                    for argv, _env in rec.calls:
                        self.assertNotIn(TOKEN, " ".join(argv), f"token on argv of {argv[:3]}")

    def test_hosted_git_failure_does_not_leak_token(self) -> None:
        """AC1 (failure): a failing fetch/clone raises without the token in exception, stderr or logs."""
        with tempfile.TemporaryDirectory() as tmp:
            for name, op in self._git_ops(Path(tmp)):
                with self.subTest(function=name):
                    rec, raised, err, logs = self._run_recorded(op, fail=True)
                    self.assertNotIsInstance(raised, AttributeError, f"{name} is missing: {raised!r}")
                    self.assertTrue(rec.calls, f"{name} started no git subprocess")
                    self.assertIsNotNone(raised, f"{name} hid a failed git run")
                    self.assertNotIn(TOKEN, _exception_text(raised))
                    self.assertNotIn(TOKEN, err)
                    self.assertNotIn(TOKEN, logs)
                    for argv, _env in rec.calls:
                        self.assertNotIn(TOKEN, " ".join(argv))

    def test_ref_writes_limited_to_candidate_prefix(self) -> None:
        """AC3: refs outside feat/qual- are refused locally with no HTTP request; candidates still write."""
        self.assertEqual(qualification.CANDIDATE_BRANCH_PREFIX, "feat/qual-")
        sha = "a" * 40
        for branch in ("main", "feature/demo", "feature/other", "release/x", "feat/other", "feat/qual", "refs/heads/feat/qual-x", ""):
            with self.subTest(refused=branch):
                calls: list[tuple] = []
                with mock.patch.object(qualification, "_http_req", lambda *a, **k: calls.append(a) or (200, {}, "")):
                    res = qualification.set_remote_branch_ref(API, SLUG, branch, sha, TOKEN)
                self.assertEqual(calls, [], f"HTTP request sent for {branch!r}")
                self.assertEqual(res[0], 0)
                self.assertIn("refused", res[-1])
        for get_code, write_method in ((200, "PATCH"), (404, "POST")):
            with self.subTest(allowed="feat/qual-cand-r1", existing=get_code == 200):
                calls = []

                def fake(method, url, *a, **k):
                    calls.append((method, url))
                    return (get_code, {}, "") if method == "GET" else (201, {"ref": "x"}, "")

                with mock.patch.object(qualification, "_http_req", fake):
                    res = qualification.set_remote_branch_ref(API, SLUG, "feat/qual-cand-r1", sha, TOKEN)
                self.assertEqual([m for m, _ in calls], ["GET", write_method])
                self.assertTrue(all("feat%2Fqual-cand-r1" in u or u.endswith("/git/refs") for _, u in calls))
                self.assertEqual(res[0], 201)

    def test_no_raw_merge_requests_in_qualification(self) -> None:
        """AC2: qualification.py builds no merge endpoint; merges go only through integrate_approved_child."""
        self.assertFalse(hasattr(qualification, "merge_remote_branch"), "merge_remote_branch still exists")
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        offenders = [
            f"line {node.lineno}: {node.value!r}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and "/merge" in node.value  # covers /pulls/N/merge and /merges
        ]
        self.assertEqual(offenders, [], "raw merge endpoint strings in factory/qualification.py")
        self.assertEqual(qualification.integrate_approved_child.__module__, "factory.integration")


if __name__ == "__main__":
    unittest.main()
