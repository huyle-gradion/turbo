"""Credential and merge-path safety for hosted qualification (issue #95).

Offline only: every git subprocess and GitHub request is replaced by a recorder.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import io
import logging
import os
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
BASIC = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
SECRET_FORMS = (TOKEN, BASIC, TOKEN[:20], TOKEN[-20:])
HEADER_KEY = "http.https://github.com/.extraheader"
CALLER_GIT_CONFIG = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.foo", "GIT_CONFIG_VALUE_0": "bar"}
# Failing git stderr longer than 500 chars, with the token straddling the 500-char tail boundary.
LONG_STDERR = "fatal: " + "x" * 600 + TOKEN + "y" * 488 + "\n"


class _GitRecorder:
    """Stand-in for subprocess.run/Popen: records argv and env, fakes git."""

    def __init__(self, fail: bool, stderr_text: str | None = None) -> None:
        self.fail = fail
        self.stderr_text = stderr_text
        self.calls: list[tuple[list[str], dict | None]] = []

    def _record(self, args, kwargs) -> list[str]:
        argv = [str(a) for a in (args if isinstance(args, (list, tuple)) else [args])]
        self.calls.append((argv, kwargs.get("env")))
        return argv

    def _stderr(self, argv: list[str]) -> bytes:
        if self.stderr_text is not None:
            return self.stderr_text.encode()
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

    def _assert_no_secret(self, text: str, where: str) -> None:
        for form in SECRET_FORMS:
            self.assertNotIn(form, text, f"secret form {form[:6]}... in {where}")

    def _assert_env_credential(self, env: dict | None) -> None:
        """The git child gets the token as an http.extraheader via GIT_CONFIG_*, keeping caller entries."""
        self.assertIsNotNone(env, "git started without an explicit environment")
        count = int(env.get("GIT_CONFIG_COUNT", "0"))
        pairs = [(env.get(f"GIT_CONFIG_KEY_{i}"), env.get(f"GIT_CONFIG_VALUE_{i}")) for i in range(count)]
        self.assertGreaterEqual(count, 2, f"GIT_CONFIG_COUNT={count}: caller entry or credential missing")
        self.assertEqual(pairs[0], ("core.foo", "bar"), "caller GIT_CONFIG_* entry not preserved at index 0")
        headers = [v for k, v in pairs if k == HEADER_KEY]
        self.assertEqual(len(headers), 1, f"no single {HEADER_KEY} entry within GIT_CONFIG_COUNT")
        prefix = "AUTHORIZATION: basic "
        self.assertTrue(headers[0].startswith(prefix))
        self.assertEqual(base64.b64decode(headers[0][len(prefix):]).decode(), f"x-access-token:{TOKEN}")

    def _run_recorded(self, op, fail: bool, stderr_text: str | None = None):
        rec = _GitRecorder(fail=fail, stderr_text=stderr_text)
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
                 mock.patch.dict(os.environ, CALLER_GIT_CONFIG), \
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
                        self._assert_no_secret(" ".join(argv), f"argv of {argv[:3]}")
                    remote = [env for argv, env in rec.calls if any("github.com" in a for a in argv)]
                    self.assertTrue(remote, f"{name} never contacted github.com")
                    for env in remote:
                        self._assert_env_credential(env)

    def test_hosted_git_failure_does_not_leak_token(self) -> None:
        """AC1 (failure): a failing fetch/clone raises without the token in exception, stderr or logs."""
        fragments = [TOKEN[i:i + 8] for i in range(len(TOKEN) - 7)]
        with tempfile.TemporaryDirectory() as tmp:
            for name, op in self._git_ops(Path(tmp)):
                for case, stderr_text in (("echoed-url", None), ("long-stderr-token-at-tail-boundary", LONG_STDERR)):
                    with self.subTest(function=name, stderr=case):
                        rec, raised, err, logs = self._run_recorded(op, fail=True, stderr_text=stderr_text)
                        self.assertNotIsInstance(raised, AttributeError, f"{name} is missing: {raised!r}")
                        self.assertTrue(rec.calls, f"{name} started no git subprocess")
                        self.assertIsNotNone(raised, f"{name} hid a failed git run")
                        exc_text = _exception_text(raised)
                        self._assert_no_secret(exc_text, "exception text")
                        self._assert_no_secret(err, "stderr")
                        self._assert_no_secret(logs, "logs")
                        for argv, _env in rec.calls:
                            self._assert_no_secret(" ".join(argv), "argv")
                        if stderr_text is not None:
                            leaked = [f for f in fragments if f in exc_text]
                            self.assertEqual(leaked, [], "token fragment survived stderr truncation")

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
