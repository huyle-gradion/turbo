"""`deliver` runs a separate test-author session before the implementer (Issue #117).

Pinned interface (the implementation follows it):

- Prompt marker. The test-author session's `--print` prompt contains the line `ROLE: test-author`
  and the child's criteria with their verification commands, not the implementation task.
  The implementer's prompt never contains that marker and names the test-author commit SHA.
  Each session runs with its own isolated HOME under the attempt directory.
- Test-author response. `result.response` holds one line `TURBO-RED: <json>` where the JSON object is
  `{"command": str, "expect": str, "tests": [str, ...]}`: the red command, the expected-failure marker
  and the declared test names. A failed session, a missing or malformed declaration, or no new commit
  is `test-author-failed`.
- Red rules, checked at the test-author commit before the implementer starts, each `red-refused`:
  the command is not one of the child's criterion verification commands; `expect` contains none of the
  declared test names; the commit changes non-test (implementation) paths; the command exits 0; the
  failing output lacks `expect`.
- After the implementer: `test-files-modified` when any file the test-author commit added or changed
  is modified, deleted or renamed at the candidate (blockers name the file; checked before
  spec-check-conflict and scope). Then the red command reruns at the candidate and a nonzero exit is
  `green-failed`. Implementer failures keep today's statuses (builder-failed, missing-implementation, ...).
  None of these refusals opens a PR.
- Evidence. `child/test-separation.json` at `evidence["test_separation_path"]`, also copied to
  `child["test_separation"]` in the record:
  `{"schema": 1,
    "test_author": {"conversation_id", "commit_sha", "tests"},
    "implementer": {"conversation_id"},
    "identity_note": str containing "host conversation ID",
    "red": {"command", "argv", "expect", "exit", "output_sha256", "output_path", "head_sha", "provenance"},
    "green": {"command", "exit", "output_path", "head_sha"},
    "byte_identity": {"result": "identical" | "modified", "files": [{"path", "sha256"}], "modified": [path, ...]}}`.
  `measurements["usage"]` token counts are the sums over both sessions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from support import git
from test_deliver import (
    EXPIRED_TEST_SOURCE, GOOD_BUILDER_SCRIPT, PARENT_TASK, READY_CHILD, TEST_AUTHOR_SCRIPT, _DisposableAsanaServer,
    _DisposableGitHubServer, _make_disposable_product_workspace, _make_fake_agy, _run_deliver,
)

RED_COMMAND = "python3 -m unittest discover -s tests -p test_auth.py -v"
MARK = "import os, pathlib, sys\npathlib.Path(os.environ['HOME'], {name!r}).write_text(sys.argv[sys.argv.index('--print') + 1], encoding='utf-8')\n"
IMPLEMENTER = MARK.format(name="implementer-ran.marker") + GOOD_BUILDER_SCRIPT
COMMIT_TESTS = "subprocess.run(['git', 'add', 'tests/test_auth.py'], check=True)\n"
WRITE_TESTS = f"pathlib.Path('tests/test_auth.py').write_text({EXPIRED_TEST_SOURCE!r}, encoding='utf-8')\n"


def _author(*swaps: tuple[str, str], prefix: str = "") -> str:
    script = TEST_AUTHOR_SCRIPT
    for old, new in swaps:
        assert old in script, old
        script = script.replace(old, new)
    return prefix + script


def _markers(rec: dict, name: str) -> list[Path]:
    return sorted(Path(rec["evidence"]["attempt_dir"]).rglob(name))


class DeliverTestSeparationTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo, self.home, self.bare = _make_disposable_product_workspace(self.root)
        self.asana = _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}])
        self.gh = _DisposableGitHubServer(bare_repo=self.bare)
        for server in (self.asana, self.gh):
            server.__enter__()
            self.addCleanup(server.__exit__, None, None, None)

    def _deliver(self, name: str, implementer: str, author: str | None = None) -> dict:
        agy = _make_fake_agy(self.root, name, implementer, author)
        res, rec = _run_deliver(self.repo, self.home, self.asana.base_url, self.gh.base_url, agy_bin=str(agy))
        self.assertTrue(rec, res.stdout + res.stderr)
        return rec

    def test_successful_delivery_records_both_sessions_red_and_byte_identity(self) -> None:
        author = _author(
            ("'input_tokens': 0, 'output_tokens': 0", "'input_tokens': 80, 'output_tokens': 20"),
            ("'total_tokens': 0", "'total_tokens': 100"),
            prefix=MARK.format(name="test-author-ran.marker"),
        )
        rec = self._deliver("agy-ok", IMPLEMENTER, author)
        self.assertEqual((rec["status"], rec["pr_opened"]), ("qa-missing", True), rec["blockers"])
        child = rec["child"]
        sep = json.loads(Path(rec["evidence"]["test_separation_path"]).read_text(encoding="utf-8"))
        self.assertEqual(child["test_separation"], sep)
        ids = (sep["test_author"]["conversation_id"], sep["implementer"]["conversation_id"])
        self.assertEqual(ids, ("ta-101", "c-101"))
        self.assertIn("host conversation ID", sep["identity_note"])

        ta_sha, cand = sep["test_author"]["commit_sha"], child["candidate_sha"]
        self.assertEqual(sep["test_author"]["tests"], ["test_expired_token"])
        self.assertEqual(git(self.bare, "diff", "--name-only", child["base_sha"], ta_sha), "tests/test_auth.py")
        git(self.bare, "merge-base", "--is-ancestor", ta_sha, cand)
        self.assertNotEqual(ta_sha, cand)

        red = sep["red"]
        self.assertEqual((red["command"], red["expect"], red["head_sha"]), (RED_COMMAND, "FAIL: test_expired_token", ta_sha))
        self.assertNotEqual(red["exit"], 0)
        self.assertIn("FAIL: test_expired_token", Path(red["output_path"]).read_text(encoding="utf-8"))
        self.assertEqual((sep["green"]["command"], sep["green"]["exit"], sep["green"]["head_sha"]), (RED_COMMAND, 0, cand))

        ident = sep["byte_identity"]
        self.assertEqual((ident["result"], ident["modified"]), ("identical", []))
        self.assertEqual(ident["files"], [{"path": "tests/test_auth.py", "sha256": hashlib.sha256(EXPIRED_TEST_SOURCE.encode()).hexdigest()}])

        usage = rec["measurements"]["usage"]
        self.assertEqual((usage["input_tokens"], usage["output_tokens"], usage["total_tokens"]), (580, 140, 740))

        ta_mark, impl_mark = _markers(rec, "test-author-ran.marker"), _markers(rec, "implementer-ran.marker")
        self.assertEqual((len(ta_mark), len(impl_mark)), (1, 1))
        self.assertNotEqual(ta_mark[0].parent, impl_mark[0].parent)
        ta_prompt, impl_prompt = ta_mark[0].read_text(encoding="utf-8"), impl_mark[0].read_text(encoding="utf-8")
        self.assertIn("ROLE: test-author", ta_prompt)
        self.assertIn(RED_COMMAND, ta_prompt)
        self.assertNotIn("ROLE: test-author", impl_prompt)
        self.assertIn(ta_sha, impl_prompt)

    def test_implementer_that_touches_a_test_author_file_is_refused(self) -> None:
        cases = {
            "modified": "pathlib.Path('tests/test_auth.py').write_text('import unittest\\n', encoding='utf-8')\n"
                        "subprocess.run(['git', 'add', '-A'], check=True)\n",
            "deleted": "subprocess.run(['git', 'rm', '-q', 'tests/test_auth.py'], check=True)\n",
            "renamed": "subprocess.run(['git', 'mv', 'tests/test_auth.py', 'tests/test_auth_moved.py'], check=True)\n",
        }
        for label, touch in cases.items():
            with self.subTest(label):
                rec = self._deliver(f"agy-{label}", IMPLEMENTER.replace("subprocess.run(['git', 'commit'", touch + "subprocess.run(['git', 'commit'", 1))
                self.assertEqual((rec["status"], rec["pr_opened"]), ("test-files-modified", False), rec["blockers"])
                self.assertTrue(any("tests/test_auth.py" in b for b in rec["blockers"]), rec["blockers"])
                ident = rec["child"]["test_separation"]["byte_identity"]
                self.assertEqual((ident["result"], ident["modified"]), ("modified", ["tests/test_auth.py"]))
        self.assertFalse([r for r in self.gh.requests if r["method"] == "POST"])

    def test_refused_test_author_commit_never_starts_the_implementer(self) -> None:
        cases = (
            ("red-refused", "passes", _author(('validate_token("expired:123")', 'raise TokenExpiredError("ok")'))),
            ("red-refused", "marker-absent", _author(('validate_token("expired:123")', "validate_token(None.x)"))),
            ("red-refused", "implementation-change", _author(
                (COMMIT_TESTS, "a = pathlib.Path('src/chat_bridge/auth.py'); a.write_text(a.read_text() + '# note\\n')\n"
                               "subprocess.run(['git', 'add', '-A'], check=True)\n"))),
            ("red-refused", "not-a-criterion-command", _author((RED_COMMAND, "python3 -m unittest discover -s tests -v"))),
            ("red-refused", "marker-names-no-declared-test", _author(("'expect': 'FAIL: test_expired_token'", "'expect': 'FAIL:'"))),
            ("test-author-failed", "no-declaration", _author(("'Committed a failing test.\\nTURBO-RED: ' + json.dumps(red)", "'Committed.'"))),
            ("test-author-failed", "no-commit", _author(
                ("subprocess.run(['git', 'commit', '-q', '-m', 'test(auth): specify expired token rejection'], check=True)\n", ""),
                (COMMIT_TESTS, ""), (WRITE_TESTS, ""))),
            ("test-author-failed", "session-error", _author(("'status': 'SUCCESS'", "'status': 'ERROR'"))),
        )
        for status, label, author in cases:
            with self.subTest(label):
                rec = self._deliver(f"agy-{label}", IMPLEMENTER, author)
                self.assertEqual((rec["status"], rec["pr_opened"]), (status, False), rec["blockers"])
                self.assertEqual(_markers(rec, "implementer-ran.marker"), [])
        self.assertFalse([r for r in self.gh.requests if r["method"] == "POST"])

    def test_red_command_failing_after_the_implementer_is_green_failed(self) -> None:
        broken = IMPLEMENTER.replace('token.startswith("expired:")', "False")
        self.assertNotEqual(broken, IMPLEMENTER)
        rec = self._deliver("agy-green", broken)
        self.assertEqual((rec["status"], rec["pr_opened"]), ("green-failed", False), rec["blockers"])
        self.assertEqual(len(_markers(rec, "implementer-ran.marker")), 1)
        self.assertFalse([r for r in self.gh.requests if r["method"] == "POST"])


if __name__ == "__main__":
    unittest.main()
