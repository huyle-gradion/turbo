"""Tests for feature-level single-child delivery and PR creation (Issue #19)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any
import unittest

from support import ROOT, config, git, home_dir, make_repo
from test_deliver_checks import _DisposableGitHubServer
from test_intake import _DisposableAsanaServer
from test_intake_eval import _child_notes


def _make_disposable_product_workspace(root: Path) -> tuple[Path, Path, Path]:
    bare = root / "origin.git"
    bare.mkdir()
    git(bare, "init", "--bare", "-q", "-b", "main")
    repo = make_repo(root)
    (repo / "src" / "chat_bridge").mkdir(parents=True)
    (repo / "src" / "chat_bridge" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "src" / "chat_bridge" / "auth.py").write_text(
        "class TokenExpiredError(Exception):\n    pass\n\n"
        "def validate_token(token: str) -> dict[str, str]:\n    return {'sub': token}\n",
        encoding="utf-8",
    )
    (repo / "tests").mkdir(exist_ok=True)
    (repo / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "tests" / "test_auth.py").write_text(
        "import sys, pathlib, unittest\n"
        "sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))\n"
        "from chat_bridge.auth import validate_token\n\n"
        "class AuthTest(unittest.TestCase):\n"
        "    def test_valid_token(self) -> None:\n"
        "        self.assertEqual(validate_token('user-1'), {'sub': 'user-1'})\n",
        encoding="utf-8",
    )
    (repo / "AGENTS.md").write_text("# Protected rules\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "initial product layout")
    git(repo, "remote", "add", "origin", str(bare))
    git(repo, "push", "-q", "-u", "origin", "main")
    home = home_dir(root)
    config(repo, home)
    return repo, home, bare


def _make_fake_agy(root: Path, name: str, body_script: str, test_author_script: str | None = None) -> Path:
    """A fake agy host. A prompt carrying `ROLE: test-author` runs the test-author script; any other runs `body_script`."""
    fake_py = root / f"{name}.py"
    fake_py.write_text(
        "import sys\nif '--version' in sys.argv:\n    print('1.5.1-test')\n    sys.exit(0)\n"
        "if 'ROLE: test-author' in (sys.argv[sys.argv.index('--print') + 1] if '--print' in sys.argv else ''):\n"
        f"    exec({(TEST_AUTHOR_SCRIPT if test_author_script is None else test_author_script)!r})\n    sys.exit(0)\n"
        + body_script,
        encoding="utf-8",
    )
    wrapper = root / name
    wrapper.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{fake_py}' \"$@\"\n", encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper


def _run_deliver(
    repo: Path, home: Path, asana_url: str, gh_url: str, *, task: str = "900",
    agy_bin: str | None = None, time_limit: str = "30s", env_extra: dict[str, str | None] | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TURBO_ASANA_API_URL": asana_url,
        "ASANA_ACCESS_TOKEN": "disposable-asana-token",
        "TURBO_GITHUB_API_URL": gh_url,
        "TURBO_GITHUB_TOKEN": "disposable-gh-token",
    }
    for key, val in (env_extra or {}).items():
        if val is None:
            env.pop(key, None)
        else:
            env[key] = val
    argv = [
        sys.executable, "-P", "-m", "factory", "--repo", str(repo), "--home", str(home),
        "deliver", "--task", task, "--time-limit", time_limit, "--json",
    ]
    if agy_bin:
        argv.extend(["--agy-bin", agy_bin])
    proc_timeout = max(180, int(time_limit[:-1]) + 30) if time_limit.endswith("s") and time_limit[:-1].isdigit() else 180
    res = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True, env=env, timeout=proc_timeout)
    return res, (json.loads(res.stdout) if res.stdout.strip().startswith("{") else {})


SINGLE_CHILD_PARENT_NOTES = (
    "## Delivery target\n"
    "- Repository: https://github.com/example/chat-bridge\n"
    "- Target feature branch: feature/chat-auth\n"
    "- Assigned SWE reviewer: @alice-swe (Asana: Alice Nguyen)\n\n"
    "## Acceptance criteria\n"
    "- P-AC-1: Given a request with an expired auth token, when validated, then TokenExpiredError is raised.\n"
    "  Evaluation: engineering\n"
    "- P-AC-2: Error copy feels clear to non-technical users during Acceptance QA.\n"
    "  Evaluation: human-judgment (Acceptance QA usability review)\n"
)

PARENT_TASK = {"gid": "900", "name": "Add chat authentication", "notes": SINGLE_CHILD_PARENT_NOTES}
READY_CHILD = {
    "gid": "101",
    "name": "Reject expired auth tokens",
    "completed": False,
    "notes": _child_notes(
        criteria=(
            "- AC-1: Given an expired token, when validate_token runs, then TokenExpiredError is raised.\n"
            "  Parent coverage: P-AC-1\n"
            "  Verification: python3 -m unittest discover -s tests -p test_auth.py -v"
        ),
    ),
}

EXPIRED_TEST_SOURCE = (
    'import sys, pathlib, unittest\n'
    'sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))\n'
    'from chat_bridge.auth import TokenExpiredError, validate_token\n\n'
    'class AuthTest(unittest.TestCase):\n'
    '    def test_valid_token(self) -> None:\n'
    '        self.assertEqual(validate_token("user-1"), {"sub": "user-1"})\n'
    '    def test_expired_token(self) -> None:\n'
    '        with self.assertRaises(TokenExpiredError):\n'
    '            validate_token("expired:123")\n'
)
# The default test author: commits only tests/test_auth.py, then declares its red run on a `TURBO-RED: ` response line.
TEST_AUTHOR_SCRIPT = (
    "import json, pathlib, subprocess\n"
    f"pathlib.Path('tests/test_auth.py').write_text({EXPIRED_TEST_SOURCE!r}, encoding='utf-8')\n"
    "subprocess.run(['git', 'add', 'tests/test_auth.py'], check=True)\n"
    "subprocess.run(['git', 'commit', '-q', '-m', 'test(auth): specify expired token rejection'], check=True)\n"
    "red = {'command': 'python3 -m unittest discover -s tests -p test_auth.py -v', 'expect': 'FAIL: test_expired_token', 'tests': ['test_expired_token']}\n"
    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'ta-101', 'status': 'SUCCESS', "
    "'response': 'Committed a failing test.\\nTURBO-RED: ' + json.dumps(red), "
    "'usage': {'input_tokens': 0, 'output_tokens': 0, 'thinking_tokens': 0, 'cache_read_tokens': 0, 'total_tokens': 0}}}))\n"
)

GOOD_BUILDER_SCRIPT = (
    "import json, pathlib, subprocess\n"
    "pathlib.Path('src/chat_bridge/auth.py').write_text(\n"
    "    'class TokenExpiredError(Exception):\\n    pass\\n\\n'\n"
    "    'def validate_token(token: str) -> dict[str, str]:\\n'\n"
    "    '    if token.startswith(\"expired:\"):\\n        raise TokenExpiredError(\"token expired\")\\n'\n"
    "    '    return {\"sub\": token}\\n', encoding='utf-8')\n"
    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
    "subprocess.run(['git', 'commit', '-q', '-m', 'feat(auth): reject expired auth tokens'], check=True)\n"
    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c-101', 'status': 'SUCCESS', 'response': 'Implemented expired token check and test.', 'usage': {'input_tokens': 500, 'output_tokens': 120, 'thinking_tokens': 20, 'cache_read_tokens': 0, 'total_tokens': 640}}}))\n"
)


class DeliverChildTest(unittest.TestCase):
    def test_deliver_single_ready_child_opens_and_confirms_pr_into_feature_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            main_sha_before = git(bare, "rev-parse", "refs/heads/main")
            fake_wrapper = _make_fake_agy(root, "fake-agy", GOOD_BUILDER_SCRIPT)
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                res, payload = _run_deliver(
                    repo, home, asana.base_url, gh.base_url,
                    task="https://app.asana.com/0/12345/900", agy_bin=str(fake_wrapper),
                )
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertEqual(
                    (payload["status"], payload["pr_opened"], payload["ci_verified"], payload["verified"], payload["delivery_approved"], payload["merged"]),
                    ("qa-missing", True, True, False, False, False),
                )
                self.assertIn("not independently reviewed", payload["verification_scope"])
                self.assertNotIn(payload["status"], ("completed", "merged", "accepted", "verified"))
                child_rec = payload["child"]
                self.assertEqual(
                    (child_rec["gid"], child_rec["status"], child_rec["ci_verified"], child_rec["verified"], child_rec["delivery_approved"], child_rec["base_branch"], child_rec["base_sha"]),
                    ("101", "qa-missing", True, False, False, "feature/chat-auth", main_sha_before),
                )
                self.assertEqual(child_rec["scope_check"]["status"], "deterministic-only-semantic-unverified")
                self.assertFalse(child_rec["scope_check"]["semantic_verified"])
                ci_ver = child_rec["ci_verification"]
                self.assertEqual((ci_ver["status"], ci_ver["verified"], ci_ver["candidate_sha"], ci_ver["base_sha"]), ("verified", True, child_rec["candidate_sha"], main_sha_before))
                self.assertEqual(ci_ver["revision_kind"], "integration-merge")
                pr_info = child_rec["pr"]
                self.assertEqual(
                    (pr_info["number"], pr_info["base_ref"], pr_info["head_ref"], pr_info["head_sha"], pr_info["verified"], pr_info["delivery_approved"], pr_info["ci_verified"]),
                    (1, "feature/chat-auth", child_rec["head_branch"], child_rec["candidate_sha"], False, False, True),
                )
                for token in (
                    "900", "101", child_rec["candidate_sha"], main_sha_before, ci_ver["tested_sha"],
                    "criterion/AC-1", "guard/gate-2", "https://github.com/example/chat-bridge/actions/runs/",
                ):
                    self.assertIn(token, pr_info["body"])
                self.assertEqual(git(bare, "rev-parse", "refs/heads/main"), main_sha_before)
                self.assertEqual(git(bare, "rev-parse", "refs/heads/feature/chat-auth"), main_sha_before)
                self.assertEqual(git(bare, "rev-parse", f"refs/heads/{child_rec['head_branch']}"), child_rec["candidate_sha"])
                self.assertTrue(all(r["method"] == "GET" for r in asana.requests))
                self.assertIn("PATCH", [r["method"] for r in gh.requests])

    def test_unsupported_multi_child_or_existing_diverged_feature_branch_refuses_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            c1 = {
                "gid": "101",
                "name": "Slice 1",
                "notes": _child_notes(criteria="- AC-1: Valid.\n  Parent coverage: P-AC-1\n  Verification: python3 -m unittest"),
            }
            c2 = {
                "gid": "102",
                "name": "Slice 2",
                "notes": _child_notes(
                    criteria="- AC-1: Valid 2.\n  Parent coverage: P-AC-1\n  Verification: python3 -m unittest",
                    blocked_by="101", required_outputs="TokenValidator contract in chat_bridge.auth", produces="Out2",
                ),
            }
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [c1, c2], "next_page": None}]) as asana,
                _DisposableGitHubServer() as gh,
            ):
                res, rec = _run_deliver(repo, home, asana.base_url, gh.base_url)
                self.assertEqual(
                    (res.returncode, rec["status"], rec["pr_opened"], len(gh.requests)),
                    (1, "unsupported-topology", False, 0),
                )
                self.assertTrue(any("101, 102" in b for b in rec["blockers"]))

            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [c2], "next_page": None}]) as asana,
                _DisposableGitHubServer() as gh,
            ):
                res_dep, rec_dep = _run_deliver(repo, home, asana.base_url, gh.base_url)
                self.assertEqual(
                    (res_dep.returncode, rec_dep["status"], rec_dep["pr_opened"]),
                    (1, "unsupported-topology", False),
                )
                self.assertTrue(any("dependencies" in b for b in rec_dep["blockers"]))

            git(repo, "checkout", "-q", "-b", "feature/chat-auth")
            (repo / "UNRELATED.txt").write_text("preserve me\n", encoding="utf-8")
            git(repo, "add", "UNRELATED.txt")
            git(repo, "commit", "-q", "-m", "existing feature work")
            feature_tip = git(repo, "rev-parse", "HEAD")
            git(repo, "push", "-q", "origin", "feature/chat-auth")
            git(repo, "checkout", "-q", "main")
            git(repo, "branch", "-f", "feature/chat-auth", "main")
            git(repo, "checkout", "-q", "feature/chat-auth")
            (repo / "DIVERGED.txt").write_text("local divergence\n", encoding="utf-8")
            git(repo, "add", "DIVERGED.txt")
            git(repo, "commit", "-q", "-m", "diverged local feature")
            local_diverged = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "main")
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [c1], "next_page": None}]) as asana,
                _DisposableGitHubServer() as gh,
            ):
                res_div, rec_div = _run_deliver(repo, home, asana.base_url, gh.base_url)
                self.assertEqual((res_div.returncode, rec_div["status"]), (1, "branch-failed"))
                self.assertEqual(git(repo, "rev-parse", "refs/heads/feature/chat-auth"), local_diverged)
                self.assertEqual(git(bare, "rev-parse", "refs/heads/feature/chat-auth"), feature_tip)
                git(repo, "remote", "set-url", "origin", "https://github.com/other-org/wrong-repo.git")
                res_org, rec_org = _run_deliver(repo, home, asana.base_url, gh.base_url)
                self.assertEqual((res_org.returncode, rec_org["status"]), (1, "branch-failed"))
                self.assertTrue(any("origin remote" in b for b in rec_org["blockers"]))
                self.assertTrue((home / "deliveries" / "900" / "attempt-1" / "record.json").exists())
                self.assertTrue((home / "deliveries" / "900" / "attempt-4" / "record.json").exists())

    def test_builder_failure_missing_impl_missing_tests_or_failing_tests_fails_closed_without_opening_pr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, _ = _make_disposable_product_workspace(root)
            cases = (
                (
                    "builder-failed",
                    "import json\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c1', 'status': 'ERROR', 'response': 'I opened PR #1!'}}))\n",
                ),
                (
                    "missing-implementation",
                    "import json\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c2', 'status': 'SUCCESS', 'response': 'Done and opened PR!'}}))\n",
                ),
                (
                    "missing-implementation",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('tests/test_extra.py').write_text('import unittest\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', 'tests/test_extra.py'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'test only'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c4', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "spec-check-conflict",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('.github/workflows').mkdir(parents=True, exist_ok=True)\n"
                    "pathlib.Path('.github/workflows/ci.yml').write_text('name: weakened\\n', encoding='utf-8')\n"
                    "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str):\\n    return {\"sub\": token}\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', '.'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'redefine CI workflow'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c5', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "timed-out",
                    "import json, pathlib, subprocess, time\n"
                    "time.sleep(5)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c6', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
            )
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _DisposableGitHubServer() as gh,
            ):
                for idx, (expected_status, body_script) in enumerate(cases, start=1):
                    with self.subTest(case=expected_status, attempt=idx):
                        wrapper = _make_fake_agy(root, f"fake-agy-{idx}", body_script)
                        limit_arg = "1s" if expected_status == "timed-out" else "30s"
                        res, payload = _run_deliver(
                            repo, home, asana.base_url, gh.base_url, agy_bin=str(wrapper), time_limit=limit_arg
                        )
                        self.assertEqual(
                            (res.returncode, payload["status"], payload["pr_opened"], payload["child"]["pr"], payload["attempt"]),
                            (1, expected_status, False, None, idx),
                        )
                        self.assertTrue((home / "deliveries" / "900" / f"attempt-{idx}" / "record.json").exists())
                self.assertEqual(len(gh.requests), 0)

    def test_unauthorized_scope_expansion_and_github_rejection_or_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            scoped_child = {
                "gid": "101",
                "name": "Reject expired auth tokens",
                "notes": (
                    "## Outcome\nDeliver bounded feature slice.\n\n"
                    "## Delivery target\n- Parent task: https://app.asana.com/0/0/900\n"
                    "- Repository: https://github.com/example/chat-bridge\n"
                    "- Target feature branch: feature/chat-auth\n"
                    "- Assigned SWE reviewer: @alice-swe (Asana: Alice Nguyen)\n- Kind: implementation\n\n"
                    "## Scope\n- In scope: `src/chat_bridge/`, `tests/`\n"
                    "- Out of scope: `src/chat_bridge/billing.py`, `billing/`\n"
                    "- Constraints: Keep logic in `src/chat_bridge/auth.py`; do not modify `docs/spec.md` or `AGENTS.md`\n\n"
                    "## Acceptance criteria\n- AC-1: Given an expired token, when validate_token runs, then TokenExpiredError is raised.\n"
                    "  Parent coverage: P-AC-1\n"
                    "  Verification: python3 -m unittest discover -s tests -p test_auth.py -v\n\n"
                    "## Dependencies and handoff\n- Blocked by: none\n- Required outputs: none\n- Produces: TokenValidator contract\n\n"
                    "## Context\n- Specification/contracts: docs/auth-spec.md\n- Test prerequisites: local fixtures\n- Open questions: none\n"
                ),
            }
            scope_scripts = (
                (
                    "out-of-scope-file",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('src/chat_bridge/billing.py').write_text('x = 1\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', '.'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'touch billing'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 's1', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "outside-in-scope-prefix",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('scripts').mkdir(exist_ok=True)\n"
                    "pathlib.Path('scripts/deploy.py').write_text('x = 1\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', '.'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'touch scripts'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 's2', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "protected-path-violation",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('AGENTS.md').write_text('# Weakened rules\\n', encoding='utf-8')\n"
                    "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str): return {\"sub\": token}\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', '.'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'touch protected AGENTS.md'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 's3', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
            )
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [scoped_child], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                for label, body_script in scope_scripts:
                    with self.subTest(scope_case=label):
                        wrapper = _make_fake_agy(root, f"fake-{label}", body_script)
                        res, rec = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(wrapper))
                        self.assertEqual((res.returncode, rec["status"], rec["pr_opened"]), (1, "scope-violation", False))
                        self.assertEqual(rec["child"]["scope_check"]["in_scope_enforcement"], "deterministic-paths")
                        self.assertEqual(rec["child"]["scope_check"]["out_of_scope_enforcement"], "deterministic-paths")
                self.assertEqual(len(gh.requests), 0)

            good_wrapper = _make_fake_agy(root, "fake-good", GOOD_BUILDER_SCRIPT)
            with _DisposableAsanaServer(PARENT_TASK, [{"data": [scoped_child], "next_page": None}]) as asana:
                with _DisposableGitHubServer(bare_repo=bare, post_status=422) as gh_422:
                    res_422, rec_422 = _run_deliver(repo, home, asana.base_url, gh_422.base_url, agy_bin=str(good_wrapper))
                    self.assertEqual((res_422.returncode, rec_422["status"], rec_422["pr_opened"]), (1, "pr-failed", False))
                    self.assertEqual(rec_422["child"]["scope_check"]["status"], "deterministic-verified")
                    self.assertTrue(rec_422["child"]["scope_check"]["semantic_verified"])
                    self.assertTrue(any("422" in b for b in rec_422["blockers"]))

                with _DisposableGitHubServer(bare_repo=bare, verify_override={"base_ref": "main"}) as gh_wrong_base:
                    res_wb, rec_wb = _run_deliver(
                        repo, home, asana.base_url, gh_wrong_base.base_url, agy_bin=str(good_wrapper)
                    )
                    self.assertEqual((res_wb.returncode, rec_wb["status"], rec_wb["pr_opened"]), (1, "pr-failed", False))
                    self.assertTrue(any("base branch mismatch" in b for b in rec_wb["blockers"]))

                with _DisposableGitHubServer(bare_repo=bare) as gh_prod_leak:
                    res_leak, rec_leak = _run_deliver(
                        repo, home, asana.base_url, gh_prod_leak.base_url, agy_bin=str(good_wrapper),
                        env_extra={"TURBO_GITHUB_TOKEN": None, "GITHUB_TOKEN": "ghp_RealProductionToken999"},
                    )
                    self.assertEqual((res_leak.returncode, rec_leak["status"], len(gh_prod_leak.requests)), (1, "pr-failed", 0))
                    self.assertTrue(any("production" in b.lower() for b in rec_leak["blockers"]))
                    self.assertNotIn("ghp_RealProductionToken999", res_leak.stdout)

    def test_safety_probes_prevent_builder_start_and_task_prose_does_not_trigger_timeout(self) -> None:
        from unittest import mock
        from factory import deliver as deliver_module
        from factory.paths import RuntimePaths

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            prose_child = {
                "gid": "101",
                "name": "Handle session when token has timed out",
                "notes": _child_notes(
                    criteria="- AC-1: Handle token.\n  Parent coverage: P-AC-1\n  Verification: python3 -m unittest",
                    open_questions="What happens when a session has timed out?",
                ),
            }
            marker = root / "builder_ran.marker"
            marker_wrapper = _make_fake_agy(
                root,
                "fake-marker",
                f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n" + GOOD_BUILDER_SCRIPT,
            )
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [prose_child], "next_page": None}]) as asana_prose,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                res_prose, rec_prose = _run_deliver(
                    repo, home, asana_prose.base_url, gh.base_url, agy_bin=str(marker_wrapper)
                )
                self.assertEqual((res_prose.returncode, rec_prose["status"]), (1, "intake-blocked"))
                self.assertFalse(marker.exists())

            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana_ok,
                _DisposableGitHubServer(bare_repo=bare) as gh,
                mock.patch.dict(
                    os.environ,
                    {
                        "TURBO_ASANA_API_URL": asana_ok.base_url,
                        "ASANA_ACCESS_TOKEN": "disposable-asana-token",
                        "TURBO_GITHUB_API_URL": gh.base_url,
                        "TURBO_GITHUB_TOKEN": "disposable-gh-token",
                    },
                ),
            ):
                with mock.patch("urllib.request.OpenerDirector.open", side_effect=TimeoutError("timed out")):
                    res_to = deliver_module.deliver_feature(
                        RuntimePaths(repo=repo, home=home),
                        deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=30, agy_bin=str(marker_wrapper)),
                    )
                    self.assertEqual(res_to.status, "timed-out")
                    self.assertFalse(marker.exists())

                with mock.patch("factory.sandbox.sandbox_available", return_value=False):
                    res_unsafe = deliver_module.deliver_feature(
                        RuntimePaths(repo=repo, home=home),
                        deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=30, agy_bin=str(marker_wrapper)),
                    )
                    self.assertEqual(res_unsafe.status, "unsafe-environment")
                    self.assertFalse(marker.exists())
                    self.assertIsNone(res_unsafe.evidence["builder_exit"])

    def test_isolated_builder_preserves_failed_evidence_without_publishing_and_avoids_branch_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            main_sha = git(repo, "rev-parse", "refs/heads/main")
            repo_sentinel = repo / "CONTROLLER_REPO_SENTINEL.txt"
            repo_sentinel.write_text("REPO_SENTINEL_INTACT\n", encoding="utf-8")
            home_sentinel = home / "controller_cred.sentinel"
            home_sentinel.write_text("HOME_SENTINEL_INTACT\n", encoding="utf-8")
            hostile_fail_script = (
                "import json, os, pathlib, shutil, subprocess, sys\n"
                "cat_bin = shutil.which('cat') or '/bin/cat'\n"
                f"for target in ({str(repo_sentinel)!r}, {str(home_sentinel)!r}):\n"
                "    env_copy = {}\n"
                "    assert subprocess.run([sys.executable, '-I', '-S', '-c', f'open({target!r}, \"rb\").read()'], env=env_copy, capture_output=True).returncode != 0\n"
                "    assert subprocess.run([sys.executable, '-I', '-S', '-c', f'open({target!r}, \"wb\").write(b\"pwn\")'], env=env_copy, capture_output=True).returncode != 0\n"
                "    assert subprocess.run([cat_bin, target], env=env_copy, capture_output=True).returncode != 0\n"
                "pathlib.Path('AGENTS.md').write_text('# Hostile rules\\n', encoding='utf-8')\n"
                "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str): return {}\\n', encoding='utf-8')\n"
                "subprocess.run(['git', 'add', '.'], check=True)\n"
                "subprocess.run(['git', 'commit', '-q', '-m', 'hostile failed attempt'], check=True)\n"
                "subprocess.run(['git', 'branch', '-f', 'main', 'HEAD'], check=False)\n"
                "subprocess.run(['git', 'branch', '-f', 'feature/chat-auth', 'HEAD'], check=False)\n"
                "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'h1', 'status': 'SUCCESS', 'response': 'Done'}}))\n"
            )
            hostile_wrapper = _make_fake_agy(root, "fake-hostile", hostile_fail_script)
            good_wrapper = _make_fake_agy(root, "fake-good-collide", GOOD_BUILDER_SCRIPT)
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                res_fail, rec_fail = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(hostile_wrapper))
                self.assertEqual((res_fail.returncode, rec_fail["status"]), (1, "scope-violation"))
                self.assertEqual(repo_sentinel.read_text(encoding="utf-8"), "REPO_SENTINEL_INTACT\n")
                self.assertEqual(home_sentinel.read_text(encoding="utf-8"), "HOME_SENTINEL_INTACT\n")
                self.assertEqual(git(repo, "rev-parse", "refs/heads/main"), main_sha)
                self.assertEqual(git(repo, "rev-parse", "refs/heads/feature/chat-auth"), main_sha)
                rejected_sha = rec_fail["child"]["candidate_sha"]
                self.assertNotEqual(rejected_sha, main_sha)
                cat_res = subprocess.run(
                    ["git", "cat-file", "-t", rejected_sha], cwd=str(repo), capture_output=True, text=True
                )
                self.assertNotEqual(cat_res.returncode, 0)
                self.assertTrue(Path(rec_fail["evidence"]["candidate_diff_path"]).exists())
                self.assertTrue(Path(rec_fail["evidence"]["worktree_status_path"]).exists())

                base_child_branch = "task/101-reject-expired-auth-tokens"
                git(repo, "branch", base_child_branch, main_sha)
                git(repo, "branch", f"{base_child_branch}-attempt-2", main_sha)
                git(repo, "push", "-q", "origin", base_child_branch, f"{base_child_branch}-attempt-2")
                res_ok, rec_ok = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(good_wrapper))
                self.assertEqual(
                    (res_ok.returncode, rec_ok["status"], rec_ok["ci_verified"], rec_ok["verified"], rec_ok["delivery_approved"], rec_ok["attempt"]),
                    (1, "qa-missing", True, False, False, 2),
                )
                self.assertEqual(rec_ok["child"]["head_branch"], f"{base_child_branch}-attempt-3")
                self.assertEqual(git(bare, "rev-parse", f"refs/heads/{base_child_branch}"), main_sha)
                self.assertEqual(git(bare, "rev-parse", f"refs/heads/{base_child_branch}-attempt-2"), main_sha)
                self.assertEqual(
                    git(bare, "rev-parse", f"refs/heads/{base_child_branch}-attempt-3"),
                    rec_ok["child"]["candidate_sha"],
                )

    def test_broken_behavior_fails_mapped_ci_check_and_restoring_passes_plus_pending_and_conflict_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            broken_script = GOOD_BUILDER_SCRIPT.replace('token.startswith("expired:")', "False")
            broken_wrapper = _make_fake_agy(root, "fake-broken", broken_script)
            fixed_wrapper = _make_fake_agy(root, "fake-fixed", GOOD_BUILDER_SCRIPT)
            conflict_child = {
                "gid": "101", "name": "Conflict slice", "completed": False,
                "notes": READY_CHILD["notes"].replace("- Out of scope: billing", "- Out of scope: `tests/test_auth.py`"),
            }
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [conflict_child], "next_page": None}]) as asana_conf,
                _DisposableGitHubServer(bare_repo=bare) as gh_conf,
            ):
                res_conf, rec_conf = _run_deliver(repo, home, asana_conf.base_url, gh_conf.base_url, agy_bin=str(fixed_wrapper))
                self.assertEqual((res_conf.returncode, rec_conf["status"], rec_conf["pr_opened"], rec_conf["verified"]), (1, "spec-check-conflict", False, False))
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                res_brk, rec_brk = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(broken_wrapper))
                self.assertEqual((res_brk.returncode, rec_brk["status"], rec_brk["pr_opened"], rec_brk["verified"], rec_brk["merged"]), (1, "green-failed", False, False, False))
                res_fix, rec_fix = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(fixed_wrapper))
                self.assertEqual(
                    (res_fix.returncode, rec_fix["status"], rec_fix["pr_opened"], rec_fix["ci_verified"], rec_fix["verified"], rec_fix["delivery_approved"], rec_fix["merged"]),
                    (1, "qa-missing", True, True, False, False, False),
                )
                self.assertEqual((rec_fix["child"]["pr"]["pr_confirmed"], rec_fix["child"]["pr"]["ci_verified"], rec_fix["child"]["pr"]["verified"]), (True, True, False))
                self.assertIn("criterion/AC-1`: **SUCCESS**", rec_fix["child"]["pr"]["body"])
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana_pend,
                _DisposableGitHubServer(bare_repo=bare, ci_spec={"mode": "none"}) as gh_pend,
            ):
                res_p, rec_p = _run_deliver(repo, home, asana_pend.base_url, gh_pend.base_url, agy_bin=str(fixed_wrapper), time_limit="2s")
                self.assertEqual((res_p.returncode, rec_p["status"], rec_p["pr_opened"], rec_p["verified"]), (1, "ci-pending", True, False))
                self.assertEqual((rec_p["child"]["pr"]["pr_confirmed"], rec_p["child"]["pr"]["ci_verified"]), (True, False))
                self.assertEqual(len(rec_p["child"]["verification_checks"]), 4)

    @unittest.skipUnless(os.environ.get("TURBO_LIVE_AGY") == "1", "requires TURBO_LIVE_AGY=1 and authenticated agy")
    def test_live_authenticated_agy_builder_delivers_prepared_child_and_opens_pr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            main_sha_before = git(bare, "rev-parse", "refs/heads/main")
            child = {
                "gid": "101",
                "name": "Reject expired auth tokens",
                "completed": False,
                "notes": _child_notes(
                    criteria=(
                        "- AC-1: Given a token starting with 'expired:', when validate_token(token) in src/chat_bridge/auth.py runs, then TokenExpiredError is raised, and a unit test in tests/test_auth.py verifies it.\n"
                        "  Parent coverage: P-AC-1\n"
                        "  Verification: python3 -m unittest discover -s tests -p test_auth.py -v"
                    ),
                ),
            }
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [child], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
            ):
                res, payload = _run_deliver(
                    repo, home, asana.base_url, gh.base_url, task="https://app.asana.com/0/12345/900", time_limit="90s"
                )
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual((payload["status"], payload["pr_opened"], payload["verified"], payload["merged"]), ("verified", True, True, False))
                self.assertEqual(git(bare, "rev-parse", "refs/heads/main"), main_sha_before)
                self.assertEqual(payload["child"]["pr"]["base_ref"], "feature/chat-auth")
                self.assertTrue(payload["child"]["pr"]["verified"])

    @unittest.skipUnless(os.environ.get("TURBO_LIVE_GITHUB_CI") == "1", "requires TURBO_LIVE_GITHUB_CI=1 and gh auth")
    def test_live_github_hosted_ci_workflow_gates_broken_and_fixed_child_prs(self) -> None:
        import base64
        import time as time_mod
        from factory import ci_gate

        gh_token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
        gh_user = subprocess.run(["gh", "api", "user", "-q", ".login"], capture_output=True, text=True, check=True).stdout.strip()
        repo_slug = f"{gh_user}/turbo-disp-ci-20-{int(time_mod.time())}"
        subprocess.run(["gh", "repo", "create", repo_slug, "--private"], check=True, capture_output=True, text=True)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo, home, _ = _make_disposable_product_workspace(root)
                wf_dir = repo / ".github" / "workflows"
                wf_dir.mkdir(parents=True, exist_ok=True)
                matrix_items = (
                    ("guard/gate-1", "guard", "gate-1", "python3 -c \"print('gate-1 ok')\""),
                    ("guard/gate-2", "guard", "gate-2", "python3 -m unittest discover -s tests -p test_smoke_guard.py -v"),
                    ("guard/gate-3", "guard", "gate-3", "python3 -c \"print('gate-3 ok')\""),
                    ("criterion/AC-1", "criterion", "ac-1", "python3 -m unittest discover -s tests -p test_auth.py -v"),
                )
                inc_yaml = "".join(
                    f"          - check_name: {cn}\n            check_kind: {ck}\n            suffix: {sf}\n            cmd: {cm}\n"
                    for cn, ck, sf, cm in matrix_items
                )
                ci_runner_py = (
                    "import json, os, pathlib, shlex, subprocess\n"
                    "subprocess.run(['git', 'diff', '--quiet', os.environ['BASE_SHA'], os.environ['TESTED_SHA'], '--', '.github', 'AGENTS.md'], check=True)\n"
                    "cmd = os.environ['CHECK_CMD']\n"
                    "p = subprocess.run(shlex.split(cmd), capture_output=True, text=True)\n"
                    "out = (p.stdout + p.stderr).strip() + '\\n'\n"
                    "cn = os.environ['CHECK_NAME']\n"
                    "run_id = int(os.environ['RUN_ID'])\n"
                    "run_attempt = int(os.environ['RUN_ATTEMPT'])\n"
                    "base_ref = os.environ.get('BASE_REF', '')\n"
                    "pol_sha = '0' * 40 if base_ref.endswith('-untrusted') else os.environ['BASE_SHA']\n"
                    "rec = {\n"
                    "    'workflow_run_id': run_id,\n"
                    "    'run_attempt': run_attempt,\n"
                    "    'workflow_path': '.github/workflows/ci.yml',\n"
                    "    'workflow_event': 'pull_request',\n"
                    "    'workflow_head_sha': os.environ['CANDIDATE_SHA'],\n"
                    "    'policy_sha': pol_sha,\n"
                    "    'candidate_sha': os.environ['CANDIDATE_SHA'],\n"
                    "    'base_sha': os.environ['BASE_SHA'],\n"
                    "    'tested_sha': os.environ['TESTED_SHA'],\n"
                    "    'revision_kind': 'integration-merge',\n"
                    "    'check_name': cn,\n"
                    "    'kind': os.environ['CHECK_KIND'],\n"
                    "    'command': cmd,\n"
                    "    'exit_code': p.returncode,\n"
                    "    'conclusion': 'success' if p.returncode == 0 else 'failure',\n"
                    "    'html_url': os.environ['RUN_URL'],\n"
                    "    'log_text': out,\n"
                    "}\n"
                    "d = pathlib.Path('ci-ev')\n"
                    "d.mkdir(exist_ok=True)\n"
                    "(d / 'turbo-ci-evidence.json').write_text(json.dumps({'schema': 1, 'workflow_run_id': run_id, 'run_attempt': run_attempt, 'checks': {cn: rec}}))\n"
                    "with open(os.environ['GITHUB_OUTPUT'], 'a') as f:\n"
                    "    f.write(f'exit_code={p.returncode}\\n')\n"
                )
                runner_b64 = base64.b64encode(ci_runner_py.encode("utf-8")).decode("ascii")
                (wf_dir / "ci.yml").write_text(
                    f"name: CI\non:\n  pull_request:\n    branches: ['feature/**']\njobs:\n  checks:\n"
                    f"    name: ${{{{ matrix.check_name }}}}\n    runs-on: ubuntu-latest\n    strategy:\n"
                    f"      fail-fast: false\n      matrix:\n        include:\n{inc_yaml}    steps:\n"
                    f"      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n"
                    f"      - name: Run check\n        id: run_check\n        env:\n"
                    f"          CHECK_NAME: ${{{{ matrix.check_name }}}}\n"
                    f"          CHECK_KIND: ${{{{ matrix.check_kind }}}}\n"
                    f"          CHECK_CMD: ${{{{ matrix.cmd }}}}\n"
                    f"          CANDIDATE_SHA: ${{{{ github.event.pull_request.head.sha }}}}\n"
                    f"          BASE_SHA: ${{{{ github.event.pull_request.base.sha }}}}\n"
                    f"          BASE_REF: ${{{{ github.event.pull_request.base.ref }}}}\n"
                    f"          TESTED_SHA: ${{{{ github.sha }}}}\n"
                    f"          RUN_ID: ${{{{ github.run_id }}}}\n"
                    f"          RUN_ATTEMPT: ${{{{ github.run_attempt }}}}\n"
                    f"          RUN_URL: https://github.com/${{{{ github.repository }}}}/actions/runs/${{{{ github.run_id }}}}\n"
                    f"        run: python3 -I -c \"import base64; exec(base64.b64decode('{runner_b64}'))\"\n"
                    f"      - uses: actions/upload-artifact@v4\n        if: always()\n        with:\n"
                    f"          name: turbo-ci-evidence-${{{{ matrix.suffix }}}}\n"
                    f"          path: ci-ev/turbo-ci-evidence.json\n"
                    f"      - if: steps.run_check.outputs.exit_code != '0'\n"
                    f"        run: exit ${{{{ steps.run_check.outputs.exit_code }}}}\n",
                    encoding="utf-8",
                )
                (repo / "tests" / "test_smoke_guard.py").write_text(
                    "import unittest\nclass SmokeGuard(unittest.TestCase):\n    def test_guard(self): self.assertTrue(True)\n",
                    encoding="utf-8",
                )
                git(repo, "config", "credential.helper", "!gh auth git-credential")
                git(repo, "add", ".")
                git(repo, "commit", "-q", "-m", "add CI workflow")
                git(repo, "remote", "set-url", "origin", f"https://github.com/{repo_slug}.git")
                git(repo, "push", "-q", "-u", "origin", "main")
                live_parent = {"gid": "900", "name": "Add chat authentication", "notes": SINGLE_CHILD_PARENT_NOTES.replace("example/chat-bridge", repo_slug)}
                live_child = {"gid": "101", "name": "Reject expired auth tokens", "completed": False, "notes": READY_CHILD["notes"].replace("example/chat-bridge", repo_slug)}
                untrusted_parent = {
                    "gid": "900", "name": "Add chat authentication",
                    "notes": live_parent["notes"].replace("feature/chat-auth", "feature/chat-auth-untrusted"),
                }
                untrusted_child = {
                    "gid": "101", "name": "Reject expired auth tokens", "completed": False,
                    "notes": live_child["notes"].replace("feature/chat-auth", "feature/chat-auth-untrusted"),
                }
                broken_w = _make_fake_agy(root, "live-broken", GOOD_BUILDER_SCRIPT.replace('token.startswith("expired:")', "False"))
                fixed_w = _make_fake_agy(root, "live-fixed", GOOD_BUILDER_SCRIPT)
                env_gh = {"TURBO_GITHUB_TOKEN": None, "GITHUB_TOKEN": gh_token}
                with _DisposableAsanaServer(live_parent, [{"data": [live_child], "next_page": None}]) as asana:
                    res1, rec1 = _run_deliver(repo, home, asana.base_url, "https://api.github.com", agy_bin=str(broken_w), time_limit="180s", env_extra=env_gh)
                    self.assertEqual((res1.returncode, rec1["status"], rec1["pr_opened"], rec1["verified"]), (1, "ci-failed", True, False))
                    self.assertEqual((rec1["child"]["pr"]["pr_confirmed"], rec1["child"]["pr"]["ci_verified"]), (True, False))
                    self.assertIn("criterion/AC-1`: **FAILURE**", rec1["child"]["pr"]["body"])

                    res2, rec2 = _run_deliver(repo, home, asana.base_url, "https://api.github.com", agy_bin=str(fixed_w), time_limit="180s", env_extra=env_gh)
                    self.assertEqual((res2.returncode, rec2["status"], rec2["pr_opened"], rec2["verified"]), (0, "verified", True, True))
                    self.assertEqual((rec2["child"]["pr"]["pr_confirmed"], rec2["child"]["pr"]["ci_verified"]), (True, True))
                    self.assertIn("criterion/AC-1`: **SUCCESS**", rec2["child"]["pr"]["body"])

                with _DisposableAsanaServer(untrusted_parent, [{"data": [untrusted_child], "next_page": None}]) as asana_untrusted:
                    res_neg, rec_neg = _run_deliver(
                        repo, home, asana_untrusted.base_url, "https://api.github.com",
                        agy_bin=str(fixed_w), time_limit="180s", env_extra=env_gh,
                    )
                    self.assertEqual((res_neg.returncode, rec_neg["status"], rec_neg["pr_opened"], rec_neg["verified"]), (1, "ci-untrusted-producer", True, False))
                    self.assertEqual((rec_neg["child"]["pr"]["pr_confirmed"], rec_neg["child"]["pr"]["ci_verified"]), (True, False))
                    self.assertTrue(any("policy_sha" in b for b in rec_neg["blockers"]), rec_neg["blockers"])

                # Advance feature/chat-auth on hosted origin and verify stale-revision invalidation
                cand_sha_green = rec2["child"]["candidate_sha"]
                git(repo, "push", "-q", "origin", f"{cand_sha_green}:refs/heads/feature/chat-auth")
                stale_reval = ci_gate.revalidate_child_verification(
                    repo=repo, base_url="https://api.github.com", token=gh_token, repo_slug=repo_slug,
                    child_record=rec2["child"], trace=[], deadline=time_mod.monotonic() + 30.0, limit_s=30,
                )
                self.assertEqual((stale_reval["status"], stale_reval["verified"]), ("stale-revision", False))
                if proof_out := os.environ.get("TURBO_LIVE_GITHUB_CI_PROOF_PATH"):
                    Path(proof_out).write_text(
                        json.dumps(
                            {
                                "repo_slug": repo_slug,
                                "red": rec1,
                                "green": rec2,
                                "negative_provenance": rec_neg,
                                "stale_revision": stale_reval,
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
        finally:
            subprocess.run(["gh", "api", "-X", "DELETE", f"repos/{repo_slug}"], check=False, capture_output=True)

    def test_delivery_enforcement_requires_exact_candidate_approval_and_rejects_missing_forged_or_stale(self) -> None:
        import time
        from automated_qa.test_automated_qa_eval import _case
        from factory import automated_qa, config as config_module, deliver as deliver_module, independent_review, runner, security_review
        from factory.paths import RuntimePaths, atomic_json
        from tests.independent_review.test_independent_review import _make_staged_reviewer_script
        from tests.security_review.test_reviewer import REVIEWER_SCRIPT as SEC_REVIEWER_SCRIPT

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            paths = RuntimePaths(repo=repo, home=home)
            conf = config_module.load(paths)
            builder_agy = _make_fake_agy(root, "agy-builder", GOOD_BUILDER_SCRIPT)
            sec_agy = _make_fake_agy(root, "agy-sec", SEC_REVIEWER_SCRIPT)
            ir_agy = _make_fake_agy(root, "agy-ir", _make_staged_reviewer_script())
            spec = deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=60, agy_bin=str(builder_agy))

            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _DisposableGitHubServer(bare_repo=bare) as gh,
                unittest.mock.patch.dict(os.environ, {
                    "TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "disposable-asana-token",
                    "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "disposable-gh-token",
                }),
            ):
                r_ci = deliver_module.deliver_feature(paths, spec)
                self.assertEqual((r_ci.status, r_ci.ci_verified, r_ci.verified, r_ci.delivery_approved, r_ci.approval_outcome, r_ci.approved_revision), ("qa-missing", True, False, False, "rejected", None))
                self.assertTrue(any("automated QA" in b or "security" in b or "independent review" in b for b in r_ci.blockers))
                cand_a, base_1, head_branch = str(r_ci.candidate_sha), str(r_ci.base_sha), str(r_ci.child["head_branch"])
                att_dir = Path(r_ci.evidence["attempt_dir"])
                child_dir = att_dir / "children" / "101"
                intake_rec = json.loads(Path(r_ci.evidence["intake_record_path"]).read_text(encoding="utf-8"))
                child_contract = intake_rec["children"][0]

                atomic_json(child_dir / "approval-gate.json", {"schema": 1, "role": "delivery-approval-gate", "status": "approved", "outcome": "approved", "delivery_approved": True, "approved_revision": cand_a, "candidate_sha": cand_a, "base_sha": base_1, "tested_sha": r_ci.tested_sha, "revision_kind": r_ci.revision_kind, "verification_scope": independent_review.APPROVAL_GATE_SCOPE_NOTE, "round": 1, "blockers": []}, home)
                r_forged = deliver_module.deliver_feature(paths, spec)
                self.assertEqual((r_forged.verified, r_forged.delivery_approved, r_forged.approved_revision), (False, False, None))
                self.assertTrue(r_forged.blockers)
                (child_dir / "approval-gate.json").unlink(missing_ok=True)

                qa_rec = automated_qa.evaluate_child_qa(repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url, token="disposable-gh-token", repo_slug="example/chat-bridge", parent=intake_rec["parent"], child=child_contract, child_record=r_ci.child, conf=conf, qa_cases=(_case("QA-AC-1"),), round_number=1, deadline=time.monotonic() + 30.0, limit_s=30)
                self.assertTrue(qa_rec["qa_verified"])
                sec_rec = security_review.review_candidate_security(repo=repo, home=home, child_dir=child_dir, child=child_contract, conf=conf, base_sha=base_1, candidate_sha=cand_a, round_num=1, agy_bin=str(sec_agy), builder_session_id="c-101", deadline=time.monotonic() + 30.0, limit_s=30)
                self.assertTrue(sec_rec["ready"])
                ir_rec = independent_review.review_candidate_independently(repo=repo, home=home, child_dir=child_dir, child=child_contract, conf=conf, base_sha=base_1, candidate_sha=cand_a, round_num=1, agy_bin=str(ir_agy), builder_session_id="c-101", builder_summary="Implemented expired token check and test.", qa_record=qa_rec, security_record=sec_rec, deadline=time.monotonic() + 30.0, limit_s=30)
                self.assertTrue(ir_rec["review_verified"])

                cli_ok, payload_ok = _run_deliver(repo, home, asana.base_url, gh.base_url, agy_bin=str(builder_agy))
                self.assertEqual(cli_ok.returncode, 0, cli_ok.stdout + cli_ok.stderr)
                for p_rec in (payload_ok, json.loads((att_dir / "record.json").read_text(encoding="utf-8")), json.loads((home / "deliveries" / "900" / "record.json").read_text(encoding="utf-8"))):
                    self.assertEqual((p_rec["status"], p_rec["verified"], p_rec["delivery_approved"], p_rec["approval_outcome"], p_rec["approved_revision"], p_rec["candidate_sha"], p_rec["base_sha"], p_rec["child"]["verified"], p_rec["child"]["delivery_approved"], p_rec["child"]["pr"]["verified"]), ("completed", True, True, "approved", cand_a, cand_a, base_1, True, True, True))

                # Isolate stateful success case so integration does not contaminate subsequent candidate/base rejection checks
                (child_dir / "integration-record.json").unlink(missing_ok=True)
                (child_dir / "integration-request.json").unlink(missing_ok=True)
                git(repo, "push", "-q", "-f", "origin", f"{base_1}:refs/heads/feature/chat-auth")
                gh.pulls[1]["state"] = "open"
                gh.pulls[1]["merged"] = False
                gh.pulls[1]["merge_commit_sha"] = None

                git(repo, "checkout", "-q", head_branch)
                (repo / "src" / "chat_bridge" / "auth.py").write_text((repo / "src" / "chat_bridge" / "auth.py").read_text(encoding="utf-8") + "# candidate B\n", encoding="utf-8")
                git(repo, "add", "src/chat_bridge/auth.py")
                git(repo, "commit", "-q", "-m", "feat(auth): candidate B")
                cand_b = git(repo, "rev-parse", "HEAD")
                git(repo, "push", "-q", "origin", f"{cand_b}:refs/heads/{head_branch}")
                git(repo, "checkout", "-q", "main")

                for resume_idx in (1, 2):
                    r_stale_cand = deliver_module.deliver_feature(paths, spec)
                    self.assertIn(r_stale_cand.status, ("stale-candidate-revision", "stale-ci-evidence"), f"resume {resume_idx}")
                    self.assertEqual((r_stale_cand.candidate_sha, r_stale_cand.base_sha, r_stale_cand.verified, r_stale_cand.delivery_approved, r_stale_cand.approved_revision, r_stale_cand.ci_verified), (cand_b, base_1, False, False, None, False), f"resume {resume_idx}")
                    self.assertNotEqual(r_stale_cand.tested_sha, cand_a)
                    self.assertTrue(r_stale_cand.blockers)
                    gate_stale = json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8"))
                    for rec_map in (json.loads((att_dir / "record.json").read_text(encoding="utf-8")), json.loads((home / "deliveries" / "900" / "record.json").read_text(encoding="utf-8"))):
                        self.assertEqual((rec_map["status"], rec_map["candidate_sha"], rec_map["base_sha"], rec_map["verified"], rec_map["delivery_approved"], rec_map["approved_revision"], rec_map.get("ci_verified")), (r_stale_cand.status, cand_b, base_1, False, False, None, False))
                        self.assertNotEqual(rec_map.get("tested_sha"), cand_a)
                    self.assertEqual((gate_stale["delivery_approved"], gate_stale["approved_revision"]), (False, None))
                    self.assertIn(gate_stale["status"], ("stale-candidate-revision", "stale-ci-evidence"))

                b_child_contract = {**child_contract, "candidate_sha": cand_b}
                gh.pulls[1]["head"]["sha"] = cand_b
                ci_b = json.loads((child_dir / "ci-verification.json").read_text(encoding="utf-8"))
                b_checks = []
                for idx, c in enumerate(ci_b.get("checks", [])):
                    txt = f"candidate_sha={cand_b}\nbase_sha={base_1}\ntested_sha={cand_b}\nrevision_kind=fast-forward-head\ncheck ok\n"
                    lp = child_dir / f"ci-b-{idx}.log"
                    lp.write_text(txt, encoding="utf-8")
                    b_checks.append({**c, "candidate_sha": cand_b, "tested_sha": cand_b, "revision_kind": "fast-forward-head", "output_path": str(lp), "output_sha256": runner.digest_text(txt)})
                ci_b_upd = {**ci_b, "candidate_sha": cand_b, "tested_sha": cand_b, "revision_kind": "fast-forward-head", "checks": b_checks, "pr": {**ci_b["pr"], "head_sha": cand_b}}
                atomic_json(child_dir / "ci-verification.json", ci_b_upd, home)

                child_rec_b = {**r_ci.child, "status": "verified", "verified": True, "candidate_sha": cand_b, "tested_sha": cand_b, "revision_kind": "fast-forward-head", "ci_verification": ci_b_upd, "pr": {**r_ci.child["pr"], "head_sha": cand_b}}
                qa_rec_b = automated_qa.evaluate_child_qa(
                    repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url, token="disposable-gh-token",
                    repo_slug="example/chat-bridge", parent=intake_rec["parent"], child=b_child_contract,
                    child_record=child_rec_b, conf=conf,
                    qa_cases=(_case("QA-AC-1"),), round_number=2, deadline=time.monotonic() + 30.0, limit_s=30,
                )
                atomic_json(child_dir / "automated-qa" / "record.json", {"status": "qa-verified", "qa_verified": True, "rounds": 2, "open_finding_ids": [], "findings": []}, home)
                sec_rec_b = security_review.review_candidate_security(
                    repo=repo, home=home, child_dir=child_dir, child=b_child_contract, conf=conf,
                    base_sha=base_1, candidate_sha=cand_b, round_num=2, agy_bin=str(sec_agy),
                    builder_session_id="c-101", deadline=time.monotonic() + 30.0, limit_s=30,
                )
                independent_review.review_candidate_independently(
                    repo=repo, home=home, child_dir=child_dir, child=b_child_contract,
                    conf=conf, base_sha=base_1, candidate_sha=cand_b, round_num=2, agy_bin=str(ir_agy),
                    builder_session_id="c-101", builder_summary="Implemented expired token check and test on candidate B.",
                    qa_record=qa_rec_b, security_record=sec_rec_b, deadline=time.monotonic() + 30.0, limit_s=30,
                )
                r_b = deliver_module.deliver_feature(paths, spec)
                self.assertEqual((r_b.status, r_b.verified, r_b.delivery_approved, r_b.approved_revision), ("completed", True, True, cand_b))
                gate_b = json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8"))
                for rec_map in (json.loads((att_dir / "record.json").read_text(encoding="utf-8")), json.loads((home / "deliveries" / "900" / "record.json").read_text(encoding="utf-8"))):
                    self.assertEqual((rec_map["status"], rec_map["verified"], rec_map["delivery_approved"], rec_map["approved_revision"]), ("completed", True, True, cand_b))
                self.assertEqual((gate_b["status"], gate_b["delivery_approved"], gate_b["approved_revision"], gate_b.get("superseded_approved_revision")), ("approved", True, cand_b, None))

                (child_dir / "integration-record.json").unlink(missing_ok=True)
                (child_dir / "integration-request.json").unlink(missing_ok=True)
                git(repo, "push", "-q", "-f", "origin", f"{base_1}:refs/heads/feature/chat-auth")
                gh.pulls[1]["state"] = "open"
                gh.pulls[1]["merged"] = False
                gh.pulls[1]["merge_commit_sha"] = None

                git(repo, "branch", "-f", head_branch, cand_a)
                git(repo, "push", "-q", "-f", "origin", f"{cand_a}:refs/heads/{head_branch}")
                git(repo, "checkout", "-q", "feature/chat-auth")
                (repo / "README_BASE.md").write_text("base advance\n", encoding="utf-8")
                git(repo, "add", "README_BASE.md")
                git(repo, "commit", "-q", "-m", "chore: advance feature base")
                base_2 = git(repo, "rev-parse", "HEAD")
                git(repo, "push", "-q", "origin", f"{base_2}:refs/heads/feature/chat-auth")
                git(repo, "checkout", "-q", "main")

                r_stale_base = deliver_module.deliver_feature(paths, spec)
                self.assertEqual((r_stale_base.status, r_stale_base.verified, r_stale_base.delivery_approved, r_stale_base.approved_revision), ("stale-candidate-revision", False, False, None))
                self.assertTrue(any(base_1 in b and base_2 in b for b in r_stale_base.blockers), r_stale_base.blockers)

    def test_qa_and_security_callers_execute_prerequisites_without_bypass_and_invalidate_on_repair(self) -> None:
        import time
        from automated_qa.test_automated_qa_eval import WHITESPACE_QA_CASE, _case
        from tests.independent_review.test_approval_gate import _valid_security_record
        from factory import automated_qa, config as config_module, deliver as deliver_module, independent_review, runner, security_review
        from factory.automated_qa.delivery import QADeliverySpec, run_automated_qa_delivery
        from factory.paths import RuntimePaths, atomic_json
        from tests.automated_qa.test_automated_qa import DEMO_REPAIR_BUILDER_SCRIPT
        from tests.independent_review.test_independent_review import _make_staged_reviewer_script
        from tests.security_review.test_reviewer import REVIEWER_SCRIPT as SEC_REVIEWER_SCRIPT
        from tests.security_review.test_security_review import _SyncingGitHubServer, _make_builder_script

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            qa_root, sec_root = root / "qa", root / "sec"
            qa_root.mkdir()
            sec_root.mkdir()
            repo_q, home_q, bare_q = _make_disposable_product_workspace(qa_root)
            paths_q = RuntimePaths(repo=repo_q, home=home_q)
            qa_builder = _make_fake_agy(qa_root, "agy-qa-repair", DEMO_REPAIR_BUILDER_SCRIPT)
            orig_eval_qa = automated_qa.delivery.evaluate_child_qa

            def _seed_prior_approval_on_round1(**kw):
                res = orig_eval_qa(**kw)
                if kw.get("round_number") == 1:
                    c_sha, b_sha = kw["child_record"]["candidate_sha"], kw["child_record"]["base_sha"]
                    atomic_json(Path(kw["child_dir"]) / "approval-gate.json", {"schema": 1, "role": "delivery-approval-gate", "status": "approved", "outcome": "approved", "delivery_approved": True, "approved_revision": c_sha, "candidate_sha": c_sha, "base_sha": b_sha, "tested_sha": kw["child_record"]["tested_sha"], "revision_kind": "integration-merge", "verification_scope": independent_review.APPROVAL_GATE_SCOPE_NOTE, "round": 1, "blockers": []}, home_q)
                return res

            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana_q,
                _SyncingGitHubServer(bare_repo=bare_q) as gh_q,
                unittest.mock.patch.dict(os.environ, {
                    "TURBO_ASANA_API_URL": asana_q.base_url, "ASANA_ACCESS_TOKEN": "disposable-asana-token",
                    "TURBO_GITHUB_API_URL": gh_q.base_url, "TURBO_GITHUB_TOKEN": "disposable-gh-token",
                }),
                unittest.mock.patch("factory.automated_qa.delivery.evaluate_child_qa", side_effect=_seed_prior_approval_on_round1),
            ):
                qa_res = run_automated_qa_delivery(paths_q, QADeliverySpec(task_ref="900", time_limit_seconds=60, agy_bin=str(qa_builder), qa_cases=(WHITESPACE_QA_CASE,)))
                self.assertEqual((qa_res.status, qa_res.ci_verified, qa_res.qa_verified, qa_res.verified, qa_res.delivery_approved), ("stale-candidate-revision", True, True, False, False))
                self.assertEqual((qa_res.child["status"], qa_res.child["qa_status"], qa_res.child["pr"]["delivery_approved"]), ("stale-candidate-revision", "qa-verified", False))
                disk_del_rec = json.loads(Path(qa_res.evidence["qa_delivery_record_path"]).read_text(encoding="utf-8"))
                self.assertEqual((disk_del_rec["status"], disk_del_rec["child"]["qa_status"]), ("stale-candidate-revision", "qa-verified"))
                r1_sha, r2_sha = qa_res.qa_rounds[0]["candidate_sha"], qa_res.qa_rounds[1]["candidate_sha"]
                self.assertNotEqual(r1_sha, r2_sha)
                self.assertTrue(any(r1_sha in b and r2_sha in b for b in qa_res.blockers), qa_res.blockers)

                def _seed_valid_gate(**kw):
                    res = orig_eval_qa(**kw)
                    cdir, c_sha, b_sha = Path(kw["child_dir"]), kw["child_record"]["candidate_sha"], kw["child_record"]["base_sha"]
                    atomic_json(cdir / "security-review.json", _valid_security_record(c_sha, b_sha, home_q), home_q)
                    ir_agy = _make_fake_agy(qa_root, "agy-ir-q", _make_staged_reviewer_script(session_id="fresh-ir-q"))
                    independent_review.review_candidate_independently(repo=repo_q, home=home_q, child_dir=cdir, child=kw["child"], conf=kw["conf"], base_sha=b_sha, candidate_sha=c_sha, round_num=1, agy_bin=str(ir_agy), builder_session_id="c-101", builder_summary="repair", qa_record=res, security_record=json.loads((cdir / "security-review.json").read_text(encoding="utf-8")), deadline=time.monotonic() + 30.0, limit_s=30)
                    independent_review.evaluate_approval_gate(candidate_sha=c_sha, base_sha=b_sha, repo=repo_q, home=home_q, child_dir=cdir, child=kw["child"], conf=kw["conf"], load_from_child_dir=True, builder_session_id="c-101")
                    return res

                with unittest.mock.patch("factory.automated_qa.delivery.evaluate_child_qa", side_effect=_seed_valid_gate):
                    qa_app = run_automated_qa_delivery(paths_q, QADeliverySpec(task_ref="900", time_limit_seconds=60, agy_bin=str(qa_builder), qa_cases=(_case("QA-AC-1"),)))
                self.assertEqual((qa_app.status, qa_app.verified, qa_app.delivery_approved), ("verified", True, True))
                self.assertEqual((qa_app.child["status"], qa_app.child["qa_status"], qa_app.child["pr"]["delivery_approved"]), ("verified", "qa-verified", True))
                disk_app = json.loads(Path(qa_app.evidence["qa_delivery_record_path"]).read_text(encoding="utf-8"))
                self.assertEqual((disk_app["status"], disk_app["child"]["qa_status"]), ("verified", "qa-verified"))

            repo_s, home_s, bare_s = _make_disposable_product_workspace(sec_root)
            paths_s = RuntimePaths(repo=repo_s, home=home_s)
            conf_s = config_module.load(paths_s)
            sec_builder = _make_fake_agy(sec_root, "agy-sec-repair", _make_builder_script("fix"))
            sec_rev_bin = _make_fake_agy(sec_root, "agy-sec-rev", SEC_REVIEWER_SCRIPT)
            ir_bin = _make_fake_agy(sec_root, "agy-ir-rev", _make_staged_reviewer_script())

            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana_s,
                _SyncingGitHubServer(bare_repo=bare_s) as gh_s,
                unittest.mock.patch.dict(os.environ, {
                    "TURBO_ASANA_API_URL": asana_s.base_url, "ASANA_ACCESS_TOKEN": "disposable-asana-token",
                    "TURBO_GITHUB_API_URL": gh_s.base_url, "TURBO_GITHUB_TOKEN": "disposable-gh-token",
                }),
            ):
                sec_res = security_review.deliver_with_security_review(
                    paths_s, security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=60, agy_bin=str(sec_builder), reviewer_agy_bin=str(sec_rev_bin), max_repair_rounds=2),
                )
                self.assertEqual((sec_res.status, sec_res.ci_verified, sec_res.child["security_verified"], sec_res.verified, sec_res.delivery_approved), ("security-verified", True, True, False, False))
                repaired_sha, base_sha = str(sec_res.candidate_sha), str(sec_res.base_sha)
                child_dir_s = Path(sec_res.evidence["attempt_dir"]) / "children" / "101"
                intake_s = json.loads(Path(sec_res.evidence["intake_record_path"]).read_text(encoding="utf-8"))
                child_contract_s = intake_s["children"][0]

                qa_rec_s = automated_qa.evaluate_child_qa(
                    repo=repo_s, home=home_s, child_dir=child_dir_s, base_url=gh_s.base_url, token="disposable-gh-token",
                    repo_slug="example/chat-bridge", parent=intake_s["parent"], child=child_contract_s,
                    child_record=sec_res.child, conf=conf_s, qa_cases=(_case("QA-AC-1"),), round_number=1,
                    deadline=time.monotonic() + 30.0, limit_s=30,
                )
                self.assertTrue(qa_rec_s["qa_verified"])
                ir_rec_s = independent_review.review_candidate_independently(
                    repo=repo_s, home=home_s, child_dir=child_dir_s, child=child_contract_s,
                    conf=conf_s, base_sha=base_sha, candidate_sha=repaired_sha, round_num=1, agy_bin=str(ir_bin),
                    builder_session_id="builder-repair-1", builder_summary="Repaired security finding.",
                    qa_record=qa_rec_s, security_record=sec_res.child["security_review"], deadline=time.monotonic() + 30.0, limit_s=30,
                )
                self.assertTrue(ir_rec_s["review_verified"])
                final_res = deliver_module.deliver_feature(paths_s, deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=60, agy_bin=str(sec_builder)))
                self.assertEqual((final_res.status, final_res.verified, final_res.delivery_approved, final_res.approved_revision), ("completed", True, True, repaired_sha))

    def test_approval_timeout_closure_across_callers(self) -> None:
        from factory import automated_qa, deliver as deliver_module, security_review
        from factory.automated_qa.delivery import QADeliverySpec, run_automated_qa_delivery
        from factory.deliver_checks import AttemptTimeoutError
        from factory.paths import RuntimePaths
        from tests.automated_qa.test_automated_qa import DEMO_REPAIR_BUILDER_SCRIPT
        from tests.automated_qa.test_automated_qa_eval import _case
        from tests.security_review.test_reviewer import REVIEWER_SCRIPT as SEC_REV_SCRIPT
        from tests.security_review.test_security_review import _SyncingGitHubServer, _make_builder_script

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home, bare = _make_disposable_product_workspace(root)
            paths = RuntimePaths(repo=repo, home=home)
            b_agy = _make_fake_agy(root, "agy-b", DEMO_REPAIR_BUILDER_SCRIPT)
            sec_b = _make_fake_agy(root, "agy-sb", _make_builder_script("fix"))
            sec_r = _make_fake_agy(root, "agy-sr", SEC_REV_SCRIPT)
            spec = deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=60, agy_bin=str(b_agy))
            with (
                _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
                _SyncingGitHubServer(bare_repo=bare) as gh,
                unittest.mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": asana.base_url, "ASANA_ACCESS_TOKEN": "tok", "TURBO_GITHUB_API_URL": gh.base_url, "TURBO_GITHUB_TOKEN": "tok"}),
                unittest.mock.patch("factory.deliver.enforce_delivery_approval", side_effect=AttemptTimeoutError("approval timed out")),
            ):
                r_fresh = deliver_module.deliver_feature(paths, spec)
                self.assertEqual((r_fresh.status, r_fresh.ci_verified, r_fresh.verified, r_fresh.delivery_approved, r_fresh.approved_revision), ("timed-out", True, False, False, None))
                self.assertTrue(any("delivery approval timed out" in b for b in r_fresh.blockers))
                c_dir = Path(r_fresh.evidence["attempt_dir"]) / "children" / "101"
                self.assertEqual(json.loads((c_dir / "approval-gate.json").read_text(encoding="utf-8"))["status"], "timed-out")

                r_res = deliver_module.deliver_feature(paths, spec)
                self.assertEqual((r_res.status, r_res.ci_verified, r_res.verified, r_res.delivery_approved, r_res.approved_revision), ("timed-out", True, False, False, None))
                for p in (Path(r_res.evidence["attempt_dir"]) / "record.json", home / "deliveries" / "900" / "record.json"):
                    self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["status"], "timed-out")

                r_qa = run_automated_qa_delivery(paths, QADeliverySpec(task_ref="900", time_limit_seconds=60, agy_bin=str(b_agy), qa_cases=(_case("QA-AC-1"),)))
                self.assertEqual((r_qa.status, r_qa.ci_verified, r_qa.qa_verified, r_qa.verified, r_qa.delivery_approved, r_qa.approved_revision), ("timed-out", True, True, False, False, None))
                self.assertEqual(r_qa.child["qa_status"], "qa-verified")

                r_sec = security_review.deliver_with_security_review(paths, security_review.DeliverSecuritySpec(task_ref="900", time_limit_seconds=60, agy_bin=str(sec_b), reviewer_agy_bin=str(sec_r), max_repair_rounds=1))
                self.assertEqual((r_sec.status, r_sec.ci_verified, r_sec.child["security_verified"], r_sec.verified, r_sec.delivery_approved, r_sec.approved_revision), ("timed-out", True, True, False, False, None))


if __name__ == "__main__":
    unittest.main()
