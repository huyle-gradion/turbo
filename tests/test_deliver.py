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


def _make_fake_agy(root: Path, name: str, body_script: str) -> Path:
    fake_py = root / f"{name}.py"
    fake_py.write_text(
        "import sys\nif '--version' in sys.argv:\n    print('1.5.1-test')\n    sys.exit(0)\n" + body_script,
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
    res = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True, env=env, timeout=180)
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

GOOD_BUILDER_SCRIPT = (
    "import json, pathlib, subprocess\n"
    "pathlib.Path('src/chat_bridge/auth.py').write_text(\n"
    "    'class TokenExpiredError(Exception):\\n    pass\\n\\n'\n"
    "    'def validate_token(token: str) -> dict[str, str]:\\n'\n"
    "    '    if token.startswith(\"expired:\"):\\n        raise TokenExpiredError(\"token expired\")\\n'\n"
    "    '    return {\"sub\": token}\\n', encoding='utf-8')\n"
    "p = pathlib.Path('tests/test_auth.py')\n"
    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_expired_token(self) -> None:\\n'\n"
    "    '        from chat_bridge.auth import TokenExpiredError\\n'\n"
    "    '        with self.assertRaises(TokenExpiredError):\\n            validate_token(\"expired:abc\")\\n', encoding='utf-8')\n"
    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py', 'tests/test_auth.py'], check=True)\n"
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
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual((payload["status"], payload["pr_opened"], payload["merged"]), ("pr-opened", True, False))
                self.assertNotIn(payload["status"], ("completed", "verified", "merged", "accepted"))
                child_rec = payload["child"]
                self.assertEqual(
                    (child_rec["gid"], child_rec["status"], child_rec["base_branch"], child_rec["base_sha"]),
                    ("101", "pr-opened", "feature/chat-auth", main_sha_before),
                )
                self.assertEqual(child_rec["scope_check"]["status"], "deterministic-only-semantic-unverified")
                self.assertFalse(child_rec["scope_check"]["semantic_verified"])
                pr_info = child_rec["pr"]
                self.assertEqual(
                    (pr_info["number"], pr_info["base_ref"], pr_info["head_ref"], pr_info["head_sha"], pr_info["verified"]),
                    (1, "feature/chat-auth", child_rec["head_branch"], child_rec["candidate_sha"], True),
                )
                for token in ("900", "101", child_rec["candidate_sha"], "deterministic-only-semantic-unverified"):
                    self.assertIn(token, pr_info["body"])
                self.assertEqual(git(bare, "rev-parse", "refs/heads/main"), main_sha_before)
                self.assertEqual(git(bare, "rev-parse", "refs/heads/feature/chat-auth"), main_sha_before)
                self.assertEqual(git(bare, "rev-parse", f"refs/heads/{child_rec['head_branch']}"), child_rec["candidate_sha"])
                self.assertTrue(all(r["method"] == "GET" for r in asana.requests))
                self.assertEqual([r["method"] for r in gh.requests], ["POST", "GET"])

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
                    "missing-tests",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str):\\n    return {\"sub\": token, \"v\": 2}\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'impl only'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c3', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "missing-implementation",
                    "import json, pathlib, subprocess\n"
                    "p = pathlib.Path('tests/test_auth.py')\n"
                    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_extra(self):\\n        self.assertTrue(True)\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', 'tests/test_auth.py'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'test only'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c4', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "verification-failed",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str):\\n    return {}\\n', encoding='utf-8')\n"
                    "p = pathlib.Path('tests/test_auth.py')\n"
                    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_broken(self):\\n        self.assertEqual(1, 2)\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py', 'tests/test_auth.py'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'broken impl and test'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c5', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "timed-out",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str):\\n    return {\"sub\": token}\\n', encoding='utf-8')\n"
                    "p = pathlib.Path('tests/test_auth.py')\n"
                    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_hang(self):\\n        import time; time.sleep(10); self.assertTrue(True)\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', 'src/chat_bridge/auth.py', 'tests/test_auth.py'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'slow verification test'], check=True)\n"
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
                        limit_arg = "2s" if expected_status == "timed-out" else "30s"
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
                    "p = pathlib.Path('tests/test_auth.py')\n"
                    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_ok(self): self.assertTrue(True)\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', '.'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'touch billing'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 's1', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "outside-in-scope-prefix",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('scripts').mkdir(exist_ok=True)\n"
                    "pathlib.Path('scripts/deploy.py').write_text('x = 1\\n', encoding='utf-8')\n"
                    "p = pathlib.Path('tests/test_auth.py')\n"
                    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_ok(self): self.assertTrue(True)\\n', encoding='utf-8')\n"
                    "subprocess.run(['git', 'add', '.'], check=True)\n"
                    "subprocess.run(['git', 'commit', '-q', '-m', 'touch scripts'], check=True)\n"
                    "print(json.dumps({'event': 'result', 'result': {'conversation_id': 's2', 'status': 'SUCCESS', 'response': 'Done'}}))\n",
                ),
                (
                    "protected-path-violation",
                    "import json, pathlib, subprocess\n"
                    "pathlib.Path('AGENTS.md').write_text('# Weakened rules\\n', encoding='utf-8')\n"
                    "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str): return {\"sub\": token}\\n', encoding='utf-8')\n"
                    "p = pathlib.Path('tests/test_auth.py')\n"
                    "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_ok(self): self.assertTrue(True)\\n', encoding='utf-8')\n"
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
                "pathlib.Path('src/chat_bridge/auth.py').write_text('def validate_token(token: str): return {}\\n', encoding='utf-8')\n"
                "p = pathlib.Path('tests/test_auth.py')\n"
                "p.write_text(p.read_text(encoding='utf-8') + '\\n    def test_fail(self): self.assertEqual(1, 2)\\n', encoding='utf-8')\n"
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
                self.assertEqual((res_fail.returncode, rec_fail["status"]), (1, "verification-failed"))
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
                self.assertEqual((res_ok.returncode, rec_ok["status"], rec_ok["attempt"]), (0, "pr-opened", 2))
                self.assertEqual(rec_ok["child"]["head_branch"], f"{base_child_branch}-attempt-3")
                self.assertEqual(git(bare, "rev-parse", f"refs/heads/{base_child_branch}"), main_sha)
                self.assertEqual(git(bare, "rev-parse", f"refs/heads/{base_child_branch}-attempt-2"), main_sha)
                self.assertEqual(
                    git(bare, "rev-parse", f"refs/heads/{base_child_branch}-attempt-3"),
                    rec_ok["child"]["candidate_sha"],
                )

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
                self.assertEqual((payload["status"], payload["pr_opened"], payload["merged"]), ("pr-opened", True, False))
                self.assertEqual(git(bare, "rev-parse", "refs/heads/main"), main_sha_before)
                self.assertEqual(payload["child"]["pr"]["base_ref"], "feature/chat-auth")
                self.assertTrue(payload["child"]["pr"]["verified"])


if __name__ == "__main__":
    unittest.main()
