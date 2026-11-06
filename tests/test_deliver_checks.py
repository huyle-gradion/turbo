"""Unit and behavioral tests for child scope checks, isolated verification, and PR confirmation (#19)."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, os, tempfile, threading, time, unittest
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import urlparse

from factory import config as config_module, deliver_checks, worker as worker_module
from factory.errors import UsageError
from support import config, git, home_dir, make_repo

ALLOWED_PR_POST_KEYS = frozenset({"title", "head", "base", "body", "draft", "maintainer_can_modify", "issue"})

class _DisposableGitHubServer:
    def __init__(
        self, *, bare_repo: Path | None = None, owner: str = "example", repo: str = "chat-bridge",
        post_status: int = 201, get_status: int = 200, redirect_to: str | None = None,
        verify_override: dict[str, Any] | None = None,
    ) -> None:
        self.bare_repo, self.owner, self.repo = bare_repo, owner, repo
        self.post_status, self.get_status, self.redirect_to = post_status, get_status, redirect_to
        self.verify_override = verify_override or {}
        self.requests: list[dict[str, Any]] = []
        self.pulls: dict[int, dict[str, Any]] = {}
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/api/v3"
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def _resolve_branch_sha(self, branch: str) -> str | None:
        if self.bare_repo is None or not branch:
            return None
        try:
            return git(self.bare_repo, "rev-parse", f"refs/heads/{branch}")
        except AssertionError:
            return None

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _record_or_redirect(self, body: dict[str, Any] | None = None) -> str | None:
                parsed = urlparse(self.path)
                outer.requests.append(
                    {"method": self.command, "path": parsed.path, "auth": self.headers.get("Authorization"), "body": body}
                )
                if outer.redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                    return None
                return parsed.path

            def _send_json(self, code: int, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
                body = json.loads(raw) if raw.strip() else {}
                path = self._record_or_redirect(body)
                if path is None:
                    return
                if path != f"/api/v3/repos/{outer.owner}/{outer.repo}/pulls":
                    self._send_json(404, {"message": "Not Found"})
                    return
                unexpected_keys = set(body.keys()) - ALLOWED_PR_POST_KEYS
                if unexpected_keys:
                    self._send_json(422, {"message": f"Unsupported PR fields: {sorted(unexpected_keys)}"})
                    return
                if outer.post_status != 201:
                    self._send_json(outer.post_status, {"message": f"GitHub HTTP {outer.post_status} rejection"})
                    return
                head_branch = str(body.get("head") or "").split(":", 1)[-1]
                base_branch = str(body.get("base") or "")
                observed_head_sha = outer._resolve_branch_sha(head_branch)
                observed_base_sha = outer._resolve_branch_sha(base_branch)
                if outer.bare_repo is not None and (not observed_head_sha or not observed_base_sha):
                    self._send_json(422, {"message": "Head or base branch ref not found on remote"})
                    return
                pr_num = len(outer.pulls) + 1
                slug = f"{outer.owner}/{outer.repo}"
                pr_obj: dict[str, Any] = {
                    "number": pr_num, "state": "open", "merged": False,
                    "title": str(body.get("title") or ""), "body": str(body.get("body") or ""),
                    "html_url": f"https://github.com/{slug}/pull/{pr_num}",
                    "head": {"ref": head_branch, "sha": observed_head_sha or "", "repo": {"full_name": slug}},
                    "base": {"ref": base_branch, "sha": observed_base_sha or "", "repo": {"full_name": slug}},
                }
                outer.pulls[pr_num] = pr_obj
                self._send_json(201, pr_obj)

            def do_GET(self) -> None:
                path = self._record_or_redirect()
                if path is None:
                    return
                prefix = f"/api/v3/repos/{outer.owner}/{outer.repo}/pulls/"
                if not path.startswith(prefix):
                    self._send_json(404, {"message": "Not Found"})
                    return
                if outer.get_status != 200:
                    self._send_json(outer.get_status, {"message": f"GitHub GET HTTP {outer.get_status} failure"})
                    return
                pr_obj = json.loads(json.dumps(outer.pulls.get(int(path[len(prefix) :]), {})))
                if not pr_obj:
                    self._send_json(404, {"message": "PR Not Found"})
                    return
                for key, val in outer.verify_override.items():
                    if key in ("head_ref", "head_sha"):
                        pr_obj["head"][key.split("_", 1)[1]] = val
                    elif key == "base_ref":
                        pr_obj["base"]["ref"] = val
                    elif key == "repo_full_name":
                        pr_obj["base"]["repo"]["full_name"] = val
                    elif key == "head_repo_full_name":
                        pr_obj["head"]["repo"]["full_name"] = val
                    else:
                        pr_obj[key] = val
                self._send_json(200, pr_obj)

            def do_PUT(self) -> None:
                self._record_or_redirect()
                self._send_json(405, {"message": "Merge forbidden in #19"})

        return Handler

    def __enter__(self) -> _DisposableGitHubServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

class DeliverChecksTest(unittest.TestCase):
    def test_scope_evaluation_anchored_globs_and_non_path_backtick_identifiers(self) -> None:
        prose = "Update `chat_bridge.auth.validate_token` and `TokenExpiredError` for `http/1.1` and/or `user.id` in v1.2"
        self.assertEqual(deliver_checks.extract_explicit_paths(prose), ([], "semantic-only"))
        self.assertEqual(deliver_checks.extract_explicit_paths("`src/chat_bridge/`, `tests/`"), (["src/chat_bridge", "tests"], "deterministic-paths"))
        semantic_child = {
            "gid": "101", "name": "Auth slice",
            "scope": {"in_scope": prose, "out_of_scope": "billing and/or webhook retries", "constraints": "stdlib only; keep `validate_token` stable"},
        }
        ok, violations, detail = deliver_checks.evaluate_scope(
            ("src/chat_bridge/auth.py", "tests/test_auth.py"), semantic_child, ("AGENTS.md", "docs/spec.md")
        )
        self.assertEqual((ok, violations, detail["status"]), (True, [], "deterministic-only-semantic-unverified"))
        self.assertEqual((detail["deterministic_ok"], detail["semantic_verified"]), (True, False))
        glob_child = {
            "gid": "102", "name": "Anchored glob slice",
            "scope": {
                "in_scope": "`src/chat_bridge/*.py`, `tests/**/*.py`",
                "out_of_scope": "`src/chat_bridge/billing.py`",
                "constraints": "Keep logic in `src/chat_bridge/auth.py`; do not modify `docs/spec.md`",
            },
        }
        ok_glob, violations_glob, detail_glob = deliver_checks.evaluate_scope(
            ("src/chat_bridge/auth.py", "tests/test_auth.py", "tests/unit/deep/test_token.py"), glob_child, ("AGENTS.md", "docs/spec.md")
        )
        self.assertTrue(ok_glob, violations_glob)
        self.assertEqual((detail_glob["status"], detail_glob["semantic_verified"], detail_glob["constraint_paths"]), ("deterministic-verified", True, ["docs/spec.md"]))
        ok_unanchored, violations_unanchored, _ = deliver_checks.evaluate_scope(
            ("other/src/chat_bridge/auth.py", "src/chat_bridge/sub/nested.py"), glob_child, ("AGENTS.md", "docs/spec.md")
        )
        self.assertEqual((ok_unanchored, len(violations_unanchored)), (False, 2))

    def test_diff_categories_handle_renames_deletions_test_helpers_prod_asserts_and_inline_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            (repo / "src").mkdir()
            (repo / "src" / "auth.py").write_text("def check(x):\n    return x\n", encoding="utf-8")
            (repo / "src" / "obsolete.py").write_text("OLD = 1\n", encoding="utf-8")
            (repo / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
            git(repo, "add", ".")
            git(repo, "commit", "-q", "-m", "base")
            base_sha = git(repo, "rev-parse", "HEAD")
            deadline = time.monotonic() + 30.0
            git(repo, "mv", "AGENTS.md", "src/moved_agents.md")
            git(repo, "rm", "-q", "src/obsolete.py")
            git(repo, "commit", "-q", "-m", "rename protected file and delete file")
            rename_diff = deliver_checks.inspect_diff_categories(repo, base_sha, git(repo, "rev-parse", "HEAD"), deadline, 30)
            for expected in ("AGENTS.md", "src/moved_agents.md", "src/obsolete.py"):
                self.assertIn(expected, rename_diff["changed_paths"])
            scope_ok, violations, _ = deliver_checks.evaluate_scope(
                tuple(rename_diff["changed_paths"]), {"scope": {"in_scope": "`src/`"}}, ("AGENTS.md",)
            )
            self.assertFalse(scope_ok)
            self.assertTrue(any("AGENTS.md" in v for v in violations))
            git(repo, "reset", "-q", "--hard", base_sha)
            (repo / "tests").mkdir(exist_ok=True)
            (repo / "tests" / "test_probe.py").write_text(
                "import unittest\n\ndef _helper_fixture():\n    return 42\n\n"
                "class ProbeTest(unittest.TestCase):\n    def test_a(self):\n        self.assertEqual(_helper_fixture(), 42)\n",
                encoding="utf-8",
            )
            git(repo, "add", "tests/test_probe.py")
            git(repo, "commit", "-q", "-m", "test file with helper")
            th_diff = deliver_checks.inspect_diff_categories(repo, base_sha, git(repo, "rev-parse", "HEAD"), deadline, 30)
            self.assertEqual((th_diff["has_implementation_changes"], th_diff["has_test_changes"]), (False, True))
            for msg, content, expected_flags in (
                ("prod assert", "def check(x):\n    assert x is not None\n    return x\n", (True, False)),
                ("inline only", "def check(x):\n    return x\n\ndef test_inline():\n    assert check(1) == 1\n", (False, True)),
                ("both", "def check(x):\n    return x + 1\n\ndef test_inline():\n    assert check(1) == 2\n", (True, True)),
            ):
                git(repo, "reset", "-q", "--hard", base_sha)
                (repo / "src" / "auth.py").write_text(content, encoding="utf-8")
                git(repo, "add", "src/auth.py")
                git(repo, "commit", "-q", "-m", msg)
                diff = deliver_checks.inspect_diff_categories(repo, base_sha, git(repo, "rev-parse", "HEAD"), deadline, 30)
                self.assertEqual((diff["has_implementation_changes"], diff["has_test_changes"]), expected_flags, msg)

    def test_isolated_git_checkout_and_verification_isolation_and_missing_executable(self) -> None:
        import socket, sys
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home = make_repo(root), home_dir(root)
            git(repo, "remote", "add", "origin", "https://github.com/example/chat-bridge.git")
            main_sha = git(repo, "rev-parse", "refs/heads/main")
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
            child_dir = home / "deliveries" / "900" / "attempt-1" / "children" / "101"
            worktree_dir = child_dir / "worktree"
            fake_source_home = root / "operator-home"
            agy_dir = fake_source_home / ".gemini" / "antigravity-cli"
            agy_dir.mkdir(parents=True)
            source_sentinel = agy_dir / "jetski_state.pbtxt"
            source_sentinel.write_text("oauth_token: 'secret-jetski'\n", encoding="utf-8")
            repo_sentinel = repo / "CONTROLLER_REPO_SENTINEL.txt"
            repo_sentinel.write_text("REPO_SENTINEL_INTACT\n", encoding="utf-8")
            home_sentinel = home / "controller_cred.sentinel"
            home_sentinel.write_text("CONTROLLER_CRED_INTACT\n", encoding="utf-8")
            deadline = time.monotonic() + 30.0
            worker_module.prepare_isolated_git_checkout(repo, worktree_dir, main_sha, deadline=deadline)
            self.assertTrue((worktree_dir / ".git").is_dir())
            self.assertEqual((git(worktree_dir, "remote"), git(worktree_dir, "for-each-ref")), ("", ""))
            git(worktree_dir, "checkout", "-q", "-b", "main")
            (worktree_dir / "README.md").write_text("mutated in isolated checkout\n", encoding="utf-8")
            git(worktree_dir, "add", "README.md")
            git(worktree_dir, "commit", "-q", "-m", "isolated commit")
            self.assertEqual(git(repo, "rev-parse", "refs/heads/main"), main_sha)
            isolated_home = worker_module.prepare_isolated_home(child_dir, fake_source_home, root=home)
            source_env = {
                **os.environ, "ASANA_ACCESS_TOKEN": "secret-asana-pat", "GITHUB_TOKEN": "ghp_secret_controller_token",
                "TURBO_GITHUB_TOKEN": "secret-test-gh-token", "TURBO_ASANA_API_URL": "http://127.0.0.1:9999/api/1.0",
                "TURBO_GITHUB_API_URL": "http://127.0.0.1:9998/api/v3",
                "SSH_AUTH_SOCK": "/tmp/controller-ssh-agent.sock", "SSH_AGENT_PID": "9999", "GIT_SSH_COMMAND": "ssh -i /root/id_rsa",
            }
            worker_env, stripped = worker_module.sanitized_env(source_env, worktree_dir, isolated_home)
            self.assertIn("SSH_AUTH_SOCK", stripped)
            self.assertEqual(
                (worker_env["SSH_AUTH_SOCK"], worker_env["GIT_ALLOW_PROTOCOL"], worker_env["GIT_CONFIG_SYSTEM"]),
                ("", "none", "/dev/null"),
            )
            accepted: list[int] = []
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(0.2)
            port = listener.getsockname()[1]
            stop_listener = threading.Event()

            def _accept_loop() -> None:
                while not stop_listener.is_set():
                    try:
                        conn, _ = listener.accept()
                        accepted.append(1)
                        conn.close()
                    except OSError:
                        pass

            accept_thread = threading.Thread(target=_accept_loop, daemon=True)
            accept_thread.start()
            try:
                sentinels = [str(repo_sentinel), str(home_sentinel), str(source_sentinel), str(repo / ".git" / "HEAD")]
                (worktree_dir / "tests").mkdir(exist_ok=True)
                (worktree_dir / "tests" / "test_isolation.py").write_text(
                    "import os, pathlib, shutil, subprocess, sys, unittest\n"
                    f"PORT = {port}\n"
                    f"SENTINELS = {sentinels!r}\n"
                    "class IsolationTest(unittest.TestCase):\n"
                    "    def test_os_boundary_blocks_python_I_S_non_python_and_abs_paths_after_env_clear(self) -> None:\n"
                    "        for k in ('ASANA_ACCESS_TOKEN', 'GITHUB_TOKEN', 'TURBO_GITHUB_TOKEN', 'TURBO_ASANA_API_URL', 'TURBO_GITHUB_API_URL', 'SSH_AGENT_PID'):\n"
                    "            self.assertIsNone(os.environ.get(k), f'{k} leaked')\n"
                    "        self.assertFalse((pathlib.Path.home() / '.gemini' / 'antigravity-cli' / 'jetski_state.pbtxt').exists())\n"
                    "        git_bin = shutil.which('git') or '/usr/bin/git'\n"
                    "        cat_bin = shutil.which('cat') or '/bin/cat'\n"
                    "        os.environ.clear()\n"
                    "        py_net = subprocess.run([sys.executable, '-I', '-S', '-c', f'import socket; s = socket.socket(); s.settimeout(1.0); s.connect((\"127.0.0.1\", {PORT}))'], capture_output=True, text=True)\n"
                    "        self.assertNotEqual(py_net.returncode, 0, py_net.stdout + py_net.stderr)\n"
                    "        bin_net = subprocess.run([git_bin, 'ls-remote', f'http://127.0.0.1:{PORT}/repo.git'], capture_output=True, text=True, timeout=3)\n"
                    "        self.assertNotEqual(bin_net.returncode, 0, bin_net.stdout + bin_net.stderr)\n"
                    "        for target in SENTINELS:\n"
                    "            py_read = subprocess.run([sys.executable, '-I', '-S', '-c', f'open({target!r}, \"rb\").read()'], capture_output=True, text=True)\n"
                    "            self.assertNotEqual(py_read.returncode, 0, f'read allowed for {target}')\n"
                    "            py_write = subprocess.run([sys.executable, '-I', '-S', '-c', f'open({target!r}, \"wb\").write(b\"pwned\")'], capture_output=True, text=True)\n"
                    "            self.assertNotEqual(py_write.returncode, 0, f'write allowed for {target}')\n"
                    "            cat_read = subprocess.run([cat_bin, target], capture_output=True, text=True)\n"
                    "            self.assertNotEqual(cat_read.returncode, 0, f'cat allowed for {target}')\n",
                    encoding="utf-8",
                )
                child = {
                    "gid": "101", "name": "Verify isolation",
                    "criteria": [{"id": "AC-1", "verification": "python3 -m unittest discover -s tests -p test_isolation.py -v"}],
                }
                ok, checks, failures = deliver_checks.run_child_verifications(worktree_dir, child, conf, child_dir, home, worker_env, deadline, 30)
                self.assertTrue(ok and checks[0]["ok"], f"{failures} / {Path(checks[0]['output_path']).read_text(encoding='utf-8')}")
                self.assertEqual(accepted, [])
                self.assertEqual(repo_sentinel.read_text(encoding="utf-8"), "REPO_SENTINEL_INTACT\n")
                self.assertEqual(home_sentinel.read_text(encoding="utf-8"), "CONTROLLER_CRED_INTACT\n")
                self.assertEqual(source_sentinel.read_text(encoding="utf-8"), "oauth_token: 'secret-jetski'\n")
            finally:
                stop_listener.set()
                listener.close()
                accept_thread.join(timeout=1.0)
            missing_bin_child = {"gid": "101", "name": "Missing", "criteria": [{"id": "AC-1", "verification": "pytest -q"}]}
            ok_miss, checks_miss, failures_miss = deliver_checks.run_child_verifications(
                worktree_dir, missing_bin_child, conf, child_dir, home, {**worker_env, "PATH": "/nonexistent-bin"}, deadline, 30
            )
            self.assertEqual((ok_miss, checks_miss[0]["ok"], checks_miss[0]["executed"]), (False, False, False))
            self.assertTrue(any("pytest" in f for f in failures_miss))
            with mock.patch("factory.sandbox.sandbox_available", return_value=False):
                with self.assertRaises(worker_module.SandboxUnavailableError):
                    deliver_checks.run_child_verifications(worktree_dir, child, conf, child_dir, home, worker_env, deadline, 30)

    def test_github_helpers_contract_missing_fields_mismatches_redirects_and_redaction_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "origin.git"
            bare.mkdir()
            git(bare, "init", "--bare", "-q", "-b", "main")
            repo = make_repo(root)
            git(repo, "remote", "add", "origin", str(bare))
            git(repo, "push", "-q", "origin", "main")
            base_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "-b", "feature/chat-auth")
            git(repo, "push", "-q", "origin", "feature/chat-auth")
            git(repo, "checkout", "-q", "-b", "task/101-auth")
            (repo / "README.md").write_text("candidate change\n", encoding="utf-8")
            git(repo, "add", "README.md")
            git(repo, "commit", "-q", "-m", "candidate")
            candidate_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "push", "-q", "origin", "task/101-auth")
            deadline = time.monotonic() + 30.0
            parent, child = {"gid": "900", "name": "Feature"}, {"gid": "101", "name": "Slice", "outcome": "Deliver slice"}
            scope_detail = {"status": "deterministic-verified", "provenance": "deterministic rules enforced"}

            def _confirm(base_url: str) -> dict[str, Any]:
                return deliver_checks.open_and_confirm_pr(
                    base_url, "tok-1", "example/chat-bridge", parent, child,
                    "task/101-auth", candidate_sha, "feature/chat-auth", [], scope_detail, [], deadline, 30,
                )

            with _DisposableGitHubServer(bare_repo=bare) as gh:
                pr = _confirm(gh.base_url)
                self.assertEqual((pr["verified"], pr["head_sha"]), (True, candidate_sha))
                self.assertEqual(set(gh.requests[0]["body"].keys()), {"title", "head", "base", "body"})
            for label, override in (
                ("missing-base-repo", {"repo_full_name": ""}), ("missing-head-repo", {"head_repo_full_name": ""}),
                ("missing-head-sha", {"head_sha": ""}), ("wrong-head-sha", {"head_sha": base_sha}),
                ("wrong-base-ref", {"base_ref": "main"}), ("wrong-head-ref", {"head_ref": "task/other"}),
                ("wrong-repo", {"repo_full_name": "other/repo"}), ("closed-pr", {"state": "closed"}),
                ("merged-pr", {"merged": True}),
            ):
                with self.subTest(case=label), _DisposableGitHubServer(bare_repo=bare, verify_override=override) as gh_bad:
                    with self.assertRaises(deliver_checks.GitHubError):
                        _confirm(gh_bad.base_url)
            with _DisposableGitHubServer(bare_repo=bare, redirect_to="https://evil.example.com/pulls") as gh_redir:
                with self.assertRaises(deliver_checks.GitHubError):
                    _confirm(gh_redir.base_url)
            with mock.patch.dict(
                os.environ,
                {"GITHUB_TOKEN": "ghp_ProdSecret123", "ASANA_ACCESS_TOKEN": "asana_Sec456", "TURBO_GITHUB_TOKEN": ""},
                clear=False,
            ):
                secrets = deliver_checks.collect_redaction_secrets()
                self.assertTrue("ghp_ProdSecret123" in secrets and "asana_Sec456" in secrets)
                with self.assertRaises(deliver_checks.GitHubError):
                    deliver_checks.resolve_github_token(True)
            for bad_url in ("http://api.github.com", "https://evil.example.com/api/v3", "https://api.github.com?x=1"):
                with mock.patch.dict(os.environ, {"TURBO_GITHUB_API_URL": bad_url}):
                    with self.assertRaises(UsageError):
                        deliver_checks.resolve_github_api()

if __name__ == "__main__":
    unittest.main()
