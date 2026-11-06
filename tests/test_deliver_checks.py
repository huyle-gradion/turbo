"""Unit and behavioral tests for child scope checks, isolated verification, and PR confirmation (#19)."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Any
import unittest
from urllib.parse import urlparse

from factory import config as config_module
from factory import deliver_checks
from factory import worker as worker_module
from support import config, git, home_dir, make_repo


class _DisposableGitHubServer:
    def __init__(
        self,
        *,
        owner: str = "example",
        repo: str = "chat-bridge",
        post_status: int = 201,
        get_status: int = 200,
        redirect_to: str | None = None,
        verify_override: dict[str, Any] | None = None,
    ) -> None:
        self.owner = owner
        self.repo = repo
        self.post_status = post_status
        self.get_status = get_status
        self.redirect_to = redirect_to
        self.verify_override = verify_override or {}
        self.requests: list[dict[str, Any]] = []
        self.pulls: dict[int, dict[str, Any]] = {}
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/api/v3"
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _record(self, body: dict[str, Any] | None = None) -> str:
                parsed = urlparse(self.path)
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": parsed.path,
                        "auth": self.headers.get("Authorization"),
                        "body": body,
                    }
                )
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
                path = self._record(body)
                if outer.redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                    return
                if path != f"/api/v3/repos/{outer.owner}/{outer.repo}/pulls":
                    self._send_json(404, {"message": "Not Found"})
                    return
                if outer.post_status != 201:
                    self._send_json(outer.post_status, {"message": f"GitHub HTTP {outer.post_status} rejection"})
                    return
                pr_num = len(outer.pulls) + 1
                head_branch = str(body.get("head") or "").split(":", 1)[-1]
                pr_obj: dict[str, Any] = {
                    "number": pr_num,
                    "state": "open",
                    "merged": False,
                    "title": str(body.get("title") or ""),
                    "body": str(body.get("body") or ""),
                    "html_url": f"https://github.com/{outer.owner}/{outer.repo}/pull/{pr_num}",
                    "head": {
                        "ref": head_branch,
                        "sha": str(body.get("head_sha") or outer.verify_override.get("head_sha") or ""),
                        "repo": {"full_name": f"{outer.owner}/{outer.repo}"},
                    },
                    "base": {
                        "ref": str(body.get("base") or ""),
                        "repo": {"full_name": f"{outer.owner}/{outer.repo}"},
                    },
                }
                outer.pulls[pr_num] = pr_obj
                self._send_json(201, pr_obj)

            def do_GET(self) -> None:
                path = self._record()
                if outer.redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
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
                    if key == "head_ref":
                        pr_obj["head"]["ref"] = val
                    elif key == "head_sha":
                        pr_obj["head"]["sha"] = val
                    elif key == "base_ref":
                        pr_obj["base"]["ref"] = val
                    elif key == "repo_full_name":
                        pr_obj["base"]["repo"]["full_name"] = val
                    else:
                        pr_obj[key] = val
                self._send_json(200, pr_obj)

            def do_PUT(self) -> None:
                self._record()
                self._send_json(405, {"message": "Merge forbidden in #19"})

        return Handler

    def __enter__(self) -> _DisposableGitHubServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


class DeliverChecksTest(unittest.TestCase):
    def test_semantic_only_scope_is_marked_unverified_while_deterministic_paths_are_enforced(self) -> None:
        semantic_child = {
            "gid": "101",
            "name": "Auth slice",
            "scope": {
                "in_scope": "authentication token validation logic",
                "out_of_scope": "billing and webhook retries",
                "constraints": "stdlib only; keep error messages concise",
            },
        }
        ok, violations, detail = deliver_checks.evaluate_scope(
            ("src/chat_bridge/auth.py", "tests/test_auth.py"),
            semantic_child,
            ("AGENTS.md", "docs/spec.md"),
        )
        self.assertTrue(ok)
        self.assertEqual(violations, [])
        self.assertEqual(detail["status"], "deterministic-only-semantic-unverified")
        self.assertTrue(detail["deterministic_ok"])
        self.assertFalse(detail["semantic_verified"])
        self.assertIn("not machine-verified", detail["provenance"])
        self.assertEqual(detail["in_scope_enforcement"], "semantic-only")
        self.assertEqual(detail["out_of_scope_enforcement"], "semantic-only")
        self.assertEqual(detail["constraints_enforcement"], "semantic-only")

        deterministic_child = {
            "gid": "102",
            "name": "Deterministic auth slice",
            "scope": {
                "in_scope": "`src/chat_bridge/`, `tests/`",
                "out_of_scope": "`src/chat_bridge/billing.py`",
                "constraints": "Keep logic in `src/chat_bridge/auth.py`; do not modify `docs/spec.md`",
            },
        }
        ok_det, violations_det, detail_det = deliver_checks.evaluate_scope(
            ("src/chat_bridge/auth.py", "tests/test_auth.py"),
            deterministic_child,
            ("AGENTS.md", "docs/spec.md"),
        )
        self.assertTrue(ok_det)
        self.assertEqual(violations_det, [])
        self.assertEqual(detail_det["status"], "deterministic-verified")
        self.assertTrue(detail_det["deterministic_ok"])
        self.assertTrue(detail_det["semantic_verified"])
        self.assertEqual(detail_det["constraint_paths"], ["docs/spec.md"])

        ok_bad, violations_bad, detail_bad = deliver_checks.evaluate_scope(
            ("src/chat_bridge/billing.py", "AGENTS.md", "scripts/release.py"),
            deterministic_child,
            ("AGENTS.md", "docs/spec.md"),
        )
        self.assertFalse(ok_bad)
        self.assertEqual(detail_bad["status"], "violation")
        self.assertFalse(detail_bad["deterministic_ok"])
        self.assertFalse(detail_bad["semantic_verified"])
        self.assertEqual(len(violations_bad), 4)

    def test_verification_commands_exclude_credentials_agy_auth_and_external_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = make_repo(root)
            home = home_dir(root)
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
            child_dir = home / "deliveries" / "900" / "attempt-1" / "children" / "101"
            child_dir.mkdir(parents=True)
            fake_source_home = root / "operator-home"
            agy_dir = fake_source_home / ".gemini" / "antigravity-cli"
            agy_dir.mkdir(parents=True)
            (agy_dir / "jetski_state.pbtxt").write_text("oauth_token: 'secret-jetski'\n", encoding="utf-8")
            isolated_home = worker_module._prepare_isolated_home(child_dir, fake_source_home)
            self.assertTrue((isolated_home / ".gemini" / "antigravity-cli" / "jetski_state.pbtxt").exists())

            source_env = {
                **os.environ,
                "ASANA_ACCESS_TOKEN": "secret-asana-pat",
                "GITHUB_TOKEN": "ghp_secret_controller_token",
                "TURBO_GITHUB_TOKEN": "secret-test-gh-token",
                "TURBO_ASANA_API_URL": "http://127.0.0.1:9999/api/1.0",
                "TURBO_GITHUB_API_URL": "http://127.0.0.1:9998/api/v3",
            }
            worker_env, _ = worker_module._sanitized_worker_env(source_env, repo, isolated_home)

            (repo / "tests").mkdir(exist_ok=True)
            (repo / "tests" / "test_isolation.py").write_text(
                "import os, pathlib, socket, unittest\n"
                "class IsolationTest(unittest.TestCase):\n"
                "    def test_no_credentials_or_agy_state_in_verification(self) -> None:\n"
                "        for k in ('ASANA_ACCESS_TOKEN', 'GITHUB_TOKEN', 'TURBO_GITHUB_TOKEN', 'TURBO_ASANA_API_URL', 'TURBO_GITHUB_API_URL'):\n"
                "            self.assertIsNone(os.environ.get(k), f'{k} leaked into verification env')\n"
                "        self.assertFalse((pathlib.Path.home() / '.gemini' / 'antigravity-cli' / 'jetski_state.pbtxt').exists())\n"
                "        self.assertEqual(os.environ.get('HTTPS_PROXY'), 'http://127.0.0.1:1')\n"
                "    def test_external_socket_connect_is_blocked(self) -> None:\n"
                "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                "        try:\n"
                "            with self.assertRaises(PermissionError):\n"
                "                s.connect(('127.0.0.1', 9999))\n"
                "        finally:\n"
                "            s.close()\n",
                encoding="utf-8",
            )
            child = {
                "gid": "101",
                "name": "Verify isolation",
                "criteria": [
                    {
                        "id": "AC-1",
                        "verification": "python3 -m unittest discover -s tests -p test_isolation.py -v",
                    }
                ],
            }
            deadline = time.monotonic() + 30.0
            ok, checks, failures = deliver_checks.run_child_verifications(
                repo, child, conf, child_dir, home, worker_env, deadline, 30
            )
            self.assertTrue(ok, failures)
            self.assertEqual(failures, [])
            self.assertTrue(checks[0]["ok"])

    def test_verification_timeout_and_expired_deadline_raise_attempt_timeout_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = make_repo(root)
            home = home_dir(root)
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
            child_dir = home / "deliveries" / "900" / "attempt-1" / "children" / "101"
            child_dir.mkdir(parents=True)
            isolated_home = worker_module._prepare_isolated_home(child_dir, root)
            worker_env, _ = worker_module._sanitized_worker_env(dict(os.environ), repo, isolated_home)
            (repo / "tests").mkdir(exist_ok=True)
            (repo / "tests" / "test_slow.py").write_text(
                "import time, unittest\n"
                "class SlowTest(unittest.TestCase):\n"
                "    def test_hang(self) -> None:\n"
                "        time.sleep(10)\n",
                encoding="utf-8",
            )
            child = {
                "gid": "101",
                "name": "Slow test",
                "criteria": [
                    {
                        "id": "AC-1",
                        "verification": "python3 -m unittest discover -s tests -p test_slow.py -v",
                    }
                ],
            }
            short_deadline = time.monotonic() + 1.0
            with self.assertRaises(deliver_checks.AttemptTimeoutError):
                deliver_checks.run_child_verifications(
                    repo, child, conf, child_dir, home, worker_env, short_deadline, 1
                )

    def test_origin_remote_verification_rejects_mismatched_or_untrusted_remotes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = make_repo(root)
            deadline = time.monotonic() + 10.0
            self.assertIn(
                "no 'origin' remote",
                deliver_checks.verify_origin_remote(repo, "example/chat-bridge", deadline, 10) or "",
            )
            git(repo, "remote", "add", "origin", "https://github.com/example/chat-bridge.git")
            self.assertIsNone(
                deliver_checks.verify_origin_remote(repo, "example/chat-bridge", deadline, 10)
            )
            git(repo, "remote", "set-url", "origin", "https://github.com/other/repo.git")
            self.assertIn(
                "does not match target repository",
                deliver_checks.verify_origin_remote(repo, "example/chat-bridge", deadline, 10) or "",
            )
            git(repo, "remote", "set-url", "origin", "https://evil.example.com/example/chat-bridge.git")
            self.assertIn(
                "untrusted or unrecognized",
                deliver_checks.verify_origin_remote(repo, "example/chat-bridge", deadline, 10) or "",
            )


if __name__ == "__main__":
    unittest.main()
