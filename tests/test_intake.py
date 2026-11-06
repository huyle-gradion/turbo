"""Tests for HTTP Asana feature intake, evidence persistence, and CLI admission (Issue #17)."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from typing import Any
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

from support import ROOT, cli, config, home_dir, make_repo
from test_intake_eval import PARENT_NOTES, _child_notes
from factory import intake as intake_module


class _DisposableAsanaServer:
    def __init__(
        self,
        parent: dict[str, Any],
        pages: list[dict[str, Any]],
        *,
        status_code: int = 200,
        redirect_to: str | None = None,
    ) -> None:
        self.parent = parent
        self.pages = pages
        self.status_code = status_code
        self.redirect_to = redirect_to
        self.requests: list[dict[str, Any]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._make_handler())
        self.base_url = f"http://127.0.0.1:{self._server.server_port}/api/1.0"
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _record(self) -> dict[str, list[str]]:
                parsed = urlparse(self.path)
                outer.requests.append({
                    "method": self.command, "path": parsed.path,
                    "query": parse_qs(parsed.query), "auth": self.headers.get("Authorization"),
                })
                return parse_qs(parsed.query)

            def do_GET(self) -> None:
                query = self._record()
                if outer.redirect_to is not None:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                    return
                if outer.status_code != 200:
                    self._send_json(outer.status_code, {"errors": [{"message": f"HTTP {outer.status_code} failure"}]})
                    return
                parsed = urlparse(self.path)
                gid = outer.parent.get("gid", "900")
                if parsed.path == f"/api/1.0/tasks/{gid}":
                    self._send_json(200, {"data": outer.parent})
                    return
                if parsed.path == f"/api/1.0/tasks/{gid}/subtasks":
                    offset = query.get("offset", [None])[0]
                    idx = 0 if offset is None else int(str(offset).replace("page-", ""))
                    if 0 <= idx < len(outer.pages):
                        self._send_json(200, outer.pages[idx])
                        return
                    self._send_json(500, {"errors": [{"message": "invalid page offset"}]})
                    return
                self._send_json(404, {"errors": [{"message": "not found"}]})

            def do_POST(self) -> None:
                self._record()
                self._send_json(405, {"errors": [{"message": "write forbidden"}]})

            do_PUT = do_PATCH = do_DELETE = do_POST

            def _send_json(self, code: int, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return Handler

    def __enter__(self) -> _DisposableAsanaServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


def _run_intake_cli(
    api_url: str,
    task_ref: str = "https://app.asana.com/0/12345/900",
    *,
    token: str = "disposable-secret-token-xyz",
    workspace: tuple[Path, Path] | None = None,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], list[Path]]:
    def _exec(repo: Path, home: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], list[Path]]:
        env = dict(
            os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1",
            TURBO_ASANA_API_URL=api_url, ASANA_ACCESS_TOKEN=token,
        )
        if not token:
            env.pop("ASANA_ACCESS_TOKEN", None)
        argv = [
            sys.executable, "-P", "-m", "factory",
            "--repo", str(repo), "--home", str(home),
            "intake", "--task", task_ref, "--json",
        ]
        res = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True, env=env, timeout=30)
        intake_root = home / "intake"
        record_path = home / "intake" / "900" / "record.json"
        files = sorted(p for p in intake_root.rglob("*") if p.is_file()) if intake_root.exists() else []
        record = json.loads(record_path.read_text(encoding="utf-8")) if record_path.exists() else {}
        for file_path in files:
            if token and token in file_path.read_text(encoding="utf-8"):
                raise AssertionError(f"secret token leaked into {file_path}")
        return res, record, files

    if workspace is not None:
        return _exec(*workspace)
    with tempfile.TemporaryDirectory() as tmp:
        repo = make_repo(Path(tmp))
        home = home_dir(Path(tmp))
        config(repo, home)
        return _exec(repo, home)


class FeatureIntakeTest(unittest.TestCase):
    def test_ready_paginated_feature_reports_coverage_waiting_dependents_and_mutates_nothing(self) -> None:
        parent = {"gid": "900", "name": "Add chat authentication", "notes": PARENT_NOTES}
        child1 = {
            "gid": "101", "name": "Validate bearer tokens", "completed": True,
            "notes": _child_notes() + "\nMerged: true (PR #42 merged into feature/chat-auth)\n",
        }
        child2 = {
            "gid": "102", "name": "Attach session context", "completed": False,
            "notes": _child_notes(
                criteria=(
                    "- AC-1: Given a validated token, when route handler runs, then request.user is populated.\n"
                    "  Parent coverage: P-AC-2\n"
                    "  Verification: pytest tests/test_routes.py -k test_user_context"
                ),
                blocked_by="https://app.asana.com/0/0/101",
                required_outputs="TokenValidator contract in chat_bridge.auth",
                produces="Protected route middleware",
            ) + "\nPrerequisite merged: yes\n",
        }
        pages = [
            {"data": [child1], "next_page": {"offset": "page-1", "path": "/tasks/900/subtasks?offset=page-1"}},
            {"data": [child2], "next_page": None},
        ]
        with _DisposableAsanaServer(parent, pages) as server:
            pages[0]["next_page"]["uri"] = f"{server.base_url}/tasks/900/subtasks?offset=page-1"
            res, record, files = _run_intake_cli(server.base_url)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertEqual(payload, record)
            self.assertTrue(payload["delivery_ready"])
            self.assertEqual((payload["status"], payload["subtask_pages"]), ("ready", 2))
            by_gid = {child["gid"]: child for child in payload["children"]}
            parent_criteria = {item["id"]: item for item in payload["parent"]["criteria"]}
            self.assertTrue(by_gid["101"]["prepared"])
            self.assertEqual(by_gid["101"]["execution_status"], "ready")
            self.assertEqual(by_gid["101"]["parent_coverage"], ["P-AC-1"])
            self.assertTrue(by_gid["102"]["prepared"])
            self.assertEqual(by_gid["102"]["execution_status"], "waiting")
            self.assertEqual(by_gid["102"]["waiting_on"], ["101"])
            self.assertEqual(by_gid["102"]["parent_coverage"], ["P-AC-2"])
            self.assertEqual(parent_criteria["P-AC-1"]["status"], "covered")
            self.assertEqual(parent_criteria["P-AC-1"]["covered_by"], ["101"])
            self.assertEqual(parent_criteria["P-AC-2"]["status"], "covered")
            self.assertEqual(parent_criteria["P-AC-2"]["covered_by"], ["102"])
            self.assertTrue(parent_criteria["P-AC-3"]["human_judgment"])
            self.assertEqual(parent_criteria["P-AC-3"]["status"], "pending-human-acceptance")
            self.assertTrue(all(req["method"] == "GET" for req in server.requests))
            self.assertEqual(len(server.requests), 3)
            self.assertGreaterEqual(len(files), 2)
            self.assertRegex(payload["factory_revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(payload["measurements"]["usage"]["state"], "unavailable")
            self.assertEqual(payload["measurements"]["cost"]["state"], "unavailable")

    def test_empty_feature_and_auth_permission_redirect_or_truncated_pagination_failures_fail_closed(self) -> None:
        parent = {"gid": "900", "name": "Human-only or empty feature", "notes": PARENT_NOTES}
        with tempfile.TemporaryDirectory() as tmp:
            workspace = (make_repo(Path(tmp)), home_dir(Path(tmp)))
            config(*workspace)
            with _DisposableAsanaServer(parent, [{"data": [], "next_page": None}]) as server:
                res, record, _ = _run_intake_cli(server.base_url, workspace=workspace)
                self.assertEqual((res.returncode, record["status"], record["delivery_ready"]), (1, "empty", False))
                self.assertTrue(any("no prepared sub-tasks" in item for item in record["blockers"]))
            for code in (401, 403, 404, 500):
                with self.subTest(http_code=code), _DisposableAsanaServer(
                    parent, [{"data": [], "next_page": None}], status_code=code
                ) as server:
                    res, record, files = _run_intake_cli(server.base_url, workspace=workspace)
                    self.assertEqual((res.returncode, record["status"], record["delivery_ready"]), (1, "retrieval-failed", False))
                    self.assertTrue(any(str(code) in item for item in record["blockers"]))
                    self.assertGreaterEqual(len(files), 2)
            with _DisposableAsanaServer(
                parent, [{"data": [], "next_page": None}], redirect_to="https://evil.example.test/steal"
            ) as server:
                res_redirect, rec_redirect, _ = _run_intake_cli(server.base_url, workspace=workspace)
                self.assertEqual((res_redirect.returncode, rec_redirect["status"], rec_redirect["delivery_ready"]), (1, "retrieval-failed", False))
                self.assertTrue(any("redirect" in item.lower() for item in rec_redirect["blockers"]))
            with _DisposableAsanaServer(parent, [{"data": [], "next_page": None}]) as server:
                res_no_token, rec_no_token, _ = _run_intake_cli(server.base_url, token="", workspace=workspace)
                self.assertEqual((res_no_token.returncode, rec_no_token["status"], len(server.requests)), (1, "retrieval-failed", 0))
            ready_child = {
                "gid": "101", "name": "Slice 1",
                "notes": _child_notes(criteria="- AC-1: Validated.\n  Parent coverage: P-AC-1, P-AC-2\n  Verification: pytest"),
            }
            untrusted_uri = "https://evil.example.test/api/1.0/tasks/900/subtasks?offset=page-1"
            bad_pages = (
                {"data": [ready_child]},
                {"data": [ready_child], "next_page": {"offset": "page-99"}},
                {"data": [ready_child], "next_page": {"offset": "page-1", "uri": untrusted_uri}},
            )
            for bad_page in bad_pages:
                with _DisposableAsanaServer(parent, [bad_page]) as server:
                    res_bad, rec_bad, _ = _run_intake_cli(server.base_url, workspace=workspace)
                    self.assertEqual((res_bad.returncode, rec_bad["status"], rec_bad["delivery_ready"]), (1, "retrieval-failed", False))
            self.assertEqual(_run_intake_cli("https://evil.example.test/api/1.0", workspace=workspace)[0].returncode, 2)

    def test_incomplete_children_conflicting_targets_missing_deps_and_cycles_report_explicit_blockers(self) -> None:
        parent = {"gid": "900", "name": "Feature with blockers", "notes": PARENT_NOTES}
        incomplete_child = {
            "gid": "201", "name": "Badly specified child",
            "notes": _child_notes(
                repo="", branch="", reviewer="@alice-only",
                criteria=(
                    "- AC-1: Check UI manually with human judgment.\n"
                    "  Parent coverage: P-AC-999\n"
                    "  Verification: manual QA human review\n"
                    "- AC-2: Another check.\n"
                    "  Parent coverage: \n"
                    "  Verification: looks good"
                ),
                blocked_by="https://app.asana.com/0/0/999",
                required_outputs="none", produces="", spec_links="",
                open_questions="Should we support OAuth1 or OAuth2?",
            ),
        }
        cycle_a = {
            "gid": "202", "name": "Cycle A",
            "notes": _child_notes(
                repo="https://github.com/example/other-repo", branch="feature/other-branch",
                blocked_by="https://app.asana.com/0/0/203", required_outputs="Contract B", produces="Contract A",
            ),
        }
        cycle_b = {
            "gid": "203", "name": "Cycle B",
            "notes": _child_notes(
                blocked_by="https://app.asana.com/0/0/202", required_outputs="Contract A", produces="Contract B",
            ),
        }
        with _DisposableAsanaServer(parent, [{"data": [incomplete_child, cycle_a, cycle_b], "next_page": None}]) as server:
            res, record, _ = _run_intake_cli(server.base_url)
            self.assertEqual((res.returncode, record["delivery_ready"], record["status"]), (1, False, "blocked"))
            by_gid = {child["gid"]: child for child in record["children"]}
            for gid in ("201", "202", "203"):
                self.assertFalse(by_gid[gid]["prepared"])
                self.assertEqual(by_gid[gid]["execution_status"], "blocked")
            issues_201 = " | ".join(by_gid["201"]["issues"])
            all_blockers = " | ".join(record["blockers"])
            for expected in (
                "missing repository", "missing target feature branch", "missing reviewer identity",
                "missing context", "blocking ambiguity", "criterion verification",
                "parent coverage", "dependency contract", "missing dependency 999",
            ):
                self.assertIn(expected, issues_201)
            for expected_blocker in (
                "conflicting repository", "conflicting target feature branch",
                "missing dependency 999", "dependency cycle", "P-AC-2",
            ):
                self.assertIn(expected_blocker, all_blockers)

    def test_5b_5c_6c_retrieval_error_isolation_path_boundaries_redaction_and_unavailable_revision(self) -> None:
        self.assertFalse(
            intake_module._same_api_origin("http://127.0.0.1:8000/api/1.0-evil/tasks", "http://127.0.0.1:8000/api/1.0")
        )
        self.assertFalse(
            intake_module._same_api_origin("http://127.0.0.1:8000/api/1.0/../secret", "http://127.0.0.1:8000/api/1.0")
        )

        secret = "disposable-secret-token-xyz"
        parent_leak = {"gid": "900", "name": f"Feature {secret}", "notes": PARENT_NOTES}
        child_leak = {
            "gid": "101", "name": f"Child {secret}",
            "notes": _child_notes(criteria="- AC-1: Valid.\n  Parent coverage: P-AC-1, P-AC-2\n  Verification: pytest"),
        }
        with _DisposableAsanaServer(parent_leak, [{"data": [child_leak], "next_page": None}]) as server:
            res, record, _ = _run_intake_cli(server.base_url, token=secret)
            self.assertEqual(res.returncode, 0)
            self.assertNotIn(secret, json.dumps(record))
            self.assertNotIn(secret, res.stdout)
            with tempfile.TemporaryDirectory() as tmp:
                repo, home = make_repo(Path(tmp)), home_dir(Path(tmp))
                config(repo, home)
                with (
                    mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": server.base_url, "ASANA_ACCESS_TOKEN": secret}),
                    mock.patch("factory.gitio.git", return_value=mock.Mock(ok=False, output="fatal")),
                ):
                    rev_res = intake_module.run_from_cli(
                        intake_module.RuntimePaths(repo=repo, home=home), mock.Mock(task="900")
                    )
                    self.assertEqual((rev_res.factory_revision, rev_res.delivery_ready), ("unavailable", True))
                with (
                    mock.patch.dict(os.environ, {"TURBO_ASANA_API_URL": server.base_url, "ASANA_ACCESS_TOKEN": secret}),
                    mock.patch("factory.intake._evaluate", side_effect=RuntimeError("internal evaluation bug")),
                ):
                    with self.assertRaisesRegex(RuntimeError, "internal evaluation bug"):
                        intake_module.run_from_cli(
                            intake_module.RuntimePaths(repo=repo, home=home), mock.Mock(task="900")
                        )

    @unittest.skipUnless(
        os.environ.get("TURBO_LIVE_ASANA") == "1" and os.environ.get("TURBO_LIVE_ASANA_TASK"),
        "requires TURBO_LIVE_ASANA=1 and TURBO_LIVE_ASANA_TASK",
    )
    def test_live_asana_feature_intake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = make_repo(Path(tmp))
            home = home_dir(Path(tmp))
            config(repo, home)
            res = cli(repo, home, "intake", "--task", os.environ["TURBO_LIVE_ASANA_TASK"], "--json")
            self.assertIn(res.returncode, (0, 1), res.stdout + res.stderr)
            self.assertIn(json.loads(res.stdout)["status"], ("ready", "blocked", "empty"))


if __name__ == "__main__":
    unittest.main()
