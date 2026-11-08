"""Unit and behavioral tests for child scope checks, isolated verification, and PR confirmation (#19, #20)."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io, json, os, socket
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable
import unittest
from unittest import mock
from urllib.parse import parse_qs, unquote, urlparse
import zipfile

from factory import ci_gate, config as config_module, deliver_checks, worker as worker_module
from factory.errors import UsageError
from support import config, git, home_dir, make_repo

ALLOWED_PR_POST_KEYS = frozenset({"title", "head", "base", "body", "draft", "maintainer_can_modify", "issue"})
ALLOWED_PR_PATCH_KEYS = frozenset({"title", "body", "state", "base", "maintainer_can_modify"})


def _build_evidence_zip(
    records: dict[str, dict[str, Any]], *, run_id: int = 700, run_attempt: int = 1,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = {"schema": 1, "workflow_run_id": run_id, "run_attempt": run_attempt, "checks": records}
        zf.writestr("turbo-ci-evidence.json", json.dumps(manifest, indent=2))
        for name, item in records.items():
            zf.writestr(f"logs/{name.replace('/', '__')}.log", str(item.get("log_text") or ""))
    return buf.getvalue()


class _DisposableGitHubServer:
    def __init__(
        self, *, bare_repo: Path | None = None, owner: str = "example", repo: str = "chat-bridge",
        post_status: int = 201, get_status: int = 200, redirect_to: str | None = None,
        verify_override: dict[str, Any] | None = None, patch_status: int = 200, ci_spec: dict[str, Any] | None = None,
        check_runs_by_sha: dict[str, list[dict[str, Any]]] | None = None,
        artifacts_by_run: dict[int, list[dict[str, Any]]] | None = None,
        artifact_zips: dict[int, bytes] | None = None, page_size: int = 100,
        on_patch_pull: Callable[[dict[str, Any]], None] | None = None,
        branch_protections: dict[str, dict[str, Any]] | None = None,
        protection_status: int = 200, merge_status: int = 200,
        merge_override: dict[str, Any] | None = None,
        on_before_merge: Callable[[int, dict[str, Any]], None] | None = None,
    ) -> None:
        self.bare_repo, self.owner, self.repo = bare_repo, owner, repo
        self.post_status, self.get_status, self.redirect_to = post_status, get_status, redirect_to
        self.verify_override = verify_override or {}
        self.patch_status, self.ci_spec, self.page_size, self.on_patch_pull = patch_status, ci_spec, page_size, on_patch_pull
        self.branch_protections, self.protection_status = branch_protections, protection_status
        self.merge_status, self.merge_override, self.on_before_merge = merge_status, merge_override, on_before_merge
        self.disconnect_after_merge = False
        self.check_runs_by_sha = check_runs_by_sha or {}
        self.artifacts_by_run = artifacts_by_run or {}
        self.artifact_zips = artifact_zips or {}
        self.artifact_redirect_by_id: dict[int, str] = {}
        self.workflow_runs_by_id: dict[int, dict[str, Any]] = {}
        self._next_run_id, self._next_artifact_id = 500, 900
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

    def _execute_real_ci_for_pr(
        self, pr_num: int, base_branch: str, base_sha: str, head_branch: str, head_sha: str,
    ) -> None:
        if self.bare_repo is None or head_sha in self.check_runs_by_sha or (self.ci_spec or {}).get("mode") == "none":
            return
        slug, run_id = f"{self.owner}/{self.repo}", self._next_run_id
        self._next_run_id += 1
        with tempfile.TemporaryDirectory() as ci_tmp:
            ci_ws = Path(ci_tmp) / "ci-checkout"
            subprocess.run(["git", "clone", "-q", "--shared", str(self.bare_repo), str(ci_ws)], check=True)
            git(ci_ws, "checkout", "-q", "-B", "ci-merge", base_sha)
            merge_proc = subprocess.run(
                ["git", "-C", str(ci_ws), "-c", "user.name=CI", "-c", "user.email=ci@example.test", "merge", "--no-ff", "-q", "-m", "Merge", head_sha],
                capture_output=True, text=True, check=False,
            )
            if merge_proc.returncode != 0:
                return
            tested_sha = git(ci_ws, "rev-parse", "HEAD")
            git(ci_ws, "push", "-q", "-f", "origin", f"{tested_sha}:refs/pull/{pr_num}/merge")
            checks_to_run = list((self.ci_spec or {}).get("checks") or [
                ("guard/gate-1", "guard", [sys.executable, "-c", "print('gate-1 host policy ok')"]),
                ("guard/gate-2", "guard", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
                ("guard/gate-3", "guard", [sys.executable, "-c", "print('gate-3 protected paths ok')"]),
                ("criterion/AC-1", "criterion", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_auth.py", "-v"]),
            ])
            runs_list, evidence_records = [], {}
            for idx, (chk_name, chk_kind, cmd_argv) in enumerate(checks_to_run, start=1):
                proc = subprocess.run(cmd_argv, cwd=str(ci_ws), capture_output=True, text=True, check=False, timeout=30)
                out_text = (proc.stdout + proc.stderr).strip() + "\n"
                conclusion = "success" if proc.returncode == 0 else "failure"
                job_id = run_id * 100 + idx
                html_url = f"https://github.com/{slug}/actions/runs/{run_id}/job/{job_id}"
                evidence_records[chk_name] = {
                    "workflow_run_id": run_id, "run_attempt": 1, "workflow_path": ".github/workflows/ci.yml",
                    "workflow_event": "pull_request", "workflow_head_sha": head_sha, "policy_sha": base_sha,
                    "candidate_sha": head_sha, "base_sha": base_sha, "tested_sha": tested_sha,
                    "revision_kind": "integration-merge", "check_name": chk_name, "kind": chk_kind,
                    "command": " ".join(cmd_argv), "exit_code": proc.returncode,
                    "conclusion": conclusion, "html_url": html_url, "log_text": out_text,
                }
                summary = (
                    f"candidate_sha={head_sha}\nbase_sha={base_sha}\npolicy_sha={base_sha}\n"
                    f"tested_sha={tested_sha}\nrevision_kind=integration-merge\nrun_attempt=1\nexit_code={proc.returncode}"
                )
                runs_list.append({
                    "id": job_id, "name": chk_name, "head_sha": head_sha, "status": "completed",
                    "conclusion": conclusion, "started_at": "2026-11-06T10:00:00Z", "completed_at": "2026-11-06T10:00:05Z",
                    "html_url": html_url, "details_url": html_url, "app": {"slug": "github-actions"},
                    "output": {"title": chk_name, "summary": summary, "text": out_text},
                })
            art_id = self._next_artifact_id
            self._next_artifact_id += 1
            self.check_runs_by_sha[head_sha] = runs_list
            self.workflow_runs_by_id[run_id] = {
                "id": run_id, "name": "CI", "path": ".github/workflows/ci.yml", "event": "pull_request",
                "run_attempt": 1, "head_branch": head_branch, "head_sha": head_sha, "pull_requests": [{"number": pr_num}],
            }
            self.artifacts_by_run[run_id] = [{
                "id": art_id, "name": "turbo-ci-evidence", "expired": False,
                "archive_download_url": f"{self.base_url}/repos/{slug}/actions/artifacts/{art_id}/zip",
                "url": f"{self.base_url}/repos/{slug}/actions/artifacts/{art_id}",
            }]
            self.artifact_zips[art_id] = _build_evidence_zip(evidence_records, run_id=run_id, run_attempt=1)

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

            def _paginate(self, items: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
                qs = parse_qs(urlparse(self.path).query)
                per_page = min(int((qs.get("per_page") or [str(outer.page_size)])[0]), outer.page_size)
                start = (max(1, int((qs.get("page") or ["1"])[0])) - 1) * per_page
                return len(items), items[start : start + per_page]

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
                body = json.loads(raw) if raw.strip() else {}
                path = self._record_or_redirect(body)
                if path is None:
                    return
                if path.startswith(f"/api/v3/repos/{outer.owner}/{outer.repo}/actions/runs/") and path.endswith("/cancel"):
                    return self._send_json(202, {})
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

            def do_PATCH(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
                body = json.loads(raw) if raw.strip() else {}
                if (path := self._record_or_redirect(body)) is None:
                    return
                prefix = f"/api/v3/repos/{outer.owner}/{outer.repo}/pulls/"
                if not path.startswith(prefix) or not (pr_obj := outer.pulls.get(int(path[len(prefix) :]))):
                    return self._send_json(404, {"message": "Not Found"})
                if unexpected_keys := set(body.keys()) - ALLOWED_PR_PATCH_KEYS:
                    return self._send_json(422, {"message": f"Unsupported PR PATCH fields: {sorted(unexpected_keys)}"})
                if outer.patch_status != 200:
                    return self._send_json(outer.patch_status, {"message": f"GitHub PATCH HTTP {outer.patch_status} failure"})
                for field in ("body", "title"):
                    if field in body:
                        pr_obj[field] = str(body[field])
                if outer.on_patch_pull is not None:
                    outer.on_patch_pull(pr_obj)
                self._send_json(200, json.loads(json.dumps(pr_obj)))

            def do_GET(self) -> None:
                path = self._record_or_redirect()
                if path is None:
                    return
                repo_prefix = f"/api/v3/repos/{outer.owner}/{outer.repo}"
                if path.startswith(f"{repo_prefix}/commits/") and path.endswith("/check-runs"):
                    sha = path[len(f"{repo_prefix}/commits/") : -len("/check-runs")]
                    if sha not in outer.check_runs_by_sha:
                        for pnum, pobj in list(outer.pulls.items()):
                            if pobj["head"]["sha"] == sha and pobj["base"]["sha"]:
                                outer._execute_real_ci_for_pr(pnum, pobj["base"]["ref"], pobj["base"]["sha"], pobj["head"]["ref"], sha)
                                break
                    total, batch = self._paginate(outer.check_runs_by_sha.get(sha, []))
                    return self._send_json(200, {"total_count": total, "check_runs": batch})
                if path.startswith(f"{repo_prefix}/actions/runs/") and path.endswith("/artifacts"):
                    run_id = int(path[len(f"{repo_prefix}/actions/runs/") : -len("/artifacts")])
                    total, batch = self._paginate(outer.artifacts_by_run.get(run_id, []))
                    return self._send_json(200, {"total_count": total, "artifacts": batch})
                if path.startswith(f"{repo_prefix}/actions/runs/"):
                    run_id = int(path[len(f"{repo_prefix}/actions/runs/") :])
                    pr1 = outer.pulls.get(1) or {"head": {"ref": "task/101-auth", "sha": ""}}
                    wf = outer.workflow_runs_by_id.get(run_id) or {
                        "id": run_id, "name": "CI", "path": ".github/workflows/ci.yml", "event": "pull_request",
                        "run_attempt": 1, "head_branch": pr1["head"]["ref"], "head_sha": pr1["head"]["sha"],
                        "pull_requests": [{"number": 1}],
                    }
                    return self._send_json(200, wf)
                if path.startswith(f"{repo_prefix}/actions/artifacts/") and path.endswith("/zip"):
                    art_id = int(path[len(f"{repo_prefix}/actions/artifacts/") : -len("/zip")])
                    if redirect_loc := outer.artifact_redirect_by_id.get(art_id):
                        self.send_response(302)
                        self.send_header("Location", redirect_loc)
                        self.end_headers()
                        return
                    if (raw_zip := outer.artifact_zips.get(art_id)) is None:
                        return self._send_json(404, {"message": "Artifact Not Found"})
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(len(raw_zip)))
                    self.end_headers()
                    self.wfile.write(raw_zip)
                    return
                if path.startswith(f"{repo_prefix}/branches/") and path.endswith("/protection"):
                    raw_segment = path[len(f"{repo_prefix}/branches/") : -len("/protection")]
                    if "/" in raw_segment or not raw_segment:
                        return self._send_json(404, {"message": "Not Found"})
                    bname = unquote(raw_segment)
                    if outer.protection_status != 200:
                        return self._send_json(outer.protection_status, {"message": f"Protection HTTP {outer.protection_status}"})
                    if outer.branch_protections is not None:
                        if bname in outer.branch_protections:
                            return self._send_json(200, outer.branch_protections[bname])
                        return self._send_json(404, {"message": "Branch not protected"})
                    if bname.startswith("feature/"):
                        return self._send_json(200, {
                            "required_status_checks": {"strict": True, "contexts": ["guard/gate-1"]},
                            "enforce_admins": {"enabled": True},
                            "allow_force_pushes": {"enabled": False},
                            "allow_deletions": {"enabled": False},
                        })
                    return self._send_json(404, {"message": "Branch not protected"})
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
                if outer.bare_repo is not None:
                    if live_head := outer._resolve_branch_sha(pr_obj["head"]["ref"]):
                        pr_obj["head"]["sha"] = live_head
                    if live_base := outer._resolve_branch_sha(pr_obj["base"]["ref"]):
                        pr_obj["base"]["sha"] = live_base
                for key, val in outer.verify_override.items():
                    if key in ("head_ref", "head_sha"):
                        pr_obj["head"][key.split("_", 1)[1]] = val
                    elif key in ("base_ref", "base_sha"):
                        pr_obj["base"][key.split("_", 1)[1]] = val
                    elif key == "repo_full_name":
                        pr_obj["base"]["repo"]["full_name"] = val
                    elif key == "head_repo_full_name":
                        pr_obj["head"]["repo"]["full_name"] = val
                    else:
                        pr_obj[key] = val
                self._send_json(200, pr_obj)

            def do_PUT(self) -> None:
                path = self._record_or_redirect()
                if path is None:
                    return
                repo_prefix = f"/api/v3/repos/{outer.owner}/{outer.repo}"
                if path.startswith(f"{repo_prefix}/pulls/") and path.endswith("/merge"):
                    pr_num = int(path[len(f"{repo_prefix}/pulls/") : -len("/merge")])
                    raw_b = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8")
                    payload = json.loads(raw_b) if raw_b else {}
                    if outer.on_before_merge:
                        outer.on_before_merge(pr_num, payload)
                    if outer.merge_status != 200:
                        return self._send_json(outer.merge_status, outer.merge_override or {"message": f"Merge failed HTTP {outer.merge_status}"})
                    if pr_num not in outer.pulls:
                        return self._send_json(404, {"message": "PR Not Found"})
                    pr_obj = outer.pulls[pr_num]
                    if pr_obj.get("state") != "open" or pr_obj.get("merged"):
                        return self._send_json(405, {"message": "Pull request is not open"})
                    req_sha = payload.get("sha")
                    if req_sha and req_sha != pr_obj["head"]["sha"]:
                        return self._send_json(409, {"message": "Head branch was modified. Review and try the merge again."})
                    base_ref = pr_obj["base"]["ref"]
                    if outer.bare_repo is not None:
                        live_base = outer._resolve_branch_sha(base_ref)
                        if live_base != pr_obj["base"]["sha"]:
                            return self._send_json(405, {"message": "Base branch was modified. Review and try the merge again."})
                        merge_sha = git(outer.bare_repo, "-c", "user.name=CI", "-c", "user.email=ci@example.test", "commit-tree", f"{pr_obj['head']['sha']}^{{tree}}", "-p", pr_obj["base"]["sha"], "-p", pr_obj["head"]["sha"], "-m", payload.get("commit_title") or f"Merge pull request #{pr_num}")
                        try:
                            git(outer.bare_repo, "update-ref", f"refs/heads/{base_ref}", merge_sha, pr_obj["base"]["sha"])
                        except AssertionError:
                            return self._send_json(405, {"message": "Base branch was modified. Review and try the merge again."})
                    else:
                        merge_sha = pr_obj["head"]["sha"]
                    pr_obj["merged"] = True
                    pr_obj["state"] = "closed"
                    pr_obj["merge_commit_sha"] = merge_sha
                    if outer.disconnect_after_merge:
                        self.close_connection = True
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                            self.connection.close()
                        except Exception:
                            pass
                        return
                    return self._send_json(200, {"sha": merge_sha, "merged": True, "message": "Pull Request successfully merged"})
                self._send_json(405, {"message": "Merge forbidden"})

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
            ("src/chat_bridge/auth.py", "tests/test_auth.py"), semantic_child, ("AGENTS.md", "docs/spec.md"),
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
            ("src/chat_bridge/auth.py", "tests/test_auth.py", "tests/unit/deep/test_token.py"), glob_child, ("AGENTS.md", "docs/spec.md"),
        )
        self.assertTrue(ok_glob, violations_glob)
        self.assertEqual((detail_glob["status"], detail_glob["semantic_verified"], detail_glob["constraint_paths"]), ("deterministic-verified", True, ["docs/spec.md"]))
        ok_unanchored, violations_unanchored, _ = deliver_checks.evaluate_scope(
            ("other/src/chat_bridge/auth.py", "src/chat_bridge/sub/nested.py"), glob_child, ("AGENTS.md", "docs/spec.md"),
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
                tuple(rename_diff["changed_paths"]), {"scope": {"in_scope": "`src/`"}}, ("AGENTS.md",),
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
        import socket

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
            self.assertEqual((worker_env["SSH_AUTH_SOCK"], worker_env["GIT_ALLOW_PROTOCOL"], worker_env["GIT_CONFIG_SYSTEM"]), ("", "none", "/dev/null"))
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
                verify_home = child_dir / "verify-home"
                verify_home.mkdir(parents=True, exist_ok=True)
                verify_env = {**worker_env, "HOME": str(verify_home)}
                iso_argv = ("python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_isolation.py", "-v")
                code, out_s, err_s, _, timed_out = worker_module.execute_stream(
                    worktree_dir, iso_argv, verify_env, 30, isolated_home=verify_home, allow_network=False,
                )
                self.assertEqual((code, timed_out), (0, False), out_s + err_s)
                self.assertEqual(accepted, [])
                self.assertEqual(repo_sentinel.read_text(encoding="utf-8"), "REPO_SENTINEL_INTACT\n")
                self.assertEqual(home_sentinel.read_text(encoding="utf-8"), "CONTROLLER_CRED_INTACT\n")
                self.assertEqual(source_sentinel.read_text(encoding="utf-8"), "oauth_token: 'secret-jetski'\n")
            finally:
                stop_listener.set()
                listener.close()
                accept_thread.join(timeout=1.0)
            with self.assertRaises(OSError):
                worker_module.execute_stream(
                    worktree_dir, ("pytest", "-q"), {**verify_env, "PATH": "/nonexistent-bin"}, 30,
                    isolated_home=verify_home, allow_network=False,
                )
            with mock.patch("factory.sandbox.sandbox_available", return_value=False):
                with self.assertRaises(worker_module.SandboxUnavailableError):
                    worker_module.execute_stream(
                        worktree_dir, iso_argv, verify_env, 30, isolated_home=verify_home, allow_network=False,
                    )

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
                self.assertEqual((pr["pr_confirmed"], pr["ci_verified"], pr["head_sha"]), (True, False, candidate_sha))
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

    def test_artifact_download_bounds_redirect_errors_size_caps_and_signed_url_redaction(self) -> None:
        class _BlobRedirectHandler(BaseHTTPRequestHandler):
            mode = "ok"
            payload = b""
            seen_auth: list[str | None] = []

            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                _BlobRedirectHandler.seen_auth.append(self.headers.get("Authorization"))
                if _BlobRedirectHandler.mode == "503":
                    self.send_response(503)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(_BlobRedirectHandler.payload)))
                self.end_headers()
                self.wfile.write(_BlobRedirectHandler.payload)

        blob_srv = ThreadingHTTPServer(("127.0.0.1", 0), _BlobRedirectHandler)
        blob_thread = threading.Thread(target=blob_srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        blob_thread.start()
        try:
            blob_port = blob_srv.server_port
            with _DisposableGitHubServer() as gh:
                valid_zip = _build_evidence_zip({"guard/gate-1": {"check_name": "guard/gate-1", "log_text": "ok\n"}})
                _BlobRedirectHandler.mode = "ok"
                _BlobRedirectHandler.payload = valid_zip
                _BlobRedirectHandler.seen_auth.clear()
                signed_url = f"http://127.0.0.1:{blob_port}/blob/artifact.zip?sig=SECRET_SAS_SIGNATURE_999&se=2026"
                gh.artifact_redirect_by_id[901] = signed_url
                dl_url = f"{gh.base_url}/repos/example/chat-bridge/actions/artifacts/901/zip"
                trace: list[dict[str, Any]] = []
                raw = deliver_checks._download_zip_bytes(dl_url, "ghp_tok", gh.base_url, trace, time.monotonic() + 10.0, 10)
                self.assertEqual(raw, valid_zip)
                self.assertEqual(_BlobRedirectHandler.seen_auth, [None])
                self.assertNotIn("SECRET_SAS_SIGNATURE_999", json.dumps(trace))

                _BlobRedirectHandler.mode = "503"
                trace_err: list[dict[str, Any]] = []
                with self.assertRaises(deliver_checks.GitHubError) as ctx_503:
                    deliver_checks._download_zip_bytes(dl_url, "ghp_tok", gh.base_url, trace_err, time.monotonic() + 10.0, 10)
                self.assertNotIn("SECRET_SAS_SIGNATURE_999", str(ctx_503.exception))
                self.assertNotIn("SECRET_SAS_SIGNATURE_999", json.dumps(trace_err))

                with mock.patch.object(deliver_checks, "MAX_ARTIFACT_ZIP_BYTES", 32):
                    _BlobRedirectHandler.mode = "ok"
                    _BlobRedirectHandler.payload = b"x" * 128
                    with self.assertRaises(deliver_checks.GitHubError) as ctx_cap:
                        deliver_checks._download_zip_bytes(dl_url, "ghp_tok", gh.base_url, [], time.monotonic() + 10.0, 10)
                    self.assertIn("exceeds maximum size", str(ctx_cap.exception))

                gh.artifact_redirect_by_id.pop(901, None)
                gh.artifacts_by_run[700] = [{
                    "id": 901, "name": "turbo-ci-evidence", "expired": False,
                    "archive_download_url": dl_url, "url": f"{gh.base_url}/repos/example/chat-bridge/actions/artifacts/901",
                }]
                gh.artifact_zips[901] = valid_zip
                with mock.patch.object(deliver_checks, "MAX_EVIDENCE_JSON_BYTES", 10):
                    _, issues = deliver_checks._fetch_run_evidence_artifacts(
                        gh.base_url, "ghp_tok", "example/chat-bridge", {700: 1}, [], time.monotonic() + 10.0, 10,
                    )
                    self.assertTrue(any("exceeds maximum size" in i for i in issues), issues)

                r_ok = {
                    "id": 1, "status": "completed", "conclusion": "success", "run_attempt": 1,
                    "started_at": "2026-11-06T10:00:00Z", "completed_at": "2026-11-06T10:00:05Z",
                    "html_url": "https://github.com/example/chat-bridge/actions/runs/700/job/1",
                }
                r_queued = {
                    "id": 2, "status": "queued", "conclusion": None, "run_attempt": 2,
                    "started_at": "", "completed_at": "",
                    "html_url": "https://github.com/example/chat-bridge/actions/runs/700/job/2",
                }
                sel_q, _, _, err_q = deliver_checks._select_authoritative_check_run(
                    "criterion/AC-1", [r_ok, r_queued], gh.base_url, "ghp_tok", "example/chat-bridge",
                    {700: {"id": 700, "run_attempt": 2}}, [], time.monotonic() + 10.0, 10,
                )
                self.assertEqual((sel_q["id"], err_q), (2, None))
                r_bad = {
                    "id": 3, "status": "completed", "conclusion": "success", "run_attempt": 2,
                    "started_at": "2026-11-06T09:00:00Z", "completed_at": "2026-11-06T09:00:05Z",
                    "html_url": "https://github.com/example/chat-bridge/actions/runs/700/job/3",
                }
                _, _, _, err_c = deliver_checks._select_authoritative_check_run(
                    "criterion/AC-1", [r_ok, r_bad], gh.base_url, "ghp_tok", "example/chat-bridge",
                    {700: {"id": 700, "run_attempt": 2}}, [], time.monotonic() + 10.0, 10,
                )
                self.assertIn("contradictory rerun ordering", str(err_c))
        finally:
            blob_srv.shutdown()
            blob_srv.server_close()

    def test_ci_gate_evaluator_covers_provenance_reruns_artifacts_drift_and_preserved_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "origin.git"
            bare.mkdir()
            git(bare, "init", "--bare", "-q", "-b", "main")
            repo, home = make_repo(root), home_dir(root)
            (repo / "AGENTS.md").write_text("# Rules\n", encoding="utf-8")
            (repo / "tests").mkdir(exist_ok=True)
            (repo / "tests" / "test_auth.py").write_text(
                "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertEqual(1, 1)\n",
                encoding="utf-8",
            )
            git(repo, "add", ".")
            git(repo, "commit", "-q", "-m", "base")
            git(repo, "remote", "add", "origin", str(bare))
            git(repo, "push", "-q", "origin", "main")
            base_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-q", "-b", "feature/chat-auth")
            git(repo, "push", "-q", "origin", "feature/chat-auth")
            git(repo, "checkout", "-q", "-b", "task/101-auth")
            (repo / "README.md").write_text("candidate\n", encoding="utf-8")
            git(repo, "add", "README.md")
            git(repo, "commit", "-q", "-m", "candidate")
            candidate_sha = git(repo, "rev-parse", "HEAD")
            git(repo, "push", "-q", "origin", "task/101-auth")
            config(repo, home)
            conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
            parent = {"gid": "900", "name": "Feature"}
            child = {
                "gid": "101", "name": "Slice", "outcome": "Deliver slice",
                "scope": {"in_scope": "`README.md`, `tests/`", "out_of_scope": "none", "constraints": "none"},
                "criteria": [{
                    "id": "AC-1", "description": "Auth works", "parent_coverage": ["P-AC-1"],
                    "verification": "python3 -m unittest discover -s tests -p test_auth.py -v",
                }],
            }
            scope_detail = {"status": "deterministic-verified", "provenance": "deterministic rules enforced"}

            def _make_run(
                run_id: int, job_idx: int, name: str, *, status: str = "completed",
                conclusion: str | None = "success", producer: str = "github-actions",
                started_at: str = "2026-11-06T10:00:00Z", completed_at: str = "2026-11-06T10:00:05Z",
                cand: str = candidate_sha, base: str = base_sha, tested: str = candidate_sha,
                policy: str = base_sha, run_attempt: int | None = 1, html_url: str | None = None,
            ) -> tuple[dict[str, Any], dict[str, Any]]:
                jid = run_id * 100 + job_idx
                url = html_url if html_url is not None else f"https://github.com/example/chat-bridge/actions/runs/{run_id}/job/{jid}"
                summary = (
                    f"candidate_sha={cand}\nbase_sha={base}\npolicy_sha={policy}\n"
                    f"tested_sha={tested}\nrevision_kind=fast-forward-head\n"
                    + (f"run_attempt={run_attempt}\n" if run_attempt is not None else "")
                )
                cr: dict[str, Any] = {
                    "id": jid, "name": name, "head_sha": candidate_sha, "status": status,
                    "conclusion": conclusion, "started_at": started_at, "completed_at": completed_at,
                    "html_url": url, "details_url": url, "app": {"slug": producer},
                    "output": {"title": name, "summary": summary, "text": f"log for {name}\n"},
                }
                if run_attempt is not None:
                    cr["run_attempt"] = run_attempt
                ev = {
                    "workflow_run_id": run_id, "run_attempt": run_attempt if run_attempt is not None else 1,
                    "workflow_path": ".github/workflows/ci.yml", "workflow_event": "pull_request",
                    "workflow_head_sha": cand, "policy_sha": policy, "candidate_sha": cand,
                    "base_sha": base, "tested_sha": tested, "revision_kind": "fast-forward-head",
                    "check_name": name, "command": f"run {name}",
                    "exit_code": 0 if conclusion == "success" else 1, "conclusion": conclusion or "pending",
                    "html_url": url, "log_text": f"raw log for {name}\n",
                }
                return cr, ev

            req_names = ("guard/gate-1", "guard/gate-2", "guard/gate-3", "criterion/AC-1")
            child_dir = home / "deliveries" / "900" / "attempt-1" / "children" / "101"
            with _DisposableGitHubServer(bare_repo=bare, page_size=2) as gh_ok:
                pr_info = deliver_checks.open_and_confirm_pr(
                    gh_ok.base_url, "tok-1", "example/chat-bridge", parent, child,
                    "task/101-auth", candidate_sha, "feature/chat-auth", [], scope_detail, [], time.monotonic() + 30.0, 30,
                )
                with mock.patch("factory.ci_gate._verify_tested_revision_in_git", wraps=ci_gate._verify_tested_revision_in_git) as spy_git_rev:
                    gate_res = ci_gate.evaluate_child_pr_ci_gate(
                        repo=repo, home=home, child_dir=child_dir, base_url=gh_ok.base_url, token="tok-1",
                        repo_slug="example/chat-bridge", parent=parent, child=child, conf=conf, pr_info=pr_info,
                        head_branch="task/101-auth", candidate_sha=candidate_sha, base_branch="feature/chat-auth",
                        base_sha=base_sha, scope_detail=scope_detail, trace=[], deadline=time.monotonic() + 30.0,
                        limit_s=30, max_missing_polls=1, artifact_retry_delay_s=0.0, sleep_fn=lambda _: None,
                    )
                    self.assertEqual(spy_git_rev.call_count, 1)
                self.assertEqual((gate_res["status"], gate_res["verified"]), ("verified", True))
                self.assertEqual((gate_res["pr"]["pr_confirmed"], gate_res["pr"]["ci_verified"], gate_res["pr"]["verified"]), (True, True, True))
                self.assertIn(f"`verified` for candidate `{candidate_sha}` against base `{base_sha}`", gate_res["pr"]["body"])
                self.assertGreaterEqual(len([r for r in gh_ok.requests if r["path"].endswith("/check-runs")]), 2)

                def _eval_custom(
                    crs: list[dict[str, Any]], ev_map: dict[str, dict[str, Any]], *, expired: bool = False,
                    omit_artifact: bool = False, extra_artifacts: list[tuple[int, dict[str, dict[str, Any]]]] | None = None,
                    wf_overrides: dict[int, dict[str, Any]] | None = None,
                    on_patch: Callable[[dict[str, Any]], None] | None = None,
                    timeout_s: float = 10.0, cancel_sup: bool = False, run_attempt: int = 1,
                    max_polls: int | None = 1,
                ) -> dict[str, Any]:
                    gh_ok.ci_spec = {"mode": "none"}
                    gh_ok.check_runs_by_sha[candidate_sha] = crs
                    gh_ok.on_patch_pull = on_patch
                    gh_ok.workflow_runs_by_id = dict(wf_overrides or {})
                    gh_ok.artifacts_by_run.clear()
                    gh_ok.artifact_zips.clear()
                    if not omit_artifact:
                        arts = [{
                            "id": 990, "name": "turbo-ci-evidence", "expired": expired,
                            "archive_download_url": f"{gh_ok.base_url}/repos/example/chat-bridge/actions/artifacts/990/zip",
                            "url": f"{gh_ok.base_url}/repos/example/chat-bridge/actions/artifacts/990",
                        }]
                        gh_ok.artifact_zips[990] = _build_evidence_zip(ev_map, run_id=700, run_attempt=run_attempt)
                        for extra_id, extra_map in extra_artifacts or ():
                            arts.append({
                                "id": extra_id, "name": f"turbo-ci-evidence-{extra_id}", "expired": False,
                                "archive_download_url": f"{gh_ok.base_url}/repos/example/chat-bridge/actions/artifacts/{extra_id}/zip",
                                "url": f"{gh_ok.base_url}/repos/example/chat-bridge/actions/artifacts/{extra_id}",
                            })
                            gh_ok.artifact_zips[extra_id] = _build_evidence_zip(extra_map, run_id=700, run_attempt=run_attempt)
                        gh_ok.artifacts_by_run[700] = arts
                    return ci_gate.evaluate_child_pr_ci_gate(
                        repo=repo, home=home, child_dir=child_dir, base_url=gh_ok.base_url, token="tok-1",
                        repo_slug="example/chat-bridge", parent=parent, child=child, conf=conf, pr_info=pr_info,
                        head_branch="task/101-auth", candidate_sha=candidate_sha, base_branch="feature/chat-auth",
                        base_sha=base_sha, scope_detail=scope_detail, trace=[], deadline=time.monotonic() + timeout_s,
                        limit_s=max(1, int(timeout_s)), poll_interval_s=0.05, max_missing_polls=1, max_polls=max_polls,
                        artifact_retry_delay_s=0.0, sleep_fn=lambda _: None, cancel_superseded=cancel_sup,
                    )

                base_pairs = [_make_run(700, idx, n) for idx, n in enumerate(req_names, start=1)]
                base_crs = [p[0] for p in base_pairs]
                base_evs = {p[0]["name"]: p[1] for p in base_pairs}

                # Newer queued rerun attempt MUST block reuse of older completed success deterministically
                queued_rerun_cr, _ = _make_run(
                    700, 5, "criterion/AC-1", status="queued", conclusion=None, started_at="", completed_at="", run_attempt=2,
                )
                res_queued_rerun = _eval_custom([*base_crs, queued_rerun_cr], base_evs)
                self.assertEqual((res_queued_rerun["status"], res_queued_rerun["verified"]), ("ci-pending", False))
                self.assertEqual(len(res_queued_rerun["checks"]), 4)
                self.assertEqual([c["run_id"] for c in res_queued_rerun["checks"]], [70001, 70002, 70003, 70005])
                self.assertEqual((res_queued_rerun["pr"]["pr_confirmed"], res_queued_rerun["pr"]["ci_verified"]), (True, False))

                # Evaluator timeout handling: expired deadline during polling or post-poll workflow/artifact inspection returns ci-pending with observed checks
                res_pre_poll_timeout = _eval_custom([*base_crs, queued_rerun_cr], base_evs, timeout_s=-1.0, max_polls=None)
                self.assertEqual((res_pre_poll_timeout["status"], res_pre_poll_timeout["verified"], len(res_pre_poll_timeout["checks"])), ("ci-pending", False, 4))
                self.assertEqual((res_pre_poll_timeout["pr"]["pr_confirmed"], res_pre_poll_timeout["pr"]["ci_verified"]), (True, False))

                completed_rerun_cr, _ = _make_run(
                    700, 6, "criterion/AC-1", status="completed", conclusion="success",
                    started_at="2026-11-06T10:02:00Z", completed_at="2026-11-06T10:02:05Z", run_attempt=2,
                )
                with mock.patch("factory.deliver_checks._fetch_workflow_run", side_effect=deliver_checks.AttemptTimeoutError("attempt timed out during rerun selection")):
                    res_sel_timeout = _eval_custom([*base_crs, completed_rerun_cr], base_evs, run_attempt=2)
                self.assertEqual((res_sel_timeout["status"], res_sel_timeout["verified"]), ("ci-pending", False))
                self.assertEqual([c["run_id"] for c in res_sel_timeout["checks"]], [70001, 70002, 70003, 70006])
                self.assertEqual((res_sel_timeout["pr"]["pr_confirmed"], res_sel_timeout["pr"]["ci_verified"]), (True, False))

                with mock.patch("factory.ci_gate._fetch_workflow_run", side_effect=deliver_checks.AttemptTimeoutError("attempt timed out during workflow run fetch")):
                    res_wf_timeout = _eval_custom(base_crs, base_evs)
                self.assertEqual((res_wf_timeout["status"], res_wf_timeout["verified"]), ("ci-pending", False))
                self.assertEqual([c["run_id"] for c in res_wf_timeout["checks"]], [70001, 70002, 70003, 70004])
                self.assertEqual((res_wf_timeout["pr"]["pr_confirmed"], res_wf_timeout["pr"]["ci_verified"]), (True, False))

                with mock.patch("factory.ci_gate._fetch_run_evidence_artifacts", side_effect=deliver_checks.AttemptTimeoutError("attempt timed out during CI artifact download")):
                    res_art_timeout = _eval_custom(base_crs, base_evs)
                self.assertEqual((res_art_timeout["status"], res_art_timeout["verified"]), ("ci-pending", False))
                self.assertEqual([c["run_id"] for c in res_art_timeout["checks"]], [70001, 70002, 70003, 70004])
                self.assertEqual((res_art_timeout["pr"]["pr_confirmed"], res_art_timeout["pr"]["ci_verified"]), (True, False))

                # Ambiguous rerun ordering (missing timestamps/attempts or contradictory attempt vs timestamp) fails closed
                ambig_cr1, _ = _make_run(700, 4, "criterion/AC-1", conclusion="success", started_at="", completed_at="", run_attempt=None)
                ambig_cr2, _ = _make_run(700, 5, "criterion/AC-1", conclusion="success", started_at="", completed_at="", run_attempt=None)
                res_ambig = _eval_custom([*base_crs[:3], ambig_cr1, ambig_cr2], base_evs)
                self.assertEqual((res_ambig["status"], res_ambig["verified"]), ("ci-evidence-invalid", False))

                contradict_cr1, _ = _make_run(
                    700, 4, "criterion/AC-1", conclusion="failure",
                    started_at="2026-11-06T10:10:00Z", completed_at="2026-11-06T10:10:05Z", run_attempt=1,
                )
                contradict_cr2, _ = _make_run(
                    700, 5, "criterion/AC-1", conclusion="success",
                    started_at="2026-11-06T10:01:00Z", completed_at="2026-11-06T10:01:05Z", run_attempt=2,
                )
                res_contradict = _eval_custom([*base_crs[:3], contradict_cr1, contradict_cr2], base_evs)
                self.assertEqual((res_contradict["status"], res_contradict["verified"]), ("ci-evidence-invalid", False))

                # Superseded run cancellation scope and newer completed failure overriding older success
                old_other_pr, _ = _make_run(
                    698, 1, "criterion/AC-1", status="completed", conclusion="success",
                    started_at="2026-11-06T09:49:00Z", completed_at="2026-11-06T09:49:05Z", run_attempt=1,
                )
                old_same_pr, _ = _make_run(
                    699, 1, "criterion/AC-1", status="completed", conclusion="success",
                    started_at="2026-11-06T09:50:00Z", completed_at="2026-11-06T09:50:05Z", run_attempt=1,
                )
                rerun_fail_cr, rerun_fail_ev = _make_run(
                    700, 5, "criterion/AC-1", conclusion="failure",
                    started_at="2026-11-06T10:05:00Z", completed_at="2026-11-06T10:05:05Z", run_attempt=2,
                )
                wfs_cancel = {
                    698: {"id": 698, "path": ".github/workflows/ci.yml", "event": "pull_request", "run_attempt": 1, "head_branch": "task/999-other", "head_sha": candidate_sha, "pull_requests": [{"number": 99}]},
                    699: {"id": 699, "path": ".github/workflows/ci.yml", "event": "pull_request", "run_attempt": 1, "head_branch": "task/101-auth", "head_sha": candidate_sha, "pull_requests": [{"number": 1}]},
                    700: {"id": 700, "path": ".github/workflows/ci.yml", "event": "pull_request", "run_attempt": 2, "head_branch": "task/101-auth", "head_sha": candidate_sha, "pull_requests": [{"number": 1}]},
                }
                res_rerun = _eval_custom(
                    [*base_crs[:3], old_other_pr, old_same_pr, rerun_fail_cr],
                    {**base_evs, "criterion/AC-1": rerun_fail_ev}, wf_overrides=wfs_cancel, cancel_sup=True, run_attempt=2,
                )
                self.assertEqual((res_rerun["status"], res_rerun["verified"], res_rerun["cancelled_workflow_runs"]), ("ci-failed", False, [699]))
                self.assertEqual((res_rerun["pr"]["pr_confirmed"], res_rerun["pr"]["ci_verified"]), (True, False))

                # Preserved checks on ci-missing and ci-untrusted-producer
                res_missing = _eval_custom(base_crs[:3], {k: v for k, v in base_evs.items() if k != "criterion/AC-1"})
                self.assertEqual((res_missing["status"], len(res_missing["checks"])), ("ci-missing", 4))
                self.assertEqual((res_missing["pr"]["pr_confirmed"], res_missing["pr"]["ci_verified"]), (True, False))

                untrusted_cr, untrusted_ev = _make_run(700, 4, "criterion/AC-1", producer="builder-self-attest")
                res_untrusted = _eval_custom([*base_crs[:3], untrusted_cr], {**base_evs, "criterion/AC-1": untrusted_ev})
                self.assertEqual((res_untrusted["status"], len(res_untrusted["checks"])), ("ci-untrusted-producer", 4))
                self.assertEqual((res_untrusted["pr"]["pr_confirmed"], res_untrusted["pr"]["ci_verified"]), (True, False))

                # Missing policy_sha, missing workflow_path, or non-zero exit_code must NEVER be filled with expected values
                for bad_override in ({"policy_sha": ""}, {"workflow_path": ""}, {"exit_code": 1}, {"run_attempt": 99}):
                    bad_ev = {**base_evs["criterion/AC-1"], **bad_override}
                    self.assertEqual(_eval_custom(base_crs, {**base_evs, "criterion/AC-1": bad_ev})["status"], "ci-evidence-invalid")

                # Duplicate check in artifacts fails closed
                res_dup = _eval_custom(base_crs, base_evs, extra_artifacts=[(991, {"criterion/AC-1": base_evs["criterion/AC-1"]})])
                self.assertEqual(res_dup["status"], "ci-evidence-invalid")

                # Drift DURING patch invalidates PR body to stale-revision; drift BEFORE patch never publishes verified
                res_stale = _eval_custom(
                    base_crs, base_evs, on_patch=lambda _: git(bare, "update-ref", "refs/heads/feature/chat-auth", candidate_sha),
                )
                self.assertEqual((res_stale["status"], res_stale["verified"]), ("stale-revision", False))
                self.assertEqual((res_stale["pr"]["pr_confirmed"], res_stale["pr"]["ci_verified"], res_stale["pr"]["verified"]), (False, False, False))
                self.assertIn("`stale-revision`", gh_ok.pulls[1]["body"])
                self.assertNotIn("`verified` for candidate", gh_ok.pulls[1]["body"])

                patch_bodies: list[str] = []
                res_pre_stale = _eval_custom(base_crs, base_evs, on_patch=lambda p: patch_bodies.append(str(p.get("body") or "")))
                self.assertEqual((res_pre_stale["status"], res_pre_stale["verified"]), ("stale-revision", False))
                self.assertTrue(all("`verified` for candidate" not in b for b in patch_bodies))


if __name__ == "__main__":
    unittest.main()
