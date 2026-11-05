"""Tests for bounded, isolated agy worker execution (Issue #18)."""

from __future__ import annotations

import json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock

from support import ROOT, cli, config, home_dir, make_repo
from factory import worker as worker_module
from factory.errors import UsageError


def _run_fake_worker(script: str, *extra_args: str, task_id: str = "task-test", time_limit: str = "30s", env_override: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo, home = make_repo(root), home_dir(root)
        config(repo, home)
        fake_bin = root / "fake-agy.py"
        fake_bin.write_text("import sys\nif '--version' in sys.argv: print('1.5.0-test'); sys.exit(0)\n" + script, encoding="utf-8")
        argv = [
            sys.executable, "-P", "-m", "factory", "--repo", str(repo), "--home", str(home),
            "worker", "--task-id", task_id, "--prompt", "Execute disposable task",
            "--artifact", "artifact.txt", "--time-limit", time_limit,
            "--agy-bin", sys.executable, "--agy-arg", str(fake_bin), "--json", *extra_args,
        ]
        run_env = {**(env_override or os.environ), "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"}
        res = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True, env=run_env, timeout=60)
        record_file = home / "workers" / task_id / "record.json"
        payload = json.loads(record_file.read_text(encoding="utf-8")) if record_file.exists() else {}
        for k, p in (("_stored_artifact_text", payload.get("artifact", {}).get("stored_path")), ("_stdout_text", payload.get("evidence", {}).get("stdout_path")), ("_stderr_text", payload.get("evidence", {}).get("stderr_path"))):
            if p: payload[k] = Path(str(p)).read_text(encoding="utf-8")
        return res, payload


class WorkerExecutionTest(unittest.TestCase):
    def test_worker_completes_disposable_task_and_records_evidence(self):
        script = (
            "import json, pathlib, sys\n"
            "pathlib.Path('artifact.txt').write_text('DISPOSABLE_RESULT\\n', encoding='utf-8')\n"
            "sys.stderr.write('diagnostic notice: tool executed\\n')\n"
            "print(json.dumps({'event': 'step_update', 'step_update': {'step_index': 1, 'state': 'DONE', 'step_type': 'tool_call'}}))\n"
            "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'conv-123', 'status': 'SUCCESS', 'response': 'Done\\n', 'duration_seconds': 1.25, 'num_turns': 1, 'usage': {'input_tokens': 120, 'output_tokens': 30, 'thinking_tokens': 10, 'cache_read_tokens': 0, 'total_tokens': 160}}}))\n"
        )
        res, payload = _run_fake_worker(script, task_id="task-1")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual((payload["status"], payload["completed"], payload["host_version"]), ("completed", True, "1.5.0-test"))
        self.assertIn(payload["platform"]["system"], ("Linux", "Darwin"))
        self.assertRegex(payload["factory_revision"], r"^[0-9a-f]{40}$")
        self.assertEqual((payload["artifact"]["relative_path"], payload["_stored_artifact_text"]), ("artifact.txt", "DISPOSABLE_RESULT\n"))
        usage, cost = payload["measurements"]["usage"], payload["measurements"]["cost"]
        self.assertEqual((usage["state"], usage["input_tokens"], usage["output_tokens"], usage["thinking_tokens"], usage["total_tokens"]), ("reported", 120, 30, 10, 160))
        self.assertEqual((cost["state"], cost["usd"]), ("unavailable", None))
        self.assertIn("diagnostic notice: tool executed", payload["_stderr_text"])

    def test_empty_artifact_file_is_preserved_as_present_and_completed(self):
        script = "import json, pathlib\npathlib.Path('artifact.txt').write_bytes(b'')\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c0', 'status': 'SUCCESS', 'response': 'Done'}}))\n"
        res, payload = _run_fake_worker(script, task_id="task-empty-art")
        self.assertEqual((res.returncode, payload["completed"], payload["artifact"]["present"], payload["_stored_artifact_text"]), (0, True, True, ""))

    def test_missing_artifact_even_with_exit_zero_and_success_message_is_incomplete(self):
        script = "import json\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c1', 'status': 'SUCCESS', 'response': 'Done!'}}))\n"
        res, payload = _run_fake_worker(script)
        self.assertEqual((res.returncode, payload["status"], payload["completed"]), (1, "missing-artifact", False))

    def test_malformed_stdout_even_when_artifact_written_and_exit_zero_is_incomplete(self):
        script = "import pathlib\npathlib.Path('artifact.txt').write_text('ok\\n', encoding='utf-8')\nprint('COMPLETE SUCCESS but not json')\n"
        res, payload = _run_fake_worker(script)
        self.assertEqual((res.returncode, payload["status"], payload["completed"]), (1, "malformed-output", False))

    def test_false_success_text_when_structured_result_status_is_error_is_incomplete(self):
        script = "import json, pathlib\npathlib.Path('artifact.txt').write_text('ok\\n', encoding='utf-8')\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c1', 'status': 'ERROR', 'response': 'SUCCESS!'}}))\n"
        res, payload = _run_fake_worker(script)
        self.assertEqual((res.returncode, payload["status"], payload["completed"]), (1, "failed", False))

    def test_permission_denial_in_stream_or_diagnostics_is_classified_permission_denied(self):
        script = (
            "import json, pathlib, sys\n"
            "pathlib.Path('artifact.txt').write_text('partial\\n', encoding='utf-8')\n"
            "sys.stderr.write('tool run_command denied by sandbox policy: permission denied\\n')\n"
            "print(json.dumps({'event': 'step_update', 'step_update': {'step_index': 1, 'state': 'ERROR', 'step_type': 'tool_call', 'error': 'permission denied'}}))\n"
            "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c1', 'status': 'SUCCESS', 'response': 'Done'}}))\n"
        )
        res, payload = _run_fake_worker(script)
        self.assertEqual((res.returncode, payload["status"], payload["completed"]), (1, "permission-denied", False))

    def test_timeout_terminates_owned_worker_processes_preserves_output_and_reports_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = Path(tmp) / "grandchild.pid"
            script = (
                "import json, subprocess, sys, time\n"
                f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
                "print(json.dumps({'event': 'init', 'conversation_id': 'c-timeout'}), flush=True)\n"
                "sys.stderr.write('partial stderr before timeout\\n'); sys.stderr.flush(); time.sleep(60)\n"
            )
            started = time.monotonic()
            res, payload = _run_fake_worker(script, task_id="task-timeout", time_limit="2s")
            self.assertEqual((res.returncode, payload["status"], payload["completed"], payload["evidence"]["timed_out"]), (1, "timed-out", False, True))
            self.assertLess(time.monotonic() - started, 8.0)
            self.assertIn("c-timeout", payload["_stdout_text"])
            self.assertIn("partial stderr before timeout", payload["_stderr_text"])
            grandchild_pid = int(pid_file.read_text(encoding="utf-8").strip())
            deadline, alive = time.monotonic() + 2.0, True
            while time.monotonic() < deadline:
                try:
                    os.kill(grandchild_pid, 0)
                except ProcessLookupError:
                    alive = False; break
                status_file = Path(f"/proc/{grandchild_pid}/status")
                if status_file.exists() and "State:\tZ" in status_file.read_text(encoding="utf-8", errors="ignore"):
                    alive = False; break
                time.sleep(0.05)
            self.assertFalse(alive, f"grandchild process {grandchild_pid} should be terminated")

    def test_absent_or_null_telemetry_and_cost_provenance(self):
        script_null = "import json, pathlib\npathlib.Path('artifact.txt').write_text('ok\\n', encoding='utf-8')\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c-notel', 'status': 'SUCCESS', 'response': 'Done', 'usage': {'input_tokens': None, 'total_tokens': None}}}))\n"
        res, payload = _run_fake_worker(script_null, task_id="task-no-telemetry")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        usage, cost = payload["measurements"]["usage"], payload["measurements"]["cost"]
        self.assertEqual((usage["state"], usage["input_tokens"], usage["output_tokens"], usage["total_tokens"], cost["state"], cost["usd"]), ("unavailable", None, None, None, "unavailable", None))
        script_est = "import json, pathlib\npathlib.Path('artifact.txt').write_text('ok\\n', encoding='utf-8')\nprint(json.dumps({'event': 'result', 'result': {'conversation_id': 'c-est', 'status': 'SUCCESS', 'response': 'Done', 'usage': {'input_tokens': 1000000, 'output_tokens': 500000, 'thinking_tokens': 0, 'cache_read_tokens': 0, 'total_tokens': 1500000}}}))\n"
        res2, payload2 = _run_fake_worker(script_est, "--input-rate-usd-per-1m", "0.50", "--output-rate-usd-per-1m", "1.50")
        self.assertEqual((res2.returncode, payload2["measurements"]["cost"]["state"]), (0, "estimated"))
        self.assertAlmostEqual(payload2["measurements"]["cost"]["usd"], 1.25)
        spec = worker_module.WorkerSpec(task_id="t1", prompt="p", artifact="a.txt", time_limit_seconds=10)
        meas = worker_module._extract_measurements({"cost_usd": 0.042, "usage": {"input_tokens": 10, "output_tokens": 5}}, 100, spec)
        self.assertEqual((meas["cost"]["state"], meas["cost"]["usd"]), ("reported", 0.042))

    def test_worker_excludes_production_credentials_and_records_explicit_boundary_probes(self):
        script = (
            "import json, os, pathlib\n"
            "leaked = [k for k in os.environ if k in ('PRODUCTION_DATABASE_URL', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'GITHUB_TOKEN', 'ASANA_ACCESS_TOKEN')]\n"
            "aws_exists = (pathlib.Path.home() / '.aws' / 'credentials').exists()\n"
            "pathlib.Path('artifact.txt').write_text(f'LEAKED={\",\".join(leaked)} AWS={aws_exists}\\n', encoding='utf-8')\n"
            "print(json.dumps({'event': 'result', 'result': {'conversation_id': 'c-safe', 'status': 'SUCCESS', 'response': 'Done'}}))\n"
        )
        env_with_secrets = dict(os.environ, PRODUCTION_DATABASE_URL="postgres://prod:secret@db.internal/prod", AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI", OPENAI_API_KEY="sk-prod-12345", GITHUB_TOKEN="ghp_prodtoken123", ASANA_ACCESS_TOKEN="1/12345:prodasana")
        res, payload = _run_fake_worker(script, task_id="task-safety", env_override=env_with_secrets)
        self.assertEqual((res.returncode, payload["_stored_artifact_text"]), (0, "LEAKED= AWS=False\n"))
        safety = payload["safety"]
        self.assertFalse(safety["bypass_permissions_used"])
        self.assertTrue({"PRODUCTION_DATABASE_URL", "AWS_SECRET_ACCESS_KEY"}.issubset(safety["stripped_env_keys"]))
        probes = {probe["name"]: probe for probe in safety["probes"]}
        self.assertTrue(probes["forbidden_credential_access"]["denied"] and probes["external_effect_restriction"]["denied"])

    def test_global_permission_bypass_and_platform_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "ran"
            res, _ = _run_fake_worker(f"import pathlib; pathlib.Path({str(marker)!r}).write_text('ran')\n", "--agy-arg=--dangerously-skip-permissions")
            self.assertEqual((res.returncode, marker.exists()), (2, False))
            self.assertIn("bypass", res.stderr.lower())
        for system_name, release, machine in (("Darwin", "24.1.0", "arm64"), ("Linux", "6.12.0", "x86_64")):
            with self.subTest(system=system_name), mock.patch("platform.system", return_value=system_name), mock.patch("platform.release", return_value=release), mock.patch("platform.machine", return_value=machine):
                info = worker_module.platform_info()
                self.assertEqual((info["system"], info["release"], info["machine"], info["supported"]), (system_name, release, machine, True))
        with mock.patch("platform.system", return_value="Windows"):
            info = worker_module.platform_info()
            self.assertFalse(info["supported"])
            with self.assertRaises(UsageError):
                worker_module._validate_spec(worker_module.WorkerSpec(task_id="t1", prompt="p", artifact="a.txt", time_limit_seconds=10), info)

    @unittest.skipUnless(os.environ.get("TURBO_LIVE_AGY") == "1", "requires TURBO_LIVE_AGY=1 and authenticated agy")
    def test_live_authenticated_agy_worker_completes_disposable_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, home = make_repo(root), home_dir(root)
            config(repo, home)
            result = cli(repo, home, "worker", "--task-id", "live-smoke-1", "--prompt", "Create a file named disposable_result.txt in the current directory containing the exact line: LIVE_WORKER_OK", "--artifact", "disposable_result.txt", "--time-limit", "60s", "--agy-arg=--model", "--agy-arg=gemini-3.8-flash-low", "--json")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["completed"])
            self.assertIn("LIVE_WORKER_OK", Path(payload["artifact"]["stored_path"]).read_text(encoding="utf-8"))
            self.assertEqual((payload["measurements"]["usage"]["state"], payload["measurements"]["cost"]["state"]), ("reported", "unavailable"))


if __name__ == "__main__":
    unittest.main()
