"""Bounded, isolated Antigravity CLI (agy) worker execution."""

from __future__ import annotations

import hashlib, json, math, os, platform, re, shutil, socket, subprocess, sys, time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from factory import config as config_module, gitio, runner, sandbox
from factory.config import now
from factory.errors import UsageError
from factory.limits import parse_duration
from factory.paths import RuntimePaths, atomic_json, safe_dir, write_evidence
from factory.sandbox import SandboxUnavailableError

FACTORY_ROOT = Path(__file__).resolve().parents[1]
TASK_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SUPPORTED_PLATFORMS = frozenset({"Linux", "Darwin"})
FORBIDDEN_BYPASS_FLAGS = frozenset({"--dangerously-skip-permissions", "--no-sandbox", "--bypass-sandbox"})
FORBIDDEN_ENV_EXACT = frozenset({
    "ASANA_ACCESS_TOKEN", "ASANA_PAT", "ASANA_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "ANTHROPIC_API_KEY", "DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "OPENAI_API_KEY",
    "PRODUCTION_DATABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "SLACK_BOT_TOKEN", "TURBO_GITHUB_TOKEN",
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND",
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
})
FORBIDDEN_ENV_PATTERNS = (
    re.compile(r"(^|_)(PROD|PRODUCTION)(_|$)", re.IGNORECASE),
    re.compile(r"(^|_)(SECRET|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|API_KEY|PAT|TOKEN)(_|$)", re.IGNORECASE),
    re.compile(r"^(AWS_|GITHUB_|GH_|ASANA_|STRIPE_|SLACK_|TWILIO_|SENDGRID_|SSH_|GIT_CONFIG_)", re.IGNORECASE),
    re.compile(r"^TURBO_.*_URL$", re.IGNORECASE),
)
DENIAL_MARKERS = ("permission denied", "denied by sandbox", "tool denied", "permission_denied", "access denied")
TOKEN_KEYS = ("input_tokens", "output_tokens", "thinking_tokens", "cache_read_tokens", "total_tokens")
REQUIRED_SAFETY_PROBES = ("forbidden_credential_access", "external_effect_restriction")


@dataclass(frozen=True, slots=True)
class RateCard:
    input_usd_per_1m: float
    output_usd_per_1m: float


@dataclass(frozen=True, slots=True)
class WorkerSpec:
    task_id: str; prompt: str; artifact: str; time_limit_seconds: int
    agy_bin: str = "agy"; agy_args: tuple[str, ...] = (); rates: RateCard | None = None


@dataclass(frozen=True, slots=True)
class WorkerResult:
    schema: int; task_id: str; status: str; completed: bool
    platform: dict[str, Any]; host_version: str; factory_revision: str
    artifact: dict[str, Any]; safety: dict[str, Any]; measurements: dict[str, Any]; evidence: dict[str, Any]; recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def platform_info() -> dict[str, Any]:
    s = platform.system()
    return {"system": s, "release": platform.release(), "machine": platform.machine(), "supported": s in SUPPORTED_PLATFORMS}


def _validate_spec(spec: WorkerSpec, plat: dict[str, Any]) -> None:
    if not plat["supported"]:
        raise UsageError(f"unsupported worker platform {plat['system']!r}; supported: macOS (Darwin) and Linux")
    if TASK_ID_PATTERN.fullmatch(spec.task_id) is None:
        raise UsageError(f"invalid --task-id {spec.task_id!r}; use 1..64 alphanumeric, '.', '_', or '-' characters")
    if not spec.prompt.strip():
        raise UsageError("worker needs a non-empty --prompt")
    if (issue := config_module.protected_entry_issue(spec.artifact)) is not None:
        raise UsageError(f"--artifact {spec.artifact!r} {issue}")
    if spec.time_limit_seconds <= 0:
        raise UsageError("worker --time-limit must be greater than zero")
    if not spec.agy_bin.strip():
        raise UsageError("worker --agy-bin must not be blank")
    if spec.rates is not None:
        for label, rate in (("--input-rate-usd-per-1m", spec.rates.input_usd_per_1m), ("--output-rate-usd-per-1m", spec.rates.output_usd_per_1m)):
            if not math.isfinite(rate) or rate < 0:
                raise UsageError(f"{label} must be a finite non-negative number")
    for token in (spec.agy_bin, *spec.agy_args):
        lower = token.strip().lower()
        if any(lower == flag or lower.startswith(f"{flag}=") for flag in FORBIDDEN_BYPASS_FLAGS):
            raise UsageError(f"global permission bypass flag {token!r} is forbidden by factory policy")


def validate_execution_options(
    plat: dict[str, Any], *, time_limit_seconds: int, agy_bin: str = "agy", agy_args: tuple[str, ...] = (), rates: RateCard | None = None
) -> None:
    _validate_spec(WorkerSpec(task_id="deliver", prompt="deliver", artifact="README.md", time_limit_seconds=time_limit_seconds, agy_bin=agy_bin, agy_args=agy_args, rates=rates), plat)


def _prepare_isolated_home(worker_dir: Path, source_home: Path, *, root: Path | None = None, home_root: Path | None = None) -> Path:
    base_root = root or home_root or worker_dir.parents[1]
    isolated_home = safe_dir(worker_dir / "home", create=True, root=base_root)
    agy_src = source_home / ".gemini" / "antigravity-cli"
    if agy_src.is_dir() and not agy_src.is_symlink():
        agy_dst = safe_dir(isolated_home / ".gemini" / "antigravity-cli", create=True, root=base_root)
        for name in ("jetski_state.pbtxt", "installation_id", "settings.json"):
            candidate = agy_src / name
            if candidate.is_file() and not candidate.is_symlink():
                shutil.copy2(candidate, agy_dst / name)
                os.chmod(agy_dst / name, 0o600)
    keychains_src = source_home / "Library" / "Keychains"
    if platform.system() == "Darwin" and keychains_src.is_dir() and not keychains_src.is_symlink():
        keychains_dst = safe_dir(isolated_home / "Library", create=True, root=base_root) / "Keychains"
        if not keychains_dst.exists() and not keychains_dst.is_symlink():
            keychains_dst.symlink_to(keychains_src)
    return isolated_home


def _sanitized_worker_env(source_env: dict[str, str], disposable_root: Path, isolated_home: Path) -> tuple[dict[str, str], list[str]]:
    clean: dict[str, str] = {}
    stripped: list[str] = []
    for key, value in source_env.items():
        if key.upper() in FORBIDDEN_ENV_EXACT or any(p.search(key.upper()) for p in FORBIDDEN_ENV_PATTERNS):
            stripped.append(key)
        else:
            clean[key] = value
    tmp_dir = str(isolated_home / ".tmp")
    clean.update({
        "HOME": str(isolated_home), "TMPDIR": tmp_dir, "TMP": tmp_dir, "TEMP": tmp_dir,
        "AWS_CONFIG_FILE": str(isolated_home / "nonexistent-aws-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(isolated_home / "nonexistent-aws-credentials"),
        "GH_CONFIG_DIR": str(isolated_home / "nonexistent-gh-config"), "GIT_CONFIG_GLOBAL": str(isolated_home / "nonexistent-gitconfig"),
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false", "SSH_AUTH_SOCK": "", "GIT_SSH_COMMAND": "false", "GIT_ALLOW_PROTOCOL": "none",
        "NETRC": str(isolated_home / "nonexistent-netrc"), "PYTHONDONTWRITEBYTECODE": "1", "GIT_TERMINAL_PROMPT": "0",
        "TURBO_EXECUTION_BOUNDARY": "disposable-only", "TURBO_DISPOSABLE_SERVICES_ONLY": "1", "TURBO_DISPOSABLE_ROOT": str(disposable_root),
    })
    return clean, sorted(stripped)


def _git_checkout_step(cwd: Path, deadline: float | None, *args: str) -> str:
    timeout_s = None if deadline is None else max(0.0, deadline - time.monotonic())
    if timeout_s is not None and timeout_s <= 0:
        raise TimeoutError("isolated git checkout timed out")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null"}
    try:
        proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=False, shell=False, env=env, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("isolated git checkout timed out") from exc
    out = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        raise UsageError(f"cannot prepare isolated git checkout ({' '.join(args)}): {out}")
    return out


def prepare_isolated_git_checkout(source_repo: Path, worktree_dir: Path, base_ref: str = "HEAD", *, deadline: float | None = None) -> str:
    target_sha = _git_checkout_step(source_repo, deadline, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
    if worktree_dir.exists():
        shutil.rmtree(worktree_dir)
    worktree_dir.mkdir(parents=True, exist_ok=True)
    for step in (
        ("init", "-q"),
        ("config", "user.name", "Turbo Builder"),
        ("config", "user.email", "builder@example.invalid"),
        ("config", "commit.gpgsign", "false"),
        ("fetch", "-q", "--no-tags", str(source_repo), target_sha),
        ("checkout", "-q", "--detach", "FETCH_HEAD"),
    ):
        _git_checkout_step(worktree_dir, deadline, *step)
    (worktree_dir / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
    return target_sha


def _run_probe(
    name: str, stem: str, script: str, env: dict[str, str], cwd: Path, worker_dir: Path,
    home: Path, *, allow_network: bool, deadline: float | None = None,
) -> dict[str, Any]:
    rem = 10.0 if deadline is None else deadline - time.monotonic()
    if rem <= 0:
        raise TimeoutError(f"safety probe {name} timed out")
    try:
        code, out_s, err_s, _, timed_out = _execute_stream(
            cwd, (sys.executable, "-c", script), env, max(1, min(10, int(math.ceil(rem)))), allow_network=allow_network
        )
    except SandboxUnavailableError as exc:
        out = f"[factory] required OS execution sandbox unavailable: {exc}\n"
        path = write_evidence(worker_dir, stem, out, home)
        return {"name": name, "attempted": True, "denied": False, "exit": 0, "output_path": str(path), "output_sha256": runner.digest_text(out), "detail": out.strip()}
    if timed_out or (deadline is not None and time.monotonic() >= deadline):
        raise TimeoutError(f"safety probe {name} timed out")
    out = (out_s + err_s).strip() + "\n"
    path = write_evidence(worker_dir, stem, out, home)
    return {"name": name, "attempted": True, "denied": code != 0, "exit": code, "output_path": str(path), "output_sha256": runner.digest_text(out), "detail": out.strip()}


def _run_safety_probes(worker_env: dict[str, str], worktree_dir: Path, worker_dir: Path, home: Path, *, deadline: float | None = None) -> list[dict[str, Any]]:
    sentinel = worker_dir / "probe-controller-secret.sentinel"
    sentinel.write_text("DISPOSABLE_CREDENTIAL_SENTINEL\n", encoding="utf-8")
    os.chmod(sentinel, 0o600)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    cred_script = (
        "import os, pathlib, shutil, subprocess, sys\n"
        "forbidden_env = ('PRODUCTION_DATABASE_URL', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'GITHUB_TOKEN', 'ASANA_ACCESS_TOKEN', 'TURBO_GITHUB_TOKEN')\n"
        "present_env = [k for k in forbidden_env if os.environ.get(k)]\n"
        "h = pathlib.Path.home()\n"
        "present_files = [str(p) for p in (h / '.aws/credentials', h / '.config/gh/hosts.yml', h / '.netrc') if p.exists()]\n"
        "cat_bin = shutil.which('cat') or '/bin/cat'\n"
        f"sentinel = {str(sentinel)!r}\n"
        "os.environ.clear()\n"
        "py_r = subprocess.run([sys.executable, '-I', '-S', '-c', f'open({sentinel!r}, \"rb\").read()'], capture_output=True).returncode != 0\n"
        "py_w = subprocess.run([sys.executable, '-I', '-S', '-c', f'open({sentinel!r}, \"wb\").write(b\"x\")'], capture_output=True).returncode != 0\n"
        "cat_r = subprocess.run([cat_bin, sentinel], capture_output=True).returncode != 0\n"
        "if not present_env and not present_files and py_r and py_w and cat_r:\n"
        "    sys.stderr.write('DENIED: forbidden env credentials, home credential stores, and absolute-path controller sentinel access excluded\\n'); sys.exit(1)\n"
        "print('ALLOWED'); sys.exit(0)\n"
    )
    ext_script = (
        "import os, pathlib, shutil, subprocess, sys\n"
        "root = pathlib.Path(os.environ.get('TURBO_DISPOSABLE_ROOT', '')).resolve()\n"
        "confined = pathlib.Path.cwd().resolve() == root and pathlib.Path.home().resolve().is_relative_to(root.parent)\n"
        "git_bin = shutil.which('git') or '/usr/bin/git'\n"
        "remotes = subprocess.run([git_bin, 'remote'], capture_output=True, text=True, timeout=2).stdout.strip()\n"
        "ssh_isolated = not os.environ.get('SSH_AUTH_SOCK') and os.environ.get('GIT_ALLOW_PROTOCOL') == 'none'\n"
        f"sentinel, port = {str(sentinel)!r}, {port}\n"
        "os.environ.clear()\n"
        "py_net = subprocess.run([sys.executable, '-I', '-S', '-c', f'import socket; s = socket.socket(); s.settimeout(1.0); s.connect((\"127.0.0.1\", {port}))'], capture_output=True).returncode != 0\n"
        "bin_net = subprocess.run([git_bin, 'ls-remote', f'http://127.0.0.1:{port}/probe.git'], capture_output=True, timeout=3).returncode != 0\n"
        "fs_denied = subprocess.run([sys.executable, '-I', '-S', '-c', f'open({sentinel!r}, \"rb\").read()'], capture_output=True).returncode != 0\n"
        "if confined and fs_denied and not remotes and py_net and bin_net and ssh_isolated:\n"
        "    sys.stderr.write('DENIED: OS filesystem, remotes, ssh, and network effects failed closed\\n'); sys.exit(1)\n"
        "print('ALLOWED'); sys.exit(0)\n"
    )
    try:
        return [
            _run_probe("forbidden_credential_access", "probe-credentials", cred_script, worker_env, worktree_dir, worker_dir, home, allow_network=True, deadline=deadline),
            _run_probe("external_effect_restriction", "probe-external-effects", ext_script, worker_env, worktree_dir, worker_dir, home, allow_network=False, deadline=deadline),
        ]
    finally:
        listener.close()
        sentinel.unlink(missing_ok=True)


def probes_passed(probes: list[dict[str, Any]]) -> bool:
    if not isinstance(probes, list) or len(probes) != len(REQUIRED_SAFETY_PROBES):
        return False
    by_name = {str(p.get("name")): p for p in probes if isinstance(p, dict)}
    return set(by_name.keys()) == set(REQUIRED_SAFETY_PROBES) and all(
        bool(by_name[name].get("denied")) and bool(by_name[name].get("attempted", True)) for name in REQUIRED_SAFETY_PROBES
    )


def _detect_host_version(agy_bin: str, agy_args: tuple[str, ...], env: dict[str, str], *, timeout_s: float = 10.0) -> str:
    try:
        res = subprocess.run([agy_bin, *agy_args, "--version"], capture_output=True, text=True, timeout=timeout_s, shell=False, env=env)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("agy --version timed out") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise UsageError(f"cannot query agy host version: {exc}") from exc
    if res.returncode != 0 or not res.stdout.strip():
        raise UsageError(f"agy --version failed (exit {res.returncode}): {res.stderr.strip()}")
    return res.stdout.strip()


def _parse_stream_events(stdout_text: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None, str | None]:
    events: list[dict[str, Any]] = []
    final_result: dict[str, Any] | None = None
    lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    if not lines:
        return [], None, "empty structured stdout"
    for line in lines:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            return events, None, f"malformed JSON line in stdout: {exc}"
        if not isinstance(parsed, dict):
            return events, None, "structured stdout line must be a JSON object"
        events.append(parsed)
        if parsed.get("event") == "result" and isinstance(parsed.get("result"), dict):
            final_result = parsed["result"]
        elif "status" in parsed and "conversation_id" in parsed and "event" not in parsed:
            final_result = parsed
    return (events, None, "missing terminal result object in structured stdout") if final_result is None else (events, final_result, None)


def _has_permission_denial(events: list[dict[str, Any]], final_result: dict[str, Any] | None, stderr_text: str) -> bool:
    if any(m in stderr_text.lower() for m in DENIAL_MARKERS):
        return True
    for event in events:
        step = event.get("step_update")
        if isinstance(step, dict) and (str(step.get("state") or "").upper() in ("DENIED", "REJECTED", "PERMISSION_DENIED") or any(m in str(step.get("error") or "").lower() for m in DENIAL_MARKERS)):
            return True
    return isinstance(final_result, dict) and any(m in str(final_result.get("error") or "").lower() for m in DENIAL_MARKERS)


def _extract_measurements(final_result: dict[str, Any] | None, elapsed_ms: int, spec: WorkerSpec | RateCard | None = None) -> dict[str, Any]:
    rates = spec.rates if isinstance(spec, WorkerSpec) else spec
    raw_usage = final_result.get("usage") if isinstance(final_result, dict) else None
    has_tokens = isinstance(raw_usage, dict) and any(isinstance(raw_usage.get(k), int) and not isinstance(raw_usage.get(k), bool) for k in TOKEN_KEYS)
    if has_tokens and isinstance(raw_usage, dict):
        usage: dict[str, Any] = {"state": "reported", "provenance": "reported by agy worker telemetry", **{k: raw_usage.get(k) for k in TOKEN_KEYS}}
    else:
        usage = {"state": "unavailable", "provenance": "unavailable; missing from worker output", **{k: None for k in TOKEN_KEYS}}
    reported_usd = None
    if isinstance(final_result, dict):
        for candidate in (final_result.get("cost_usd"), raw_usage.get("cost_usd") if isinstance(raw_usage, dict) else None):
            if isinstance(candidate, (int, float)) and not isinstance(candidate, bool) and math.isfinite(candidate) and candidate >= 0:
                reported_usd = float(candidate)
                break
    in_tok, out_tok = usage["input_tokens"], usage["output_tokens"]
    if reported_usd is not None:
        cost = {"state": "reported", "usd": reported_usd, "provenance": "reported by agy worker telemetry"}
    elif usage["state"] == "reported" and isinstance(in_tok, int) and isinstance(out_tok, int) and rates is not None:
        usd = round((in_tok / 1_000_000.0) * rates.input_usd_per_1m + (out_tok / 1_000_000.0) * rates.output_usd_per_1m, 6)
        cost = {"state": "estimated", "usd": usd, "input_rate_usd_per_1m": rates.input_usd_per_1m, "output_rate_usd_per_1m": rates.output_usd_per_1m, "provenance": "estimated from reported token usage and operator-supplied per-1M rates"}
    else:
        cost = {"state": "unavailable", "usd": None, "input_rate_usd_per_1m": rates.input_usd_per_1m if rates else None, "output_rate_usd_per_1m": rates.output_usd_per_1m if rates else None, "provenance": "unavailable; missing reported token usage or per-1M rate (unavailable is not zero)"}
    return {"elapsed_ms": elapsed_ms, "reported_duration_seconds": final_result.get("duration_seconds") if isinstance(final_result, dict) else None, "usage": usage, "cost": cost}


def _execute_stream(
    cwd: Path, argv: tuple[str, ...], env: dict[str, str], timeout_s: int,
    *, isolated_home: Path | None = None, allow_network: bool = True,
) -> tuple[int, str, str, int, bool]:
    home_dir = isolated_home or Path(env.get("HOME") or cwd)
    exec_argv, preexec = sandbox.prepare_sandboxed_exec(cwd, home_dir, argv, env, allow_network=allow_network)
    started = time.monotonic()
    sandbox.set_controller_dumpable(False)
    try:
        try:
            process = subprocess.Popen(
                list(exec_argv), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, env=env, start_new_session=True, preexec_fn=preexec,
            )
        except subprocess.SubprocessError as exc:
            raise SandboxUnavailableError(f"failed to initialize OS execution sandbox: {exc}") from exc
        timed_out = False
        try:
            stdout_b, stderr_b = process.communicate(timeout=timeout_s)
            exit_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            runner._kill_group(process)
            partial_out, partial_err = (exc.stdout if isinstance(exc.stdout, bytes) else b""), (exc.stderr if isinstance(exc.stderr, bytes) else b"")
            try:
                rem_out, rem_err = process.communicate(timeout=5)
                stdout_b, stderr_b = partial_out + rem_out, partial_err + rem_err
            except subprocess.TimeoutExpired as exc2:
                stdout_b = partial_out + (exc2.stdout if isinstance(exc2.stdout, bytes) else b"")
                stderr_b = partial_err + (exc2.stderr if isinstance(exc2.stderr, bytes) else b"")
            exit_code = 124
    finally:
        sandbox.set_controller_dumpable(True)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    stdout_text = stdout_b.decode("utf-8", "replace")
    stderr_text = stderr_b.decode("utf-8", "replace") + (f"\n[factory] worker timed out after {timeout_s}s\n" if timed_out else "")
    return exit_code, stdout_text, stderr_text, elapsed_ms, timed_out


prepare_isolated_home, sanitized_env, run_safety_probes = _prepare_isolated_home, _sanitized_worker_env, _run_safety_probes
detect_host_version, parse_stream_events, has_permission_denial = _detect_host_version, _parse_stream_events, _has_permission_denial
extract_measurements, execute_stream = _extract_measurements, _execute_stream


def run_worker(paths: RuntimePaths, spec: WorkerSpec) -> WorkerResult:
    plat = platform_info()
    _validate_spec(spec, plat)
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    worker_dir = safe_dir(paths.home / "workers" / spec.task_id, create=True, root=paths.home)
    worktree_dir = worker_dir / "worktree"
    isolated_home = _prepare_isolated_home(worker_dir, Path.home())
    worker_env, stripped_keys = _sanitized_worker_env(dict(os.environ), worktree_dir, isolated_home)
    host_version = _detect_host_version(spec.agy_bin, spec.agy_args, worker_env)
    rev_res = gitio.git(FACTORY_ROOT, "rev-parse", "HEAD")
    factory_rev = rev_res.output if rev_res.ok else "unknown"
    prepare_isolated_git_checkout(paths.repo, worktree_dir, "HEAD")
    try:
        probes = run_safety_probes(worker_env, worktree_dir, worker_dir, paths.home)
        argv = (spec.agy_bin, *spec.agy_args, "--print", spec.prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
        sandbox_ok = probes_passed(probes)
        if not sandbox_ok:
            exit_code, stdout_text, stderr_text, elapsed_ms, timed_out = 1, "", "[factory] safety probes failed; worker execution aborted before start\n", 0, False
        else:
            try:
                exit_code, stdout_text, stderr_text, elapsed_ms, timed_out = _execute_stream(worktree_dir, argv, worker_env, spec.time_limit_seconds, isolated_home=isolated_home)
            except SandboxUnavailableError as exc:
                sandbox_ok = False
                exit_code, stdout_text, stderr_text, elapsed_ms, timed_out = 1, "", f"[factory] OS execution sandbox unavailable: {exc}\n", 0, False
        stdout_path, stderr_path = write_evidence(worker_dir, "stdout", stdout_text, paths.home), write_evidence(worker_dir, "stderr", stderr_text, paths.home)
        events, final_result, parse_error = _parse_stream_events(stdout_text)
        candidate = worktree_dir / spec.artifact
        artifact_info: dict[str, Any] = {"relative_path": spec.artifact, "stored_path": None, "sha256": None, "present": False}
        if candidate.exists() and not candidate.is_symlink() and candidate.is_file() and candidate.resolve().is_relative_to(worktree_dir.resolve()):
            data = candidate.read_bytes()
            stored = worker_dir / "artifact" / spec.artifact
            safe_dir(stored.parent, create=True, root=paths.home)
            stored.write_bytes(data)
            os.chmod(stored, 0o600)
            artifact_info = {"relative_path": spec.artifact, "stored_path": str(stored), "sha256": hashlib.sha256(data).hexdigest(), "present": True}
        if not sandbox_ok: status = "unsafe-environment"
        elif timed_out: status = "timed-out"
        elif parse_error is not None: status = "malformed-output"
        elif _has_permission_denial(events, final_result, stderr_text): status = "permission-denied"
        elif exit_code != 0 or not isinstance(final_result, dict) or final_result.get("status") != "SUCCESS": status = "failed"
        elif not artifact_info["present"]: status = "missing-artifact"
        else: status = "completed"
        record = WorkerResult(
            schema=1, task_id=spec.task_id, status=status, completed=(status == "completed"),
            platform=plat, host_version=host_version, factory_revision=factory_rev, artifact=artifact_info,
            safety={"sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False, "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": probes},
            measurements=_extract_measurements(final_result, elapsed_ms, spec),
            evidence={"argv": list(argv), "exit": exit_code, "timed_out": timed_out, "parse_error": parse_error, "result_status": final_result.get("status") if isinstance(final_result, dict) else None, "stdout_path": str(stdout_path), "stdout_sha256": runner.digest_text(stdout_text), "stderr_path": str(stderr_path), "stderr_sha256": runner.digest_text(stderr_text)},
            recorded_at=now(),
        )
        atomic_json(worker_dir / "record.json", record.to_dict(), paths.home)
        return record
    finally:
        shutil.rmtree(worktree_dir, ignore_errors=True)


def run_from_cli(paths: RuntimePaths, args: object) -> WorkerResult:
    in_rate, out_rate = getattr(args, "input_rate_usd_per_1m", None), getattr(args, "output_rate_usd_per_1m", None)
    if (in_rate is None) != (out_rate is None):
        raise UsageError("worker requires both --input-rate-usd-per-1m and --output-rate-usd-per-1m when estimating cost")
    rates = RateCard(float(in_rate), float(out_rate)) if in_rate is not None and out_rate is not None else None
    spec = WorkerSpec(
        task_id=str(getattr(args, "task_id")).strip(), prompt=str(getattr(args, "prompt")),
        artifact=str(getattr(args, "artifact")).strip(), time_limit_seconds=parse_duration(str(getattr(args, "time_limit"))),
        agy_bin=str(getattr(args, "agy_bin") or "agy"), agy_args=tuple(getattr(args, "agy_arg") or ()), rates=rates,
    )
    return run_worker(paths, spec)
