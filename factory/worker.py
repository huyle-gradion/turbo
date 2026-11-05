"""Bounded, isolated Antigravity CLI (agy) worker execution."""

from __future__ import annotations

import hashlib, json, math, os, platform, re, shutil, subprocess, sys, time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from factory import config as config_module, gitio, runner
from factory.config import now
from factory.errors import UsageError
from factory.limits import parse_duration
from factory.paths import RuntimePaths, atomic_json, safe_dir, write_evidence

FACTORY_ROOT = Path(__file__).resolve().parents[1]
TASK_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SUPPORTED_PLATFORMS = frozenset({"Linux", "Darwin"})
FORBIDDEN_BYPASS_FLAGS = frozenset({"--dangerously-skip-permissions", "--no-sandbox", "--bypass-sandbox"})
FORBIDDEN_ENV_EXACT = frozenset({
    "ASANA_ACCESS_TOKEN", "ASANA_PAT", "ASANA_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "ANTHROPIC_API_KEY", "DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "OPENAI_API_KEY",
    "PRODUCTION_DATABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "SLACK_BOT_TOKEN",
})
FORBIDDEN_ENV_PATTERNS = (
    re.compile(r"(^|_)(PROD|PRODUCTION)(_|$)", re.IGNORECASE),
    re.compile(r"(^|_)(SECRET|PASSWORD|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|API_KEY|PAT)(_|$)", re.IGNORECASE),
    re.compile(r"^(AWS_|GITHUB_|GH_|ASANA_|STRIPE_|SLACK_|TWILIO_|SENDGRID_)", re.IGNORECASE),
)
DENIAL_MARKERS = ("permission denied", "denied by sandbox", "tool denied", "permission_denied", "access denied")
TOKEN_KEYS = ("input_tokens", "output_tokens", "thinking_tokens", "cache_read_tokens", "total_tokens")


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


def _prepare_isolated_home(worker_dir: Path, source_home: Path) -> Path:
    isolated_home = safe_dir(worker_dir / "home", create=True, root=worker_dir.parents[1])
    agy_src = source_home / ".gemini" / "antigravity-cli"
    if agy_src.is_dir() and not agy_src.is_symlink():
        agy_dst = safe_dir(isolated_home / ".gemini" / "antigravity-cli", create=True, root=worker_dir.parents[1])
        for name in ("jetski_state.pbtxt", "installation_id", "settings.json"):
            candidate = agy_src / name
            if candidate.is_file() and not candidate.is_symlink():
                shutil.copy2(candidate, agy_dst / name)
                os.chmod(agy_dst / name, 0o600)
    return isolated_home


def _sanitized_worker_env(source_env: dict[str, str], disposable_root: Path, isolated_home: Path) -> tuple[dict[str, str], list[str]]:
    clean: dict[str, str] = {}
    stripped: list[str] = []
    for key, value in source_env.items():
        if key.upper() in FORBIDDEN_ENV_EXACT or any(p.search(key.upper()) for p in FORBIDDEN_ENV_PATTERNS):
            stripped.append(key)
        else:
            clean[key] = value
    clean.update({
        "HOME": str(isolated_home), "AWS_CONFIG_FILE": str(isolated_home / "nonexistent-aws-config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(isolated_home / "nonexistent-aws-credentials"),
        "GH_CONFIG_DIR": str(isolated_home / "nonexistent-gh-config"), "GIT_CONFIG_GLOBAL": str(isolated_home / "nonexistent-gitconfig"),
        "NETRC": str(isolated_home / "nonexistent-netrc"), "PYTHONDONTWRITEBYTECODE": "1", "GIT_TERMINAL_PROMPT": "0",
        "TURBO_EXECUTION_BOUNDARY": "disposable-only", "TURBO_DISPOSABLE_SERVICES_ONLY": "1", "TURBO_DISPOSABLE_ROOT": str(disposable_root),
    })
    return clean, sorted(stripped)


def _run_probe(name: str, stem: str, script: str, env: dict[str, str], cwd: Path, worker_dir: Path, home: Path) -> dict[str, Any]:
    proc = subprocess.run([sys.executable, "-c", script], cwd=cwd, env=env, capture_output=True, text=True, timeout=10, shell=False)
    out = (proc.stdout + proc.stderr).strip() + "\n"
    path = write_evidence(worker_dir, stem, out, home)
    return {"name": name, "denied": proc.returncode != 0, "exit": proc.returncode, "output_path": str(path), "output_sha256": runner.digest_text(out), "detail": out.strip()}


def _run_safety_probes(worker_env: dict[str, str], worktree_dir: Path, worker_dir: Path, home: Path) -> list[dict[str, Any]]:
    cred_script = (
        "import os, pathlib, sys\n"
        "forbidden_env = ('PRODUCTION_DATABASE_URL', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'GITHUB_TOKEN', 'ASANA_ACCESS_TOKEN')\n"
        "present_env = [k for k in forbidden_env if os.environ.get(k)]\n"
        "h = pathlib.Path.home()\n"
        "present_files = [str(p) for p in (h / '.aws/credentials', h / '.config/gh/hosts.yml', h / '.netrc') if p.exists()]\n"
        "if not present_env and not present_files:\n"
        "    sys.stderr.write('DENIED: forbidden env credentials and home credential stores excluded\\n'); sys.exit(1)\n"
        "print('ALLOWED: ' + ','.join(present_env + present_files)); sys.exit(0)\n"
    )
    ext_script = (
        "import os, pathlib, subprocess, sys\n"
        "root = pathlib.Path(os.environ.get('TURBO_DISPOSABLE_ROOT', '')).resolve()\n"
        "confined = pathlib.Path.cwd().resolve() == root and pathlib.Path.home().resolve().is_relative_to(root.parent)\n"
        "try: pathlib.Path('/etc/turbo-production-sink').write_text('probe', encoding='utf-8'); fs_denied = False\n"
        "except OSError: fs_denied = True\n"
        "push_denied = subprocess.run(['git', 'push', 'https://127.0.0.1:1/prod.git', 'HEAD'], capture_output=True, timeout=2).returncode != 0\n"
        "if confined and fs_denied and push_denied: sys.stderr.write('DENIED: external filesystem and git push effects failed closed\\n'); sys.exit(1)\n"
        "print('ALLOWED'); sys.exit(0)\n"
    )
    return [
        _run_probe("forbidden_credential_access", "probe-credentials", cred_script, worker_env, worktree_dir, worker_dir, home),
        _run_probe("external_effect_restriction", "probe-external-effects", ext_script, worker_env, worktree_dir, worker_dir, home),
    ]


def _detect_host_version(agy_bin: str, agy_args: tuple[str, ...], env: dict[str, str]) -> str:
    try:
        res = subprocess.run([agy_bin, *agy_args, "--version"], capture_output=True, text=True, timeout=10, shell=False, env=env)
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


def _extract_measurements(final_result: dict[str, Any] | None, elapsed_ms: int, spec: WorkerSpec) -> dict[str, Any]:
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
    elif usage["state"] == "reported" and isinstance(in_tok, int) and isinstance(out_tok, int) and spec.rates is not None:
        usd = round((in_tok / 1_000_000.0) * spec.rates.input_usd_per_1m + (out_tok / 1_000_000.0) * spec.rates.output_usd_per_1m, 6)
        cost = {"state": "estimated", "usd": usd, "input_rate_usd_per_1m": spec.rates.input_usd_per_1m, "output_rate_usd_per_1m": spec.rates.output_usd_per_1m, "provenance": "estimated from reported token usage and operator-supplied per-1M rates"}
    else:
        cost = {"state": "unavailable", "usd": None, "input_rate_usd_per_1m": spec.rates.input_usd_per_1m if spec.rates else None, "output_rate_usd_per_1m": spec.rates.output_usd_per_1m if spec.rates else None, "provenance": "unavailable; missing reported token usage or per-1M rate (unavailable is not zero)"}
    return {"elapsed_ms": elapsed_ms, "reported_duration_seconds": final_result.get("duration_seconds") if isinstance(final_result, dict) else None, "usage": usage, "cost": cost}


def _execute_stream(cwd: Path, argv: tuple[str, ...], env: dict[str, str], timeout_s: int) -> tuple[int, str, str, int, bool]:
    started = time.monotonic()
    process = subprocess.Popen(list(argv), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, env=env, start_new_session=True)
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
    elapsed_ms = int((time.monotonic() - started) * 1000)
    stdout_text = stdout_b.decode("utf-8", "replace")
    stderr_text = stderr_b.decode("utf-8", "replace") + (f"\n[factory] worker timed out after {timeout_s}s\n" if timed_out else "")
    return exit_code, stdout_text, stderr_text, elapsed_ms, timed_out


def run_worker(paths: RuntimePaths, spec: WorkerSpec) -> WorkerResult:
    plat = platform_info()
    _validate_spec(spec, plat)
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    worker_dir = safe_dir(paths.home / "workers" / spec.task_id, create=True, root=paths.home)
    worktree_dir = worker_dir / "worktree"
    if worktree_dir.exists():
        gitio.git(paths.repo, "worktree", "remove", "--force", str(worktree_dir))
    isolated_home = _prepare_isolated_home(worker_dir, Path.home())
    worker_env, stripped_keys = _sanitized_worker_env(dict(os.environ), worktree_dir, isolated_home)
    host_version = _detect_host_version(spec.agy_bin, spec.agy_args, worker_env)
    rev_res = gitio.git(FACTORY_ROOT, "rev-parse", "HEAD")
    factory_rev = rev_res.output if rev_res.ok else "unknown"
    add_res = gitio.git(paths.repo, "worktree", "add", "--detach", str(worktree_dir), "HEAD")
    if not add_res.ok:
        raise UsageError(f"cannot create disposable worktree: {add_res.output}")
    try:
        probes = _run_safety_probes(worker_env, worktree_dir, worker_dir, paths.home)
        argv = (spec.agy_bin, *spec.agy_args, "--print", spec.prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
        exit_code, stdout_text, stderr_text, elapsed_ms, timed_out = _execute_stream(worktree_dir, argv, worker_env, spec.time_limit_seconds)
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
        if not all(bool(p["denied"]) for p in probes): status = "unsafe-environment"
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
        gitio.git(paths.repo, "worktree", "remove", "--force", str(worktree_dir))


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
