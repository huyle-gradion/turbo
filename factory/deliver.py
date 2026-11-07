"""Single-child feature delivery orchestration and child PR creation (Issue #19)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json, math, os, re, shutil, time
from pathlib import Path
from typing import Any

from factory import ci_gate, config as config_module, gitio, intake as intake_module, runner, worker as worker_module
from factory.config import now
from factory.deliver_checks import (
    AttemptTimeoutError, GitHubError, collect_redaction_secrets, evaluate_scope, git_timed,
    inspect_diff_categories, open_and_confirm_pr, parse_repo_slug, remaining_seconds,
    resolve_github_api, resolve_github_token, verify_origin_remote,
)
from factory.errors import UsageError
from factory.intake import redact_value
from factory.limits import parse_duration
from factory.paths import RuntimePaths, atomic_json, safe_dir, write_evidence

FACTORY_ROOT = Path(__file__).resolve().parents[1]
SLUG_TOKEN_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class DeliverSpec:
    task_ref: str
    time_limit_seconds: int
    agy_bin: str = "agy"
    rates: worker_module.RateCard | None = None


@dataclass(frozen=True, slots=True)
class DeliverResult:
    schema: int
    task_gid: str
    attempt: int
    status: str
    pr_opened: bool
    verified: bool
    verification_scope: str
    merged: bool
    factory_revision: str
    feature_branch: str
    parent: dict[str, Any]
    child: dict[str, Any] | None
    blockers: list[str]
    measurements: dict[str, Any]
    evidence: dict[str, Any]
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _child_branch_name(repo: Path, child_gid: str, child_name: str, attempt: int) -> str:
    slug = SLUG_TOKEN_RE.sub("-", child_name.strip().lower()).strip("-")[:40].strip("-") or "slice"
    base = f"task/{child_gid}-{slug}"
    if not gitio.branch_exists(repo, base) and gitio.remote_ref(repo, base) is None:
        return base
    n = max(1, attempt)
    while True:
        candidate = f"{base}-attempt-{n}"
        if not gitio.branch_exists(repo, candidate) and gitio.remote_ref(repo, candidate) is None:
            return candidate
        n += 1


def _ensure_feature_branch(repo: Path, feature_branch: str, deadline: float, limit_s: int) -> tuple[str, list[str]]:
    if feature_branch in ("main", "master") or not feature_branch.startswith("feature/"):
        return "", [f"target feature branch must be a feature/<name> branch, got {feature_branch!r}"]
    fetch_res = git_timed(repo, deadline, limit_s, "git fetch origin", "fetch", "origin")
    if not fetch_res.ok:
        return "", [f"cannot fetch origin before branch setup: {fetch_res.output}"]
    remote_sha = gitio.remote_ref(repo, feature_branch)
    local_exists = gitio.branch_exists(repo, feature_branch)
    if remote_sha and local_exists:
        local_sha = gitio.commit_sha(repo, f"refs/heads/{feature_branch}")
        if local_sha != remote_sha:
            if gitio.is_ancestor(repo, local_sha, remote_sha):
                if gitio.branch(repo) == feature_branch:
                    return "", [f"local {feature_branch} ({local_sha}) is checked out and behind origin/{feature_branch} ({remote_sha}); refusing to update checked-out branch"]
                ff_res = git_timed(repo, deadline, limit_s, "feature branch fast-forward", "update-ref", f"refs/heads/{feature_branch}", remote_sha, local_sha)
                if not ff_res.ok:
                    return "", [f"cannot fast-forward {feature_branch}: {ff_res.output}"]
                return remote_sha, []
            if not gitio.is_ancestor(repo, remote_sha, local_sha):
                return "", [f"existing local {feature_branch} ({local_sha}) diverged from origin/{feature_branch} ({remote_sha}); refusing to reset"]
        return local_sha, []
    if remote_sha and not local_exists:
        br_res = git_timed(repo, deadline, limit_s, "feature branch creation", "branch", feature_branch, remote_sha)
        if not br_res.ok:
            return "", [f"cannot create feature branch {feature_branch}: {br_res.output}"]
        return remote_sha, []
    if local_exists:
        return gitio.commit_sha(repo, f"refs/heads/{feature_branch}"), []
    base_ref = "refs/remotes/origin/main" if gitio.remote_ref(repo, "main") else "HEAD"
    base_sha = gitio.commit_sha(repo, base_ref)
    br_res = git_timed(repo, deadline, limit_s, "feature branch creation", "branch", feature_branch, base_sha)
    if not br_res.ok:
        return "", [f"cannot create feature branch {feature_branch}: {br_res.output}"]
    return base_sha, []


def _build_worker_prompt(parent: dict[str, Any], child: dict[str, Any], feature_branch: str) -> str:
    criteria_lines = "\n".join(
        f"- {c['id']}: {c['description']} (Verification: {c['verification']})"
        for c in (child.get("criteria") or [])
    )
    scope = child.get("scope") or {}
    return (
        f"Implement prepared Asana sub-task {child['gid']} ({child['name']}) "
        f"for parent feature {parent['gid']} ({parent['name']}).\n"
        f"Target feature branch: {feature_branch}\n"
        f"Outcome: {child.get('outcome') or child['name']}\n"
        f"In scope: {scope.get('in_scope') or 'as specified'}\n"
        f"Out of scope: {scope.get('out_of_scope') or 'none'}\n"
        f"Constraints: {scope.get('constraints') or 'none'}\n"
        f"Acceptance criteria:\n{criteria_lines}\n"
        "Implement the bounded change and relevant tests within scope, run verification checks, "
        "and commit your changes to the current worktree HEAD. Do not push or touch main.\n"
    )


def _next_attempt_dir(deliveries_root: Path, home: Path) -> tuple[int, Path]:
    safe_dir(deliveries_root, create=True, root=home)
    attempt = 1
    while (deliveries_root / f"attempt-{attempt}").exists():
        attempt += 1
    return attempt, safe_dir(deliveries_root / f"attempt-{attempt}", create=True, root=home)


def deliver_feature(paths: RuntimePaths, spec: DeliverSpec) -> DeliverResult:
    started = time.monotonic()
    limit_s = spec.time_limit_seconds
    deadline = started + limit_s
    plat = worker_module.platform_info()
    worker_module.validate_execution_options(
        plat, time_limit_seconds=limit_s, agy_bin=spec.agy_bin, rates=spec.rates
    )
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    secrets = collect_redaction_secrets()
    gh_api_url, gh_is_loopback = resolve_github_api()
    intake_args = type("IntakeArgs", (), {"task": spec.task_ref, "deadline": deadline})()
    intake_res = intake_module.run_from_cli(paths, intake_args)
    task_gid = intake_res.task_gid
    parent_root = safe_dir(paths.home / "deliveries" / task_gid, create=True, root=paths.home)
    attempt, attempt_dir = _next_attempt_dir(parent_root, paths.home)
    intake_src = paths.home / "intake" / task_gid / "record.json"
    intake_snap = attempt_dir / "intake-record.json"
    if intake_src.exists():
        shutil.copy2(intake_src, intake_snap)
    rev_res = gitio.git(FACTORY_ROOT, "rev-parse", "HEAD")
    factory_rev = rev_res.output if rev_res.ok and re.fullmatch(r"[0-9a-f]{40}", rev_res.output) else "unavailable"
    feature_branch = str(intake_res.parent.get("target_feature_branch") or "")

    def _finish(
        status: str, blockers: list[str], child_payload: dict[str, Any] | None,
        measurements: dict[str, Any], evidence: dict[str, Any], active_secrets: tuple[str, ...] = secrets,
        *, pr_opened: bool = False,
    ) -> DeliverResult:
        is_verified = status == "verified"
        res = DeliverResult(
            schema=1, task_gid=task_gid, attempt=attempt, status=status,
            pr_opened=pr_opened, verified=is_verified, verification_scope=ci_gate.VERIFICATION_SCOPE_NOTE,
            merged=False, factory_revision=factory_rev,
            feature_branch=feature_branch, parent=redact_value(intake_res.parent, active_secrets),
            child=redact_value(child_payload, active_secrets) if child_payload is not None else None,
            blockers=redact_value(blockers, active_secrets), measurements=measurements,
            evidence=redact_value(evidence, active_secrets), recorded_at=now(),
        )
        atomic_json(attempt_dir / "record.json", res.to_dict(), paths.home)
        atomic_json(parent_root / "record.json", res.to_dict(), paths.home)
        return res

    def _default_meas() -> dict[str, Any]:
        return {
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "usage": {"state": "unavailable", "provenance": "unavailable; builder did not run"},
            "cost": {"state": "unavailable", "usd": None, "provenance": "unavailable; builder did not run"},
        }

    base_evidence: dict[str, Any] = {
        "attempt_dir": str(attempt_dir),
        "intake_record_path": str(intake_snap if intake_snap.exists() else intake_src),
        "intake_status": intake_res.status,
    }
    intake_reqs = intake_res.evidence.get("requests") if isinstance(intake_res.evidence, dict) else []
    intake_timed_out = time.monotonic() >= deadline or any(
        isinstance(r, dict) and r.get("status") == "timeout" for r in (intake_reqs or [])
    )
    if intake_timed_out:
        return _finish("timed-out", [f"attempt timed out during intake after {limit_s}s", *intake_res.blockers], None, _default_meas(), base_evidence)
    if len(intake_res.children) > 1:
        gids = ", ".join(c["gid"] for c in intake_res.children)
        return _finish("unsupported-topology", [f"slice #19 supports exactly 1 prepared child sub-task, found {len(intake_res.children)} ({gids})", *intake_res.blockers], None, _default_meas(), base_evidence)
    if len(intake_res.children) == 1 and intake_res.children[0].get("blocked_by"):
        c0 = intake_res.children[0]
        return _finish("unsupported-topology", [f"child {c0['gid']} declares dependencies ({c0.get('blocked_by')}), which is outside slice #19 single-child delivery", *intake_res.blockers], c0, _default_meas(), base_evidence)
    if not intake_res.delivery_ready:
        return _finish(f"intake-{intake_res.status}", list(intake_res.blockers), None, _default_meas(), base_evidence)
    child = intake_res.children[0]
    child_gid = str(child["gid"])
    pre_policy_detail = ci_gate.evaluate_spec_check_policy(child, conf)
    if pre_conflicts := pre_policy_detail["conflicts"]:
        return _finish(
            "spec-check-conflict", pre_conflicts,
            {
                "gid": child_gid, "name": child["name"], "status": "spec-check-conflict",
                "verified": False, "spec_check_policy": pre_policy_detail, "pr": None,
            },
            _default_meas(), base_evidence,
        )
    child_dir = safe_dir(attempt_dir / "children" / child_gid, create=True, root=paths.home)
    worktree_dir = child_dir / "worktree"
    gh_trace: list[dict[str, Any]] = []
    measurements = _default_meas()
    pr_info: dict[str, Any] | None = None

    try:
        repo_slug = parse_repo_slug(str(intake_res.parent.get("repository") or child.get("repository") or ""))
        if (origin_issue := verify_origin_remote(paths.repo, repo_slug, deadline, limit_s)) is not None:
            return _finish("branch-failed", [origin_issue], child, _default_meas(), base_evidence)
        main_before = gitio.commit_sha(paths.repo, "refs/heads/main") if gitio.branch_exists(paths.repo, "main") else gitio.head(paths.repo)
        remote_main_before = gitio.remote_ref(paths.repo, "main")
        base_sha, branch_issues = _ensure_feature_branch(paths.repo, feature_branch, deadline, limit_s)
        if branch_issues:
            return _finish("branch-failed", branch_issues, child, _default_meas(), base_evidence)

        isolated_home = worker_module.prepare_isolated_home(child_dir, Path.home(), root=paths.home)
        worker_env, stripped_keys = worker_module.sanitized_env(dict(os.environ), worktree_dir, isolated_home)
        host_version = worker_module.detect_host_version(spec.agy_bin, (), worker_env)
        head_branch = _child_branch_name(paths.repo, child_gid, str(child.get("name") or ""), attempt)
        try:
            worker_module.prepare_isolated_git_checkout(paths.repo, worktree_dir, base_sha, deadline=deadline)
        except TimeoutError as exc:
            raise AttemptTimeoutError(f"worktree preparation timed out after {limit_s}s") from exc
        except RuntimeError as exc:
            return _finish("branch-failed", [str(exc)], child, _default_meas(), base_evidence)

        remaining_seconds(deadline, "safety probes", limit_s)
        try:
            probes = worker_module.run_safety_probes(worker_env, worktree_dir, child_dir, paths.home, deadline=deadline)
        except TimeoutError as exc:
            raise AttemptTimeoutError(f"safety probes timed out after {limit_s}s") from exc
        if time.monotonic() >= deadline:
            raise AttemptTimeoutError(f"safety probes timed out after {limit_s}s")
        prompt_text = _build_worker_prompt(intake_res.parent, child, feature_branch)
        argv = (spec.agy_bin, "--print", prompt_text, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
        if worker_module.probes_passed(probes):
            builder_timeout = max(1, int(math.ceil(remaining_seconds(deadline, "builder execution", limit_s))))
            try:
                exit_code, stdout_text, stderr_text, worker_ms, timed_out = worker_module.execute_stream(
                    worktree_dir, argv, worker_env, builder_timeout, isolated_home=isolated_home
                )
            except worker_module.SandboxUnavailableError:
                exit_code, stdout_text, stderr_text, timed_out = None, "", "", False
                events, final_result, parse_error, probes = [], None, None, []
            else:
                events, final_result, parse_error = worker_module.parse_stream_events(stdout_text)
                measurements = worker_module.extract_measurements(final_result, int((time.monotonic() - started) * 1000), spec.rates)
                measurements["builder_elapsed_ms"] = worker_ms
                if timed_out or time.monotonic() >= deadline:
                    raise AttemptTimeoutError(f"builder timed out after {limit_s}s")
        else:
            exit_code, stdout_text, stderr_text, timed_out = None, "", "", False
            events, final_result, parse_error = [], None, None

        stdout_path = write_evidence(child_dir, "builder-stdout", stdout_text, paths.home)
        stderr_path = write_evidence(child_dir, "builder-stderr", stderr_text, paths.home)
        candidate_sha = gitio.head(worktree_dir)
        dirty_after = gitio.status_porcelain(worktree_dir)
        cand_diff_text = (
            git_timed(worktree_dir, deadline, limit_s, "candidate diff", "diff", "--binary", base_sha, candidate_sha).output
            if candidate_sha != base_sha else ""
        )
        cand_diff_path = write_evidence(child_dir, "candidate-diff", redact_value(cand_diff_text, secrets), paths.home)
        wt_status_path = write_evidence(child_dir, "worktree-status", redact_value(dirty_after, secrets), paths.home)
        diff_info = (
            inspect_diff_categories(worktree_dir, base_sha, candidate_sha, deadline, limit_s)
            if candidate_sha != base_sha
            else {"changed_paths": [], "implementation_paths": [], "test_paths": [], "has_implementation_changes": False, "has_test_changes": False}
        )
        gate3 = conf.gates.get("3")
        protected_paths = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
        scope_ok, scope_violations, scope_detail = evaluate_scope(tuple(diff_info["changed_paths"]), child, protected_paths)
        post_policy_detail = ci_gate.evaluate_spec_check_policy(
            child, conf, tuple(diff_info["changed_paths"]), repo=worktree_dir,
        )
        post_conflicts = post_policy_detail["conflicts"]
        scope_detail["spec_check_policy"] = post_policy_detail

        fetch_after = git_timed(paths.repo, deadline, limit_s, "git fetch origin", "fetch", "origin")
        main_after = gitio.commit_sha(paths.repo, "refs/heads/main") if gitio.branch_exists(paths.repo, "main") else main_before
        remote_main_after = gitio.remote_ref(paths.repo, "main")
        feature_after = gitio.commit_sha(paths.repo, f"refs/heads/{feature_branch}") if gitio.branch_exists(paths.repo, feature_branch) else ""
        if (
            not fetch_after.ok or main_after != main_before
            or (remote_main_before is not None and remote_main_after != remote_main_before)
            or feature_after != base_sha
        ):
            scope_ok = False
            scope_violations.append("unauthorized repository or remote branch mutation detected")

        builder_status, blockers = "completed", []
        if not worker_module.probes_passed(probes):
            builder_status, blockers = "unsafe-environment", ["worker environment safety probes failed"]
        elif parse_error is not None:
            builder_status, blockers = "malformed-output", [f"builder produced malformed structured output: {parse_error}"]
        elif worker_module.has_permission_denial(events, final_result, stderr_text):
            builder_status, blockers = "permission-denied", ["builder encountered sandbox or tool permission denial"]
        elif exit_code != 0 or not isinstance(final_result, dict) or final_result.get("status") != "SUCCESS":
            res_status = final_result.get("status") if isinstance(final_result, dict) else None
            builder_status, blockers = "builder-failed", [f"builder exited with code {exit_code} and result status {res_status!r}"]
        elif dirty_after:
            builder_status, blockers = "uncommitted-changes", [f"builder left uncommitted changes in worktree: {dirty_after}"]
        elif candidate_sha == base_sha or not diff_info["changed_paths"]:
            builder_status, blockers = "missing-implementation", ["builder produced no committed changes relative to the feature branch base"]
        elif not gitio.is_ancestor(worktree_dir, base_sha, candidate_sha):
            builder_status, blockers = "scope-violation", ["builder rewrote history or diverged from the feature branch base"]
        elif post_conflicts:
            builder_status, blockers = "spec-check-conflict", post_conflicts
        elif not scope_ok:
            builder_status, blockers = "scope-violation", list(scope_violations)
        elif not diff_info["has_implementation_changes"]:
            builder_status, blockers = "missing-implementation", ["builder committed test changes only without implementation changes"]
        elif not diff_info["has_test_changes"]:
            builder_status, blockers = "missing-tests", ["builder committed implementation changes without relevant test changes"]

        ci_verification: dict[str, Any] | None = None
        if builder_status == "completed":
            try:
                gh_token = resolve_github_token(gh_is_loopback)
                if not gh_token:
                    raise GitHubError("missing GitHub authentication token (GITHUB_TOKEN, GH_TOKEN, or TURBO_GITHUB_TOKEN)")
                fetch_cand = git_timed(paths.repo, deadline, limit_s, "fetch candidate commit", "fetch", "-q", "--no-tags", str(worktree_dir), candidate_sha)
                if not fetch_cand.ok or gitio.commit_sha(paths.repo, "FETCH_HEAD") != candidate_sha:
                    raise GitHubError(f"failed to import verified candidate commit {candidate_sha}: {fetch_cand.output}")
                (paths.repo / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
                head_branch = _child_branch_name(paths.repo, child_gid, str(child.get("name") or ""), attempt)
                br_child = git_timed(paths.repo, deadline, limit_s, "branch child head", "branch", head_branch, candidate_sha)
                if not br_child.ok:
                    raise GitHubError(f"failed to create child branch {head_branch}: {br_child.output}")
                push_feat = git_timed(paths.repo, deadline, limit_s, "push feature branch", "push", "origin", f"{base_sha}:refs/heads/{feature_branch}")
                if not push_feat.ok:
                    raise GitHubError(f"failed to push feature branch {feature_branch} to origin: {push_feat.output}")
                push_child = git_timed(paths.repo, deadline, limit_s, "push child branch", "push", "origin", f"{candidate_sha}:refs/heads/{head_branch}")
                if not push_child.ok:
                    raise GitHubError(f"failed to push child branch {head_branch} to origin: {push_child.output}")
                pr_info = open_and_confirm_pr(
                    gh_api_url, gh_token, repo_slug, intake_res.parent, child, head_branch,
                    candidate_sha, feature_branch, [], scope_detail, gh_trace, deadline, limit_s,
                )
                ci_verification = ci_gate.evaluate_child_pr_ci_gate(
                    repo=paths.repo, home=paths.home, child_dir=child_dir, base_url=gh_api_url, token=gh_token,
                    repo_slug=repo_slug, parent=intake_res.parent, child=child, conf=conf, pr_info=pr_info,
                    head_branch=head_branch, candidate_sha=candidate_sha, base_branch=feature_branch,
                    base_sha=base_sha, scope_detail=scope_detail, trace=gh_trace, deadline=deadline, limit_s=limit_s,
                    changed_paths=tuple(diff_info["changed_paths"]),
                    poll_interval_s=0.05 if gh_is_loopback else 2.0,
                    max_missing_polls=3 if gh_is_loopback else 15,
                    artifact_retry_delay_s=0.0 if gh_is_loopback else 2.0,
                )
                pr_info = ci_verification.get("pr") or pr_info
                final_status = str(ci_verification["status"])
                blockers.extend(ci_verification.get("blockers") or [])
            except AttemptTimeoutError as exc:
                if pr_info is not None:
                    pr_info = {**pr_info, "pr_confirmed": True, "ci_verified": False, "verified": False}
                    final_status = "ci-pending"
                    blockers.append(f"CI verification still pending when time allowance expired: {exc}")
                else:
                    raise
            except GitHubError as exc:
                final_status = "pr-failed"
                blockers.append(str(exc))
        else:
            final_status = builder_status

        measurements["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        gh_trace_text = json.dumps(
            redact_value({"requests": gh_trace, "pr": pr_info, "ci_verification": ci_verification}, secrets),
            indent=2, sort_keys=True,
        ) + "\n"
        gh_evidence_path = write_evidence(child_dir, "github-pr", gh_trace_text, paths.home)
        child_payload = {
            "gid": child_gid, "name": child["name"], "status": final_status,
            "verified": final_status == "verified", "verification_scope": ci_gate.VERIFICATION_SCOPE_NOTE,
            "base_branch": feature_branch, "base_sha": base_sha, "head_branch": head_branch,
            "candidate_sha": candidate_sha,
            "tested_sha": ci_verification.get("tested_sha") if isinstance(ci_verification, dict) else None,
            "diff": diff_info, "scope_check": scope_detail,
            "verification_checks": ci_verification.get("checks", []) if isinstance(ci_verification, dict) else [],
            "ci_verification": ci_verification, "pr": pr_info,
            "safety": {
                "sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False,
                "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": probes,
            },
        }
        evidence = {
            **base_evidence, "host_version": host_version, "platform": plat,
            "builder_argv": list(argv), "builder_exit": exit_code, "builder_timed_out": timed_out,
            "builder_parse_error": parse_error, "builder_stdout_path": str(stdout_path),
            "builder_stdout_sha256": runner.digest_text(stdout_text), "builder_stderr_path": str(stderr_path),
            "builder_stderr_sha256": runner.digest_text(stderr_text), "candidate_diff_path": str(cand_diff_path),
            "worktree_status_path": str(wt_status_path), "github_evidence_path": str(gh_evidence_path),
            "github_evidence_sha256": runner.digest_text(gh_trace_text), "github_requests": gh_trace,
        }
        return _finish(final_status, blockers, child_payload, measurements, evidence, pr_opened=(pr_info is not None))
    except AttemptTimeoutError as exc:
        measurements["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        child_timeout_payload = {"gid": child_gid, "name": child["name"], "status": "timed-out", "verified": False, "pr": pr_info}
        return _finish("timed-out", [str(exc)], child_timeout_payload, measurements, base_evidence, pr_opened=(pr_info is not None))
    finally:
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)


def run_from_cli(paths: RuntimePaths, args: object) -> DeliverResult:
    in_rate = getattr(args, "input_rate_usd_per_1m", None)
    out_rate = getattr(args, "output_rate_usd_per_1m", None)
    if (in_rate is None) != (out_rate is None):
        raise UsageError("deliver requires both --input-rate-usd-per-1m and --output-rate-usd-per-1m when estimating cost")
    rates = worker_module.RateCard(float(in_rate), float(out_rate)) if in_rate is not None and out_rate is not None else None
    spec = DeliverSpec(
        task_ref=str(getattr(args, "task") or ""),
        time_limit_seconds=parse_duration(str(getattr(args, "time_limit") or "15m")),
        agy_bin=str(getattr(args, "agy_bin") or "agy"),
        rates=rates,
    )
    return deliver_feature(paths, spec)
