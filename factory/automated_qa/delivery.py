"""Automated QA bounded repair orchestration and CLI runner (Issue #21)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import shutil
import time
from typing import Any

from factory import ci_gate, config as config_module, deliver, deliver_checks, gitio, intake, worker as worker_module
from factory.automated_qa import (
    QA_VERIFICATION_SCOPE_NOTE, QAEvaluationCase, build_parent_acceptance_boundary,
    evaluate_child_qa, load_qa_cases_file,
)
from factory.config import now
from factory.deliver_checks import AttemptTimeoutError, GitHubError
from factory.errors import UsageError
from factory.limits import parse_duration
from factory.paths import RuntimePaths, atomic_json, safe_dir, write_evidence


@dataclass(frozen=True, slots=True)
class QADeliverySpec:
    task_ref: str
    time_limit_seconds: int
    agy_bin: str = "agy"
    rates: worker_module.RateCard | None = None
    qa_cases: tuple[QAEvaluationCase, ...] = ()
    max_correction_attempts: int = 2
    approve_parent_acceptance: bool = False


@dataclass(frozen=True, slots=True)
class QADeliveryResult:
    schema: int
    task_gid: str
    attempt: int
    status: str
    pr_opened: bool
    ci_verified: bool
    qa_verified: bool
    verification_scope: str
    merged: bool
    parent_accepted: bool
    parent_acceptance: dict[str, Any]
    correction_attempts_used: int
    max_correction_attempts: int
    factory_revision: str
    feature_branch: str
    parent: dict[str, Any]
    child: dict[str, Any] | None
    qa_rounds: list[dict[str, Any]]
    repair_attempts: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    blockers: list[str]
    measurements: dict[str, Any]
    evidence: dict[str, Any]
    recorded_at: str
    delivery_approved: bool = False
    approval_outcome: str = "rejected"
    approved_revision: str | None = None
    candidate_sha: str | None = None
    base_sha: str | None = None
    tested_sha: str | None = None
    revision_kind: str | None = None
    approval: dict[str, Any] | None = None

    @property
    def verified(self) -> bool:
        return bool(self.delivery_approved)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "verified": bool(self.delivery_approved)}


def _validate_max_attempts(val: Any) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or not 0 <= val <= 5:
        raise UsageError(f"max_correction_attempts must be an integer between 0 and 5, got {val!r}")
    return val


def _is_num(val: Any, allow_float: bool = False) -> bool:
    return isinstance(val, (int, float) if allow_float else int) and not isinstance(val, bool)


def _is_expired_ci_pending(status: str, blockers: list[str] | tuple[str, ...], deadline: float) -> bool:
    return status == "ci-pending" and (
        time.monotonic() >= deadline
        or any("time allowance expired" in str(b) or "until deadline" in str(b) for b in blockers)
    )


def _build_qa_repair_prompt(
    parent: dict[str, Any], child: dict[str, Any], feature_branch: str,
    open_findings: list[dict[str, Any]], repair_round: int, max_attempts: int,
) -> str:
    scope = child.get("scope") or {}
    blocks = [
        f"- Finding ID: {f['finding_id']} | Criterion: {f['criterion_id']} (Case: {f['case_id']})\n"
        f"  Command: {(f.get('failing_evidence') or {}).get('command')} (exit {(f.get('failing_evidence') or {}).get('exit_code')})\n"
        f"  Rubric failures: {(f.get('failing_evidence') or {}).get('rubric_failures')}\n"
        f"  Evidence excerpt: {(f.get('failing_evidence') or {}).get('output_excerpt')}\n"
        f"  Requested correction: {f['requested_correction']}"
        for f in open_findings
    ]
    return (
        f"Automated QA repair attempt {repair_round}/{max_attempts} for sub-task {child['gid']} ({child['name']}) "
        f"under parent feature {parent['gid']} ({parent['name']}) on {feature_branch}.\n"
        f"In scope: {scope.get('in_scope') or 'as specified'} | Out of scope: {scope.get('out_of_scope') or 'none'} | "
        f"Constraints: {scope.get('constraints') or 'none'}\nOpen Automated QA Findings:\n" + "\n".join(blocks) + "\n"
        "Address every open finding within scope, keep/expand tests without weakening checks or touching protected files, and commit to the current worktree HEAD.\n"
    )


def _unavailable_measurements(reason: str, rates: worker_module.RateCard | None) -> dict[str, Any]:
    return {
        "elapsed_ms": 0, "reported_duration_seconds": None,
        "usage": {"state": "unavailable", "provenance": reason, **{k: None for k in worker_module.TOKEN_KEYS}},
        "cost": {
            "state": "unavailable", "usd": None, "provenance": reason,
            "input_rate_usd_per_1m": rates.input_usd_per_1m if rates else None,
            "output_rate_usd_per_1m": rates.output_usd_per_1m if rates else None,
        },
    }


def _merge_measurements(
    initial: dict[str, Any], repair_attempts: list[dict[str, Any]], elapsed_ms: int, rates: worker_module.RateCard | None,
) -> dict[str, Any]:
    repair_meas = [r["measurements"] for r in repair_attempts if isinstance(r.get("measurements"), dict)]
    if not repair_meas:
        return {**initial, "elapsed_ms": elapsed_ms, "initial_measurements": initial, "repair_measurements": []}
    runs = [initial, *repair_meas]
    prov = "aggregated across initial builder and QA repair builder runs"
    usage_valid = all(
        isinstance(m.get("usage"), dict) and m["usage"].get("state") == "reported"
        and all(m["usage"].get(k) is None or _is_num(m["usage"].get(k)) for k in worker_module.TOKEN_KEYS)
        and any(_is_num(m["usage"].get(k)) for k in worker_module.TOKEN_KEYS)
        for m in runs
    )
    summed = {
        k: sum(int(m["usage"][k]) for m in runs) if usage_valid and all(_is_num(m["usage"].get(k)) for m in runs) else None
        for k in worker_module.TOKEN_KEYS
    }
    usage = (
        {"state": "reported", "provenance": prov, **summed}
        if usage_valid and any(v is not None for v in summed.values())
        else _unavailable_measurements("unavailable; incomplete builder token usage", rates)["usage"]
    )
    if all(
        isinstance(m.get("cost"), dict) and m["cost"].get("state") in ("reported", "estimated")
        and _is_num(m["cost"].get("usd"), allow_float=True) for m in runs
    ):
        states = {str(m["cost"]["state"]) for m in runs}
        cost: dict[str, Any] = {
            "state": "reported" if states == {"reported"} else "estimated",
            "usd": round(sum(float(m["cost"]["usd"]) for m in runs), 6),
            "input_rate_usd_per_1m": rates.input_usd_per_1m if rates else None,
            "output_rate_usd_per_1m": rates.output_usd_per_1m if rates else None,
            "provenance": prov,
        }
    else:
        cost = _unavailable_measurements("unavailable; missing reported token usage or per-1M rate (unavailable is not zero)", rates)["cost"]
    return {"elapsed_ms": elapsed_ms, "usage": usage, "cost": cost, "initial_measurements": initial, "repair_measurements": repair_meas}


def _inspect_repair_diffs(
    worktree_dir: Path, base_sha: str, prev_sha: str, new_sha: str, deadline: float, limit_s: int,
) -> tuple[dict[str, Any], dict[str, Any], tuple[str, ...]]:
    empty = {"changed_paths": [], "implementation_paths": [], "test_paths": [], "has_implementation_changes": False, "has_test_changes": False}
    cum_diff = deliver_checks.inspect_diff_categories(worktree_dir, base_sha, new_sha, deadline, limit_s) if new_sha != base_sha else dict(empty)
    inc_diff = deliver_checks.inspect_diff_categories(worktree_dir, prev_sha, new_sha, deadline, limit_s) if new_sha != prev_sha else dict(empty)
    deleted: list[str] = []
    for ref_a in (base_sha, prev_sha):
        if new_sha != ref_a:
            del_res = deliver_checks.git_timed(worktree_dir, deadline, limit_s, "repair deleted paths", "diff", "--diff-filter=D", "--name-only", ref_a, new_sha)
            if del_res.ok:
                deleted.extend(p for ln in del_res.output.splitlines() if (p := ln.strip().strip("/")) and p not in deleted)
    cum_diff["changed_paths"] = list(dict.fromkeys([*cum_diff["changed_paths"], *inc_diff["changed_paths"]]))
    cum_diff["deleted_paths"] = deleted
    return cum_diff, inc_diff, tuple(deleted)


def _run_repair_attempt(
    *, paths: RuntimePaths, spec: QADeliverySpec, conf: config_module.Config, parent_contract: dict[str, Any],
    child_contract: dict[str, Any], child_rec: dict[str, Any], child_dir: Path, qa_root: Path,
    feature_branch: str, repo_slug: str, gh_api_url: str, gh_token: str, gh_is_loopback: bool,
    open_findings: list[dict[str, Any]], repair_idx: int, deadline: float, limit_s: int, secrets: tuple[str, ...],
) -> tuple[dict[str, Any], dict[str, Any], str | None, list[str]]:
    repair_dir = safe_dir(qa_root / f"repair-{repair_idx}", create=True, root=paths.home)
    worktree_dir = repair_dir / "worktree"
    prev_sha, base_sha, head_branch = str(child_rec["candidate_sha"]), str(child_rec["base_sha"]), str(child_rec["head_branch"])
    main_before = gitio.commit_sha(paths.repo, "refs/heads/main") if gitio.branch_exists(paths.repo, "main") else gitio.head(paths.repo)
    remote_main_before = gitio.remote_ref(paths.repo, "main")
    gh_trace: list[dict[str, Any]] = []
    unverified_child = {**child_rec, "ci_verified": False, "verified": False, "delivery_approved": False}
    repair_record: dict[str, Any] = {
        "repair_attempt": repair_idx, "previous_candidate_sha": prev_sha, "candidate_sha": prev_sha,
        "status": "builder-failed", "blockers": [], "routed_finding_ids": [f["finding_id"] for f in open_findings],
        "builder_exit": None, "duration_ms": 0, "stdout_path": None, "stderr_path": None, "diff_path": None,
        "changed_paths": [], "isolated_home": None, "stripped_env_keys": [], "probes": [],
        "github_requests": [], "github_requests_path": None,
        "measurements": _unavailable_measurements("unavailable; repair builder did not run", spec.rates),
    }

    try:
        isolated_home = worker_module.prepare_isolated_home(repair_dir, Path.home(), root=paths.home)
        worker_env, stripped_env_keys = worker_module.sanitized_env(dict(os.environ), worktree_dir, isolated_home)
        repair_record.update(isolated_home=str(isolated_home), stripped_env_keys=list(stripped_env_keys))
        worker_module.prepare_isolated_git_checkout(paths.repo, worktree_dir, prev_sha, deadline=deadline)
        probes = worker_module.run_safety_probes(worker_env, worktree_dir, repair_dir, paths.home, deadline=deadline)
        repair_record["probes"] = list(probes)
        if not worker_module.probes_passed(probes):
            repair_record.update(status="unsafe-environment", blockers=["worker environment safety probes failed during QA repair"])
            return repair_record, unverified_child, repair_record["status"], list(repair_record["blockers"])

        prompt = _build_qa_repair_prompt(parent_contract, child_contract, feature_branch, open_findings, repair_idx, spec.max_correction_attempts)
        argv = (spec.agy_bin, "--print", prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
        b_timeout = max(1, int(math.ceil(deliver_checks.remaining_seconds(deadline, "QA repair builder", limit_s))))
        try:
            exit_code, stdout_text, stderr_text, worker_ms, timed_out = worker_module.execute_stream(worktree_dir, argv, worker_env, b_timeout, isolated_home=isolated_home)
        except worker_module.SandboxUnavailableError as exc:
            repair_record.update(status="unsafe-environment", blockers=[f"OS execution sandbox unavailable during QA repair: {exc}"])
            return repair_record, unverified_child, repair_record["status"], list(repair_record["blockers"])

        stdout_path = write_evidence(repair_dir, "repair-stdout", intake.redact_value(stdout_text, secrets), paths.home)
        stderr_path = write_evidence(repair_dir, "repair-stderr", intake.redact_value(stderr_text, secrets), paths.home)
        events, final_result, parse_error = worker_module.parse_stream_events(stdout_text)
        repair_meas = worker_module.extract_measurements(final_result, worker_ms, spec.rates)
        new_sha, dirty_after = gitio.head(worktree_dir), gitio.status_porcelain(worktree_dir)
        unverified_child = {**child_rec, "ci_verified": False, "verified": False, "delivery_approved": False, "candidate_sha": new_sha}
        repair_record.update(candidate_sha=new_sha, builder_exit=exit_code, duration_ms=worker_ms, stdout_path=str(stdout_path), stderr_path=str(stderr_path), measurements=repair_meas)
        if timed_out or time.monotonic() >= deadline:
            repair_record.update(status="timed-out", blockers=[f"QA repair builder timed out after {limit_s}s"])
            return repair_record, unverified_child, repair_record["status"], list(repair_record["blockers"])

        early_fail: tuple[str, list[str]] | None = None
        if parse_error is not None:
            early_fail = ("malformed-output", [f"QA repair builder produced malformed structured output: {parse_error}"])
        elif worker_module.has_permission_denial(events, final_result, stderr_text):
            early_fail = ("permission-denied", ["QA repair builder encountered sandbox or tool permission denial"])
        elif exit_code != 0 or not isinstance(final_result, dict) or final_result.get("status") != "SUCCESS":
            early_fail = ("builder-failed", [f"QA repair builder exited with code {exit_code}"])
        elif dirty_after:
            early_fail = ("uncommitted-changes", [f"QA repair builder left uncommitted changes: {dirty_after}"])
        elif new_sha == prev_sha:
            early_fail = ("missing-implementation", ["QA repair builder produced no new commit on candidate branch"])
        if early_fail is not None:
            repair_record.update(status=early_fail[0], blockers=early_fail[1])
            return repair_record, unverified_child, early_fail[0], early_fail[1]

        diff_text = deliver_checks.git_timed(worktree_dir, deadline, limit_s, "repair diff", "diff", "--binary", base_sha, new_sha).output if new_sha != base_sha else ""
        diff_path = write_evidence(repair_dir, "repair-diff", intake.redact_value(diff_text, secrets), paths.home)
        cum_diff, inc_diff, deleted_paths = _inspect_repair_diffs(worktree_dir, base_sha, prev_sha, new_sha, deadline, limit_s)
        repair_record.update(diff_path=str(diff_path), changed_paths=cum_diff["changed_paths"])
        gate3 = conf.gates.get("3")
        protected_paths = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
        scope_ok, scope_violations, scope_detail = deliver_checks.evaluate_scope(tuple(cum_diff["changed_paths"]), child_contract, protected_paths)
        post_policy = ci_gate.evaluate_spec_check_policy(child_contract, conf, tuple(cum_diff["changed_paths"]), deleted_paths=deleted_paths, repo=worktree_dir)
        scope_detail["spec_check_policy"] = post_policy

        fetch_after = deliver_checks.git_timed(paths.repo, deadline, limit_s, "git fetch origin", "fetch", "origin")
        main_after = gitio.commit_sha(paths.repo, "refs/heads/main") if gitio.branch_exists(paths.repo, "main") else main_before
        remote_main_after = gitio.remote_ref(paths.repo, "main")
        feature_after = gitio.commit_sha(paths.repo, f"refs/heads/{feature_branch}") if gitio.branch_exists(paths.repo, feature_branch) else ""
        if not fetch_after.ok or main_after != main_before or remote_main_after != remote_main_before or feature_after != base_sha:
            scope_ok = False
            scope_violations.append("unauthorized repository or remote branch mutation detected")

        if not inc_diff["changed_paths"]:
            step_status, step_blockers = "missing-implementation", ["QA repair builder produced no new commit on candidate branch"]
        elif not gitio.is_ancestor(worktree_dir, prev_sha, new_sha):
            step_status, step_blockers = "scope-violation", ["QA repair builder rewrote candidate branch history"]
        elif post_policy["conflicts"]:
            step_status, step_blockers = "spec-check-conflict", list(post_policy["conflicts"])
        elif not scope_ok:
            step_status, step_blockers = "scope-violation", list(scope_violations)
        elif not inc_diff["has_implementation_changes"] or not cum_diff["has_implementation_changes"]:
            step_status, step_blockers = "missing-implementation", ["QA repair committed test changes only without implementation changes"]
        elif not cum_diff["has_test_changes"]:
            step_status, step_blockers = "missing-tests", ["QA repair must maintain relevant test changes in scope"]
        else:
            step_status, step_blockers = "completed", []
        repair_record.update(status=step_status, blockers=step_blockers)
        if step_status != "completed":
            return repair_record, unverified_child, step_status, step_blockers

        fetch_cand = deliver_checks.git_timed(paths.repo, deadline, limit_s, "fetch repair commit", "fetch", "-q", "--no-tags", str(worktree_dir), new_sha)
        if not fetch_cand.ok or gitio.commit_sha(paths.repo, "FETCH_HEAD") != new_sha:
            raise GitHubError(f"failed to import QA repair commit {new_sha}: {fetch_cand.output}")
        (paths.repo / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
        upd_ref = deliver_checks.git_timed(paths.repo, deadline, limit_s, "update child branch", "update-ref", f"refs/heads/{head_branch}", new_sha, prev_sha)
        if not upd_ref.ok:
            raise GitHubError(f"failed to update local child branch {head_branch}: {upd_ref.output}")
        push_child = deliver_checks.git_timed(paths.repo, deadline, limit_s, "push repaired child branch", "push", "origin", f"{new_sha}:refs/heads/{head_branch}")
        if not push_child.ok:
            raise GitHubError(f"failed to push repaired child branch {head_branch}: {push_child.output}")

        pr_info = dict(child_rec.get("pr") or {})
        pr_num = int(pr_info["number"])
        pr_live = deliver_checks.github_request("GET", f"{gh_api_url}/repos/{repo_slug}/pulls/{pr_num}", gh_token, gh_api_url, gh_trace, deadline, limit_s)
        live_head_sha = str((pr_live.get("head") or {}).get("sha") or "").strip()
        if live_head_sha != new_sha or str(pr_live.get("state") or "") != "open" or bool(pr_live.get("merged")):
            raise GitHubError(f"PR #{pr_num} head SHA did not advance to {new_sha} (got {live_head_sha!r})")
        pr_info["head_sha"] = new_sha
        ci_verification = ci_gate.evaluate_child_pr_ci_gate(
            repo=paths.repo, home=paths.home, child_dir=child_dir, base_url=gh_api_url, token=gh_token, repo_slug=repo_slug,
            parent=parent_contract, child=child_contract, conf=conf, pr_info=pr_info, head_branch=head_branch,
            candidate_sha=new_sha, base_branch=feature_branch, base_sha=base_sha, scope_detail=scope_detail,
            trace=gh_trace, deadline=deadline, limit_s=limit_s, changed_paths=tuple(cum_diff["changed_paths"]),
            deleted_paths=deleted_paths, poll_interval_s=0.05 if gh_is_loopback else 2.0,
            max_missing_polls=3 if gh_is_loopback else 15, artifact_retry_delay_s=0.0 if gh_is_loopback else 2.0,
        )
        if _is_expired_ci_pending(str(ci_verification.get("status") or ""), ci_verification.get("blockers") or (), deadline):
            ci_verification["status"] = "timed-out"
        atomic_json(child_dir / "ci-verification.json", intake.redact_value(ci_verification, secrets), paths.home)
        ci_ok = ci_verification["status"] == "verified" and bool(ci_verification.get("verified"))
        pr_out = {**(ci_verification.get("pr") or pr_info), "ci_verified": ci_ok, "verified": False, "delivery_approved": False}
        updated_child = {
            **child_rec, "status": "ci-verified" if ci_ok else str(ci_verification["status"]),
            "ci_verified": ci_ok, "verified": False, "delivery_approved": False,
            "candidate_sha": new_sha, "tested_sha": ci_verification.get("tested_sha"),
            "revision_kind": ci_verification.get("revision_kind"), "diff": cum_diff,
            "scope_check": scope_detail, "verification_checks": ci_verification.get("checks", []),
            "ci_verification": ci_verification, "pr": pr_out,
        }
        repair_record["ci_status"] = ci_verification["status"]
        if not ci_ok:
            stop_st, stop_blk = str(ci_verification["status"]), list(ci_verification.get("blockers") or [])
            repair_record.update(status=stop_st, blockers=stop_blk)
            return repair_record, {**updated_child, "ci_verified": False, "verified": False, "delivery_approved": False}, stop_st, stop_blk
        return repair_record, updated_child, None, []
    except (AttemptTimeoutError, TimeoutError) as exc:
        repair_record.update(status="timed-out", blockers=[str(exc)])
        return repair_record, unverified_child, "timed-out", [str(exc)]
    except GitHubError as exc:
        repair_record.update(status="pr-failed", blockers=[str(exc)])
        return repair_record, unverified_child, "pr-failed", [str(exc)]
    finally:
        gh_redacted = intake.redact_value(gh_trace, secrets)
        gh_path = write_evidence(repair_dir, "repair-github-requests", json.dumps(gh_redacted, indent=2, sort_keys=True) + "\n", paths.home)
        repair_record.update(github_requests=gh_redacted, github_requests_path=str(gh_path))
        repair_record = intake.redact_value(repair_record, secrets)
        atomic_json(repair_dir / "record.json", repair_record, paths.home)
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)


def run_automated_qa_delivery(paths: RuntimePaths, spec: QADeliverySpec) -> QADeliveryResult:
    if spec.approve_parent_acceptance:
        raise UsageError("parent task human acceptance is outside automated QA authority")
    max_attempts = _validate_max_attempts(spec.max_correction_attempts)
    started, limit_s = time.monotonic(), spec.time_limit_seconds
    deadline = started + limit_s
    deliver_res = deliver.deliver_ci_prerequisite(
        paths, deliver.DeliverSpec(task_ref=spec.task_ref, time_limit_seconds=limit_s, agy_bin=spec.agy_bin, rates=spec.rates),
    )
    secrets = deliver_checks.collect_redaction_secrets()
    boundary = build_parent_acceptance_boundary(deliver_res.parent)
    attempt_dir = Path(deliver_res.evidence["attempt_dir"])
    parent_root = paths.home / "deliveries" / deliver_res.task_gid
    qa_rounds: list[dict[str, Any]] = []
    repair_attempts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    def _finish_delivery(
        status: str, ci_verified: bool, qa_verified: bool, child_payload: dict[str, Any] | None,
        blockers: list[str], measurements: dict[str, Any], extra_evidence: dict[str, Any],
        *, delivery_approved: bool = False, approval_outcome: str = "rejected",
        approved_revision: str | None = None, candidate_sha: str | None = None,
        base_sha: str | None = None, tested_sha: str | None = None,
        revision_kind: str | None = None, approval: dict[str, Any] | None = None,
        verification_scope: str = QA_VERIFICATION_SCOPE_NOTE,
    ) -> QADeliveryResult:
        res = QADeliveryResult(
            schema=1, task_gid=deliver_res.task_gid, attempt=deliver_res.attempt, status=status,
            pr_opened=deliver_res.pr_opened, ci_verified=ci_verified, qa_verified=qa_verified,
            verification_scope=verification_scope, merged=False, parent_accepted=False,
            parent_acceptance=intake.redact_value(boundary, secrets), correction_attempts_used=len(repair_attempts),
            max_correction_attempts=max_attempts, factory_revision=deliver_res.factory_revision,
            feature_branch=deliver_res.feature_branch, parent=intake.redact_value(deliver_res.parent, secrets),
            child=intake.redact_value(child_payload, secrets), qa_rounds=intake.redact_value(qa_rounds, secrets),
            repair_attempts=intake.redact_value(repair_attempts, secrets), findings=intake.redact_value(findings, secrets),
            blockers=intake.redact_value(blockers, secrets), measurements=measurements,
            evidence=intake.redact_value({**deliver_res.evidence, **extra_evidence}, secrets), recorded_at=now(),
            delivery_approved=delivery_approved, approval_outcome=approval_outcome,
            approved_revision=approved_revision if delivery_approved else None,
            candidate_sha=candidate_sha, base_sha=base_sha, tested_sha=tested_sha,
            revision_kind=revision_kind, approval=intake.redact_value(approval, secrets) if approval is not None else None,
        )
        payload = intake.redact_value(res.to_dict(), secrets)
        for dst in (attempt_dir / "qa-delivery-record.json", attempt_dir / "record.json", parent_root / "record.json"):
            atomic_json(dst, payload, paths.home)
        return res

    if not (deliver_res.ci_verified or deliver_res.status == "verified") or deliver_res.child is None:
        init_st = "timed-out" if _is_expired_ci_pending(deliver_res.status, deliver_res.blockers, deadline) else deliver_res.status
        return _finish_delivery(
            init_st, False, False, deliver_res.child, list(deliver_res.blockers),
            deliver_res.measurements, {"qa_delivery_record_path": str(attempt_dir / "qa-delivery-record.json")},
        )

    conf = config_module.load(paths)
    gh_api_url, gh_is_loopback = deliver_checks.resolve_github_api()
    gh_token = deliver_checks.resolve_github_token(gh_is_loopback)
    if gh_token.strip() and gh_token.strip() not in secrets:
        secrets = (*secrets, gh_token.strip())
    intake_record = json.loads(Path(deliver_res.evidence["intake_record_path"]).read_text(encoding="utf-8"))
    parent_contract = intake_record["parent"]
    delivered_gid = str(deliver_res.child["gid"])
    child_contract = next((c for c in (intake_record.get("children") or ()) if isinstance(c, dict) and str(c.get("gid")) == delivered_gid), None)
    if child_contract is None:
        return _finish_delivery(
            "intake-contract-mismatch", False, False, {**deliver_res.child, "verified": False},
            [f"delivered child {delivered_gid!r} was not found in intake record children"],
            deliver_res.measurements, {"qa_delivery_record_path": str(attempt_dir / "qa-delivery-record.json")},
        )
    child_gid = str(child_contract["gid"])
    child_dir = safe_dir(attempt_dir / "children" / child_gid, create=True, root=paths.home)
    qa_root = safe_dir(child_dir / "automated-qa", create=True, root=paths.home)
    repo_slug = deliver_checks.parse_repo_slug(str(parent_contract.get("repository") or child_contract.get("repository") or ""))
    child_rec = dict(deliver_res.child)
    repair_stop_status: str | None = None
    repair_blockers: list[str] = []
    current_qa: dict[str, Any] = {"qa_verified": False, "status": "qa-failed", "open_finding_ids": []}

    def _eval_round(r_num: int, prior: list[dict[str, Any]] | None) -> dict[str, Any]:
        return evaluate_child_qa(
            repo=paths.repo, home=paths.home, child_dir=child_dir, base_url=gh_api_url, token=gh_token, repo_slug=repo_slug,
            parent=parent_contract, child=child_contract, child_record=child_rec, conf=conf, qa_cases=spec.qa_cases,
            prior_findings=prior, round_number=r_num, deadline=deadline, limit_s=limit_s,
        )

    try:
        current_qa = _eval_round(1, None)
        qa_rounds.append(current_qa)
        findings = list(current_qa["findings"])

        for repair_idx in range(1, max_attempts + 1):
            open_findings = [f for f in findings if f["status"] != "resolved"]
            if current_qa["qa_verified"] or current_qa["status"] != "qa-failed" or not open_findings:
                break
            rep_rec, child_rec, stop_st, stop_blk = _run_repair_attempt(
                paths=paths, spec=spec, conf=conf, parent_contract=parent_contract, child_contract=child_contract,
                child_rec=child_rec, child_dir=child_dir, qa_root=qa_root, feature_branch=deliver_res.feature_branch,
                repo_slug=repo_slug, gh_api_url=gh_api_url, gh_token=gh_token, gh_is_loopback=gh_is_loopback,
                open_findings=open_findings, repair_idx=repair_idx, deadline=deadline, limit_s=limit_s, secrets=secrets,
            )
            repair_attempts.append(rep_rec)
            if stop_st is not None:
                repair_stop_status, repair_blockers = stop_st, stop_blk
                break
            current_qa = _eval_round(repair_idx + 1, findings)
            qa_rounds.append(current_qa)
            findings = list(current_qa["findings"])
    except (AttemptTimeoutError, TimeoutError) as exc:
        repair_stop_status, repair_blockers = "timed-out", [str(exc)]
    except GitHubError as exc:
        repair_stop_status, repair_blockers = "pr-failed", [str(exc)]
    except worker_module.SandboxUnavailableError as exc:
        repair_stop_status, repair_blockers = "unsafe-environment", [str(exc)]

    attempts_used = len(repair_attempts)
    if repair_stop_status is not None:
        final_status, final_blockers, qa_verified = repair_stop_status, repair_blockers, False
    elif current_qa["qa_verified"]:
        final_status, final_blockers, qa_verified = "qa-verified", [], True
    elif current_qa["status"] == "qa-failed" and attempts_used >= max_attempts:
        open_ids = ", ".join(current_qa.get("open_finding_ids") or ())
        final_status, qa_verified = "qa-exhausted", False
        final_blockers = [f"automated QA correction budget exhausted after {attempts_used} repair attempt(s); open findings: {open_ids}"]
    else:
        final_status, qa_verified = str(current_qa["status"]), False
        open_ids = ", ".join(current_qa.get("open_finding_ids") or ())
        final_blockers = [f"automated QA failed ({final_status}); open findings: {open_ids}"] if open_ids else [f"automated QA stopped with status {final_status}"]

    ci_verified = bool(
        repair_stop_status is None and (child_rec.get("ci_verified") or child_rec.get("verified"))
        and (current_qa.get("ci_revalidation") or {}).get("verified")
        and child_rec.get("candidate_sha") == current_qa.get("candidate_sha")
        and (child_rec.get("ci_verification") or {}).get("candidate_sha") == child_rec.get("candidate_sha")
    )
    child_rec["automated_qa"] = {
        "status": final_status, "qa_verified": qa_verified, "delivery_approved": False, "rounds": len(qa_rounds),
        "correction_attempts_used": attempts_used, "max_correction_attempts": max_attempts,
        "open_finding_ids": [f["finding_id"] for f in findings if f["status"] != "resolved"],
        "findings": findings, "parent_acceptance_boundary": boundary,
    }
    qa_summary_path = qa_root / "record.json"
    atomic_json(qa_summary_path, intake.redact_value(child_rec["automated_qa"], secrets), paths.home)

    qa_exec_status = final_status
    cand_sha, base_sha = str(child_rec.get("candidate_sha") or ""), str(child_rec.get("base_sha") or "")
    approval_rec: dict[str, Any] | None = None
    delivery_approved = False
    top_level_status = final_status
    if ci_verified and qa_verified:
        try:
            approval_rec = deliver.enforce_delivery_approval(
                candidate_sha=cand_sha, base_sha=base_sha, repo=paths.repo, home=paths.home, child_dir=child_dir,
                child=child_contract, conf=conf, ci_record=child_rec.get("ci_verification"), qa_record=current_qa,
                deadline=deadline, limit_s=limit_s,
            )
        except (deliver_checks.AttemptTimeoutError, TimeoutError) as exc:
            t_msg = f"delivery approval timed out: {exc}"
            approval_rec = {"schema": 1, "role": "delivery-approval-gate", "status": "timed-out", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": cand_sha, "base_sha": base_sha, "blockers": [t_msg]}
            if child_dir.exists(): atomic_json(child_dir / "approval-gate.json", approval_rec, paths.home)
        delivery_approved = bool(approval_rec.get("delivery_approved") is True and approval_rec.get("status") == "approved" and approval_rec.get("outcome") == "approved" and approval_rec.get("approved_revision") == cand_sha)
        if delivery_approved:
            top_level_status = "verified"
        elif approval_rec.get("status") in ("timed-out", "stale-candidate-revision", "authority-violation", "prerequisite-unverified", "approval-missing", "invalid-candidate-revision") or approval_rec.get("prior_approval_rejected"):
            top_level_status = str(approval_rec["status"])
        final_blockers = list(dict.fromkeys([*final_blockers, *(approval_rec.get("blockers") or [])]))
    app_out, app_rev = ("approved" if delivery_approved else "rejected"), (cand_sha if delivery_approved else None)
    t_sha = (approval_rec or {}).get("tested_sha") or child_rec.get("tested_sha")
    r_kind = (approval_rec or {}).get("revision_kind") or child_rec.get("revision_kind") or (child_rec.get("ci_verification") or {}).get("revision_kind")
    v_scope = str(approval_rec["verification_scope"]) if (delivery_approved and isinstance(approval_rec, dict)) else QA_VERIFICATION_SCOPE_NOTE
    if isinstance(child_rec.get("pr"), dict):
        child_rec["pr"] = {**child_rec["pr"], "ci_verified": ci_verified, "qa_verified": qa_verified, "verified": delivery_approved, "delivery_approved": delivery_approved, "approved_revision": app_rev}
    child_rec.update(
        status=top_level_status, ci_verified=ci_verified, verified=delivery_approved, delivery_approved=delivery_approved,
        approval_outcome=app_out, approved_revision=app_rev, qa_status=qa_exec_status, qa_verified=qa_verified,
        verification_scope=v_scope, tested_sha=t_sha, revision_kind=r_kind, approval=approval_rec,
    )
    extra_ev: dict[str, Any] = {"qa_record_path": str(qa_summary_path), "qa_delivery_record_path": str(attempt_dir / "qa-delivery-record.json")}
    if approval_rec is not None:
        extra_ev["approval_gate_path"] = str(child_dir / "approval-gate.json")
    measurements = _merge_measurements(deliver_res.measurements, repair_attempts, int((time.monotonic() - started) * 1000), spec.rates)
    return _finish_delivery(
        top_level_status, ci_verified, qa_verified, child_rec, final_blockers, measurements, extra_ev,
        delivery_approved=delivery_approved, approval_outcome=app_out, approved_revision=app_rev,
        candidate_sha=cand_sha or None, base_sha=base_sha or None, tested_sha=t_sha, revision_kind=r_kind, approval=approval_rec, verification_scope=v_scope,
    )


def run_from_cli(paths: RuntimePaths, args: object) -> QADeliveryResult:
    in_rate, out_rate = getattr(args, "input_rate_usd_per_1m", None), getattr(args, "output_rate_usd_per_1m", None)
    if (in_rate is None) != (out_rate is None):
        raise UsageError("automated_qa requires both --input-rate-usd-per-1m and --output-rate-usd-per-1m when estimating cost")
    rates = worker_module.RateCard(float(in_rate), float(out_rate)) if in_rate is not None and out_rate is not None else None
    cases_file = getattr(args, "qa_cases_file", None)
    qa_cases = load_qa_cases_file(Path(cases_file)) if cases_file else ()
    max_attempts = _validate_max_attempts(getattr(args, "max_correction_attempts", 2))
    return run_automated_qa_delivery(
        paths,
        QADeliverySpec(
            task_ref=str(getattr(args, "task") or ""), time_limit_seconds=parse_duration(str(getattr(args, "time_limit") or "15m")),
            agy_bin=str(getattr(args, "agy_bin") or "agy"), rates=rates, qa_cases=qa_cases, max_correction_attempts=max_attempts,
            approve_parent_acceptance=bool(getattr(args, "approve_parent_acceptance", False)),
        ),
    )
