"""Security-gated child PR evaluation and bounded repair delivery orchestration (Issue #22)."""

from __future__ import annotations

import json, re, time, urllib.parse
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from factory import ci_gate, config as config_module, deliver as deliver_module, gitio, runner, worker as worker_module
from factory.config import now
from factory.deliver_checks import (
    AttemptTimeoutError, GitHubError, collect_redaction_secrets, evaluate_scope, git_timed,
    github_request, inspect_diff_categories, parse_repo_slug, resolve_github_api, resolve_github_token,
)
from factory.errors import FactoryError
from factory.intake import redact_value
from factory.paths import RuntimePaths, atomic_json, write_evidence

VERIFICATION_SCOPE_SECURITY_NOTE = "ci-criterion-and-security-verified; not independently code-reviewed (#23), merge-approved (#24), or human-accepted"
PR_SECURITY_HEADER_RE = re.compile(r"\n?## Security Review Evidence\b")


@dataclass(frozen=True, slots=True)
class DeliverSecuritySpec:
    task_ref: str; time_limit_seconds: int = 900; agy_bin: str = "agy"; reviewer_agy_bin: str | None = None
    max_repair_rounds: int = 2; rates: worker_module.RateCard | None = None


def _format_security_pr_section(candidate_sha: str, base_sha: str, sec_gate: dict[str, Any], sec_record: dict[str, Any] | None) -> str:
    if not isinstance(sec_record, dict):
        return (f"\n## Security Review Evidence\n- Status: `{sec_gate['status']}` (verified=`False`)\n"
                f"- Candidate revision: `{candidate_sha}`\n- Blockers: {', '.join(sec_gate['blockers']) or 'missing review'}\n")
    pol_ids = ", ".join(f"`{p['id']}`" for p in (sec_record.get("applicable_policies") or [])) or "none"
    scope_paths = ", ".join(f"`{p}`" for p in (sec_record.get("inspected_scope", {}).get("changed_paths") or [])) or "none"
    block_lines = [f"- `{f['finding_id']}` (`{f.get('policy_id')}`, `{f.get('severity')}`): **{f.get('status', 'open').upper()}** at `{f.get('file_path')}` — {f.get('title')}"
                   for f in (sec_record.get("findings") or []) if isinstance(f, dict) and f.get("blocking", True)] or ["- None"]
    sugg_lines = [f"- `{s['finding_id']}` (non-blocking suggestion at `{s.get('file_path')}`): {s.get('title')}"
                  for s in (sec_gate.get("non_blocking_suggestions") or [])] or ["- None"]
    return (f"\n## Security Review Evidence\n- Security gate status: `{sec_gate['status']}` (verified=`{sec_gate['verified']}`)\n"
            f"- Reviewer role: `{sec_record.get('role')}` (round `{sec_record.get('round')}`, session `{sec_record.get('reviewer_session_id')}`)\n"
            f"- Reviewed revision: `{sec_record.get('reviewed_revision')}` (policy `{sec_record.get('policy_sha')}`, base `{base_sha}`)\n"
            f"- Inspected scope: {scope_paths}\n- Applicable security policies: {pol_ids}\n"
            f"### Security Findings\n" + "\n".join(block_lines) + "\n### Non-Blocking Security Suggestions\n" + "\n".join(sugg_lines) + "\n")


def evaluate_child_pr_with_security_gate(
    *, repo: Path, home: Path, child_dir: Path, base_url: str, token: str, repo_slug: str,
    parent: dict[str, Any], child: dict[str, Any], conf: config_module.Config, pr_info: dict[str, Any],
    head_branch: str, candidate_sha: str, base_branch: str, base_sha: str, scope_detail: dict[str, Any],
    security_review_record: dict[str, Any] | None, trace: list[dict[str, Any]], deadline: float, limit_s: int,
    changed_paths: tuple[str, ...] = (), deleted_paths: tuple[str, ...] = (),
    ci_result: dict[str, Any] | None = None, is_loopback: bool | None = None, sleep_fn: Any = time.sleep,
) -> dict[str, Any]:
    from factory import security_review as sr_mod
    secrets = collect_redaction_secrets()
    loopback = is_loopback if is_loopback is not None else (urllib.parse.urlparse(base_url).hostname in ("127.0.0.1", "localhost", "::1"))
    if isinstance(ci_result, dict) and str(ci_result.get("candidate_sha") or "") == candidate_sha and bool(base_sha) and str(ci_result.get("base_sha") or "") == base_sha:
        ci_res = dict(ci_result)
    else:
        ci_res = ci_gate.evaluate_child_pr_ci_gate(
            repo=repo, home=home, child_dir=child_dir, base_url=base_url, token=token, repo_slug=repo_slug,
            parent=parent, child=child, conf=conf, pr_info=pr_info, head_branch=head_branch,
            candidate_sha=candidate_sha, base_branch=base_branch, base_sha=base_sha, scope_detail=scope_detail,
            trace=trace, deadline=deadline, limit_s=limit_s, changed_paths=changed_paths, deleted_paths=deleted_paths,
            poll_interval_s=0.05 if loopback else 2.0, max_missing_polls=3 if loopback else 15,
            artifact_retry_delay_s=0.0 if loopback else 2.0, sleep_fn=sleep_fn)
    sec_gate = sr_mod.evaluate_security_review_gate(candidate_sha, base_sha, security_review_record, home=home)
    if sec_gate["status"] == "stale-security-review":
        combined_status, combined_blockers, is_verified = "stale-security-review", [*sec_gate["blockers"], *ci_res.get("blockers", [])], False
    elif not ci_res["verified"]:
        combined_status, combined_blockers, is_verified = str(ci_res["status"]), [*ci_res.get("blockers", []), *sec_gate["blockers"]], False
    else:
        combined_status, combined_blockers, is_verified = str(sec_gate["status"]), list(sec_gate["blockers"]), bool(sec_gate["verified"])

    pr_obj = dict(ci_res.get("pr") or pr_info)
    pr_number = int(pr_obj.get("number") or 0)
    if pr_number > 0 and ci_res.get("status") != "ci-pending":
        base_body = PR_SECURITY_HEADER_RE.split(str(pr_obj.get("body") or ""))[0].rstrip()
        effective_gate = {**sec_gate, "verified": is_verified}
        new_body = redact_value(base_body + "\n" + _format_security_pr_section(candidate_sha, base_sha, effective_gate, security_review_record), secrets)
        github_request("PATCH", f"{base_url}/repos/{repo_slug}/pulls/{pr_number}", token, base_url, trace, deadline, limit_s, {"body": new_body})
        pr_obj["body"] = new_body
        live_fields, drift_reasons = ci_gate._check_pr_revision_drift(
            repo, base_url, token, repo_slug, pr_number, head_branch, candidate_sha, base_branch, base_sha, trace, deadline, limit_s)
        pr_obj.update(live_fields)
        if drift_reasons:
            combined_status, combined_blockers, is_verified = "stale-security-review", drift_reasons, False
            sec_gate = {**sec_gate, "status": "stale-security-review", "verified": False, "blockers": drift_reasons}
            stale_body = redact_value(base_body + "\n" + _format_security_pr_section(candidate_sha, base_sha, sec_gate, security_review_record), secrets)
            github_request("PATCH", f"{base_url}/repos/{repo_slug}/pulls/{pr_number}", token, base_url, trace, deadline, limit_s, {"body": stale_body})
            pr_obj["body"] = stale_body; pr_obj["ci_verified"] = pr_obj["pr_confirmed"] = False

    pr_obj["security_verified"] = bool(sec_gate["verified"]) and is_verified
    pr_obj["verified"] = is_verified
    return {**ci_res, "status": combined_status, "verified": is_verified, "verification_scope": VERIFICATION_SCOPE_SECURITY_NOTE,
            "blockers": combined_blockers, "security_gate": sec_gate, "security_review": security_review_record, "pr": pr_obj}


def build_security_repair_prompt(
    parent: dict[str, Any], child: dict[str, Any], feature_branch: str, head_branch: str,
    candidate_sha: str, blocking_findings: list[dict[str, Any]], repair_round: int, max_repair_rounds: int,
) -> str:
    finding_lines = "\n".join(
        f"- Finding ID: {f['finding_id']} (Policy: {f.get('policy_id')}, Severity: {f.get('severity')})\n"
        f"  File: {f.get('file_path')} (line {f.get('line')})\n  Evidence: {f.get('evidence')}\n"
        f"  Actionable correction: {f.get('actionable_correction')}" for f in blocking_findings)
    scope = child.get("scope") or {}
    return (f"SECURITY REPAIR ROUND {repair_round}/{max_repair_rounds} for Asana sub-task {child.get('gid')} ({child.get('name')}) "
            f"under parent {parent.get('gid')}.\nChild branch: {head_branch} -> {feature_branch} (current candidate: {candidate_sha})\n"
            f"In scope: {scope.get('in_scope') or 'as specified'}\nOut of scope: {scope.get('out_of_scope') or 'none'}\n"
            f"Constraints: {scope.get('constraints') or 'none'}\nBlocking security findings requiring remediation:\n{finding_lines}\n"
            "Repair every blocking security finding within the existing sub-task scope, keep all criteria and regression tests "
            "passing, do not relax security policies or touch protected paths, and commit your fix to HEAD.\n")


def _merge_measurements(
    base_meas: dict[str, Any], repair_meas_list: list[dict[str, Any]], total_elapsed_ms: int, rates: worker_module.RateCard | None = None,
) -> dict[str, Any]:
    merged = {**base_meas, "elapsed_ms": total_elapsed_ms, "repair_measurements": repair_meas_list}
    base_usage = dict(base_meas.get("usage") or {})
    for r_meas in repair_meas_list:
        r_usage = r_meas.get("usage") or {}
        if r_usage.get("state") == "reported":
            base_usage["state"] = "reported"
            base_usage["provenance"] = "reported by agy worker telemetry across initial and repair runs (unverified billing)"
            for k in worker_module.TOKEN_KEYS:
                if isinstance(r_usage.get(k), int):
                    base_usage[k] = int(base_usage.get(k) or 0) + int(r_usage[k])
    merged["usage"] = base_usage
    all_meas = [base_meas, *repair_meas_list]
    if repair_meas_list and all((m.get("cost") or {}).get("state") == "reported" and isinstance((m.get("cost") or {}).get("usd"), (int, float)) for m in all_meas):
        merged["cost"] = {"state": "reported", "usd": round(sum(float(m["cost"]["usd"]) for m in all_meas), 6),
                          "input_rate_usd_per_1m": None, "output_rate_usd_per_1m": None,
                          "provenance": "reported by agy worker telemetry across initial and repair runs (unverified billing)"}
    elif base_usage.get("state") == "reported" and rates is not None and isinstance(base_usage.get("input_tokens"), int) and isinstance(base_usage.get("output_tokens"), int):
        in_tok, out_tok = int(base_usage["input_tokens"]), int(base_usage["output_tokens"])
        merged["cost"] = {"state": "estimated", "usd": round((in_tok / 1_000_000.0) * rates.input_usd_per_1m + (out_tok / 1_000_000.0) * rates.output_usd_per_1m, 6),
                          "input_rate_usd_per_1m": rates.input_usd_per_1m, "output_rate_usd_per_1m": rates.output_usd_per_1m,
                          "provenance": "estimated from reported token usage and operator-supplied per-1M rates"}
    return merged


def _classify_repair_failure(rep_out: dict[str, Any], candidate_sha: str, limit_s: int) -> tuple[str, list[str]] | None:
    if not rep_out["probes_ok"]:
        return "unsafe-environment", ["repair worker safety probes failed"]
    if rep_out["timed_out"]:
        return "timed-out", [f"security repair builder timed out after {limit_s}s"]
    if rep_out["perm_denied"]:
        return "permission-denied", ["repair builder encountered sandbox or tool permission denial"]
    if rep_out["parse_err"] is not None:
        return "malformed-output", [f"repair builder output was not valid stream-json: {rep_out['parse_err']}"]
    if rep_out["exit_code"] != 0 or not isinstance(rep_out["final_res"], dict) or rep_out["final_res"].get("status") != "SUCCESS":
        return "builder-failed", [f"security repair builder failed (exit={rep_out['exit_code']})"]
    if rep_out["dirty_after"] or not rep_out["anc_ok"]:
        return ("uncommitted-changes" if rep_out["dirty_after"] else "scope-violation",
                [f"repair builder left dirty worktree: {rep_out['dirty_after']}" if rep_out["dirty_after"] else "repair builder rewrote history on child branch"])
    if rep_out["pol_detail"]["conflicts"] or not rep_out["scope_ok"]:
        return ("spec-check-conflict" if rep_out["pol_detail"]["conflicts"] else "scope-violation",
                list(rep_out["pol_detail"]["conflicts"] if rep_out["pol_detail"]["conflicts"] else rep_out["scope_violations"]))
    if rep_out["new_sha"] == candidate_sha or not rep_out["new_diff_info"]["has_implementation_changes"]:
        return "missing-implementation", ["repair builder did not produce implementation changes relative to base"]
    if not rep_out["new_diff_info"]["has_test_changes"]:
        return "missing-tests", ["repair candidate is missing test changes relative to base"]
    if not rep_out["imp_ok"] or not rep_out["push_ok"]:
        return "pr-failed", [f"failed to import/push repaired child branch: {rep_out['push_err']}"]
    return None


def deliver_with_security_review(paths: RuntimePaths, spec: DeliverSecuritySpec) -> deliver_module.DeliverResult:
    from factory import security_review as sr_mod
    started, limit_s = time.monotonic(), spec.time_limit_seconds
    deadline = started + limit_s
    reviewer_bin = spec.reviewer_agy_bin if spec.reviewer_agy_bin is not None else spec.agy_bin
    if reviewer_bin and str(reviewer_bin).strip():
        worker_module.validate_execution_options(
            worker_module.platform_info(), time_limit_seconds=limit_s, agy_bin=str(reviewer_bin), rates=spec.rates,
        )
    initial_res = deliver_module.deliver_feature(
        paths, deliver_module.DeliverSpec(task_ref=spec.task_ref, time_limit_seconds=limit_s, agy_bin=spec.agy_bin, rates=spec.rates),
    )
    if initial_res.status != "verified" or initial_res.child is None:
        return initial_res

    secrets = collect_redaction_secrets()
    attempt_dir, parent_root = Path(str(initial_res.evidence["attempt_dir"])), paths.home / "deliveries" / initial_res.task_gid
    child_rec = dict(initial_res.child)
    child_gid, child_dir = str(child_rec["gid"]), attempt_dir / "children" / str(child_rec["gid"])
    base_sha, feature_branch, head_branch, candidate_sha = (str(child_rec[k]) for k in ("base_sha", "base_branch", "head_branch", "candidate_sha"))
    pr_info, scope_detail, diff_info = dict(child_rec["pr"]), dict(child_rec["scope_check"]), dict(child_rec["diff"])
    gh_trace: list[dict[str, Any]] = list(initial_res.evidence.get("github_requests") or [])
    cand_diff_path = str(initial_res.evidence.get("candidate_diff_path") or "")
    init_ci = dict(child_rec["ci_verification"]) if isinstance(child_rec.get("ci_verification"), dict) else None
    combined_gate: dict[str, Any] = dict(init_ci) if init_ci is not None else {}

    pending_res = replace(
        initial_res, status="security-review-pending", verified=False, verification_scope=VERIFICATION_SCOPE_SECURITY_NOTE,
        child=redact_value({**child_rec, "status": "security-review-pending", "verified": False, "verification_scope": VERIFICATION_SCOPE_SECURITY_NOTE}, secrets),
        recorded_at=now(),
    )
    atomic_json(attempt_dir / "record.json", pending_res.to_dict(), paths.home); atomic_json(parent_root / "record.json", pending_res.to_dict(), paths.home)

    rounds_history, repair_records, repair_meas_list, prior_findings = [], [], [], []
    repairs_used, final_status, final_blockers = 0, "security-review-pending", []
    sec_rev: dict[str, Any] = {}

    try:
        conf = config_module.load(paths)
        gh_api_url, gh_is_loopback = resolve_github_api()
        gh_token = resolve_github_token(gh_is_loopback)
        intake_snap = json.loads(Path(str(initial_res.evidence["intake_record_path"])).read_text(encoding="utf-8"))
        child_spec = next((c for c in (intake_snap.get("children") or []) if str(c.get("gid")) == child_gid), child_rec)
        repo_slug = parse_repo_slug(str(initial_res.parent.get("repository") or child_spec.get("repository") or ""))
        gate3 = conf.gates.get("3")
        protected_paths = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
        init_stdout_path = Path(str(initial_res.evidence.get("builder_stdout_path") or ""))
        _, init_final, _ = worker_module.parse_stream_events(init_stdout_path.read_text(encoding="utf-8") if init_stdout_path.is_file() else "")
        builder_session_id = str(init_final.get("conversation_id") or "builder-0") if isinstance(init_final, dict) else "builder-0"

        for round_num in range(1, spec.max_repair_rounds + 2):
            sec_rev = sr_mod.review_candidate_security(
                repo=paths.repo, home=paths.home, child_dir=child_dir, child=child_spec, conf=conf,
                base_sha=base_sha, candidate_sha=candidate_sha, round_num=round_num,
                agy_bin=reviewer_bin, prior_findings=prior_findings, builder_session_id=builder_session_id, deadline=deadline, limit_s=limit_s,
            )
            rounds_history.append(sec_rev)
            prior_findings = list(sec_rev.get("findings") or [])
            combined_gate = sr_mod.evaluate_child_pr_with_security_gate(
                repo=paths.repo, home=paths.home, child_dir=child_dir, base_url=gh_api_url, token=gh_token,
                repo_slug=repo_slug, parent=initial_res.parent, child=child_spec, conf=conf, pr_info=pr_info,
                head_branch=head_branch, candidate_sha=candidate_sha, base_branch=feature_branch, base_sha=base_sha,
                scope_detail=scope_detail, security_review_record=sec_rev, trace=gh_trace, deadline=deadline, limit_s=limit_s,
                changed_paths=tuple(diff_info.get("changed_paths") or ()),
                ci_result=init_ci if round_num == 1 else None, is_loopback=gh_is_loopback,
            )
            pr_info = dict(combined_gate.get("pr") or pr_info)
            final_status, final_blockers = str(combined_gate["status"]), list(combined_gate.get("blockers") or [])
            if combined_gate["verified"] or final_status != "security-blockers-unresolved":
                break
            if repairs_used >= spec.max_repair_rounds:
                if spec.max_repair_rounds > 0:
                    final_status = "security-repair-exhausted"
                    final_blockers = [f"security repair cap ({spec.max_repair_rounds}) exhausted with unresolved blocking findings", *final_blockers]
                break

            repairs_used += 1
            repair_dir = child_dir / f"security-repair-{repairs_used}"
            repair_prompt = build_security_repair_prompt(
                initial_res.parent, child_spec, feature_branch, head_branch, candidate_sha,
                list(sec_rev.get("blocking_findings") or []), repairs_used, spec.max_repair_rounds,
            )

            def _after_repair(repair_wt: Path, rctx: dict[str, Any]) -> dict[str, Any]:
                new_sha, dirty_after = gitio.head(repair_wt), gitio.status_porcelain(repair_wt)
                if not rctx["probes_ok"] or rctx["timed_out"]:
                    d_path = write_evidence(repair_dir, "repair-diff", "", paths.home)
                    return {**rctx, "new_sha": new_sha, "dirty_after": dirty_after, "diff_path": d_path,
                            "new_diff_info": {"changed_paths": [], "implementation_paths": [], "test_paths": [], "has_implementation_changes": False, "has_test_changes": False},
                            "scope_ok": False, "scope_violations": [], "new_scope_detail": dict(scope_detail),
                            "pol_detail": {"conflicts": []}, "anc_ok": False, "imp_ok": False, "push_ok": False, "push_err": ""}
                new_diff_text = git_timed(repair_wt, deadline, limit_s, "repair diff", "diff", "--binary", base_sha, new_sha).output
                d_path = write_evidence(repair_dir, "repair-diff", redact_value(new_diff_text, secrets), paths.home)
                new_diff_info = (inspect_diff_categories(repair_wt, base_sha, new_sha, deadline, limit_s)
                                 if new_sha != base_sha else {"changed_paths": [], "deleted_paths": [], "implementation_paths": [], "test_paths": [], "has_implementation_changes": False, "has_test_changes": False})
                step_paths = inspect_diff_categories(repair_wt, candidate_sha, new_sha, deadline, limit_s)["changed_paths"] if new_sha != candidate_sha else []
                del_paths = tuple(p for p in dict.fromkeys([*new_diff_info["changed_paths"], *step_paths]) if not (repair_wt / p).is_file())
                s_ok, s_viol, new_s_detail = evaluate_scope(tuple(new_diff_info["changed_paths"]), child_spec, protected_paths)
                pol_detail = ci_gate.evaluate_spec_check_policy(child_spec, conf, tuple(new_diff_info["changed_paths"]), deleted_paths=del_paths, repo=repair_wt)
                new_s_detail["spec_check_policy"] = pol_detail
                anc_ok = gitio.is_ancestor(repair_wt, candidate_sha, new_sha)
                imp_ok, push_ok, push_err = True, True, ""
                if (rctx["parse_err"] is None and not rctx["perm_denied"] and rctx["exit_code"] == 0
                        and isinstance(rctx["final_res"], dict) and rctx["final_res"].get("status") == "SUCCESS"
                        and not dirty_after and anc_ok and not pol_detail["conflicts"] and s_ok
                        and new_sha != candidate_sha and new_diff_info["has_implementation_changes"] and new_diff_info["has_test_changes"]):
                    f_rep = git_timed(paths.repo, deadline, limit_s, "import repair commit", "fetch", "-q", "--no-tags", str(repair_wt), new_sha)
                    (paths.repo / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
                    b_ok = git_timed(paths.repo, deadline, limit_s, "update child branch", "branch", "-f", head_branch, new_sha).ok if f_rep.ok else False
                    p_rep = git_timed(paths.repo, deadline, limit_s, "push repaired child branch", "push", "-f", "origin", f"{new_sha}:refs/heads/{head_branch}") if b_ok else None
                    imp_ok, push_ok, push_err = f_rep.ok and b_ok, bool(p_rep and p_rep.ok), (p_rep.output if p_rep else f_rep.output)
                return {**rctx, "new_sha": new_sha, "dirty_after": dirty_after, "diff_path": d_path, "new_diff_info": new_diff_info,
                        "scope_ok": s_ok, "scope_violations": s_viol, "new_scope_detail": new_s_detail, "pol_detail": pol_detail,
                        "anc_ok": anc_ok, "imp_ok": imp_ok, "push_ok": push_ok, "push_err": push_err}

            rep_out = sr_mod._run_isolated_role_checkout(
                repo=paths.repo, home=paths.home, role_dir=repair_dir, candidate_sha=candidate_sha, base_sha=base_sha,
                agy_bin=spec.agy_bin, evidence_prefix="repair", secrets=secrets, deadline=deadline, limit_s=limit_s,
                build_prompt_fn=lambda _wt, _pr: (repair_prompt, {}), after_fn=_after_repair,
            )
            rep_meas = worker_module.extract_measurements(rep_out["final_res"], rep_out["elapsed_ms"], spec.rates)
            if rep_out["executed"]:
                repair_meas_list.append(rep_meas)
            repair_records.append({
                "repair_round": repairs_used, "from_sha": candidate_sha, "to_sha": rep_out["new_sha"], "exit_code": rep_out["exit_code"],
                "elapsed_ms": rep_out["elapsed_ms"], "stdout_path": rep_out["stdout_path"], "stderr_path": rep_out["stderr_path"],
                "diff_path": str(rep_out["diff_path"]), "measurements": rep_meas,
                "routed_finding_ids": [f["finding_id"] for f in (sec_rev.get("blocking_findings") or [])], "safety": rep_out["safety"],
            })
            if (rep_fail := _classify_repair_failure(rep_out, candidate_sha, limit_s)) is not None:
                final_status, final_blockers = rep_fail; break
            live_pr = github_request("GET", f"{gh_api_url}/repos/{repo_slug}/pulls/{pr_info['number']}", gh_token, gh_api_url, gh_trace, deadline, limit_s)
            obs_sha = str((live_pr.get("head") if isinstance(live_pr.get("head"), dict) else {}).get("sha") or "").strip()
            if obs_sha and obs_sha != rep_out["new_sha"]:
                final_status, final_blockers = "pr-failed", [f"repaired PR head SHA {obs_sha} does not match pushed {rep_out['new_sha']}"]; break
            builder_session_id = str(rep_out["final_res"].get("conversation_id") or f"builder-repair-{repairs_used}")
            candidate_sha, diff_info, scope_detail, cand_diff_path = rep_out["new_sha"], rep_out["new_diff_info"], rep_out["new_scope_detail"], str(rep_out["diff_path"])
    except GitHubError as exc:
        final_status, final_blockers = "pr-failed", [str(exc), *final_blockers]
    except worker_module.SandboxUnavailableError as exc:
        final_status, final_blockers = "unsafe-environment", [f"sandbox unavailable during security review: {exc}", *final_blockers]
    except (AttemptTimeoutError, TimeoutError) as exc:
        final_status, final_blockers = "timed-out", [f"security review or repair timed out: {exc}", *final_blockers]
    except (FactoryError, OSError, ValueError, KeyError) as exc:
        final_status, final_blockers = "security-review-failed", [f"security review failed: {exc}", *final_blockers]

    is_verified = final_status == "verified"
    pr_info["verified"] = pr_info["security_verified"] = is_verified
    gh_trace_text = json.dumps(redact_value({"requests": gh_trace, "pr": pr_info, "ci_verification": combined_gate}, secrets), indent=2, sort_keys=True) + "\n"
    gh_evidence_path = str(write_evidence(child_dir, "github-pr", gh_trace_text, paths.home))
    updated_child = {
        **child_rec, "status": final_status, "verified": is_verified, "verification_scope": VERIFICATION_SCOPE_SECURITY_NOTE,
        "candidate_sha": candidate_sha, "tested_sha": combined_gate.get("tested_sha"), "diff": diff_info,
        "scope_check": scope_detail, "verification_checks": combined_gate.get("checks", []), "ci_verification": combined_gate,
        "security_review": sec_rev, "security_repair": {"repairs_used": repairs_used, "max_repair_rounds": spec.max_repair_rounds,
                                                        "repair_attempts": repair_records, "rounds": rounds_history}, "pr": pr_info,
    }
    updated_evidence = {
        **initial_res.evidence, "candidate_diff_path": cand_diff_path, "github_evidence_path": gh_evidence_path,
        "github_evidence_sha256": runner.digest_text(gh_trace_text),
        "security_review_path": str(child_dir / "security-review.json"), "security_rounds": len(rounds_history),
        "security_repairs_used": repairs_used, "github_requests": gh_trace,
    }
    updated_meas = _merge_measurements(initial_res.measurements, repair_meas_list, int((time.monotonic() - started) * 1000), spec.rates)
    result = replace(
        initial_res, status=final_status, verified=is_verified, verification_scope=VERIFICATION_SCOPE_SECURITY_NOTE,
        child=redact_value(updated_child, secrets), blockers=redact_value(final_blockers, secrets),
        measurements=updated_meas, evidence=redact_value(updated_evidence, secrets), recorded_at=now(),
    )
    atomic_json(attempt_dir / "record.json", result.to_dict(), paths.home); atomic_json(parent_root / "record.json", result.to_dict(), paths.home)
    return result
