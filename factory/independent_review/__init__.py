"""Standalone independent reviewer role and observed verification (Issue #52, Part 1 of #23)."""

from __future__ import annotations

import json, math, os, re, shutil, sys
from pathlib import Path
from typing import Any

from factory import ci_selection, config as config_module, deliver_checks, gitio, runner, security_review, worker as worker_module
from factory.config import now
from factory.deliver_checks import collect_redaction_secrets, evaluate_scope, git_timed, inspect_diff_categories, remaining_seconds
from factory.intake import redact_value
from factory.paths import atomic_json, safe_dir, write_evidence

INDEPENDENT_REVIEW_SCOPE_NOTE = (
    "standalone-independent-review-only; not delivery-approval-gated (#53), merge-approved (#24), or parent-accepted"
)
SLUG_RE = re.compile(r"[^a-z0-9]+")
FINDING_CATEGORIES = frozenset({
    "missing-behavior",
    "bug",
    "verification-gap",
    "scope-drift",
    "non-blocking-suggestion",
})
ASSESSMENT_KEYS = (
    "requirement_compliance",
    "project_standards",
    "criterion_coverage",
    "edge_cases",
    "test_effectiveness",
    "qa_security_outcomes",
)
BASELINE_PROJECT_STANDARDS: tuple[dict[str, str], ...] = (
    {"id": "STD-SCOPE-01", "name": "subtask-scope-and-protected-paths", "source": "factory-policy",
     "description": "Keep changes within declared sub-task scope and preserve protected policy and verification paths."},
    {"id": "STD-TEST-01", "name": "observable-behavior-and-regression-coverage", "source": "factory-policy",
     "description": "Verify acceptance criteria and edge cases with deterministic executable tests without weakening checks."},
)


def compute_review_finding_id(category: str, target: str, rule_or_concern: str) -> str:
    cat_slug = SLUG_RE.sub("-", (category or "").strip().lower()).strip("-").upper() or "FINDING"
    tgt_slug = SLUG_RE.sub("-", (target or "").strip().lower()).strip("-") or "repository"
    rule_slug = SLUG_RE.sub("-", (rule_or_concern or "").strip().lower()).strip("-") or "concern"
    return f"REV-{cat_slug}-{tgt_slug}-{rule_slug}"


def load_project_standards(
    repo: Path, base_sha: str, child: dict[str, Any], conf: config_module.Config, deadline: float, limit_s: int,
) -> list[dict[str, Any]]:
    standards = [{**s, "standard_sha": base_sha, "enforced": True} for s in BASELINE_PROJECT_STANDARDS]
    for doc_name, std_id in (("AGENTS.md", "STD-DOC-AGENTS"), ("CONTRIBUTING.md", "STD-DOC-CONTRIBUTING"), ("CONTEXT.md", "STD-DOC-CONTEXT")):
        res = git_timed(repo, deadline, limit_s, f"read {doc_name}", "show", f"{base_sha}:{doc_name}")
        if res.ok and res.output.strip():
            first_line = next((ln.strip("# ").strip() for ln in res.output.splitlines() if ln.strip()), doc_name)
            standards.append({
                "id": std_id, "name": doc_name.lower().replace(".", "-"), "source": f"{doc_name}@{base_sha[:12]}",
                "standard_sha": base_sha, "enforced": True, "description": first_line[:160],
            })
    constraints = str((child.get("scope") or {}).get("constraints") or "").strip()
    if constraints and constraints.lower() != "none":
        standards.append({
            "id": "STD-SUBTASK-CONSTRAINTS", "name": "subtask-constraints",
            "source": f"asana-subtask:{child.get('gid')}", "standard_sha": base_sha, "enforced": True,
            "description": constraints[:200],
        })
    return standards


def build_phase1_prompt(
    child: dict[str, Any], base_sha: str, candidate_sha: str, diff_text: str, standards: list[dict[str, Any]],
) -> str:
    scope = child.get("scope") or {}
    crit_lines = "\n".join(
        f"- {c.get('id')}: {c.get('description')} (verification: `{c.get('verification')}`)"
        for c in (child.get("criteria") or []) if isinstance(c, dict)
    ) or "- None"
    std_lines = "\n".join(f"- {s['id']} ({s['name']}, source={s['source']}): {s['description']}" for s in standards)
    return (
        "Role: independent-reviewer (fresh session separate from builder). Do not edit files or commit.\n"
        "PHASE: 1 (pre-summary independent hypothesis formation)\n"
        f"Sub-task: {child.get('gid')} ({child.get('name')})\n"
        f"Candidate revision: {candidate_sha} (base: {base_sha})\n"
        f"In scope: {scope.get('in_scope') or 'as specified'}\n"
        f"Out of scope: {scope.get('out_of_scope') or 'none'}\n"
        f"Constraints: {scope.get('constraints') or 'none'}\n"
        f"Requirements & Acceptance Criteria:\n{crit_lines}\n"
        f"Applicable Project Standards:\n{std_lines}\n"
        f"Exact Base-to-Candidate Diff:\n{diff_text}\n"
        'Respond with raw JSON only: {"hypotheses": ["<independent failure hypothesis 1>", ...]}\n'
    )


def build_phase2_prompt(
    child: dict[str, Any], base_sha: str, candidate_sha: str, hypotheses: list[str],
    builder_summary: str, qa_eval: dict[str, Any], sec_eval: dict[str, Any],
) -> str:
    hyp_lines = "\n".join(f"- {h}" for h in hypotheses)
    schema = (
        '{"outcome":"review-passed|changes-requested","assessment":{'
        '"requirement_compliance":{"status":"satisfied|unsatisfied","summary":"..."},'
        '"project_standards":{"status":"satisfied|unsatisfied","summary":"..."},'
        '"criterion_coverage":{"status":"satisfied|unsatisfied","summary":"..."},'
        '"edge_cases":{"status":"satisfied|unsatisfied","summary":"..."},'
        '"test_effectiveness":{"status":"satisfied|unsatisfied","summary":"..."},'
        '"qa_security_outcomes":{"status":"satisfied|unsatisfied","summary":"..."}},'
        '"findings":[{"finding_id":"REV-...","category":"missing-behavior|bug|verification-gap|scope-drift|non-blocking-suggestion",'
        '"blocking":true,"target":"<file_path_or_criterion_id>","rule":"<concern_slug>","title":"...",'
        '"evidence":"...","actionable_correction":"..."}]}'
    )
    return (
        "Role: independent-reviewer (fresh session separate from builder). Do not edit files or commit.\n"
        "PHASE: 2 (substantive-assessment after independent hypotheses were persisted)\n"
        f"Sub-task: {child.get('gid')} ({child.get('name')})\n"
        f"Candidate revision: {candidate_sha} (base: {base_sha})\n"
        f"Persisted Phase-1 Hypotheses:\n{hyp_lines}\n"
        f"Same-Candidate Automated QA Gate Summary: status={qa_eval['status']} verified={qa_eval['verified']}\n"
        f"Same-Candidate Security Review Gate Summary: status={sec_eval['status']} verified={sec_eval['verified']}\n"
        f"Builder Summary (untrusted claim):\n{builder_summary or '(none provided)'}\n"
        f"Required JSON response schema:\n{schema}\n"
    )


def _parse_phase1_hypotheses(response_text: str) -> tuple[list[str], list[str]]:
    text = (response_text or "").strip()
    if not (text.startswith("{") and text.endswith("}")):
        return [], ["phase-1 reviewer response must be a raw JSON object without markdown fences"]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [f"phase-1 reviewer response is not valid JSON: {exc}"]
    if not isinstance(parsed, dict):
        return [], ["phase-1 reviewer response must be a JSON object"]
    raw_hyps = parsed.get("hypotheses")
    if not isinstance(raw_hyps, list) or not raw_hyps or any(not isinstance(h, str) or not h.strip() for h in raw_hyps):
        return [], ["phase-1 reviewer response must contain a non-empty list of non-blank failure hypotheses"]
    return [h.strip() for h in raw_hyps], []


def evaluate_upstream_evidence(
    candidate_sha: str, base_sha: str, qa_record: dict[str, Any] | None,
    security_record: dict[str, Any] | None, *, home: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    gaps: list[dict[str, Any]] = []
    if not isinstance(qa_record, dict) or not qa_record:
        qa_eval = {"status": "qa-missing", "verified": False, "blockers": [f"missing automated QA evidence for candidate {candidate_sha}"]}
    elif str(qa_record.get("candidate_sha") or "") != candidate_sha or str(qa_record.get("base_sha") or "") != base_sha:
        qa_eval = {
            "status": "stale-qa-evidence", "verified": False,
            "blockers": [f"stale automated QA evidence: qa=({qa_record.get('candidate_sha')}, base={qa_record.get('base_sha')}) != candidate=({candidate_sha}, base={base_sha})"],
        }
    elif not bool(qa_record.get("qa_verified")) or str(qa_record.get("status") or "") != "qa-verified" or bool(qa_record.get("open_finding_ids")):
        qa_eval = {
            "status": str(qa_record.get("status") or "qa-failed"), "verified": False,
            "blockers": [f"automated QA not verified on {candidate_sha} (status={qa_record.get('status')!r}, open_findings={qa_record.get('open_finding_ids')})"],
        }
    else:
        qa_eval = {"status": "qa-verified", "verified": True, "blockers": []}

    if not qa_eval["verified"]:
        rule = "stale-qa-evidence" if qa_eval["status"] == "stale-qa-evidence" else "qa-evidence-unverified"
        gaps.append({
            "finding_id": compute_review_finding_id("verification-gap", "automated-qa", rule),
            "category": "verification-gap", "blocking": True, "target": "automated-qa", "rule": rule,
            "title": f"Automated QA evidence gap ({qa_eval['status']})",
            "evidence": "; ".join(qa_eval["blockers"]),
            "actionable_correction": f"Run automated QA on candidate {candidate_sha} (base {base_sha}) and resolve all QA findings before independent review.",
            "source": "observed-upstream-gate",
        })

    sec_eval = security_review.evaluate_security_review_gate(candidate_sha, base_sha, security_record, home=home)
    if not sec_eval["verified"]:
        rule = "stale-security-evidence" if sec_eval["status"] == "stale-security-review" else "security-evidence-unverified"
        gaps.append({
            "finding_id": compute_review_finding_id("verification-gap", "security-review", rule),
            "category": "verification-gap", "blocking": True, "target": "security-review", "rule": rule,
            "title": f"Security review evidence gap ({sec_eval['status']})",
            "evidence": "; ".join(sec_eval["blockers"]),
            "actionable_correction": f"Run security review on candidate {candidate_sha} (base {base_sha}) and resolve all security blockers before independent review.",
            "source": "observed-upstream-gate",
        })
    return qa_eval, sec_eval, gaps


def _parse_phase2_response(
    response_text: str,
) -> tuple[str | None, dict[str, dict[str, str]], list[dict[str, Any]], list[str]]:
    text = (response_text or "").strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None, {}, [], ["phase-2 reviewer response must be a raw JSON object without markdown fences"]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, {}, [], [f"phase-2 reviewer response is not valid JSON: {exc}"]
    if not isinstance(parsed, dict):
        return None, {}, [], ["phase-2 reviewer response must be a JSON object"]
    outcome = parsed.get("outcome")
    if outcome not in ("review-passed", "changes-requested"):
        return None, {}, [], [f"phase-2 reviewer response has invalid or missing outcome {outcome!r}"]

    raw_assess = parsed.get("assessment")
    if not isinstance(raw_assess, dict):
        return outcome, {}, [], ["phase-2 reviewer response is missing an 'assessment' object"]
    assessment: dict[str, dict[str, str]] = {}
    issues: list[str] = []
    for key in ASSESSMENT_KEYS:
        entry = raw_assess.get(key)
        if not isinstance(entry, dict):
            issues.append(f"assessment is missing required dimension {key!r}")
            continue
        st = str(entry.get("status") or "").strip()
        summ = str(entry.get("summary") or "").strip()
        if st not in ("satisfied", "unsatisfied") or not summ:
            issues.append(f"assessment dimension {key!r} must have status in ('satisfied', 'unsatisfied') and non-empty summary")
            continue
        assessment[key] = {"status": st, "summary": summ}

    raw_findings = parsed.get("findings")
    if not isinstance(raw_findings, list) or any(not isinstance(item, dict) for item in raw_findings):
        return outcome, assessment, [], [*issues, "phase-2 reviewer response is missing a valid 'findings' list of objects"]

    findings: list[dict[str, Any]] = []
    for idx, raw in enumerate(raw_findings):
        cat = str(raw.get("category") or "").strip()
        if cat not in FINDING_CATEGORIES:
            issues.append(f"finding[{idx}] has unsupported category {cat!r}")
            continue
        raw_blk = raw.get("blocking")
        if cat == "non-blocking-suggestion":
            if raw_blk is True:
                issues.append(f"finding[{idx}] category 'non-blocking-suggestion' cannot have blocking=True")
                continue
            blocking = False
        else:
            if raw_blk is False:
                issues.append(f"finding[{idx}] blocking category {cat!r} cannot have blocking=False")
                continue
            blocking = True
        target = str(raw.get("target") or raw.get("file_path") or raw.get("criterion_id") or "").strip()
        rule = str(raw.get("rule") or "").strip()
        title = str(raw.get("title") or rule or cat).strip()
        evidence = str(raw.get("evidence") or "").strip()
        correction = str(raw.get("actionable_correction") or "").strip()
        if blocking:
            if not target or not rule:
                issues.append(f"blocker finding[{idx}] requires explicit non-empty 'target' and 'rule' for stable identity")
                continue
            if not evidence:
                issues.append(f"blocker finding[{idx}] ({target}:{rule}) is missing concrete 'evidence'")
                continue
            if not correction:
                issues.append(f"blocker finding[{idx}] ({target}:{rule}) is missing 'actionable_correction'")
                continue
        else:
            target = target or "repository"
            rule = rule or SLUG_RE.sub("-", title.lower()).strip("-") or "suggestion"
        fid = compute_review_finding_id(cat, target, rule)
        findings.append({
            "finding_id": fid, "category": cat, "blocking": blocking, "target": target, "rule": rule,
            "title": title, "evidence": evidence or f"Suggestion on {target}",
            "actionable_correction": correction or "Optional maintainability improvement.",
            "source": "reviewer-agent",
        })

    has_blocking = any(f["blocking"] for f in findings)
    if outcome == "review-passed" and has_blocking:
        issues.append("reviewer reported outcome='review-passed' despite blocking findings")
    if outcome == "changes-requested" and not has_blocking and all(v.get("status") == "satisfied" for v in assessment.values()):
        issues.append("reviewer reported outcome='changes-requested' without any blocking findings or unsatisfied assessment dimensions")
    return outcome, assessment, findings, issues


def _run_observed_verification(
    worktree: Path, verify_dir: Path, home: Path, child: dict[str, Any], conf: config_module.Config,
    changed_paths: tuple[str, ...], deleted_paths: tuple[str, ...], candidate_sha: str,
    secrets: tuple[str, ...], deadline: float, limit_s: int,
) -> dict[str, Any]:
    plan = ci_selection.select_ci_test_plan(child, conf, changed_paths, deleted_paths=deleted_paths, repo=worktree)
    verify_home = safe_dir(verify_dir / "verify-home", create=True, root=home)
    safe_dir(verify_home / ".tmp", create=True, root=home)
    env, _ = worker_module.sanitized_env(dict(os.environ), worktree, verify_home)
    if (worktree / "tests").is_dir():
        env["PYTHONPATH"] = "tests:."
    specs: list[tuple[str, str, str, tuple[str, ...] | None, str]] = []
    for guard in plan.get("essential_guards") or []:
        gid = str(guard.get("id") or "")
        g_cfg = conf.gates.get(gid.removeprefix("gate-"))
        if g_cfg is not None and g_cfg.kind == "command" and g_cfg.argv:
            specs.append((str(guard["name"]), "guard", gid, tuple(g_cfg.argv), " ".join(g_cfg.argv)))
    criteria_list = list(child.get("criteria") or [])
    for crit in criteria_list:
        cid = str(crit.get("id") or "AC").strip()
        vcmd = str(crit.get("verification") or "").strip()
        argv = deliver_checks._verification_argv(vcmd)
        if argv is not None and ci_selection.WEAKENED_CMD_RE.search(vcmd):
            argv = None
        specs.append((f"criterion/{cid}", "criterion", cid, argv, vcmd))
    if plan.get("mode") == "affected-only" and plan.get("affected_tests"):
        aff = tuple(str(t).strip() for t in plan["affected_tests"] if str(t).strip())
        if aff:
            specs.append(("regression/affected-tests", "regression", "regression-suite", (sys.executable, "-m", "unittest", *aff, "-v"), f"unittest {' '.join(aff)}"))
    gate2 = conf.gates.get("2")
    if gate2 is not None and gate2.kind == "command" and gate2.argv:
        specs.append(("regression/gate-2", "regression", "gate-2", tuple(gate2.argv), " ".join(gate2.argv)))

    checks: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    if not criteria_list:
        gaps.append({
            "finding_id": compute_review_finding_id("verification-gap", "criteria", "missing-criteria"),
            "category": "verification-gap", "blocking": True, "target": "criteria", "rule": "missing-criteria",
            "title": "Sub-task has no acceptance criteria to verify",
            "evidence": "child.criteria is empty",
            "actionable_correction": "Define executable acceptance criteria on the sub-task before independent review.",
            "source": "observed-verification",
        })
    if not specs:
        gaps.append({
            "finding_id": compute_review_finding_id("verification-gap", "verification-plan", "no-executable-checks"),
            "category": "verification-gap", "blocking": True, "target": "verification-plan", "rule": "no-executable-checks",
            "title": "No executable verification checks configured for candidate",
            "evidence": f"selection plan produced 0 checks on {candidate_sha}",
            "actionable_correction": "Configure required criterion and regression checks before independent review.",
            "source": "observed-verification",
        })

    all_ok = bool(criteria_list) and bool(specs)
    for name, kind, concern_id, argv, raw_cmd in specs:
        stem = f"ind-verify-{SLUG_RE.sub('-', name.lower()).strip('-')}"
        if not argv:
            msg = redact_value(f"unexecutable or missing verification command for {concern_id}: {raw_cmd!r}\n", secrets)
            ev_path = write_evidence(verify_dir, stem, msg, home)
            all_ok = False
            checks.append({
                "name": name, "kind": kind, "assesses": concern_id, "command": redact_value(raw_cmd, secrets),
                "argv": [], "executed": False, "exit_code": None, "ok": False, "timed_out": False, "duration_ms": 0,
                "head_sha": candidate_sha, "output_path": str(ev_path), "output_sha256": runner.digest_text(msg),
                "output_excerpt": msg.strip()[:400], "provenance": "observed-independent-verification",
            })
            gaps.append({
                "finding_id": compute_review_finding_id("verification-gap", concern_id, "unexecutable-check"),
                "category": "verification-gap", "blocking": True, "target": concern_id, "rule": "unexecutable-check",
                "title": f"Missing or unexecutable check for {concern_id}",
                "evidence": msg.strip(),
                "actionable_correction": f"Provide an executable verification command for {concern_id} without skip flags.",
                "source": "observed-verification",
            })
            continue
        try:
            timeout_s = max(1, int(math.ceil(remaining_seconds(deadline, f"independent verification {name}", limit_s))))
            code, out_s, err_s, elapsed_ms, timed_out = worker_module.execute_stream(
                worktree, argv, env, timeout_s, isolated_home=verify_home, allow_network=False,
            )
        except (deliver_checks.AttemptTimeoutError, TimeoutError) as exc:
            code, out_s, err_s, elapsed_ms, timed_out = 124, "", f"[factory] check timed out: {exc}\n", 0, True
        except (worker_module.SandboxUnavailableError, OSError) as exc:
            code, out_s, err_s, elapsed_ms, timed_out = 1, "", f"[factory] check execution error: {exc}\n", 0, False
        combined = redact_value((out_s + err_s).strip() + "\n", secrets)
        ev_path = write_evidence(verify_dir, stem, combined, home)
        ok = code == 0 and not timed_out
        all_ok = all_ok and ok
        checks.append({
            "name": name, "kind": kind, "assesses": concern_id, "command": redact_value(raw_cmd, secrets),
            "argv": list(redact_value(list(argv), secrets)), "executed": not timed_out, "exit_code": code,
            "ok": ok, "timed_out": timed_out, "duration_ms": elapsed_ms, "head_sha": candidate_sha,
            "output_path": str(ev_path), "output_sha256": runner.digest_text(combined),
            "output_excerpt": combined.strip()[:400], "provenance": "observed-independent-verification",
        })
        if not ok:
            rule = "check-timed-out" if timed_out else "check-failed"
            gaps.append({
                "finding_id": compute_review_finding_id("verification-gap", concern_id, rule),
                "category": "verification-gap", "blocking": True, "target": concern_id, "rule": rule,
                "title": f"Observed verification check {name} {'timed out' if timed_out else 'failed'} (exit {code})",
                "evidence": f"command={raw_cmd!r} exit_code={code} output_path={ev_path}: {combined.strip()[:240]}",
                "actionable_correction": f"Fix candidate {candidate_sha} so `{raw_cmd}` exits 0 within the timeout.",
                "source": "observed-verification",
            })

    return {
        "executed": True, "ok": all_ok and len(gaps) == 0, "head_sha": candidate_sha,
        "selection_plan": plan, "checks": checks, "verification_gaps": gaps,
        "provenance": "observed-independent-verification",
    }


def _check_worktree_mutation(
    worktree: Path, expected_sha: str, round_dir: Path, home: Path, phase_label: str, secrets: tuple[str, ...],
) -> dict[str, Any]:
    head_after = gitio.head(worktree)
    status_out = gitio.status_porcelain(worktree)
    mutated = head_after != expected_sha or bool(status_out.strip())
    evidence_path = None
    if mutated:
        diff_res = gitio.git(worktree, "diff", "--binary", expected_sha)
        snap = redact_value(
            f"phase={phase_label}\nexpected_sha={expected_sha}\nhead_after={head_after}\n"
            f"status_porcelain:\n{status_out}\ndiff:\n{diff_res.output}\n",
            secrets,
        )
        evidence_path = str(write_evidence(round_dir, f"reviewer-mutation-{phase_label}", snap, home))
    return {
        "phase": phase_label, "head_before": expected_sha, "head_after": head_after,
        "status_porcelain": redact_value(status_out, secrets), "worktree_clean": not mutated,
        "candidate_modified_by_reviewer": mutated, "mutation_evidence_path": evidence_path,
    }


def review_candidate_independently(
    *, repo: Path, home: Path, child_dir: Path, child: dict[str, Any], conf: config_module.Config,
    base_sha: str, candidate_sha: str, builder_session_id: str | None, builder_summary: str = "",
    qa_record: dict[str, Any] | None = None, security_record: dict[str, Any] | None = None,
    round_num: int = 1, agy_bin: str | None = None, deadline: float, limit_s: int,
) -> dict[str, Any]:
    round_dir = safe_dir(child_dir / f"independent-review-round-{round_num}", create=True, root=home)
    worktree = round_dir / "worktree"
    isolated_home = worker_module.prepare_isolated_home(round_dir, Path.home(), root=home)
    safe_dir(isolated_home / ".tmp", create=True, root=home)
    worker_env, stripped_keys = worker_module.sanitized_env(dict(os.environ), worktree, isolated_home)
    secrets = collect_redaction_secrets()
    resolved_sha = worker_module.prepare_isolated_git_checkout(repo, worktree, candidate_sha, deadline=deadline)

    try:
        fetch_res = git_timed(worktree, deadline, limit_s, "fetch base_sha", "fetch", "-q", "--no-tags", str(repo), base_sha)
        rev_res = git_timed(worktree, deadline, limit_s, "verify base_sha", "rev-parse", "--verify", f"{base_sha}^{{commit}}")
        (worktree / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
        base_ok = fetch_res.ok and rev_res.ok

        probes, probes_ok, sandbox_error = [], False, None
        try:
            if agy_bin and str(agy_bin).strip():
                worker_module.validate_execution_options(worker_module.platform_info(), time_limit_seconds=limit_s, agy_bin=str(agy_bin))
            probes = worker_module.run_safety_probes(worker_env, worktree, round_dir, home, deadline=deadline)
            probes_ok = worker_module.probes_passed(probes)
        except worker_module.SandboxUnavailableError as exc:
            sandbox_error = str(exc)

        name_status = git_timed(worktree, deadline, limit_s, "diff name-status", "diff", "--find-renames", "--name-status", base_sha, resolved_sha)
        del_res = git_timed(worktree, deadline, limit_s, "diff deleted", "diff", "--diff-filter=D", "--name-only", base_sha, resolved_sha)
        deleted_paths = tuple(p for ln in (del_res.output.splitlines() if del_res.ok else ()) if (p := ln.strip().strip("/")))
        diff_info = inspect_diff_categories(worktree, base_sha, resolved_sha, deadline, limit_s)
        gate3 = conf.gates.get("3")
        protected = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
        scope_ok, scope_violations, scope_detail = evaluate_scope(tuple(diff_info["changed_paths"]), child, protected)
        diff_res = git_timed(worktree, deadline, limit_s, "independent review diff", "diff", "--binary", base_sha, resolved_sha)
        diff_ok = base_ok and name_status.ok and diff_res.ok and bool(diff_res.output.strip())
        if not diff_ok:
            scope_detail = {**scope_detail, "status": "diff-failed", "deterministic_ok": False}
            scope_ok = False
        diff_text = redact_value(diff_res.output + ("\n" if not diff_res.output.endswith("\n") else ""), secrets)
        diff_path = write_evidence(round_dir, "reviewed-diff", diff_text, home)
        standards = load_project_standards(repo, base_sha, child, conf, deadline, limit_s)
        qa_eval, sec_eval, upstream_gaps = evaluate_upstream_evidence(resolved_sha, base_sha, qa_record, security_record, home=home)

        role_issues: list[str] = []
        if sandbox_error:
            role_issues.append(f"sandbox unavailable: {sandbox_error}")
        elif not probes_ok:
            role_issues.append("independent reviewer safety probes failed")
        if not diff_ok:
            role_issues.append("failed to produce non-empty exact base-to-candidate diff")

        b_sid = str(builder_session_id or "").strip()
        if not b_sid:
            role_issues.append("missing builder_session_id; builder identity evidence is required to prove session separation")
        if not (agy_bin and str(agy_bin).strip()):
            role_issues.append("independent reviewer executable is required; missing reviewer execution fails closed")

        p1_prompt = build_phase1_prompt(child, base_sha, resolved_sha, diff_text, standards)
        p1_prompt_red = redact_value(p1_prompt, secrets)
        p1_prompt_path = write_evidence(round_dir, "phase1-prompt", p1_prompt_red, home)
        summary_norm = (builder_summary or "").strip()
        p1_omitted_summary = (not summary_norm or summary_norm not in p1_prompt) and "Builder Summary" not in p1_prompt and "Builder summary:" not in p1_prompt
        p1_has_exact_diff = bool(diff_res.output.strip()) and diff_text.strip() in p1_prompt_red
        if not p1_omitted_summary:
            role_issues.append("protocol violation: phase-1 prompt exposed builder summary before hypotheses were recorded")
        if not p1_has_exact_diff:
            role_issues.append("protocol violation: phase-1 prompt did not include exact base-to-candidate diff")

        p1_executed, p2_executed = False, False
        p1_stdout_path, p1_stderr_path, p2_stdout_path, p2_stderr_path = None, None, None, None
        p2_prompt_path, hypotheses_path, hypotheses_sha256 = None, None, None
        hypotheses: list[str] = []
        reviewer_session_id: str | None = None
        phase2_session_id: str | None = None
        agent_outcome: str | None = None
        assessment: dict[str, dict[str, str]] = {}
        agent_findings: list[dict[str, Any]] = []
        p1_mut = _check_worktree_mutation(worktree, resolved_sha, round_dir, home, "pre-phase1", secrets)
        p2_mut = p1_mut

        can_run_p1 = (
            probes_ok and diff_ok and bool(b_sid) and bool(agy_bin and str(agy_bin).strip())
            and p1_omitted_summary and p1_has_exact_diff
        )
        if can_run_p1:
            argv1 = (str(agy_bin), "--print", p1_prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
            t1 = max(1, int(math.ceil(remaining_seconds(deadline, "independent review phase 1", limit_s))))
            try:
                c1, out1, err1, _, to1 = worker_module.execute_stream(worktree, argv1, worker_env, t1, isolated_home=isolated_home)
                p1_executed = True
                p1_stdout_path = str(write_evidence(round_dir, "phase1-stdout", redact_value(out1, secrets), home))
                p1_stderr_path = str(write_evidence(round_dir, "phase1-stderr", redact_value(err1, secrets), home))
                ev1, res1, perr1 = worker_module.parse_stream_events(out1)
                denied1 = worker_module.has_permission_denial(ev1, res1, err1)
                p1_mut = _check_worktree_mutation(worktree, resolved_sha, round_dir, home, "phase1", secrets)
                if p1_mut["candidate_modified_by_reviewer"]:
                    role_issues.append("independent reviewer mutated the candidate worktree during phase 1")
                if to1 or perr1 is not None or denied1 or c1 != 0 or not isinstance(res1, dict) or res1.get("status") != "SUCCESS":
                    role_issues.append(f"phase-1 reviewer execution failed (exit={c1}, parse_error={perr1})")
                else:
                    reviewer_session_id = str(res1.get("conversation_id") or "").strip() or None
                    if not reviewer_session_id:
                        role_issues.append("phase-1 reviewer did not record a conversation_id")
                    elif reviewer_session_id == b_sid:
                        role_issues.append(f"independent reviewer session {reviewer_session_id!r} matches builder session {b_sid!r}; self-approval is forbidden")
                    else:
                        hypotheses, hyp_issues = _parse_phase1_hypotheses(str(res1.get("response") or ""))
                        role_issues.extend(hyp_issues)
                        if hypotheses and not hyp_issues and not p1_mut["candidate_modified_by_reviewer"]:
                            hyp_payload = json.dumps({
                                "reviewer_session_id": reviewer_session_id, "candidate_sha": resolved_sha,
                                "base_sha": base_sha, "hypotheses": redact_value(hypotheses, secrets),
                            }, indent=2, sort_keys=True) + "\n"
                            hyp_file = write_evidence(round_dir, "phase1-hypotheses", hyp_payload, home)
                            hypotheses_path = str(hyp_file)
                            hypotheses_sha256 = runner.digest_text(hyp_payload)
            except worker_module.SandboxUnavailableError as exc:
                role_issues.append(f"sandbox unavailable during phase 1: {exc}")

        if hypotheses_path is not None and not role_issues:
            p2_prompt = build_phase2_prompt(child, base_sha, resolved_sha, hypotheses, builder_summary, qa_eval, sec_eval)
            p2_prompt_red = redact_value(p2_prompt, secrets)
            p2_prompt_path = str(write_evidence(round_dir, "phase2-prompt", p2_prompt_red, home))
            argv2 = (str(agy_bin), "--print", p2_prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
            t2 = max(1, int(math.ceil(remaining_seconds(deadline, "independent review phase 2", limit_s))))
            try:
                c2, out2, err2, _, to2 = worker_module.execute_stream(worktree, argv2, worker_env, t2, isolated_home=isolated_home)
                p2_executed = True
                p2_stdout_path = str(write_evidence(round_dir, "phase2-stdout", redact_value(out2, secrets), home))
                p2_stderr_path = str(write_evidence(round_dir, "phase2-stderr", redact_value(err2, secrets), home))
                ev2, res2, perr2 = worker_module.parse_stream_events(out2)
                denied2 = worker_module.has_permission_denial(ev2, res2, err2)
                p2_mut = _check_worktree_mutation(worktree, resolved_sha, round_dir, home, "phase2", secrets)
                if p2_mut["candidate_modified_by_reviewer"]:
                    role_issues.append("independent reviewer mutated the candidate worktree during phase 2")
                if to2 or perr2 is not None or denied2 or c2 != 0 or not isinstance(res2, dict) or res2.get("status") != "SUCCESS":
                    role_issues.append(f"phase-2 reviewer execution failed (exit={c2}, parse_error={perr2})")
                else:
                    phase2_session_id = str(res2.get("conversation_id") or "").strip() or None
                    if not phase2_session_id:
                        role_issues.append("phase-2 reviewer did not record a conversation_id")
                    elif phase2_session_id == b_sid:
                        role_issues.append(f"phase-2 reviewer session {phase2_session_id!r} matches builder session {b_sid!r}")
                    elif phase2_session_id != reviewer_session_id:
                        role_issues.append(f"phase-2 reviewer session {phase2_session_id!r} drifted from phase-1 session {reviewer_session_id!r}")
                    else:
                        agent_outcome, assessment, agent_findings, p2_issues = _parse_phase2_response(str(res2.get("response") or ""))
                        role_issues.extend(p2_issues)
            except worker_module.SandboxUnavailableError as exc:
                role_issues.append(f"sandbox unavailable during phase 2: {exc}")

        worktree_mutated = bool(p1_mut["candidate_modified_by_reviewer"] or p2_mut["candidate_modified_by_reviewer"])
        mutation_record = p2_mut if p2_mut["candidate_modified_by_reviewer"] else p1_mut

        if probes_ok and diff_ok and not worktree_mutated:
            obs_ver = _run_observed_verification(
                worktree, round_dir, home, child, conf, tuple(diff_info["changed_paths"]),
                deleted_paths, resolved_sha, secrets, deadline, limit_s,
            )
            post_ver_mut = _check_worktree_mutation(worktree, resolved_sha, round_dir, home, "post-verification", secrets)
            if post_ver_mut["candidate_modified_by_reviewer"]:
                worktree_mutated = True
                mutation_record = post_ver_mut
                role_issues.append("candidate worktree was mutated during verification checks")
        else:
            obs_ver = {
                "executed": False, "ok": False, "head_sha": resolved_sha, "selection_plan": {},
                "checks": [], "verification_gaps": [], "provenance": "skipped-due-to-role-or-mutation-failure",
            }

        deterministic_findings: list[dict[str, Any]] = []
        for sv in ([] if scope_ok else scope_violations):
            rule_slug = SLUG_RE.sub("-", sv.lower()).strip("-")[:32] or "out-of-scope"
            deterministic_findings.append({
                "finding_id": compute_review_finding_id("scope-drift", "scope", rule_slug),
                "category": "scope-drift", "blocking": True, "target": "scope", "rule": rule_slug,
                "title": f"Scope or protected-path drift: {sv}",
                "evidence": sv,
                "actionable_correction": "Revert out-of-scope or protected-path modifications so the diff stays within declared sub-task scope.",
                "source": "observed-scope-check",
            })
        deterministic_findings.extend(upstream_gaps)
        deterministic_findings.extend(obs_ver.get("verification_gaps") or [])

        by_fid: dict[str, dict[str, Any]] = {}
        for item in (*agent_findings, *deterministic_findings):
            fid = str(item["finding_id"])
            if fid not in by_fid or item.get("source") != "reviewer-agent":
                by_fid[fid] = item
        all_findings = list(by_fid.values())
        blocking_findings = [f for f in all_findings if f.get("blocking")]
        suggestions = [f for f in all_findings if not f.get("blocking")]

        unsatisfied_dims = [k for k, v in assessment.items() if v.get("status") != "satisfied"]
        protocol_ordering = {
            "enforced": bool(p1_omitted_summary and p1_has_exact_diff and hypotheses_path is not None and p2_executed),
            "phase_1_executed": p1_executed,
            "phase_1_omitted_builder_summary": p1_omitted_summary,
            "phase_1_included_exact_diff": p1_has_exact_diff,
            "phase_1_prompt_path": str(p1_prompt_path),
            "phase_1_stdout_path": p1_stdout_path,
            "phase_1_stderr_path": p1_stderr_path,
            "hypotheses_persisted_before_summary": hypotheses_path is not None,
            "hypotheses_path": hypotheses_path,
            "hypotheses_sha256": hypotheses_sha256,
            "phase_2_executed": p2_executed,
            "phase_2_prompt_path": p2_prompt_path,
            "phase_2_stdout_path": p2_stdout_path,
            "phase_2_stderr_path": p2_stderr_path,
        }

        role_sep_ok = (
            p1_executed and p2_executed and bool(reviewer_session_id) and bool(b_sid)
            and reviewer_session_id != b_sid and phase2_session_id == reviewer_session_id
            and protocol_ordering["enforced"] and not worktree_mutated and len(role_issues) == 0
        )

        if not role_sep_ok:
            outcome = "invalid-review"
        elif blocking_findings or unsatisfied_dims or agent_outcome == "changes-requested" or not obs_ver["ok"] or not qa_eval["verified"] or not sec_eval["verified"]:
            outcome = "changes-requested"
        else:
            outcome = "review-passed"

        review_verified = (
            outcome == "review-passed" and role_sep_ok and obs_ver["ok"]
            and qa_eval["verified"] and sec_eval["verified"] and len(blocking_findings) == 0
        )

        record = redact_value({
            "schema": 1,
            "role": "independent-reviewer",
            "builder_role": "builder",
            "verification_scope": INDEPENDENT_REVIEW_SCOPE_NOTE,
            "delivery_approved": False,
            "round": round_num,
            "reviewed_revision": resolved_sha,
            "base_sha": base_sha,
            "standards_sha": base_sha,
            "builder_session_id": b_sid or None,
            "reviewer_session_id": reviewer_session_id,
            "reviewer_executed": p1_executed and p2_executed,
            "role_separation_verified": role_sep_ok,
            "role_issues": role_issues,
            "protocol_ordering": protocol_ordering,
            "failure_hypotheses": hypotheses,
            "builder_summary_claim": {
                "summary": builder_summary,
                "treated_as_execution_evidence": False,
                "contradicted_by_observed_execution": bool(
                    summary_norm and (not obs_ver["ok"] or not qa_eval["verified"] or not sec_eval["verified"] or blocking_findings)
                ),
            },
            "inspected_scope": {
                "changed_paths": diff_info["changed_paths"],
                "deleted_paths": list(deleted_paths),
                "implementation_paths": diff_info["implementation_paths"],
                "test_paths": diff_info["test_paths"],
                "scope_status": scope_detail["status"],
                "deterministic_ok": scope_detail["deterministic_ok"],
                "diff_path": str(diff_path),
                "diff_sha256": runner.digest_text(diff_text),
            },
            "applicable_standards": standards,
            "assessment": assessment,
            "upstream_evidence": {
                "automated_qa": qa_eval,
                "security_review": sec_eval,
            },
            "observed_verification": obs_ver,
            "findings": all_findings,
            "blocking_findings": blocking_findings,
            "non_blocking_suggestions": suggestions,
            "worktree_integrity": mutation_record,
            "safety": {
                "sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False,
                "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": probes,
            },
            "outcome": outcome,
            "review_verified": review_verified,
            "recorded_at": now(),
        }, secrets)
        atomic_json(round_dir / "record.json", record, home)
        atomic_json(child_dir / "independent-review.json", record, home)
        return record
    finally:
        shutil.rmtree(worktree, ignore_errors=True)


__all__ = [
    "ASSESSMENT_KEYS",
    "BASELINE_PROJECT_STANDARDS",
    "FINDING_CATEGORIES",
    "INDEPENDENT_REVIEW_SCOPE_NOTE",
    "build_phase1_prompt",
    "build_phase2_prompt",
    "compute_review_finding_id",
    "evaluate_upstream_evidence",
    "load_project_standards",
    "review_candidate_independently",
]
