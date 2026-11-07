"""Standalone independent reviewer role, observed verification, and blocker reconciliation (Issues #52, #55; Part 1 & 2a of #23)."""
from __future__ import annotations
import ctypes, hashlib, json, math, os, re, shutil, stat, sys, time
from pathlib import Path
from typing import Any
from factory import ci_gate, ci_selection, config as config_module, deliver_checks, errors as errors_module, gitio, runner, security_review, worker as worker_module
from factory.config import now
from factory.deliver_checks import collect_redaction_secrets, evaluate_scope, git_timed, inspect_diff_categories, remaining_seconds
from factory.intake import redact_value
from factory.paths import atomic_json, read_json, safe_dir, write_evidence

INDEPENDENT_REVIEW_SCOPE_NOTE = "standalone-independent-review-only; not delivery-approval-gated (#53), merge-approved (#24), or parent-accepted"
SLUG_RE = re.compile(r"[^a-z0-9]+")
FINDING_CATEGORIES = frozenset({"missing-behavior", "bug", "verification-gap", "scope-drift", "non-blocking-suggestion"})
ASSESSMENT_KEYS = ("requirement_compliance", "project_standards", "criterion_coverage", "edge_cases", "test_effectiveness", "qa_security_outcomes")
RESOLUTION_CLAIMS = frozenset({"fixed", "no-longer-applicable", "open", "unresolved", "thread-closed", "comment-resolved", "dismissed"})
BASELINE_PROJECT_STANDARDS: tuple[dict[str, str], ...] = (
    {"id": "STD-SCOPE-01", "name": "subtask-scope-and-protected-paths", "source": "factory-policy", "description": "Keep changes within declared sub-task scope and preserve protected policy and verification paths."},
    {"id": "STD-TEST-01", "name": "observable-behavior-and-regression-coverage", "source": "factory-policy", "description": "Verify acceptance criteria and edge cases with deterministic executable tests without weakening checks."},
)

def compute_review_finding_id(category: str, target: str, rule_or_concern: str) -> str:
    cat_slug = SLUG_RE.sub("-", (category or "").strip().lower()).strip("-").upper() or "FINDING"
    tgt_slug = SLUG_RE.sub("-", (target or "").strip().lower()).strip("-") or "repository"
    rule_slug = SLUG_RE.sub("-", (rule_or_concern or "").strip().lower()).strip("-") or "concern"
    return f"REV-{cat_slug}-{tgt_slug}-{rule_slug}"

def _gap_finding(target: str, rule: str, title: str, evidence: str, correction: str, source: str, cat: str = "verification-gap", vcmd: str = "") -> dict[str, Any]:
    return {"finding_id": compute_review_finding_id(cat, target, rule), "category": cat, "blocking": True, "target": target, "rule": rule, "title": title, "evidence": evidence, "actionable_correction": correction, "verification_command": vcmd, "source": source}

def _normalize_prior_findings(child_dir: Path, home: Path, round_num: int, prior_findings: list[dict[str, Any]] | None, *, recovered_out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    disk_items: list[dict[str, Any]] = []
    corrupt_err: str | None = None
    paths = [*(child_dir / f"independent-review-round-{r}" / "record.json" for r in range(1, max(round_num, 1))), *((child_dir / "prior-blockers.json",) if round_num > 1 or (child_dir / "prior-blockers.json").exists() or (child_dir / "prior-blockers.json").is_symlink() else ())]
    for p in paths:
        if p.exists() or p.is_symlink():
            try:
                rec = read_json(p, home)
                items = rec.get("findings") if isinstance(rec, dict) and "findings" in rec else (rec.get("blocking_findings") if isinstance(rec, dict) else None)
                if not isinstance(rec, dict) or not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                    corrupt_err = corrupt_err or f"corrupt prior review history structure in {p}"
                else:
                    disk_items.extend(dict(item) for item in items)
            except (errors_module.FactoryError, OSError) as exc:
                corrupt_err = corrupt_err or f"unreadable or corrupt prior review history in {p}: {exc}"
    if prior_findings is not None and (not isinstance(prior_findings, list) or any(not isinstance(f, dict) for f in prior_findings)):
        corrupt_err = corrupt_err or "prior_findings must be a list of finding objects"
    by_id: dict[str, dict[str, Any]] = {}
    for raw in (*disk_items, *(dict(f) for f in (prior_findings if isinstance(prior_findings, list) else ()) if isinstance(f, dict))):
        cat = str(raw.get("category") or "bug").strip()
        target = str(raw.get("target") or raw.get("file_path") or raw.get("criterion_id") or "repository").strip()
        rule = str(raw.get("rule") or raw.get("title") or "concern").strip()
        fid = compute_review_finding_id(cat, target, rule) if (cat in FINDING_CATEGORIES and raw.get("target") and raw.get("rule")) else (str(raw.get("finding_id") or "").strip() or compute_review_finding_id(cat, target, rule))
        if not raw.get("blocking", cat != "non-blocking-suggestion"): continue
        prev = by_id.get(fid, {})
        hist_map = {int(h["round"]): dict(h) for h in (*(prev.get("history") or ()), *(raw.get("history") or ())) if isinstance(h, dict) and isinstance(h.get("round"), int)}
        hist = [hist_map[k] for k in sorted(hist_map)]
        ev_hist: list[dict[str, Any]] = []
        for e in (*(prev.get("evidence_history") or ()), *(raw.get("evidence_history") or ())):
            if isinstance(e, dict) and not any(x.get("round") == e.get("round") and x.get("evidence") == e.get("evidence") for x in ev_hist): ev_hist.append(dict(e))
        intro_round = int(prev.get("introduced_in_round") or raw.get("introduced_in_round") or raw.get("created_round") or 1)
        intro_rev = str(prev.get("introduced_in_revision") or raw.get("introduced_in_revision") or raw.get("created_candidate_sha") or raw.get("last_seen_revision") or "")
        orig_ev = str(prev.get("evidence") or raw.get("evidence") or "")
        latest_ev = str(raw.get("latest_evidence") or raw.get("evidence") or prev.get("latest_evidence") or orig_ev)
        if orig_ev and not ev_hist:
            ev_hist.append({"round": intro_round, "candidate_sha": intro_rev, "evidence": orig_ev, "actionable_correction": str(raw.get("actionable_correction") or ""), "source": str(raw.get("source") or "reviewer-agent")})
        if not hist:
            hist.append({"round": intro_round, "candidate_sha": intro_rev, "status": str(raw.get("status") or "open"), "resolution_blocker": raw.get("resolution_blocker"), "evidence": orig_ev, "verification_command": str(raw.get("verification_command") or ""), "reproducer_verification": raw.get("reproducer_verification"), "resolution_evidence": raw.get("resolution_evidence")})
        by_id[fid] = {
            **prev, **raw, "finding_id": fid, "category": cat if cat in FINDING_CATEGORIES else "bug", "blocking": True, "target": target, "rule": rule,
            "title": str(prev.get("title") or raw.get("title") or rule), "evidence": orig_ev, "latest_evidence": latest_ev,
            "actionable_correction": str(raw.get("actionable_correction") or prev.get("actionable_correction") or ""),
            "verification_command": str(raw.get("verification_command") or prev.get("verification_command") or "").strip(),
            "source": str(prev.get("source") or raw.get("source") or "reviewer-agent"), "status": str(raw.get("status") or prev.get("status") or "open"),
            "introduced_in_round": intro_round, "created_round": intro_round, "introduced_in_revision": intro_rev, "created_candidate_sha": intro_rev,
            "last_seen_round": int(raw.get("last_seen_round") or raw.get("latest_round") or prev.get("last_seen_round") or intro_round),
            "last_seen_revision": str(raw.get("last_seen_revision") or raw.get("latest_candidate_sha") or prev.get("last_seen_revision") or intro_rev),
            "resolved_in_round": raw.get("resolved_in_round") if raw.get("resolved_in_round") is not None else (raw.get("resolved_round") if raw.get("resolved_round") is not None else prev.get("resolved_in_round")),
            "resolved_in_revision": raw.get("resolved_in_revision") or raw.get("resolved_candidate_sha") or prev.get("resolved_in_revision"),
            "resolution_blocker": raw.get("resolution_blocker"), "resolution_evidence": raw.get("resolution_evidence") or prev.get("resolution_evidence"),
            "reproducer_verification": raw.get("reproducer_verification") or prev.get("reproducer_verification"), "history": hist, "evidence_history": ev_hist,
        }
    if recovered_out is not None: recovered_out.extend(by_id.values())
    if corrupt_err is not None: raise errors_module.FactoryError(corrupt_err)
    return list(by_id.values())

def load_project_standards(repo: Path, base_sha: str, child: dict[str, Any], conf: config_module.Config, deadline: float, limit_s: int) -> list[dict[str, Any]]:
    standards = [{**s, "standard_sha": base_sha, "enforced": True} for s in BASELINE_PROJECT_STANDARDS]
    for doc_name, std_id in (("AGENTS.md", "STD-DOC-AGENTS"), ("CONTRIBUTING.md", "STD-DOC-CONTRIBUTING"), ("CONTEXT.md", "STD-DOC-CONTEXT")):
        res = git_timed(repo, deadline, limit_s, f"read {doc_name}", "show", f"{base_sha}:{doc_name}")
        if res.ok and res.output.strip():
            body = " | ".join(ln.strip("# ").strip() for ln in res.output.splitlines() if ln.strip("# ").strip()) or doc_name
            standards.append({"id": std_id, "name": doc_name.lower().replace(".", "-"), "source": f"{doc_name}@{base_sha[:12]}", "standard_sha": base_sha, "enforced": True, "description": body[:1600]})
    constraints = str((child.get("scope") or {}).get("constraints") or "").strip()
    if constraints and constraints.lower() != "none":
        standards.append({"id": "STD-SUBTASK-CONSTRAINTS", "name": "subtask-constraints", "source": f"asana-subtask:{child.get('gid')}", "standard_sha": base_sha, "enforced": True, "description": constraints[:200]})
    return standards

def _render_phase1_prompt(child: dict[str, Any], base_sha: str, candidate_sha: str, diff_text: str, standards: list[dict[str, Any]]) -> str:
    scope = child.get("scope") or {}
    crit_lines = "\n".join(f"- {c.get('id')}: {c.get('description')} (verification: `{c.get('verification')}`)" for c in (child.get("criteria") or []) if isinstance(c, dict)) or "- None"
    std_lines = "\n".join(f"- {s['id']} ({s['name']}, source={s['source']}): {s['description']}" for s in standards)
    return (f"Role: independent-reviewer (fresh session separate from builder). Do not edit files or commit.\nPHASE: 1 (pre-summary independent hypothesis formation)\nSub-task: {child.get('gid')} ({child.get('name')})\n"
            f"Candidate revision: {candidate_sha} (base: {base_sha})\nIn scope: {scope.get('in_scope') or 'as specified'}\nOut of scope: {scope.get('out_of_scope') or 'none'}\nConstraints: {scope.get('constraints') or 'none'}\n"
            f"Requirements & Acceptance Criteria:\n{crit_lines}\nApplicable Project Standards:\n{std_lines}\nExact Base-to-Candidate Diff:\n{diff_text}\n"
            'Respond with raw JSON only: {"hypotheses": ["<independent failure hypothesis 1>", ...]}\n')

def build_phase1_prompt(child: dict[str, Any], base_sha: str, candidate_sha: str, diff_text: str, standards: list[dict[str, Any]]) -> str:
    return _render_phase1_prompt(child, base_sha, candidate_sha, diff_text, standards)

def build_phase2_prompt(child: dict[str, Any], base_sha: str, candidate_sha: str, diff_text: str, standards: list[dict[str, Any]], hypotheses: list[str], builder_summary: str, qa_eval: dict[str, Any], sec_eval: dict[str, Any], prior_findings: list[dict[str, Any]] | None = None) -> str:
    hyp_lines = "\n".join(f"- {h}" for h in hypotheses)
    crit_lines = "\n".join(f"- {c.get('id')}: {c.get('description')} (verification: `{c.get('verification')}`)" for c in (child.get("criteria") or []) if isinstance(c, dict)) or "- None"
    std_lines = "\n".join(f"- {s['id']} ({s['name']}): {s['description']}" for s in standards)
    prior_lines = "\n".join(f"- {f.get('finding_id')} [{f.get('status', 'open')}] (introduced round {f.get('introduced_in_round', 1)} on {f.get('introduced_in_revision', '')[:12]}): target={f.get('target')} rule={f.get('rule')} verification_command={f.get('verification_command') or '(none)'} evidence={f.get('evidence')}" for f in (prior_findings or []) if isinstance(f, dict) and f.get("blocking", True)) or "- None"
    schema = ('{"outcome":"review-passed|changes-requested","assessment":{key:{"status":"satisfied|unsatisfied","summary":"..."}},'
              '"findings":[{"finding_id":"REV-...","category":"missing-behavior|bug|verification-gap|scope-drift|non-blocking-suggestion","blocking":true,"target":"<file_or_criterion>","rule":"<concern>","title":"...","evidence":"...","actionable_correction":"...","verification_command":"..."}],'
              '"reconciliations":[{"finding_id":"REV-...","resolution":"fixed|no-longer-applicable|open","evidence":"...","verification_command":"..."}]}')
    return (f"Role: independent-reviewer (fresh session separate from builder). Do not edit files or commit.\nPHASE: 2 (substantive-assessment after independent hypotheses were persisted)\nSub-task: {child.get('gid')} ({child.get('name')})\n"
            f"Candidate revision: {candidate_sha} (base: {base_sha})\nRequired Assessment Dimensions: {', '.join(ASSESSMENT_KEYS)}\nRequirements & Acceptance Criteria:\n{crit_lines}\nApplicable Project Standards:\n{std_lines}\n"
            f"Persisted Phase-1 Hypotheses:\n{hyp_lines}\nPrior Blocking Findings Requiring Verified Reconciliation:\n{prior_lines}\nSame-Candidate Automated QA Gate Summary: status={qa_eval['status']} verified={qa_eval['verified']}\n"
            f"Same-Candidate Security Review Gate Summary: status={sec_eval['status']} verified={sec_eval['verified']}\nBuilder Summary (untrusted claim):\n{builder_summary or '(none provided)'}\nExact Base-to-Candidate Diff:\n{diff_text}\nRequired JSON response schema:\n{schema}\n")

def _parse_json_obj(text: str, phase: str) -> tuple[dict[str, Any] | None, list[str]]:
    s = (text or "").strip()
    if not (s.startswith("{") and s.endswith("}")): return None, [f"{phase} reviewer response must be a raw JSON object without markdown fences"]
    try: obj = json.loads(s)
    except json.JSONDecodeError as exc: return None, [f"{phase} reviewer response is not valid JSON: {exc}"]
    return (obj, []) if isinstance(obj, dict) else (None, [f"{phase} reviewer response must be a JSON object"])

def _parse_phase1_hypotheses(response_text: str) -> tuple[list[str], list[str]]:
    parsed, errs = _parse_json_obj(response_text, "phase-1")
    if parsed is None: return [], errs
    raw_hyps = parsed.get("hypotheses")
    if not isinstance(raw_hyps, list) or not raw_hyps or any(not isinstance(h, str) or not h.strip() for h in raw_hyps):
        return [], ["phase-1 reviewer response must contain a non-empty list of non-blank failure hypotheses"]
    return [h.strip() for h in raw_hyps], []

def _validate_qa_record(candidate_sha: str, base_sha: str, qa_record: dict[str, Any] | None, *, repo: Path | None = None, child: dict[str, Any] | None = None, deadline: float | None = None, limit_s: int = 30) -> dict[str, Any]:
    if not isinstance(qa_record, dict) or not qa_record:
        return {"status": "qa-missing", "verified": False, "blockers": [f"missing automated QA evidence for candidate {candidate_sha}"]}
    rec_cand, rec_base, rec_tested = qa_record.get("candidate_sha"), qa_record.get("base_sha"), qa_record.get("tested_sha")
    if not all(isinstance(x, str) and ci_gate.SHA40_RE.fullmatch(x) for x in (rec_cand, rec_base, rec_tested)):
        return {"status": "stale-qa-evidence", "verified": False, "blockers": ["QA record is missing valid 40-char candidate_sha, base_sha, or tested_sha"]}
    if rec_cand != candidate_sha or rec_base != base_sha:
        return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"stale automated QA evidence: qa=({rec_cand}, base={rec_base}) != candidate=({candidate_sha}, base={base_sha})"]}
    ci_reval, role_sep, cov = qa_record.get("ci_revalidation"), qa_record.get("role_separation"), qa_record.get("criterion_coverage")
    reg_checks, findings, open_fids, boundary = qa_record.get("regression_checks"), qa_record.get("findings"), qa_record.get("open_finding_ids"), qa_record.get("parent_acceptance_boundary")
    if not isinstance(ci_reval, dict) or not isinstance(role_sep, dict) or not isinstance(cov, list) or not cov:
        return {"status": "qa-invalid", "verified": False, "blockers": ["QA record is missing required ci_revalidation, role_separation, or criterion_coverage"]}
    rev_kind = qa_record.get("revision_kind") or ci_reval.get("revision_kind")
    if rev_kind not in (None, "fast-forward-head", "integration-merge"):
        return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"invalid QA revision_kind {rev_kind!r}"]}
    if rec_tested == candidate_sha:
        if rev_kind == "integration-merge": return {"status": "stale-qa-evidence", "verified": False, "blockers": ["integration-merge QA record cannot have tested_sha == candidate_sha"]}
        if repo is not None and gitio.git(repo, "cat-file", "-t", candidate_sha).ok and gitio.git(repo, "cat-file", "-t", base_sha).ok and not gitio.is_ancestor(repo, base_sha, candidate_sha):
            return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"candidate_sha {candidate_sha} does not descend from base_sha {base_sha}"]}
    else:
        if rev_kind not in (None, "integration-merge"): return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"tested_sha != candidate_sha requires integration-merge, got {rev_kind!r}"]}
        parents_ok = False
        if repo is not None:
            ok_git, git_kind, git_err = ci_gate._verify_tested_revision_in_git(repo, base_sha, candidate_sha, rec_tested, 0, deadline or (time.monotonic() + 10.0), limit_s)
            if not ok_git or git_kind != "integration-merge": return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"invalid integration-merge tested_sha {rec_tested}: {git_err or git_kind}"]}
            parents_ok = True
        rec_parents = qa_record["merge_parents"] if "merge_parents" in qa_record else ci_reval.get("merge_parents")
        if rec_parents is not None:
            if not isinstance(rec_parents, (list, tuple)) or len(rec_parents) != 2 or not all(isinstance(p, str) for p in rec_parents) or set(rec_parents) != {base_sha, candidate_sha}:
                return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"integration-merge parents {rec_parents!r} do not match [base_sha, candidate_sha]"]}
            parents_ok = True
        if not parents_ok: return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"unverified integration-merge tested_sha {rec_tested}"]}
    if any(ci_reval.get(k) not in (None, exp) for k, exp in (("candidate_sha", candidate_sha), ("base_sha", base_sha), ("tested_sha", rec_tested))):
        return {"status": "stale-qa-evidence", "verified": False, "blockers": ["ci_revalidation revision bindings do not match QA record"]}
    cov_ok = all(
        isinstance(c, dict) and isinstance(c.get("criterion_id"), str) and bool(c["criterion_id"].strip()) and c["criterion_id"] != "CRITERIA-MISSING"
        and c.get("passed") is True and isinstance(det := c.get("deterministic_check"), dict) and det.get("passed") is True and det.get("executed") is True
        and det.get("timed_out") is not True and det.get("status") != "invalid-rubric" and isinstance(ecs := c.get("evaluation_cases", []), list)
        and all(isinstance(ec, dict) and ec.get("passed") is True and ec.get("executed") is True and ec.get("timed_out") is not True and ec.get("status") != "invalid-rubric" for ec in ecs)
        for c in cov
    )
    req_cids = {str(cr.get("id") or "AC").strip() for cr in ((child or {}).get("criteria") or ()) if isinstance(cr, dict)} if isinstance(child, dict) else set()
    cov_cids = {c["criterion_id"].strip() for c in cov if isinstance(c, dict) and isinstance(c.get("criterion_id"), str)}
    reg_ok = qa_record.get("regression_passed") is True and (reg_checks is None or (isinstance(reg_checks, list) and bool(reg_checks) and all(isinstance(rc, dict) and rc.get("passed") is True and rc.get("executed") is True and rc.get("timed_out") is not True for rc in reg_checks)))
    findings_ok = isinstance(open_fids, list) and len(open_fids) == 0 and isinstance(findings, list) and all(isinstance(f, dict) and f.get("status") == "resolved" and f.get("resolution_blocker") is None and f.get("latest_candidate_sha", candidate_sha) == candidate_sha for f in findings)
    role_ok = (qa_record.get("role") == "automated-qa" and qa_record.get("status") == "qa-verified" and qa_record.get("qa_verified") is True and ci_reval.get("verified") is True and ci_reval.get("status") in (None, "verified") and not ci_reval.get("blockers")
               and role_sep.get("role") in (None, "automated-qa") and role_sep.get("candidate_modified_by_qa") is False and role_sep.get("worktree_clean") is True and role_sep.get("head_before", candidate_sha) == candidate_sha and role_sep.get("head_after", candidate_sha) == candidate_sha
               and (boundary is None or (isinstance(boundary, dict) and boundary.get("parent_accepted") is False)))
    if not (role_ok and cov_ok and req_cids.issubset(cov_cids) and reg_ok and findings_ok):
        st = str(qa_record.get("status") if isinstance(qa_record.get("status"), str) and qa_record.get("status") != "qa-verified" else "qa-failed")
        return {"status": st, "verified": False, "blockers": [f"automated QA contract not satisfied on {candidate_sha}"]}
    return {"status": "qa-verified", "verified": True, "blockers": []}

def evaluate_upstream_evidence(candidate_sha: str, base_sha: str, qa_record: dict[str, Any] | None, security_record: dict[str, Any] | None, *, home: Path | None = None, repo: Path | None = None, child: dict[str, Any] | None = None, deadline: float | None = None, limit_s: int = 30) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    gaps: list[dict[str, Any]] = []
    qa_eval = _validate_qa_record(candidate_sha, base_sha, qa_record, repo=repo, child=child, deadline=deadline, limit_s=limit_s)
    if not qa_eval["verified"]:
        rule = "stale-qa-evidence" if qa_eval["status"] == "stale-qa-evidence" else "qa-evidence-unverified"
        gaps.append(_gap_finding("automated-qa", rule, f"Automated QA evidence gap ({qa_eval['status']})", "; ".join(qa_eval["blockers"]), f"Run automated QA on candidate {candidate_sha} (base {base_sha}) and resolve all QA findings.", "observed-upstream-gate"))
    sec_eval = security_review.evaluate_security_review_gate(candidate_sha, base_sha, security_record, home=home)
    if not sec_eval["verified"]:
        rule = "stale-security-evidence" if sec_eval["status"] == "stale-security-review" else "security-evidence-unverified"
        gaps.append(_gap_finding("security-review", rule, f"Security review evidence gap ({sec_eval['status']})", "; ".join(sec_eval["blockers"]), f"Run security review on candidate {candidate_sha} (base {base_sha}) and resolve all security blockers.", "observed-upstream-gate"))
    return qa_eval, sec_eval, gaps

def _parse_phase2_response(response_text: str) -> tuple[str | None, dict[str, dict[str, str]], list[dict[str, Any]], list[str]]:
    outcome, assessment, findings, _, issues = _parse_phase2_response_full(response_text)
    return outcome, assessment, findings, issues

def _parse_phase2_response_full(response_text: str, *, has_prior_blockers: bool = False) -> tuple[str | None, dict[str, dict[str, str]], list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    parsed, errs = _parse_json_obj(response_text, "phase-2")
    if parsed is None: return None, {}, [], {}, errs
    outcome, raw_assess, raw_findings = parsed.get("outcome"), parsed.get("assessment"), parsed.get("findings")
    raw_reconcils = parsed.get("reconciliations", parsed.get("previous_findings_resolution", []))
    if outcome not in ("review-passed", "changes-requested"): return None, {}, [], {}, [f"phase-2 reviewer response has invalid or missing outcome {outcome!r}"]
    if not isinstance(raw_assess, dict): return outcome, {}, [], {}, ["phase-2 reviewer response is missing an 'assessment' object"]
    assessment: dict[str, dict[str, str]] = {}
    issues: list[str] = []
    for key in ASSESSMENT_KEYS:
        entry = raw_assess.get(key)
        st = str(entry.get("status") or "").strip() if isinstance(entry, dict) else ""
        summ = str(entry.get("summary") or "").strip() if isinstance(entry, dict) else ""
        if st not in ("satisfied", "unsatisfied") or not summ: issues.append(f"assessment dimension {key!r} must have status in ('satisfied', 'unsatisfied') and non-empty summary")
        else: assessment[key] = {"status": st, "summary": summ}
    if not isinstance(raw_findings, list) or any(not isinstance(item, dict) for item in raw_findings):
        return outcome, assessment, [], {}, [*issues, "phase-2 reviewer response is missing a valid 'findings' list of objects"]
    if raw_reconcils is not None and (not isinstance(raw_reconcils, list) or any(not isinstance(item, dict) for item in raw_reconcils)):
        return outcome, assessment, [], {}, [*issues, "phase-2 reviewer response 'reconciliations' must be a list of objects"]
    findings: list[dict[str, Any]] = []
    reconcils: dict[str, dict[str, Any]] = {}
    seen_fids: set[str] = set()
    for idx, raw in enumerate(raw_findings):
        cat, raw_blk = str(raw.get("category") or "").strip(), raw.get("blocking")
        if cat not in FINDING_CATEGORIES: issues.append(f"finding[{idx}] has unsupported category {cat!r}"); continue
        if not isinstance(raw_blk, bool) or (cat == "non-blocking-suggestion" and raw_blk is True) or (cat != "non-blocking-suggestion" and raw_blk is False):
            issues.append(f"finding[{idx}] category {cat!r} conflicts with blocking={raw_blk!r}"); continue
        blocking = raw_blk
        target = str(raw.get("target") or raw.get("file_path") or raw.get("criterion_id") or "").strip()
        rule, title = str(raw.get("rule") or "").strip(), str(raw.get("title") or raw.get("rule") or cat).strip()
        evidence, correction = str(raw.get("evidence") or "").strip(), str(raw.get("actionable_correction") or "").strip()
        vcmd = str(raw.get("verification_command") or "").strip()
        raw_res = str(raw.get("resolution") or raw.get("status") or ("thread-closed" if raw.get("thread_closed") or raw.get("comment_resolved") else "")).strip().lower()
        tgt_slug, rule_slug = SLUG_RE.sub("-", target.lower()).strip("-"), SLUG_RE.sub("-", rule.lower()).strip("-")
        if blocking and raw_res in ("fixed", "no-longer-applicable", "no_longer_applicable", "resolved", "thread-closed", "comment-resolved", "dismissed"):
            fid = compute_review_finding_id(cat, target, rule) if (tgt_slug and rule_slug) else str(raw.get("finding_id") or "").strip()
            if fid:
                norm_r = "fixed" if raw_res == "resolved" else raw_res.replace("_", "-")
                reconcils[fid] = {"finding_id": fid, "target": target, "rule": rule, "resolution": norm_r, "evidence": evidence, "verification_command": vcmd, "reproducer_verification": raw.get("reproducer_verification"), "evidence_sha": str(raw.get("evidence_sha") or raw.get("candidate_sha") or raw.get("verified_on_revision") or "").strip()}
            continue
        if blocking and (not tgt_slug or not rule_slug or not evidence or not correction):
            issues.append(f"blocker finding[{idx}] requires alphanumeric target and rule slugs, concrete evidence, and actionable_correction"); continue
        target, rule = target or "repository", rule or SLUG_RE.sub("-", title.lower()).strip("-") or "suggestion"
        fid = compute_review_finding_id(cat, target, rule)
        if fid in seen_fids: issues.append(f"finding[{idx}] has duplicate or colliding finding_id {fid!r}"); continue
        seen_fids.add(fid)
        findings.append({"finding_id": fid, "category": cat, "blocking": blocking, "target": target, "rule": rule, "title": title, "evidence": evidence or f"Suggestion on {target}", "actionable_correction": correction or "Optional maintainability improvement.", "verification_command": vcmd, "source": "reviewer-agent"})
    for r_item in raw_reconcils or ():
        cat, target, rule = str(r_item.get("category") or "").strip(), str(r_item.get("target") or r_item.get("file_path") or "").strip(), str(r_item.get("rule") or "").strip()
        raw_fid = str(r_item.get("finding_id") or "").strip()
        rfid = compute_review_finding_id(cat, target, rule) if (cat in FINDING_CATEGORIES and target and rule) else raw_fid
        if not rfid and not (target and rule): continue
        raw_res = str(r_item.get("resolution") or r_item.get("status") or ("thread-closed" if r_item.get("thread_closed") or r_item.get("comment_resolved") else "")).strip().lower().replace("_", "-")
        entry_r = {
            "finding_id": rfid or raw_fid, "target": target, "rule": rule, "resolution": "fixed" if raw_res == "resolved" else raw_res,
            "evidence": str(r_item.get("evidence") or r_item.get("resolution_evidence") or "").strip(),
            "verification_command": str(r_item.get("verification_command") or "").strip(),
            "reproducer_verification": r_item.get("reproducer_verification") or r_item.get("observed_evidence"),
            "evidence_sha": str(r_item.get("evidence_sha") or r_item.get("candidate_sha") or r_item.get("verified_on_revision") or "").strip(),
        }
        if rfid: reconcils[rfid] = entry_r
        if raw_fid and raw_fid != rfid: reconcils[raw_fid] = entry_r
    has_blocking, has_unsatisfied = any(f["blocking"] for f in findings), any(v.get("status") != "satisfied" for v in assessment.values())
    has_open_reconcil = has_prior_blockers or any(r.get("resolution") not in ("fixed", "no-longer-applicable") for r in reconcils.values())
    if outcome == "review-passed" and (has_blocking or has_unsatisfied): issues.append("reviewer reported outcome='review-passed' despite blocking findings or unsatisfied assessment dimensions")
    if (outcome == "changes-requested" or has_unsatisfied) and not has_blocking and not has_open_reconcil: issues.append("reviewer reported outcome='changes-requested' or unsatisfied assessment without any complete blocking findings")
    return outcome, assessment, findings, reconcils, issues

def _run_observed_verification(worktree: Path, verify_dir: Path, home: Path, child: dict[str, Any], conf: config_module.Config, changed_paths: tuple[str, ...], deleted_paths: tuple[str, ...], candidate_sha: str, secrets: tuple[str, ...], deadline: float, limit_s: int, *, repro_targets: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    plan = ci_selection.select_ci_test_plan(child, conf, changed_paths, deleted_paths=deleted_paths, repo=worktree)
    verify_home = safe_dir(verify_dir / "verify-home", create=True, root=home); safe_dir(verify_home / ".tmp", create=True, root=home)
    env, _ = worker_module.sanitized_env(dict(os.environ), worktree, verify_home)
    env["GIT_OPTIONAL_LOCKS"] = env["PYTHONNOUSERSITE"] = "1"
    specs: list[tuple[str, str, str, tuple[str, ...] | None, str]] = []
    for guard in plan.get("essential_guards") or []:
        gid = str(guard.get("id") or "")
        if (g_cfg := conf.gates.get(gid.removeprefix("gate-"))) is not None and g_cfg.kind == "command" and g_cfg.argv:
            specs.append((str(guard["name"]), "guard", gid, tuple(g_cfg.argv), " ".join(g_cfg.argv)))
    criteria_list = list(child.get("criteria") or [])
    for crit in criteria_list:
        cid, vcmd = str(crit.get("id") or "AC").strip(), str(crit.get("verification") or "").strip()
        specs.append((f"criterion/{cid}", "criterion", cid, None if ci_selection.WEAKENED_CMD_RE.search(vcmd) else deliver_checks._verification_argv(vcmd), vcmd))
    if (gate2 := conf.gates.get("2")) is not None and gate2.kind == "command" and gate2.argv:
        specs.append(("regression/gate-2", "regression", "gate-2", tuple(gate2.argv), " ".join(gate2.argv)))
    aff = tuple(str(t).strip() for t in (plan.get("affected_tests") or ()) if str(t).strip())
    if plan.get("mode") == "affected-only" and aff:
        specs.append(("regression/affected-tests", "regression", "regression-suite", (sys.executable, "-m", "unittest", *aff, "-v"), f"unittest {' '.join(aff)}"))
    else:
        g2_argv = tuple(gate2.argv) if gate2 is not None and gate2.kind == "command" and gate2.argv else ()
        if not ("unittest" in g2_argv and "discover" in g2_argv):
            specs.append(("regression/full-suite", "regression", "regression-suite", (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"), "python3 -m unittest discover -s tests -v"))
    checks, gaps = [], [_gap_finding(str(dt), "deleted-test-coverage", f"Candidate deleted test file {dt}", f"deleted test path {dt!r}", f"Restore test coverage in {dt} or justify replacement without deleting test coverage.", "observed-verification") for dt in (plan.get("deleted_tests") or ())]
    if not criteria_list: gaps.append(_gap_finding("criteria", "missing-criteria", "Sub-task has no acceptance criteria to verify", "child.criteria is empty", "Define executable acceptance criteria on the sub-task before independent review.", "observed-verification"))
    if not specs: gaps.append(_gap_finding("verification-plan", "no-executable-checks", "No executable verification checks configured", f"0 checks on {candidate_sha}", "Configure required criterion and regression checks before independent review.", "observed-verification"))
    all_ok = bool(criteria_list) and bool(specs) and not bool(plan.get("deleted_tests"))

    def _exec_check(name: str, kind: str, concern_id: str, argv: tuple[str, ...] | None, raw_cmd: str, stem_prefix: str = "ind-verify") -> dict[str, Any]:
        stem = f"{stem_prefix}-{SLUG_RE.sub('-', name.lower()).strip('-')[:56]}"
        if not argv:
            msg = redact_value(f"unexecutable or missing verification command for {concern_id}: {raw_cmd!r}\n", secrets)
            ev_path = write_evidence(verify_dir, stem, msg, home)
            return {"name": name, "kind": kind, "assesses": concern_id, "command": redact_value(raw_cmd, secrets), "argv": [], "executed": False, "completed": False, "exit_code": None, "ok": False, "timed_out": False, "duration_ms": 0, "head_sha": candidate_sha, "output_path": str(ev_path), "output_sha256": runner.digest_text(msg), "output_excerpt": msg.strip()[:400], "provenance": "observed-independent-verification"}
        executed, completed, launched = False, False, False
        try:
            timeout_s = max(1, int(math.ceil(remaining_seconds(deadline, f"independent verification {name}", limit_s))))
            launched = executed = True
            code, out_s, err_s, elapsed_ms, timed_out = worker_module.execute_stream(worktree, argv, env, timeout_s, isolated_home=verify_home, allow_network=False)
            completed = not timed_out
        except (deliver_checks.AttemptTimeoutError, TimeoutError) as exc:
            code, out_s, err_s, elapsed_ms, timed_out, executed, completed = (124 if launched else None), "", f"[factory] check timed out: {exc}\n", 0, launched, launched, False
        except (worker_module.SandboxUnavailableError, OSError) as exc:
            code, out_s, err_s, elapsed_ms, timed_out, executed, completed = None, "", f"[factory] check execution error: {exc}\n", 0, False, False, False
        combined = redact_value((out_s + err_s).strip() + "\n", secrets)
        ev_path = write_evidence(verify_dir, stem, combined, home)
        ok = executed and completed and code == 0 and not timed_out
        return {"name": name, "kind": kind, "assesses": concern_id, "command": redact_value(raw_cmd, secrets), "argv": list(redact_value(list(argv), secrets)), "executed": executed, "completed": completed, "exit_code": code, "ok": ok, "timed_out": timed_out, "duration_ms": elapsed_ms, "head_sha": candidate_sha, "output_path": str(ev_path), "output_sha256": runner.digest_text(combined), "output_excerpt": combined.strip()[:400], "provenance": "observed-independent-verification"}

    for name, kind, concern_id, argv, raw_cmd in specs:
        chk = _exec_check(name, kind, concern_id, argv, raw_cmd)
        checks.append(chk); all_ok = all_ok and chk["ok"]
        if not chk["ok"]:
            if not argv:
                gaps.append(_gap_finding(concern_id, "unexecutable-check", f"Missing or unexecutable check for {concern_id}", chk["output_excerpt"], f"Provide an executable verification command for {concern_id} without skip flags.", "observed-verification", vcmd=raw_cmd))
            else:
                rule = "check-timed-out" if chk["timed_out"] else ("check-not-executed" if not chk["executed"] else "check-failed")
                fail_desc = "timed out" if chk["timed_out"] else ("could not execute" if not chk["executed"] else f"failed (exit {chk['exit_code']})")
                gaps.append(_gap_finding(concern_id, rule, f"Observed verification check {name} {fail_desc}", f"command={raw_cmd!r} exit_code={chk['exit_code']} output_path={chk['output_path']}: {chk['output_excerpt'][:240]}", f"Fix candidate {candidate_sha} so `{raw_cmd}` exits 0 within the timeout.", "observed-verification", vcmd=raw_cmd))

    finding_vers: dict[str, dict[str, Any]] = {}
    for fid, fobj in (repro_targets or {}).items():
        vcmd = str(fobj.get("verification_command") or "").strip()
        if not vcmd: continue
        argv = None if ci_selection.WEAKENED_CMD_RE.search(vcmd) else deliver_checks._verification_argv(vcmd)
        f_chk = _exec_check(f"finding/{fid}", "finding-reproducer", fid, argv, vcmd, stem_prefix="ind-repro")
        finding_vers[fid] = {**f_chk, "finding_id": fid, "reproduced": not f_chk["ok"], "provenance": "observed-finding-reproducer"}
    return {"executed": any(c["executed"] for c in checks), "ok": all_ok and len(gaps) == 0, "head_sha": candidate_sha, "selection_plan": plan, "checks": checks, "finding_verifications": finding_vers, "verification_gaps": gaps, "provenance": "observed-independent-verification"}

def _verify_stored_check(chk: Any, candidate_sha: str, home: Path | None, *, finding_id: str | None = None, target: str | None = None) -> str | None:
    if not isinstance(chk, dict): return "missing observed verification check record"
    if chk.get("head_sha") != candidate_sha: return f"stale check evidence: head_sha={chk.get('head_sha')!r} != candidate={candidate_sha!r}"
    if finding_id or target:
        valid_binds = {x for x in (finding_id, target, f"criterion/{target}" if target else None, f"finding/{finding_id}" if finding_id else None) if x}
        if not ({chk.get("finding_id"), chk.get("assesses"), chk.get("name")} & valid_binds):
            return f"unbound check evidence: check {chk.get('name') or chk.get('command')!r} is not bound to finding {finding_id!r} or target {target!r}"
    if not bool(chk.get("executed")) or not bool(chk.get("ok")) or bool(chk.get("timed_out")) or type(chk.get("exit_code")) is not int or chk.get("exit_code") != 0:
        return f"check {chk.get('name') or chk.get('command')!r} did not pass on {candidate_sha}"
    out_p = Path(str(chk.get("output_path") or ""))
    try:
        if out_p.is_symlink() or not out_p.is_file() or (home is not None and not out_p.resolve().is_relative_to(home.resolve())):
            return f"check {chk.get('name') or chk.get('command')!r} is missing stored log evidence inside runtime home"
        if runner.digest_text(out_p.read_text(encoding="utf-8", errors="replace")) != chk.get("output_sha256"):
            return f"check {chk.get('name') or chk.get('command')!r} stored log digest mismatch"
    except OSError:
        return f"check {chk.get('name') or chk.get('command')!r} stored log is unreadable"
    return None

def reconcile_review_findings(
    *, round_num: int, candidate_sha: str, base_sha: str, agent_findings: list[dict[str, Any]], det_findings: list[dict[str, Any]],
    prior_findings: list[dict[str, Any]] | None = None, reconciliations: dict[str, dict[str, Any]] | None = None,
    obs_ver: dict[str, Any] | None = None, qa_eval: dict[str, Any] | None = None, sec_eval: dict[str, Any] | None = None,
    scope_ok: bool = True, changed_paths: tuple[str, ...] = (), deleted_paths: tuple[str, ...] = (),
    role_sep_ok: bool = True, home: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    prior_map, prior_alias = {}, {}
    for pf in prior_findings or ():
        if not isinstance(pf, dict): continue
        cat, target, rule, raw_fid = str(pf.get("category") or "bug"), str(pf.get("target") or "repository"), str(pf.get("rule") or "concern"), str(pf.get("finding_id") or "").strip()
        fid = compute_review_finding_id(cat, target, rule) if (cat in FINDING_CATEGORIES and pf.get("target") and pf.get("rule")) else raw_fid
        if fid and pf.get("blocking", cat != "non-blocking-suggestion"):
            prior_map[fid] = {**pf, "finding_id": fid, "blocking": True}
            if raw_fid: prior_alias[raw_fid] = fid
            prior_alias[f"{SLUG_RE.sub('-', target.lower()).strip('-')}::{SLUG_RE.sub('-', rule.lower()).strip('-')}"] = fid

    cur_by_id, downgrade_ids = {}, set()
    for item in (*agent_findings, *det_findings):
        fid = str(item["finding_id"])
        tr_key = f"{SLUG_RE.sub('-', str(item.get('target') or '').lower()).strip('-')}::{SLUG_RE.sub('-', str(item.get('rule') or '').lower()).strip('-')}"
        if not item.get("blocking") and (fid in prior_map or prior_alias.get(fid) in prior_map or prior_alias.get(tr_key) in prior_map):
            downgrade_ids.add(prior_alias.get(fid) or prior_alias.get(tr_key) or fid); continue
        if fid not in cur_by_id or item.get("source") != "reviewer-agent" or (item.get("blocking") and not cur_by_id[fid].get("blocking")):
            cur_by_id[fid] = dict(item)

    obs = obs_ver or {}
    obs_ok = bool(obs.get("executed") and obs.get("ok") and obs.get("head_sha") == candidate_sha)
    qa_ok, sec_ok = bool((qa_eval or {}).get("verified")), bool((sec_eval or {}).get("verified"))
    f_vers = obs.get("finding_verifications") if isinstance(obs.get("finding_verifications"), dict) else {}
    obs_checks = [c for c in (obs.get("checks") or ()) if isinstance(c, dict)]
    reconcil_map: dict[str, dict[str, Any]] = {}
    for rk, rv in (reconciliations or {}).items():
        if not isinstance(rv, dict): continue
        reconcil_map[rk] = rv
        tr_k = f"{SLUG_RE.sub('-', str(rv.get('target') or '').lower()).strip('-')}::{SLUG_RE.sub('-', str(rv.get('rule') or '').lower()).strip('-')}"
        if (mapped := prior_alias.get(rk) or prior_alias.get(tr_k)): reconcil_map.setdefault(mapped, rv)

    all_findings, resolutions = [], []
    for fid in dict.fromkeys([*prior_map, *cur_by_id]):
        old_f, cur_f = prior_map.get(fid), cur_by_id.get(fid)
        if old_f is None and cur_f is not None and not cur_f.get("blocking"):
            all_findings.append({**cur_f, "blocking": False, "status": "suggestion", "introduced_in_round": round_num, "introduced_in_revision": candidate_sha, "last_seen_round": round_num, "last_seen_revision": candidate_sha})
            continue
        base_f = old_f if old_f is not None else cur_f
        assert base_f is not None
        cat, target, rule = str(base_f.get("category") or "bug"), str(base_f.get("target") or "repository"), str(base_f.get("rule") or "concern")
        stable_fid = compute_review_finding_id(cat, target, rule) if (cat in FINDING_CATEGORIES and target and rule) else fid
        intro_round = int(old_f.get("introduced_in_round") or old_f.get("created_round") or 1) if old_f else round_num
        intro_rev = str(old_f.get("introduced_in_revision") or old_f.get("created_candidate_sha") or old_f.get("last_seen_revision") or candidate_sha) if old_f else candidate_sha
        prev_status, prev_seen_rev = (str(old_f.get("status") or "open"), str(old_f.get("last_seen_revision") or old_f.get("latest_candidate_sha") or intro_rev)) if old_f else ("new", "")
        hist = [dict(h) for h in (old_f.get("history") or ()) if isinstance(h, dict)] if old_f else []
        ev_hist = [dict(e) for e in (old_f.get("evidence_history") or ()) if isinstance(e, dict)] if old_f else []
        if old_f and not ev_hist and old_f.get("evidence"):
            ev_hist.append({"round": intro_round, "candidate_sha": intro_rev, "evidence": str(old_f["evidence"]), "actionable_correction": str(old_f.get("actionable_correction") or ""), "source": str(old_f.get("source") or "reviewer-agent")})
        if old_f and not hist:
            hist.append({"round": intro_round, "candidate_sha": intro_rev, "status": prev_status, "resolution_blocker": old_f.get("resolution_blocker"), "evidence": str(old_f.get("evidence") or ""), "verification_command": str(old_f.get("verification_command") or ""), "reproducer_verification": old_f.get("reproducer_verification"), "resolution_evidence": old_f.get("resolution_evidence")})
        if cur_f is not None and cur_f.get("evidence"):
            cur_ev_entry = {"round": round_num, "candidate_sha": candidate_sha, "evidence": str(cur_f["evidence"]), "actionable_correction": str(cur_f.get("actionable_correction") or ""), "source": str(cur_f.get("source") or "reviewer-agent")}
            if not ev_hist or ev_hist[-1].get("round") != round_num or ev_hist[-1].get("evidence") != cur_ev_entry["evidence"]: ev_hist.append(cur_ev_entry)

        rec_claim = reconcil_map.get(stable_fid) or reconcil_map.get(fid)
        vcmd = str((rec_claim or {}).get("verification_command") or (cur_f or {}).get("verification_command") or (old_f or {}).get("verification_command") or "").strip()
        f_ver = f_vers.get(stable_fid) or f_vers.get(fid)
        claim_ver = rec_claim.get("reproducer_verification") if isinstance(rec_claim, dict) and isinstance(rec_claim.get("reproducer_verification"), dict) else None
        if claim_ver is not None and (f_ver is None or _verify_stored_check(claim_ver, candidate_sha, home, finding_id=stable_fid, target=target) is not None): f_ver = claim_ver

        claim_res = str((rec_claim or {}).get("resolution") or "").strip().lower()
        if old_f is None: status, blocker, res_kind, res_ev = "open", "active-finding", None, None
        elif cur_f is not None and cur_f.get("blocking") and (cur_f.get("source") != "reviewer-agent" or claim_res in ("", "open", "unresolved")):
            status, blocker, res_kind, res_ev = "open", ("check-failed" if (cur_f.get("source") != "reviewer-agent" or (f_ver is not None and not f_ver.get("ok"))) else "re-reported-by-reviewer"), None, None
        elif not role_sep_ok: status, blocker, res_kind, res_ev = "open", "invalid-review", None, None
        elif prev_status == "resolved" and rec_claim is None and stable_fid not in downgrade_ids and (f_ver is None or _verify_stored_check(f_ver, candidate_sha, home, finding_id=stable_fid, target=target) is None) and obs_ok and qa_ok and sec_ok and scope_ok:
            status, blocker, res_kind, res_ev = "resolved", None, str(old_f.get("resolution") or "fixed"), str(old_f.get("resolution_evidence") or "")
        else:
            source, claim_ev, claim_sha = str(old_f.get("source") or "reviewer-agent"), str((rec_claim or {}).get("evidence") or "").strip(), str((rec_claim or {}).get("evidence_sha") or "").strip()
            same_open_rev = prev_status == "open" and prev_seen_rev == candidate_sha
            det_reconciled, det_ev, det_chk, det_blocker = False, "", None, None
            if source == "observed-upstream-gate":
                if target == "automated-qa": det_reconciled, det_ev, det_blocker = (qa_ok and not same_open_rev), f"Observed automated-qa gate verified on {candidate_sha} (base {base_sha}).", ("stale-evidence" if ((qa_eval or {}).get("status") == "stale-qa-evidence" or same_open_rev) else "upstream-unverified")
                elif target == "security-review": det_reconciled, det_ev, det_blocker = (sec_ok and not same_open_rev), f"Observed security-review gate verified on {candidate_sha} (base {base_sha}).", ("stale-evidence" if ((sec_eval or {}).get("status") == "stale-security-review" or same_open_rev) else "upstream-unverified")
            elif source == "observed-scope-check":
                det_reconciled, det_ev, det_blocker = (scope_ok and obs_ok and not same_open_rev), f"Observed scope check satisfied on {candidate_sha} (base {base_sha}).", ("stale-evidence" if same_open_rev else ("scope-drift-persists" if not scope_ok else "missing-verification"))
            elif source == "observed-verification":
                match_chk = next((c for c in obs_checks if c.get("assesses") == target or c.get("name") == target), None)
                if rule == "deleted-test-coverage":
                    det_reconciled, det_ev = (target not in deleted_paths and obs_ok and not same_open_rev), f"Deleted test coverage restored or satisfied with passing observed verification on {candidate_sha}."
                    det_blocker = "stale-evidence" if same_open_rev else ("check-failed" if not det_reconciled else None)
                elif match_chk is not None and _verify_stored_check(match_chk, candidate_sha, home, finding_id=stable_fid, target=target) is None and obs_ok and not same_open_rev:
                    det_reconciled, det_chk, det_ev = True, match_chk, f"Observed verification check {match_chk['name']!r} ({match_chk['command']!r}) exited 0 on {candidate_sha} ({match_chk['output_path']})."
                else:
                    det_blocker = "stale-evidence" if (same_open_rev or (match_chk and match_chk.get("head_sha") != candidate_sha)) else ("missing-verification" if not (match_chk and match_chk.get("executed")) else "check-failed")

            if det_reconciled and claim_res not in ("thread-closed", "comment-resolved", "dismissed"):
                status, blocker, res_kind, res_ev = "resolved", None, (claim_res if claim_res in ("fixed", "no-longer-applicable") else "fixed"), det_ev
                if det_chk is not None and f_ver is None: f_ver = det_chk
            elif source != "reviewer-agent" and det_blocker is not None and rec_claim is None: status, blocker, res_kind, res_ev = "open", det_blocker, None, None
            elif stable_fid in downgrade_ids and rec_claim is None: status, blocker, res_kind, res_ev = "open", "unsupported-assertion", None, None
            elif rec_claim is None: status, blocker, res_kind, res_ev = "open", "omitted-from-review", None, None
            elif claim_res in ("thread-closed", "comment-resolved", "dismissed"): status, blocker, res_kind, res_ev = "open", "thread-closure-only", None, None
            elif claim_res not in ("fixed", "no-longer-applicable"): status, blocker, res_kind, res_ev = "open", "unresolved-claim", None, None
            elif (claim_sha and claim_sha != candidate_sha) or (obs.get("head_sha") and obs.get("head_sha") != candidate_sha) or same_open_rev:
                status, blocker, res_kind, res_ev = "open", "stale-evidence", None, None
            elif not claim_ev: status, blocker, res_kind, res_ev = "open", "missing-evidence", None, None
            else:
                ver_err = _verify_stored_check(f_ver, candidate_sha, home, finding_id=stable_fid, target=target) if f_ver is not None else None
                if f_ver is not None and ver_err is not None:
                    b_code = "stale-evidence" if "stale" in ver_err else ("unsupported-assertion" if "unbound" in ver_err else ("missing-verification" if (not bool(f_ver.get("executed")) or "missing" in ver_err or "digest" in ver_err or "unreadable" in ver_err) else "check-failed"))
                    status, blocker, res_kind, res_ev = "open", b_code, None, None
                elif not obs_ok or not qa_ok or not sec_ok or not scope_ok:
                    b_code = "stale-evidence" if ((qa_eval or {}).get("status") == "stale-qa-evidence" or (sec_eval or {}).get("status") == "stale-security-review") else ("check-failed" if obs.get("executed") and not obs.get("ok") else "missing-verification")
                    status, blocker, res_kind, res_ev = "open", b_code, None, None
                elif f_ver is not None and ver_err is None:
                    status, blocker, res_kind, res_ev = "resolved", None, claim_res, f"{claim_ev} [verified by {f_ver.get('command')!r} on {candidate_sha}: {f_ver.get('output_path')}]"
                else:
                    bound_chk = next((c for c in obs_checks if _verify_stored_check(c, candidate_sha, home, finding_id=stable_fid, target=target) is None), None)
                    if bound_chk is None and claim_res == "no-longer-applicable" and target in deleted_paths and obs_checks and all(_verify_stored_check(c, candidate_sha, home) is None for c in obs_checks):
                        bound_chk = obs_checks[0]
                    if bound_chk is not None:
                        f_ver, status, blocker, res_kind, res_ev = bound_chk, "resolved", None, claim_res, f"{claim_ev} [verified by observed check {bound_chk['name']!r} on {candidate_sha}: {bound_chk['output_path']}]"
                    else: status, blocker, res_kind, res_ev = "open", "unsupported-assertion", None, None

        if rec_claim is not None and rec_claim.get("evidence"):
            rec_ev_entry = {"round": round_num, "candidate_sha": candidate_sha, "evidence": str(rec_claim["evidence"]), "claimed_resolution": claim_res or None, "status": status, "resolution_blocker": blocker, "source": "reconciliation-claim"}
            if not ev_hist or ev_hist[-1].get("round") != round_num or ev_hist[-1].get("evidence") != rec_ev_entry["evidence"]: ev_hist.append(rec_ev_entry)

        was_resolved = old_f is not None and prev_status == "resolved" and (old_f.get("resolved_in_round") is not None or old_f.get("resolved_round") is not None)
        res_round = (int(old_f.get("resolved_in_round") or old_f.get("resolved_round") or round_num) if was_resolved else round_num) if status == "resolved" else None
        res_rev = (str(old_f.get("resolved_in_revision") or old_f.get("resolved_candidate_sha") or candidate_sha) if was_resolved else candidate_sha) if status == "resolved" else None
        hist.append({"round": round_num, "candidate_sha": candidate_sha, "status": status, "resolution": res_kind, "resolution_blocker": blocker, "claimed_resolution": (rec_claim or {}).get("resolution") if isinstance(rec_claim, dict) else None, "evidence": str((cur_f or {}).get("evidence") or (rec_claim or {}).get("evidence") or (old_f or {}).get("evidence") or ""), "verification_command": vcmd, "reproducer_verification": f_ver, "resolution_evidence": res_ev})
        all_findings.append({
            **(old_f or {}), **(cur_f or {}), "finding_id": stable_fid, "category": cat, "blocking": True, "target": target, "rule": rule,
            "title": str((old_f or cur_f or {}).get("title") or rule), "evidence": str((old_f or cur_f or {}).get("evidence") or ""),
            "latest_evidence": str((cur_f or {}).get("evidence") or (rec_claim or {}).get("evidence") or (old_f or {}).get("latest_evidence") or (old_f or {}).get("evidence") or ""),
            "actionable_correction": str((cur_f or {}).get("actionable_correction") or (old_f or {}).get("actionable_correction") or ""),
            "verification_command": vcmd, "source": str((old_f or cur_f or {}).get("source") or "reviewer-agent"),
            "status": status, "resolution": res_kind, "resolution_blocker": blocker,
            "introduced_in_round": intro_round, "created_round": intro_round, "introduced_in_revision": intro_rev, "created_candidate_sha": intro_rev,
            "last_seen_round": round_num, "latest_round": round_num, "last_seen_revision": candidate_sha, "latest_candidate_sha": candidate_sha,
            "resolved_in_round": res_round, "resolved_round": res_round, "resolved_in_revision": res_rev, "resolved_candidate_sha": res_rev,
            "resolution_evidence": res_ev, "reproducer_verification": f_ver, "history": hist, "evidence_history": ev_hist,
        })
        if old_f is not None:
            resolutions.append({"finding_id": stable_fid, "previous_status": prev_status, "status": status, "resolution": res_kind, "resolution_blocker": blocker, "claimed_resolution": (rec_claim or {}).get("resolution") if isinstance(rec_claim, dict) else None, "introduced_in_round": intro_round, "introduced_in_revision": intro_rev, "verified_on_revision": candidate_sha if status == "resolved" else None, "candidate_sha": candidate_sha, "reproducer_verification": f_ver, "resolution_evidence": res_ev})
    blocking_findings = [f for f in all_findings if f.get("blocking") and f.get("status") != "resolved"]
    return all_findings, blocking_findings, [f for f in all_findings if not f.get("blocking")], resolutions

def _snapshot_worktree(worktree: Path) -> dict[str, tuple[Any, ...]]:
    snap: dict[str, tuple[Any, ...]] = {}
    for root, dirs, files in os.walk(worktree, topdown=True, followlinks=False):
        dirs.sort(); files.sort(); rp = Path(root)
        for name in (*dirs, *files):
            p = rp / name; st = p.lstat()
            payload = f"symlink:{os.readlink(p)}" if stat.S_ISLNK(st.st_mode) else (hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(st.st_mode) else "dir")
            snap[str(p.relative_to(worktree))] = (st.st_mode, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, payload)
    return snap

def _open_inotify_watch(worktree: Path) -> int | None:
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        if (fd := libc.inotify_init1(0o4000 | 0o2000000)) < 0: return None
        mask = 0x002 | 0x004 | 0x008 | 0x040 | 0x080 | 0x100 | 0x200 | 0x400 | 0x800
        for root, dirs, _ in os.walk(worktree, topdown=True, followlinks=False):
            if libc.inotify_add_watch(fd, os.fsencode(root), mask) < 0: os.close(fd); return None
        return int(fd)
    except Exception: return None

def _drain_inotify_watch(fd: int | None) -> bool:
    if fd is None: return True
    try:
        chunks: list[bytes] = []
        while True:
            try:
                if not (buf := os.read(fd, 65536)): break
                chunks.append(buf)
            except BlockingIOError: break
        return bool(b"".join(chunks))
    except OSError: return True
    finally:
        try: os.close(fd)
        except OSError: pass

def _read_head_pure(worktree: Path) -> str:
    try:
        raw = (worktree / ".git" / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        if raw.startswith("ref: ") and (ref_p := worktree / ".git" / raw[5:].strip()).is_file():
            return ref_p.read_text(encoding="utf-8", errors="replace").strip()
        return raw
    except OSError: return "invalid-head"

def _check_worktree_mutation(worktree: Path, expected_sha: str, round_dir: Path, home: Path, phase_label: str, secrets: tuple[str, ...], baseline_snap: dict[str, tuple[Any, ...]] | None = None, inotify_triggered: bool = False) -> dict[str, Any]:
    head_after, cur_snap = _read_head_pure(worktree), _snapshot_worktree(worktree)
    base_snap = cur_snap if baseline_snap is None else baseline_snap
    changed = sorted(set(base_snap) ^ set(cur_snap) | {k for k in set(base_snap) & set(cur_snap) if base_snap[k] != cur_snap[k]})
    if inotify_triggered and not changed: changed.append("<transient-filesystem-write-event>")
    status_out = "\n".join(f"M {p}" for p in changed)
    mutated = head_after != expected_sha or bool(changed)
    evidence_path = str(write_evidence(round_dir, f"reviewer-mutation-{phase_label}", redact_value(f"phase={phase_label}\nexpected_sha={expected_sha}\nhead_after={head_after}\nchanged:\n{status_out}\n", secrets), home)) if mutated else None
    return {"phase": phase_label, "head_before": expected_sha, "head_after": head_after, "status_porcelain": redact_value(status_out, secrets), "worktree_clean": not mutated, "candidate_modified_by_reviewer": mutated, "mutation_evidence_path": evidence_path}

def _run_phase_exec(worktree: Path, round_dir: Path, home: Path, isolated_home: Path, worker_env: dict[str, str], agy_bin: str, prompt: str, phase_tag: str, expected_sha: str, secrets: tuple[str, ...], deadline: float, limit_s: int, *, continue_session_id: str | None = None, baseline_snap: dict[str, tuple[Any, ...]] | None = None) -> dict[str, Any]:
    cont = ("--conversation", str(continue_session_id)) if continue_session_id else ()
    argv = (str(agy_bin), *cont, "--print", prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
    t_out = max(1, int(math.ceil(remaining_seconds(deadline, f"independent review {phase_tag}", limit_s))))
    ifd = _open_inotify_watch(worktree)
    try: code, out_s, err_s, _, timed_out = worker_module.execute_stream(worktree, argv, worker_env, t_out, isolated_home=isolated_home)
    finally: wrote_ev = _drain_inotify_watch(ifd)
    stdout_p = str(write_evidence(round_dir, f"{phase_tag}-stdout", redact_value(out_s, secrets), home))
    stderr_p = str(write_evidence(round_dir, f"{phase_tag}-stderr", redact_value(err_s, secrets), home))
    ev, res, perr = worker_module.parse_stream_events(out_s)
    denied, mut = worker_module.has_permission_denial(ev, res, err_s), _check_worktree_mutation(worktree, expected_sha, round_dir, home, phase_tag, secrets, baseline_snap, wrote_ev)
    ok = not timed_out and perr is None and not denied and code == 0 and isinstance(res, dict) and res.get("status") == "SUCCESS"
    sid = str(res.get("conversation_id") or "").strip() or None if isinstance(res, dict) else None
    return {"executed": True, "ok": ok, "exit_code": code, "parse_err": perr, "stdout_path": stdout_p, "stderr_path": stderr_p, "session_id": sid, "response": str(res.get("response") or "") if isinstance(res, dict) else "", "mut": mut}

def review_candidate_independently(*, repo: Path, home: Path, child_dir: Path, child: dict[str, Any], conf: config_module.Config, base_sha: str, candidate_sha: str, builder_session_id: str | None, builder_summary: str = "", qa_record: dict[str, Any] | None = None, security_record: dict[str, Any] | None = None, prior_findings: list[dict[str, Any]] | None = None, round_num: int = 1, agy_bin: str | None = None, deadline: float, limit_s: int) -> dict[str, Any]:
    prior_list: list[dict[str, Any]] = []
    history_corrupt = False
    round_dir = safe_dir(child_dir / f"independent-review-round-{round_num}", create=True, root=home)
    worktree = round_dir / "worktree"
    isolated_home = worker_module.prepare_isolated_home(round_dir, Path.home(), root=home); safe_dir(isolated_home / ".tmp", create=True, root=home)
    worker_env, stripped_keys = worker_module.sanitized_env(dict(os.environ), worktree, isolated_home)
    worker_env["GIT_OPTIONAL_LOCKS"] = worker_env["PYTHONNOUSERSITE"] = "1"
    secrets, resolved_sha = collect_redaction_secrets(), str(candidate_sha or "").strip()
    try:
        try:
            try:
                prior_list = _normalize_prior_findings(child_dir, home, round_num, prior_findings, recovered_out=prior_list)
            except errors_module.FactoryError:
                history_corrupt = True
                raise
            resolved_sha = worker_module.prepare_isolated_git_checkout(repo, worktree, candidate_sha, deadline=deadline)
            fetch_res = git_timed(worktree, deadline, limit_s, "fetch base_sha", "fetch", "-q", "--no-tags", str(repo), base_sha)
            rev_res = git_timed(worktree, deadline, limit_s, "verify base_sha", "rev-parse", "--verify", f"{base_sha}^{{commit}}")
            (worktree / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
            probes, probes_ok, sandbox_error = [], False, None
            try:
                if agy_bin and str(agy_bin).strip():
                    worker_module.validate_execution_options(worker_module.platform_info(), time_limit_seconds=limit_s, agy_bin=str(agy_bin))
                probes = worker_module.run_safety_probes(worker_env, worktree, round_dir, home, deadline=deadline)
                probes_ok = worker_module.probes_passed(probes)
            except (worker_module.SandboxUnavailableError, errors_module.FactoryError, deliver_checks.AttemptTimeoutError, TimeoutError, OSError) as exc:
                sandbox_error = str(exc)

            name_status = git_timed(worktree, deadline, limit_s, "diff name-status", "diff", "--find-renames", "--name-status", base_sha, resolved_sha)
            del_res = git_timed(worktree, deadline, limit_s, "diff deleted", "diff", "--diff-filter=D", "--name-only", base_sha, resolved_sha)
            deleted_paths = tuple(p for ln in (del_res.output.splitlines() if del_res.ok else ()) if (p := ln.strip().strip("/")))
            diff_info = inspect_diff_categories(worktree, base_sha, resolved_sha, deadline, limit_s)
            scope_ok, scope_violations, scope_detail = evaluate_scope(tuple(diff_info["changed_paths"]), child, ci_selection.protected_chain_paths(conf))
            diff_res = git_timed(worktree, deadline, limit_s, "independent review diff", "diff", "--binary", base_sha, resolved_sha)
            diff_ok = fetch_res.ok and rev_res.ok and name_status.ok and diff_res.ok and bool(diff_res.output.strip())
            if not diff_ok: scope_detail, scope_ok = {**scope_detail, "status": "diff-failed", "deterministic_ok": False}, False
            diff_text = redact_value(diff_res.output + ("\n" if not diff_res.output.endswith("\n") else ""), secrets)
            diff_path = write_evidence(round_dir, "reviewed-diff", diff_text, home)
            standards = load_project_standards(repo, base_sha, child, conf, deadline, limit_s)
            qa_eval, sec_eval, upstream_gaps = evaluate_upstream_evidence(resolved_sha, base_sha, qa_record, security_record, home=home, repo=repo, child=child, deadline=deadline, limit_s=limit_s)

            role_issues = [f"sandbox or execution unavailable: {sandbox_error}"] if sandbox_error else ([] if probes_ok else ["independent reviewer safety probes failed"])
            if not diff_ok: role_issues.append("failed to produce non-empty exact base-to-candidate diff")
            b_sid = str(builder_session_id or "").strip()
            if not b_sid: role_issues.append("missing builder_session_id; builder identity evidence is required to prove session separation")
            if not (agy_bin and str(agy_bin).strip()): role_issues.append("independent reviewer executable is required; missing reviewer execution fails closed")

            expected_p1_red = redact_value(_render_phase1_prompt(child, base_sha, resolved_sha, diff_text, standards), secrets)
            p1_prompt_red = redact_value(build_phase1_prompt(child, base_sha, resolved_sha, diff_text, standards), secrets)
            p1_prompt_path = write_evidence(round_dir, "phase1-prompt", p1_prompt_red, home)
            summary_norm = (builder_summary or "").strip()
            p1_omitted_summary = p1_prompt_red.split("Exact Base-to-Candidate Diff:", 1)[0] == expected_p1_red.split("Exact Base-to-Candidate Diff:", 1)[0]
            p1_has_exact_diff = bool(diff_res.output.strip()) and diff_text.strip() in p1_prompt_red
            if not p1_omitted_summary: role_issues.append("protocol violation: phase-1 prompt exposed builder summary before hypotheses were recorded")
            if not p1_has_exact_diff: role_issues.append("protocol violation: phase-1 prompt did not include exact base-to-candidate diff")

            base_snap = _snapshot_worktree(worktree)
            p1_res: dict[str, Any] = {"executed": False, "stdout_path": None, "stderr_path": None, "session_id": None, "mut": _check_worktree_mutation(worktree, resolved_sha, round_dir, home, "pre-phase1", secrets, base_snap)}
            p2_res: dict[str, Any] = {"executed": False, "stdout_path": None, "stderr_path": None, "session_id": None, "mut": p1_res["mut"]}
            p2_prompt_path, hypotheses_path, hypotheses_sha256, agent_outcome = None, None, None, None
            hypotheses, assessment, agent_findings, reconcils = [], {}, [], {}

            if probes_ok and diff_ok and bool(b_sid) and bool(agy_bin and str(agy_bin).strip()) and p1_omitted_summary and p1_has_exact_diff:
                try:
                    p1_res = _run_phase_exec(worktree, round_dir, home, isolated_home, worker_env, str(agy_bin), p1_prompt_red, "phase1", resolved_sha, secrets, deadline, limit_s, baseline_snap=base_snap)
                    p2_res["mut"] = p1_res["mut"]
                    if p1_res["mut"]["candidate_modified_by_reviewer"]: role_issues.append("independent reviewer mutated the candidate worktree during phase 1")
                    if not p1_res["ok"]: role_issues.append(f"phase-1 reviewer execution failed (exit={p1_res['exit_code']}, parse_error={p1_res['parse_err']})")
                    elif not p1_res["session_id"]: role_issues.append("phase-1 reviewer did not record a conversation_id")
                    elif p1_res["session_id"] == b_sid: role_issues.append(f"independent reviewer session {p1_res['session_id']!r} matches builder session {b_sid!r}; self-approval is forbidden")
                    else:
                        hypotheses, hyp_issues = _parse_phase1_hypotheses(p1_res["response"])
                        role_issues.extend(hyp_issues)
                        if hypotheses and not hyp_issues and not p1_res["mut"]["candidate_modified_by_reviewer"]:
                            hyp_payload = json.dumps({"reviewer_session_id": p1_res["session_id"], "candidate_sha": resolved_sha, "base_sha": base_sha, "hypotheses": redact_value(hypotheses, secrets)}, indent=2, sort_keys=True) + "\n"
                            hypotheses_path = str(write_evidence(round_dir, "phase1-hypotheses", hyp_payload, home))
                            hypotheses_sha256 = runner.digest_text(hyp_payload)
                except (worker_module.SandboxUnavailableError, errors_module.FactoryError, deliver_checks.AttemptTimeoutError, TimeoutError, OSError) as exc:
                    role_issues.append(f"phase-1 operational failure: {exc}")

            if hypotheses_path is not None and not role_issues:
                p2_prompt_red = redact_value(build_phase2_prompt(child, base_sha, resolved_sha, diff_text, standards, hypotheses, builder_summary, qa_eval, sec_eval, prior_list), secrets)
                p2_prompt_path = str(write_evidence(round_dir, "phase2-prompt", p2_prompt_red, home))
                try:
                    p2_res = _run_phase_exec(worktree, round_dir, home, isolated_home, worker_env, str(agy_bin), p2_prompt_red, "phase2", resolved_sha, secrets, deadline, limit_s, continue_session_id=p1_res["session_id"], baseline_snap=base_snap)
                    if p2_res["mut"]["candidate_modified_by_reviewer"]: role_issues.append("independent reviewer mutated the candidate worktree during phase 2")
                    if not p2_res["ok"]: role_issues.append(f"phase-2 reviewer execution failed (exit={p2_res['exit_code']}, parse_error={p2_res['parse_err']})")
                    elif not p2_res["session_id"]: role_issues.append("phase-2 reviewer did not record a conversation_id")
                    elif p2_res["session_id"] == b_sid: role_issues.append(f"phase-2 reviewer session {p2_res['session_id']!r} matches builder session {b_sid!r}")
                    elif p2_res["session_id"] != p1_res["session_id"]: role_issues.append(f"phase-2 reviewer session {p2_res['session_id']!r} drifted from phase-1 session {p1_res['session_id']!r}")
                    else:
                        agent_outcome, assessment, agent_findings, reconcils, p2_issues = _parse_phase2_response_full(p2_res["response"], has_prior_blockers=bool(prior_list))
                        role_issues.extend(p2_issues)
                except (worker_module.SandboxUnavailableError, errors_module.FactoryError, deliver_checks.AttemptTimeoutError, TimeoutError, OSError) as exc:
                    role_issues.append(f"phase-2 operational failure: {exc}")

            repro_targets: dict[str, dict[str, Any]] = {}
            for item in (*prior_list, *agent_findings):
                if isinstance(item, dict) and item.get("finding_id") and item.get("blocking", True):
                    fid = str(item["finding_id"])
                    vcmd = str((reconcils.get(fid) or {}).get("verification_command") or item.get("verification_command") or "").strip()
                    if vcmd: repro_targets[fid] = {**item, "verification_command": vcmd}
            for rfid, rclaim in reconcils.items():
                if rfid not in repro_targets and rclaim.get("verification_command"):
                    repro_targets[rfid] = {"finding_id": rfid, "verification_command": str(rclaim["verification_command"]).strip()}

            mutation_record = p2_res["mut"] if p2_res["mut"]["candidate_modified_by_reviewer"] else p1_res["mut"]
            worktree_mutated = bool(mutation_record["candidate_modified_by_reviewer"])
            if probes_ok and diff_ok and not worktree_mutated:
                obs_ver = _run_observed_verification(worktree, round_dir, home, child, conf, tuple(diff_info["changed_paths"]), deleted_paths, resolved_sha, secrets, deadline, limit_s, repro_targets=repro_targets)
                post_ver_mut = _check_worktree_mutation(worktree, resolved_sha, round_dir, home, "post-verification", secrets, base_snap)
                if post_ver_mut["candidate_modified_by_reviewer"]:
                    worktree_mutated, mutation_record = True, post_ver_mut
                    role_issues.append("candidate worktree was mutated during verification checks")
            else:
                obs_ver = {"executed": False, "ok": False, "head_sha": resolved_sha, "selection_plan": {}, "checks": [], "finding_verifications": {}, "verification_gaps": [], "provenance": "skipped-due-to-role-or-mutation-failure"}

            det_findings = [_gap_finding("scope", SLUG_RE.sub("-", sv.lower()).strip("-") or "out-of-scope", f"Scope or protected-path drift: {sv}", sv, "Revert out-of-scope or protected-path modifications so the diff stays within declared sub-task scope.", "observed-scope-check", cat="scope-drift") for sv in ([] if scope_ok else scope_violations)] + upstream_gaps + list(obs_ver.get("verification_gaps") or [])
            protocol_ordering = {
                "enforced": bool(p1_omitted_summary and p1_has_exact_diff and hypotheses_path is not None and p2_res["executed"]),
                "phase_1_executed": p1_res["executed"], "phase_1_omitted_builder_summary": p1_omitted_summary, "phase_1_included_exact_diff": p1_has_exact_diff,
                "phase_1_prompt_path": str(p1_prompt_path), "phase_1_stdout_path": p1_res["stdout_path"], "phase_1_stderr_path": p1_res["stderr_path"],
                "hypotheses_persisted_before_summary": hypotheses_path is not None, "hypotheses_path": hypotheses_path, "hypotheses_sha256": hypotheses_sha256,
                "phase_2_executed": p2_res["executed"], "phase_2_continued_session_id": p1_res["session_id"] if p2_res["executed"] else None,
                "phase_2_prompt_path": p2_prompt_path, "phase_2_stdout_path": p2_res["stdout_path"], "phase_2_stderr_path": p2_res["stderr_path"],
            }
            role_sep_ok = (p1_res["executed"] and p2_res["executed"] and bool(p1_res["session_id"]) and bool(b_sid) and p1_res["session_id"] != b_sid and p2_res["session_id"] == p1_res["session_id"] and protocol_ordering["enforced"] and not worktree_mutated and len(role_issues) == 0)
            all_findings, blocking_findings, suggestions, resolutions = reconcile_review_findings(
                round_num=round_num, candidate_sha=resolved_sha, base_sha=base_sha, agent_findings=agent_findings, det_findings=det_findings,
                prior_findings=prior_list, reconciliations=reconcils, obs_ver=obs_ver, qa_eval=qa_eval, sec_eval=sec_eval,
                scope_ok=scope_ok, changed_paths=tuple(diff_info["changed_paths"]), deleted_paths=deleted_paths, role_sep_ok=role_sep_ok, home=home,
            )
            unsatisfied_dims = [k for k, v in assessment.items() if v.get("status") != "satisfied"]
            outcome = "invalid-review" if not role_sep_ok else ("changes-requested" if (blocking_findings or unsatisfied_dims or agent_outcome == "changes-requested" or not obs_ver["ok"] or not qa_eval["verified"] or not sec_eval["verified"]) else "review-passed")
            review_verified = outcome == "review-passed" and role_sep_ok and obs_ver["ok"] and qa_eval["verified"] and sec_eval["verified"] and not blocking_findings and all(r.get("status") == "resolved" for r in resolutions)

            record = redact_value({
                "schema": 1, "role": "independent-reviewer", "builder_role": "builder", "verification_scope": INDEPENDENT_REVIEW_SCOPE_NOTE, "delivery_approved": False, "round": round_num,
                "reviewed_revision": resolved_sha, "base_sha": base_sha, "standards_sha": base_sha, "builder_session_id": b_sid or None, "reviewer_session_id": p1_res["session_id"],
                "reviewer_executed": p1_res["executed"] and p2_res["executed"], "role_separation_verified": role_sep_ok, "role_issues": role_issues, "protocol_ordering": protocol_ordering, "failure_hypotheses": hypotheses,
                "builder_summary_claim": {"summary": builder_summary, "treated_as_execution_evidence": False, "contradicted_by_observed_execution": bool(summary_norm and any(c.get("executed") and not c.get("ok") for c in (obs_ver.get("checks") or [])))},
                "inspected_scope": {"changed_paths": diff_info["changed_paths"], "deleted_paths": list(deleted_paths), "implementation_paths": diff_info["implementation_paths"], "test_paths": diff_info["test_paths"], "scope_status": scope_detail["status"], "deterministic_ok": scope_detail["deterministic_ok"], "diff_path": str(diff_path), "diff_sha256": runner.digest_text(diff_text)},
                "applicable_standards": standards, "assessment": assessment, "upstream_evidence": {"automated_qa": qa_eval, "security_review": sec_eval},
                "observed_verification": obs_ver, "findings": all_findings, "blocking_findings": blocking_findings, "open_finding_ids": [f["finding_id"] for f in blocking_findings],
                "non_blocking_suggestions": suggestions, "previous_findings_resolution": resolutions, "worktree_integrity": mutation_record,
                "safety": {"sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False, "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": probes},
                "outcome": outcome, "review_verified": review_verified, "recorded_at": now(),
            }, secrets)
        except (worker_module.SandboxUnavailableError, errors_module.FactoryError, deliver_checks.AttemptTimeoutError, TimeoutError, OSError) as exc:
            corrupt_gaps = [_gap_finding("prior-history", "corrupt-prior-history", "Corrupt or unreadable prior blocker history", str(exc), "Restore valid prior review records before re-running independent review.", "observed-setup")] if history_corrupt else []
            all_findings, blocking_findings, suggestions, resolutions = reconcile_review_findings(
                round_num=round_num, candidate_sha=resolved_sha, base_sha=base_sha, agent_findings=[], det_findings=corrupt_gaps,
                prior_findings=prior_list, reconciliations={}, obs_ver=None, qa_eval=None, sec_eval=None, scope_ok=False, role_sep_ok=False, home=home,
            )
            record = redact_value({
                "schema": 1, "role": "independent-reviewer", "builder_role": "builder", "verification_scope": INDEPENDENT_REVIEW_SCOPE_NOTE, "delivery_approved": False, "round": round_num,
                "reviewed_revision": resolved_sha, "base_sha": base_sha, "standards_sha": base_sha, "builder_session_id": str(builder_session_id or "").strip() or None, "reviewer_session_id": None,
                "reviewer_executed": False, "role_separation_verified": False, "role_issues": [f"operational failure during independent review setup: {exc}"],
                "protocol_ordering": {"enforced": False, "phase_1_executed": False, "phase_2_executed": False, "phase_2_continued_session_id": None}, "failure_hypotheses": [],
                "builder_summary_claim": {"summary": builder_summary, "treated_as_execution_evidence": False, "contradicted_by_observed_execution": False},
                "inspected_scope": {"changed_paths": [], "deleted_paths": [], "implementation_paths": [], "test_paths": [], "scope_status": "operational-failure", "deterministic_ok": False, "diff_path": None, "diff_sha256": None},
                "applicable_standards": [], "assessment": {}, "upstream_evidence": {"automated_qa": {"status": "not-evaluated", "verified": False}, "security_review": {"status": "not-evaluated", "verified": False}},
                "observed_verification": {"executed": False, "ok": False, "head_sha": resolved_sha, "selection_plan": {}, "checks": [], "finding_verifications": {}, "verification_gaps": [], "provenance": "skipped-due-to-operational-failure"},
                "findings": all_findings, "blocking_findings": blocking_findings, "open_finding_ids": [f["finding_id"] for f in blocking_findings],
                "non_blocking_suggestions": suggestions, "previous_findings_resolution": resolutions,
                "worktree_integrity": {"phase": "setup", "head_before": resolved_sha, "head_after": resolved_sha, "status_porcelain": "", "worktree_clean": True, "candidate_modified_by_reviewer": False, "mutation_evidence_path": None},
                "safety": {"sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False, "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": []},
                "outcome": "invalid-review", "review_verified": False, "recorded_at": now(),
            }, secrets)
        atomic_json(round_dir / "record.json", record, home); atomic_json(child_dir / "independent-review.json", record, home)
        if not history_corrupt:
            atomic_json(child_dir / "prior-blockers.json", {"schema": 1, "updated_in_round": round_num, "reviewed_revision": record["reviewed_revision"], "findings": [f for f in record["findings"] if f.get("blocking")]}, home)
        return record
    finally:
        shutil.rmtree(worktree, ignore_errors=True)

def run_disposable_demo(tmp: Path) -> dict[str, Any]:
    from tests.independent_review.test_independent_review import run_disposable_demo as _run_demo
    return _run_demo(tmp)

def main(argv: list[str] | None = None) -> int:
    import argparse, tempfile
    p = argparse.ArgumentParser(prog="python3 -m factory.independent_review", description="Standalone independent reviewer role demo (#52).")
    p.add_argument("--demo", action="store_true", help="Run disposable independent-review demonstration.")
    p.add_argument("--evidence-dir", type=Path, default=None, help="Optional directory to retain demo evidence.")
    args = p.parse_args(argv)
    if not args.demo: p.error("standalone independent-review slice (#52) supports --demo; delivery approval gate is #53")
    if args.evidence_dir is not None:
        args.evidence_dir.mkdir(parents=True, exist_ok=True); summary = run_disposable_demo(args.evidence_dir)
    else:
        with tempfile.TemporaryDirectory() as tmp: summary = run_disposable_demo(Path(tmp))
    print(json.dumps(summary, indent=2, sort_keys=True)); print("DEMO_INDEPENDENT_REVIEW_OK")
    return 0
