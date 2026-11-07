"""Exact-candidate final approval gate and prerequisite evidence adapters (Issue #58; Part 2b-a of #23)."""
from __future__ import annotations
import json, re, time
from pathlib import Path
from typing import Any
from factory import ci_gate, ci_selection, config as config_module, errors as errors_module, gitio, independent_review as ir_pkg, runner, security_review, worker as worker_module
from factory.config import now
from factory.deliver_checks import collect_redaction_secrets
from factory.intake import redact_value
from factory.paths import atomic_json, read_json

APPROVAL_GATE_SCOPE_NOTE = "exact-candidate-delivery-approval-gate (#58); not merge-approved (#24) or parent-accepted"


def _verify_file_digest(path_val: Any, sha_val: Any, home: Path | None, label: str) -> str | None:
    if not isinstance(path_val, str) or not path_val.strip() or not isinstance(sha_val, str) or not sha_val.strip():
        return f"{label} is missing stored output_path or output_sha256"
    p = Path(path_val)
    try:
        if p.is_symlink() or not p.is_file() or (home is not None and not p.resolve().is_relative_to(home.resolve())):
            return f"{label} stored evidence file {p} is missing or outside runtime home"
        if runner.digest_text(p.read_text(encoding="utf-8", errors="replace")) != sha_val:
            return f"{label} stored evidence file {p} sha256 mismatch"
    except OSError:
        return f"{label} stored evidence file {p} is unreadable"
    return None


def load_prerequisite_evidence(child_dir: Path, home: Path, *, attempt_dir: Path | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"ci_record": None, "qa_record": None, "security_record": None, "review_record": None}
    att_dir = attempt_dir or (child_dir.parent.parent if child_dir.parent.name == "children" else None)
    if (ci_p := child_dir / "ci-verification.json").is_file():
        out["ci_record"] = read_json(ci_p, home)
    elif att_dir is not None and (att_rec_p := att_dir / "record.json").is_file():
        att_rec = read_json(att_rec_p, home)
        if isinstance(att_rec, dict) and isinstance(att_rec.get("child"), dict):
            out["ci_record"] = att_rec["child"].get("ci_verification")
    if (qa_dir := child_dir / "automated-qa").is_dir():
        rounds = sorted((int(m.group(1)), p / "record.json") for p in qa_dir.iterdir() if p.is_dir() and (m := re.fullmatch(r"round-(\d+)", p.name)) and (p / "record.json").is_file())
        if rounds:
            out["qa_record"] = read_json(rounds[-1][1], home)
        elif (qa_rec_p := qa_dir / "record.json").is_file():
            out["qa_record"] = read_json(qa_rec_p, home)
    if (sec_p := child_dir / "security-review.json").is_file():
        out["security_record"] = read_json(sec_p, home)
    if (rev_p := child_dir / "independent-review.json").is_file():
        out["review_record"] = read_json(rev_p, home)
    return out


def evaluate_ci_prerequisite(
    candidate_sha: str, base_sha: str, ci_record: Any, *, repo: Path | None = None, home: Path | None = None,
    child: dict[str, Any] | None = None, conf: config_module.Config | None = None, deadline: float | None = None, limit_s: int = 30,
) -> dict[str, Any]:
    if hasattr(ci_record, "to_dict"): ci_record = ci_record.to_dict()
    if isinstance(ci_record, dict) and isinstance(ci_record.get("child"), dict) and isinstance(ci_record["child"].get("ci_verification"), dict):
        ci_record = ci_record["child"]
    if isinstance(ci_record, dict) and isinstance(ci_record.get("ci_verification"), dict):
        if ci_record.get("delivery_approved") is True:
            return {"status": "authority-violation", "verified": False, "blockers": ["non-gate wrapper record cannot issue delivery_approved=True"]}
        if ci_record.get("verified") is False or ci_record.get("status") not in (None, "verified"):
            return {"status": str(ci_record.get("status") or "ci-failed"), "verified": False, "blockers": ["delivery wrapper marks CI as unverified"]}
        ci_record = ci_record["ci_verification"]
    if not isinstance(ci_record, dict) or not ci_record:
        return {"status": "ci-missing", "verified": False, "blockers": [f"missing CI verification evidence for candidate {candidate_sha}"]}
    if ci_record.get("delivery_approved") is True:
        return {"status": "authority-violation", "verified": False, "blockers": ["non-gate producer CI record cannot issue delivery_approved=True"]}
    if not (isinstance(candidate_sha, str) and ci_gate.SHA40_RE.fullmatch(candidate_sha) and isinstance(base_sha, str) and ci_gate.SHA40_RE.fullmatch(base_sha)):
        return {"status": "ci-evidence-invalid", "verified": False, "blockers": ["candidate_sha and base_sha must be 40-char git SHAs"]}
    rec_cand, rec_base, rec_tested, rec_pol = ci_record.get("candidate_sha"), ci_record.get("base_sha"), ci_record.get("tested_sha"), ci_record.get("policy_sha")
    if isinstance(rec_cand, str) and ci_gate.SHA40_RE.fullmatch(rec_cand) and rec_cand != candidate_sha:
        return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"stale CI evidence: candidate_sha={rec_cand} != {candidate_sha}"]}
    if isinstance(rec_base, str) and ci_gate.SHA40_RE.fullmatch(rec_base) and rec_base != base_sha:
        return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"stale CI evidence: base_sha={rec_base} != {base_sha}"]}
    if isinstance(rec_pol, str) and ci_gate.SHA40_RE.fullmatch(rec_pol) and rec_pol != base_sha:
        return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"stale CI policy_sha={rec_pol} != {base_sha}"]}
    if ci_record.get("status") not in (None, "verified") and ci_record.get("verified") is False:
        st = "stale-ci-evidence" if ci_record.get("status") == "stale-revision" else str(ci_record.get("status") or "ci-failed")
        return {"status": st, "verified": False, "blockers": list(ci_record.get("blockers") or [f"CI verification status is {st}"])}
    if not all(isinstance(x, str) and ci_gate.SHA40_RE.fullmatch(x) for x in (rec_cand, rec_base, rec_tested, rec_pol)):
        return {"status": "ci-evidence-invalid", "verified": False, "blockers": ["CI record is missing valid 40-char candidate_sha, base_sha, policy_sha, or tested_sha"]}
    rev_kind = ci_record.get("revision_kind")
    if rev_kind not in ("fast-forward-head", "integration-merge"):
        return {"status": "ci-evidence-invalid", "verified": False, "blockers": [f"invalid CI revision_kind {rev_kind!r}"]}
    if rec_tested == candidate_sha:
        if rev_kind != "fast-forward-head":
            return {"status": "stale-ci-evidence", "verified": False, "blockers": ["integration-merge CI record cannot have tested_sha == candidate_sha"]}
        if repo is not None and gitio.git(repo, "cat-file", "-t", candidate_sha).ok and gitio.git(repo, "cat-file", "-t", base_sha).ok and not gitio.is_ancestor(repo, base_sha, candidate_sha):
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"candidate_sha {candidate_sha} does not descend from base_sha {base_sha}"]}
    else:
        if rev_kind != "integration-merge":
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"tested_sha != candidate_sha requires integration-merge, got {rev_kind!r}"]}
        parents_ok = False
        if repo is not None:
            ok_git, git_kind, git_err = ci_gate._verify_tested_revision_in_git(repo, base_sha, candidate_sha, rec_tested, int(ci_record.get("pr_number") or 0), deadline or (time.monotonic() + 10.0), limit_s)
            if not ok_git or git_kind != "integration-merge":
                return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"invalid CI integration-merge tested_sha {rec_tested}: {git_err or git_kind}"]}
            parents_ok = True
        rec_parents = ci_record.get("merge_parents")
        if rec_parents is not None:
            if not isinstance(rec_parents, (list, tuple)) or len(rec_parents) != 2 or not all(isinstance(p, str) for p in rec_parents) or set(rec_parents) != {base_sha, candidate_sha}:
                return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"CI integration-merge parents {rec_parents!r} do not match [base_sha, candidate_sha]"]}
            parents_ok = True
        if not parents_ok:
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"unverified CI integration-merge tested_sha {rec_tested}"]}
    if repo is not None and conf is not None and gitio.git(repo, "cat-file", "-t", rec_tested).ok and gitio.git(repo, "cat-file", "-t", base_sha).ok:
        pol_errs = ci_gate._verify_policy_revision_in_git(repo, base_sha, candidate_sha, rec_tested, ci_selection.protected_chain_paths(conf), deadline or (time.monotonic() + 10.0), limit_s)
        if pol_errs:
            return {"status": "ci-untrusted-producer", "verified": False, "blockers": pol_errs}
    producers, workflows = ci_record.get("trusted_producers"), ci_record.get("trusted_workflows")
    if not isinstance(producers, list) or not producers or any(not isinstance(p, str) or p not in ci_gate.TRUSTED_CHECK_PRODUCERS for p in producers):
        return {"status": "ci-untrusted-producer", "verified": False, "blockers": ["CI record has missing or untrusted check producers"]}
    if not isinstance(workflows, list) or not workflows or any(not isinstance(w, str) or w not in ci_gate.TRUSTED_WORKFLOW_PATHS for w in workflows):
        return {"status": "ci-untrusted-producer", "verified": False, "blockers": ["CI record has missing or untrusted workflow paths"]}
    checks = ci_record.get("checks")
    if not isinstance(checks, list) or not checks or any(not isinstance(c, dict) for c in checks):
        return {"status": "ci-evidence-invalid", "verified": False, "blockers": ["CI record is missing a non-empty list of check records"]}
    req_names = {r["name"] for r in ci_selection.build_required_ci_checks(child, conf)} if (isinstance(child, dict) and conf is not None) else set()
    for r_item in ci_record.get("required_checks") or ():
        if isinstance(r_item, dict) and r_item.get("name"): req_names.add(str(r_item["name"]))
        elif isinstance(r_item, str) and r_item.strip(): req_names.add(r_item.strip())
    for c in checks:
        cname = str(c.get("name") or "").strip()
        if not cname:
            return {"status": "ci-evidence-invalid", "verified": False, "blockers": ["CI check record is missing name"]}
        if c.get("producer") not in ci_gate.TRUSTED_CHECK_PRODUCERS or c.get("workflow_path") not in ci_gate.TRUSTED_WORKFLOW_PATHS:
            return {"status": "ci-untrusted-producer", "verified": False, "blockers": [f"CI check {cname!r} used untrusted producer or workflow"]}
        if bool(c.get("cached_result")) or (c.get("cached_from_sha") and c.get("cached_from_sha") != candidate_sha):
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"CI check {cname!r} reused cached result across revisions"]}
        if any(c.get(k) != exp for k, exp in (("candidate_sha", candidate_sha), ("base_sha", base_sha), ("policy_sha", base_sha), ("tested_sha", rec_tested), ("revision_kind", rev_kind))):
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"CI check {cname!r} revision binding mismatch"]}
        if c.get("status") != "completed":
            return {"status": "ci-pending", "verified": False, "blockers": [f"CI check {cname!r} is not completed"]}
        if c.get("conclusion") != "success":
            st = "ci-skipped" if c.get("conclusion") in ("skipped", "neutral", "cancelled") else "ci-failed"
            return {"status": st, "verified": False, "blockers": [f"CI check {cname!r} conclusion is {c.get('conclusion')!r}"]}
        if not str(c.get("html_url") or "").startswith(ci_gate._URL_PREFIXES) or not str(c.get("artifact_url") or "").startswith(ci_gate._URL_PREFIXES):
            return {"status": "ci-evidence-invalid", "verified": False, "blockers": [f"CI check {cname!r} is missing accessible GitHub log or artifact URL"]}
        if (err := _verify_file_digest(c.get("output_path"), c.get("output_sha256"), home, f"CI check {cname!r}")) is not None:
            return {"status": "ci-evidence-invalid", "verified": False, "blockers": [err]}
    missing_req = sorted(req_names - {str(c.get("name") or "").strip() for c in checks})
    if missing_req:
        return {"status": "ci-missing", "verified": False, "blockers": [f"missing required CI checks on {candidate_sha}: {', '.join(missing_req)}"]}
    pr = ci_record.get("pr")
    if pr is not None:
        if not isinstance(pr, dict):
            return {"status": "ci-evidence-invalid", "verified": False, "blockers": ["CI record pr field must be an object"]}
        if pr.get("state", "open") != "open" or pr.get("merged") is True or pr.get("head_sha", candidate_sha) != candidate_sha or pr.get("base_sha", base_sha) != base_sha:
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"PR state or revision drifted from candidate {candidate_sha}"]}
        if pr.get("pr_confirmed") is not True or pr.get("ci_verified") is not True or pr.get("verified") is not True:
            return {"status": "ci-failed", "verified": False, "blockers": ["CI record PR verification flags are not True"]}
    head_branch = str(ci_record.get("head_branch") or "").strip()
    if repo is not None and head_branch:
        br_res = gitio.git(repo, "rev-parse", "--verify", f"refs/heads/{head_branch}")
        if br_res.ok and br_res.output.strip() != candidate_sha:
            return {"status": "stale-ci-evidence", "verified": False, "blockers": [f"branch {head_branch} head {br_res.output.strip()} drifted from CI candidate {candidate_sha}"]}
    if ci_record.get("status") != "verified" or ci_record.get("verified") is not True or not isinstance(ci_record.get("blockers", []), list) or bool(ci_record.get("blockers")):
        return {"status": "ci-failed", "verified": False, "blockers": list(ci_record.get("blockers") or ["CI record is not verified"])}
    return {"status": "verified", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": rec_tested, "revision_kind": rev_kind, "blockers": []}


def evaluate_qa_prerequisite(
    candidate_sha: str, base_sha: str, qa_record: Any, *, child_dir: Path | None = None, home: Path | None = None,
    repo: Path | None = None, child: dict[str, Any] | None = None, expected_tested_sha: str | None = None,
    expected_revision_kind: str | None = None, deadline: float | None = None, limit_s: int = 30,
) -> dict[str, Any]:
    if hasattr(qa_record, "to_dict"): qa_record = qa_record.to_dict()
    prior_qa_fids: set[str] = set()
    if isinstance(qa_record, dict) and qa_record.get("delivery_approved") is True:
        return {"status": "authority-violation", "verified": False, "blockers": ["non-gate producer automated-qa cannot issue delivery_approved=True"]}
    if isinstance(qa_record, dict) and isinstance(qa_record.get("automated_qa"), dict) and "criterion_coverage" not in qa_record:
        qa_record = qa_record["automated_qa"]
    if isinstance(qa_record, dict) and isinstance(qa_record.get("qa_rounds"), list):
        if qa_record.get("qa_verified") is not True or qa_record.get("ci_verified") is False or qa_record.get("status") not in (None, "qa-verified") or bool(qa_record.get("open_finding_ids")):
            return {"status": str(qa_record.get("status") or "qa-failed"), "verified": False, "blockers": ["QA delivery wrapper is not verified"]}
        rounds_list = [r for r in qa_record["qa_rounds"] if isinstance(r, dict)]
        if not rounds_list:
            return {"status": "qa-missing", "verified": False, "blockers": [f"missing automated QA round records for {candidate_sha}"]}
        for pr_r in rounds_list[:-1]:
            prior_qa_fids.update(str(f["finding_id"]) for f in (pr_r.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id"))
        qa_record = rounds_list[-1]
    elif isinstance(qa_record, dict) and "criterion_coverage" not in qa_record and child_dir is not None and home is not None:
        if qa_record.get("qa_verified") is not True or qa_record.get("status") not in (None, "qa-verified") or bool(qa_record.get("open_finding_ids")):
            return {"status": str(qa_record.get("status") or "qa-failed"), "verified": False, "blockers": ["QA summary record is not verified"]}
        r_count = int(qa_record.get("rounds") or 0)
        r_path = child_dir / "automated-qa" / f"round-{r_count}" / "record.json" if r_count > 0 else None
        if r_path is not None and r_path.is_file():
            qa_record = read_json(r_path, home)
    if isinstance(qa_record, dict) and qa_record.get("delivery_approved") is True:
        return {"status": "authority-violation", "verified": False, "blockers": ["non-gate producer automated-qa cannot issue delivery_approved=True"]}
    if child_dir is not None and home is not None and (qa_dir := child_dir / "automated-qa").is_dir() and isinstance(qa_record, dict):
        cur_r = qa_record.get("round") if isinstance(qa_record.get("round"), int) else None
        for p in sorted(qa_dir.iterdir()):
            if p.is_dir() and (m := re.fullmatch(r"round-(\d+)", p.name)) and ((rp := p / "record.json").exists() or rp.is_symlink()):
                r_idx = int(m.group(1))
                try:
                    r_obj = read_json(rp, home)
                except (errors_module.FactoryError, OSError) as exc:
                    return {"status": "qa-invalid", "verified": False, "blockers": [f"corrupt automated-qa round history in {rp}: {exc}"]}
                if not isinstance(r_obj, dict) or not isinstance(r_obj.get("findings", []), list):
                    return {"status": "qa-invalid", "verified": False, "blockers": [f"invalid automated-qa round record in {rp}"]}
                if cur_r is not None and r_idx > cur_r:
                    return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"automated-qa round {cur_r} is superseded by round {r_idx}"]}
                if (cur_r is not None and r_idx < cur_r) or (cur_r is None and r_obj.get("candidate_sha") != candidate_sha):
                    prior_qa_fids.update(str(f["finding_id"]) for f in (r_obj.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id"))
    qa_eval = ir_pkg._validate_qa_record(candidate_sha, base_sha, qa_record, repo=repo, child=child, deadline=deadline, limit_s=limit_s)
    if not qa_eval["verified"]:
        return qa_eval
    cur_qa_fids = {str(f.get("finding_id")): f for f in (qa_record.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id")}
    if not prior_qa_fids.issubset(cur_qa_fids):
        omitted = sorted(prior_qa_fids - set(cur_qa_fids))
        return {"status": "qa-findings-open", "verified": False, "blockers": [f"historical automated-qa findings omitted from reconciliation: {', '.join(omitted)}"]}
    for cov in qa_record.get("criterion_coverage") or ():
        for chk in (cov.get("deterministic_check"), *(cov.get("evaluation_cases") or ())):
            if isinstance(chk, dict) and (chk.get("output_path") is not None or chk.get("output_sha256") is not None):
                if (err := _verify_file_digest(chk.get("output_path"), chk.get("output_sha256"), home, "QA check")) is not None:
                    return {"status": "qa-invalid", "verified": False, "blockers": [err]}
    for rc in qa_record.get("regression_checks") or ():
        if isinstance(rc, dict) and (rc.get("output_path") is not None or rc.get("output_sha256") is not None):
            if (err := _verify_file_digest(rc.get("output_path"), rc.get("output_sha256"), home, "QA regression check")) is not None:
                return {"status": "qa-invalid", "verified": False, "blockers": [err]}
    qa_tested = str(qa_record.get("tested_sha") or "")
    ci_reval = qa_record.get("ci_revalidation") or {}
    qa_kind = str(qa_record.get("revision_kind") or ci_reval.get("revision_kind") or ("fast-forward-head" if qa_tested == candidate_sha else "integration-merge"))
    if expected_tested_sha and qa_tested != expected_tested_sha:
        return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"QA tested_sha {qa_tested} does not match CI tested_sha {expected_tested_sha}"]}
    if expected_revision_kind and qa_kind != expected_revision_kind:
        return {"status": "stale-qa-evidence", "verified": False, "blockers": [f"QA revision_kind {qa_kind!r} does not match CI revision_kind {expected_revision_kind!r}"]}
    return {"status": "qa-verified", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": qa_tested, "revision_kind": qa_kind, "blockers": []}


def evaluate_security_prerequisite(
    candidate_sha: str, base_sha: str, security_record: Any, *, child_dir: Path | None = None, home: Path | None = None,
) -> dict[str, Any]:
    if hasattr(security_record, "to_dict"): security_record = security_record.to_dict()
    if isinstance(security_record, dict) and isinstance(security_record.get("child"), dict) and isinstance(security_record["child"].get("security_review"), dict):
        security_record = security_record["child"]
    if isinstance(security_record, dict) and isinstance(security_record.get("security_review"), dict):
        if security_record.get("delivery_approved") is True:
            return {"status": "authority-violation", "verified": False, "blockers": ["non-gate security wrapper cannot issue delivery_approved=True"]}
        if isinstance(security_record.get("security_gate"), dict) and security_record["security_gate"].get("verified") is False:
            return {"status": str(security_record["security_gate"].get("status") or "security-blockers-unresolved"), "verified": False, "blockers": list(security_record["security_gate"].get("blockers") or ["security gate unverified"])}
        security_record = security_record["security_review"]
    if isinstance(security_record, dict) and security_record.get("delivery_approved") is True:
        return {"status": "authority-violation", "verified": False, "blockers": ["non-gate producer security-reviewer cannot issue delivery_approved=True"]}
    sec_eval = security_review.evaluate_security_review_gate(candidate_sha, base_sha, security_record, home=home)
    if not sec_eval["verified"]:
        return sec_eval
    if child_dir is not None and home is not None and child_dir.is_dir() and isinstance(security_record, dict):
        cur_r = security_record.get("round") if isinstance(security_record.get("round"), int) else None
        prior_sec_fids: set[str] = set()
        for p in sorted(child_dir.iterdir()):
            if p.is_dir() and (m := re.fullmatch(r"security-round-(\d+)", p.name)) and ((rp := p / "record.json").exists() or rp.is_symlink()):
                r_idx = int(m.group(1))
                try:
                    r_obj = read_json(rp, home)
                except (errors_module.FactoryError, OSError) as exc:
                    return {"status": "security-review-invalid", "verified": False, "blockers": [f"corrupt security round history in {rp}: {exc}"]}
                if not isinstance(r_obj, dict) or not isinstance(r_obj.get("findings", []), list):
                    return {"status": "security-review-invalid", "verified": False, "blockers": [f"invalid security round record in {rp}"]}
                if cur_r is not None and r_idx > cur_r:
                    return {"status": "stale-security-review", "verified": False, "blockers": [f"security review round {cur_r} is superseded by round {r_idx}"]}
                if (cur_r is not None and r_idx < cur_r) or (cur_r is None and r_obj.get("reviewed_revision") != candidate_sha):
                    prior_sec_fids.update(str(f["finding_id"]) for f in (r_obj.get("findings") or ()) if isinstance(f, dict) and f.get("blocking") and f.get("finding_id"))
        cur_f_map = {str(f.get("finding_id")): f for f in (security_record.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id")}
        cur_r_map = {str(r.get("finding_id")): r for r in (security_record.get("previous_findings_resolution") or ()) if isinstance(r, dict) and r.get("finding_id")}
        for sfid in sorted(prior_sec_fids):
            if sfid not in cur_f_map or sfid not in cur_r_map or cur_f_map[sfid].get("status") != "resolved" or cur_r_map[sfid].get("status") != "resolved" or cur_r_map[sfid].get("verified_on_revision") != candidate_sha:
                return {"status": "security-blockers-unresolved", "verified": False, "blockers": [f"historical security blocker {sfid} was omitted or unresolved on {candidate_sha}"]}
    return sec_eval


def _load_review_history_for_gate(
    child_dir: Path | None, home: Path | None, rec_round: int, candidate_sha: str, prior_findings: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None, str | None]:
    if prior_findings is not None and (not isinstance(prior_findings, list) or any(not isinstance(f, dict) for f in prior_findings)):
        return [], [], "corrupt-prior-history", "prior_findings must be a list of finding objects"
    if child_dir is not None and home is not None:
        if child_dir.is_dir():
            for p in sorted(child_dir.iterdir()):
                if p.is_dir() and (m := re.fullmatch(r"independent-review-round-(\d+)", p.name)) and ((rp := p / "record.json").exists() or rp.is_symlink()):
                    r_idx = int(m.group(1))
                    if r_idx > rec_round:
                        return [], [], "stale-independent-review", f"independent review round {rec_round} is superseded by round {r_idx}"
        pb_p = child_dir / "prior-blockers.json"
        if pb_p.exists() or pb_p.is_symlink():
            try:
                pb_obj = read_json(pb_p, home)
                if not isinstance(pb_obj, dict) or not isinstance(pb_obj.get("findings"), list) or any(not isinstance(x, dict) for x in pb_obj["findings"]):
                    return [], [], "corrupt-prior-history", f"corrupt prior review history structure in {pb_p}"
                if isinstance(pb_obj.get("updated_in_round"), int) and pb_obj["updated_in_round"] > rec_round:
                    return [], [], "stale-independent-review", f"prior-blockers.json updated_in_round {pb_obj['updated_in_round']} supersedes round {rec_round}"
            except (errors_module.FactoryError, OSError) as exc:
                return [], [], "corrupt-prior-history", f"unreadable or corrupt prior review history in {pb_p}: {exc}"
        try:
            all_hist = ir_pkg._normalize_prior_findings(child_dir, home, rec_round + 1, prior_findings)
        except errors_module.FactoryError as exc:
            return [], [], "corrupt-prior-history", str(exc)
    else:
        try:
            all_hist = ir_pkg._normalize_prior_findings(Path("/nonexistent"), home or Path("/tmp"), 1, prior_findings)
        except errors_module.FactoryError as exc:
            return [], [], "corrupt-prior-history", str(exc)
    prior_entering: list[dict[str, Any]] = []
    for pf in all_hist:
        intro_r = int(pf.get("introduced_in_round") or pf.get("created_round") or 1)
        intro_rev = str(pf.get("introduced_in_revision") or pf.get("created_candidate_sha") or "")
        prior_hist = [h for h in (pf.get("history") or ()) if isinstance(h, dict) and isinstance(h.get("round"), int) and int(h["round"]) < rec_round]
        if prior_hist:
            last_h = prior_hist[-1]
            prior_entering.append({
                **pf, "status": str(last_h.get("status") or "open"), "resolution": last_h.get("resolution"),
                "resolution_blocker": last_h.get("resolution_blocker"), "last_seen_round": int(last_h["round"]),
                "last_seen_revision": str(last_h.get("candidate_sha") or intro_rev),
                "resolved_in_round": int(last_h["round"]) if last_h.get("status") == "resolved" else None,
                "resolved_in_revision": str(last_h.get("candidate_sha") or "") if last_h.get("status") == "resolved" else None,
                "history": prior_hist,
            })
        elif intro_r < rec_round or (intro_rev and intro_rev != candidate_sha) or (prior_findings and any(pf["finding_id"] == str(x.get("finding_id") or ir_pkg.compute_review_finding_id(str(x.get("category") or "bug"), str(x.get("target") or "repository"), str(x.get("rule") or "concern"))) for x in prior_findings)):
            prior_entering.append({
                **pf, "status": "open" if pf.get("resolved_in_round") in (None, rec_round) else str(pf.get("status") or "open"),
                "last_seen_round": min(intro_r, max(1, rec_round - 1)), "last_seen_revision": intro_rev,
                "resolved_in_round": None if pf.get("resolved_in_round") == rec_round else pf.get("resolved_in_round"),
                "resolved_in_revision": None if pf.get("resolved_in_round") == rec_round else pf.get("resolved_in_revision"),
            })
    return all_hist, prior_entering, None, None


def evaluate_independent_review_prerequisite(
    candidate_sha: str, base_sha: str, review_record: Any, *, child_dir: Path | None = None, home: Path | None = None,
    repo: Path | None = None, child: dict[str, Any] | None = None, conf: config_module.Config | None = None,
    builder_session_id: str | None = None, prior_findings: list[dict[str, Any]] | None = None,
    qa_eval: dict[str, Any] | None = None, sec_eval: dict[str, Any] | None = None, deadline: float | None = None, limit_s: int = 30,
) -> dict[str, Any]:
    if not isinstance(review_record, dict) or not review_record:
        return {"status": "independent-review-missing", "verified": False, "historical_blockers": [], "blockers": [f"missing independent review evidence for candidate {candidate_sha}"]}
    if review_record.get("role") != "independent-reviewer" or review_record.get("delivery_approved") is not False or review_record.get("verification_scope") != ir_pkg.INDEPENDENT_REVIEW_SCOPE_NOTE:
        return {"status": "authority-violation", "verified": False, "historical_blockers": [], "blockers": ["non-gate producer independent-reviewer cannot issue delivery_approved=True or alter role scope"]}
    rec_round = review_record.get("round") if isinstance(review_record.get("round"), int) and review_record.get("round") >= 1 else 1
    all_hist, prior_entering, hist_st, hist_err = _load_review_history_for_gate(child_dir, home, rec_round, candidate_sha, prior_findings)
    if hist_st is not None:
        return {"status": hist_st, "verified": False, "historical_blockers": all_hist, "blockers": [hist_err or hist_st]}
    rev_cand, rev_base, std_sha = review_record.get("reviewed_revision"), review_record.get("base_sha"), review_record.get("standards_sha")
    if not all(isinstance(x, str) and ci_gate.SHA40_RE.fullmatch(x) for x in (rev_cand, rev_base, std_sha)):
        return {"status": "invalid-review", "verified": False, "historical_blockers": all_hist, "blockers": ["independent review record is missing valid 40-char reviewed_revision, base_sha, or standards_sha"]}
    if rev_cand != candidate_sha or rev_base != base_sha or std_sha != base_sha:
        return {"status": "stale-independent-review", "verified": False, "historical_blockers": all_hist, "blockers": [f"stale independent review: reviewed=({rev_cand}, base={rev_base}, std={std_sha}) != expected=({candidate_sha}, base={base_sha})"]}
    wt = review_record.get("worktree_integrity")
    if not isinstance(wt, dict) or wt.get("worktree_clean") is not True or wt.get("candidate_modified_by_reviewer") is not False or wt.get("head_before") != candidate_sha or wt.get("head_after") != candidate_sha or wt.get("status_porcelain") != "" or wt.get("mutation_evidence_path") is not None:
        return {"status": "reviewer-modified-worktree", "verified": False, "historical_blockers": all_hist, "blockers": ["independent reviewer modified the candidate worktree"]}
    b_sid, r_sid = str(review_record.get("builder_session_id") or "").strip(), str(review_record.get("reviewer_session_id") or "").strip()
    if not b_sid or not r_sid or r_sid == b_sid or (builder_session_id is not None and b_sid != str(builder_session_id).strip()):
        return {"status": "reused-builder-identity", "verified": False, "historical_blockers": all_hist, "blockers": [f"invalid or reused session identity: builder={b_sid!r}, reviewer={r_sid!r}"]}
    po, hyps = review_record.get("protocol_ordering"), review_record.get("failure_hypotheses")
    if not isinstance(po, dict) or not (po.get("enforced") is True and po.get("phase_1_executed") is True and po.get("phase_1_omitted_builder_summary") is True and po.get("phase_1_included_exact_diff") is True and po.get("hypotheses_persisted_before_summary") is True and po.get("phase_2_executed") is True and po.get("phase_2_continued_session_id") == r_sid):
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["independent review two-phase protocol ordering was not enforced"]}
    if not isinstance(hyps, list) or not hyps or any(not isinstance(h, str) or not h.strip() for h in hyps):
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["independent review is missing non-empty pre-summary failure hypotheses"]}
    if (hyp_err := _verify_file_digest(po.get("hypotheses_path"), po.get("hypotheses_sha256"), home, "phase-1 hypotheses")) is not None:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": [hyp_err]}
    try:
        hyp_obj = read_json(Path(str(po["hypotheses_path"])), home)
        if not isinstance(hyp_obj, dict) or hyp_obj.get("reviewer_session_id") != r_sid or hyp_obj.get("candidate_sha") != candidate_sha or hyp_obj.get("base_sha") != base_sha or hyp_obj.get("hypotheses") != hyps:
            return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["persisted phase-1 hypotheses metadata mismatch"]}
        p1_p, p1_out, p2_p, p2_out = (Path(str(po.get(k) or "")) for k in ("phase_1_prompt_path", "phase_1_stdout_path", "phase_2_prompt_path", "phase_2_stdout_path"))
        for fp in (p1_p, p1_out, p2_p, p2_out):
            if fp.is_symlink() or not fp.is_file() or (home is not None and not fp.resolve().is_relative_to(home.resolve())):
                return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": [f"missing or untrusted protocol artifact {fp}"]}
        p1_prompt_txt = p1_p.read_text(encoding="utf-8", errors="replace")
        _, p1_res, p1_perr = worker_module.parse_stream_events(p1_out.read_text(encoding="utf-8", errors="replace"))
        _, p2_res, p2_perr = worker_module.parse_stream_events(p2_out.read_text(encoding="utf-8", errors="replace"))
    except (errors_module.FactoryError, OSError) as exc:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": [f"unreadable protocol artifacts: {exc}"]}
    if "PHASE: 1" not in p1_prompt_txt or "Exact Base-to-Candidate Diff:" not in p1_prompt_txt:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["phase-1 prompt is missing required phase header or diff section"]}
    pre_diff_p1 = p1_prompt_txt.split("Exact Base-to-Candidate Diff:", 1)[0]
    if "Builder summary:" in pre_diff_p1 or "Builder Summary" in pre_diff_p1:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["phase-1 prompt leaked builder summary before hypotheses"]}
    if p1_perr is not None or not isinstance(p1_res, dict) or p1_res.get("status") != "SUCCESS" or str(p1_res.get("conversation_id") or "").strip() != r_sid:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["phase-1 stream output failed or session mismatched"]}
    parsed_hyps, p1_h_errs = ir_pkg._parse_phase1_hypotheses(str(p1_res.get("response") or ""))
    if p1_h_errs or parsed_hyps != hyps:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": p1_h_errs or ["phase-1 hypotheses do not match stream output"]}
    if p2_perr is not None or not isinstance(p2_res, dict) or p2_res.get("status") != "SUCCESS" or str(p2_res.get("conversation_id") or "").strip() != r_sid:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["phase-2 stream output failed or session drifted"]}
    p2_outcome, p2_assess, p2_findings, p2_reconcils, p2_issues = ir_pkg._parse_phase2_response_full(str(p2_res.get("response") or ""), has_prior_blockers=bool(prior_entering))
    if p2_issues or p2_outcome != "review-passed":
        return {"status": "invalid-review-protocol" if p2_issues else "changes-requested", "verified": False, "historical_blockers": all_hist, "blockers": p2_issues or [f"phase-2 reviewer outcome was {p2_outcome!r}"]}
    if review_record.get("reviewer_executed") is not True or review_record.get("role_separation_verified") is not True or review_record.get("role_issues") != []:
        return {"status": "invalid-review", "verified": False, "historical_blockers": all_hist, "blockers": list(review_record.get("role_issues") or ["independent review role separation failed"])}
    safety = review_record.get("safety")
    if not isinstance(safety, dict) or safety.get("sandbox_flag") != "--sandbox" or safety.get("permission_mode") != "auto" or safety.get("bypass_permissions_used") is not False or not worker_module.probes_passed(safety.get("probes") or []):
        return {"status": "invalid-review", "verified": False, "historical_blockers": all_hist, "blockers": ["independent review safety probes or sandbox configuration failed"]}
    scope_obj, stds = review_record.get("inspected_scope"), review_record.get("applicable_standards")
    if not isinstance(scope_obj, dict) or scope_obj.get("deterministic_ok") is not True or scope_obj.get("scope_status") in ("violation", "diff-failed", "operational-failure"):
        return {"status": "scope-violation", "verified": False, "historical_blockers": all_hist, "blockers": ["candidate scope or diff inspection failed"]}
    if (diff_err := _verify_file_digest(scope_obj.get("diff_path"), scope_obj.get("diff_sha256"), home, "reviewed diff")) is not None:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": [diff_err]}
    diff_txt = Path(str(scope_obj["diff_path"])).read_text(encoding="utf-8", errors="replace")
    if not diff_txt.strip() or diff_txt.strip() not in p1_prompt_txt:
        return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["phase-1 prompt did not include exact base-to-candidate diff"]}
    if not isinstance(stds, list) or not stds or any(not isinstance(s, dict) or s.get("standard_sha") != base_sha or s.get("enforced") is not True for s in stds):
        return {"status": "invalid-review", "verified": False, "historical_blockers": all_hist, "blockers": ["applicable project standards missing or not bound to base_sha"]}
    if isinstance(child, dict):
        exp_p1 = redact_value(ir_pkg._render_phase1_prompt(child, base_sha, candidate_sha, diff_txt, stds), collect_redaction_secrets())
        if pre_diff_p1 != exp_p1.split("Exact Base-to-Candidate Diff:", 1)[0]:
            return {"status": "invalid-review-protocol", "verified": False, "historical_blockers": all_hist, "blockers": ["phase-1 prompt pre-diff section does not match canonical summary-free template"]}
    assess = review_record.get("assessment")
    if not isinstance(assess, dict) or any(not isinstance(assess.get(k), dict) or assess[k].get("status") != "satisfied" or not str(assess[k].get("summary") or "").strip() for k in ir_pkg.ASSESSMENT_KEYS):
        return {"status": "changes-requested", "verified": False, "historical_blockers": all_hist, "blockers": ["one or more required assessment dimensions are unsatisfied or missing"]}
    b_claim = review_record.get("builder_summary_claim")
    if not isinstance(b_claim, dict) or b_claim.get("treated_as_execution_evidence") is not False or b_claim.get("contradicted_by_observed_execution") is not False:
        return {"status": "unsupported-success-claim", "verified": False, "historical_blockers": all_hist, "blockers": ["builder summary claim was contradicted by observed execution or treated as evidence"]}
    obs = review_record.get("observed_verification")
    if not isinstance(obs, dict) or obs.get("executed") is not True or obs.get("ok") is not True or obs.get("head_sha") != candidate_sha or bool(obs.get("verification_gaps")):
        return {"status": "verification-failed", "verified": False, "historical_blockers": all_hist, "blockers": ["observed independent verification did not pass on candidate"]}
    obs_checks = obs.get("checks")
    if not isinstance(obs_checks, list) or not obs_checks or any(not isinstance(c, dict) for c in obs_checks):
        return {"status": "verification-failed", "verified": False, "historical_blockers": all_hist, "blockers": ["observed independent verification executed no checks"]}
    if not any(c.get("kind") == "criterion" for c in obs_checks) or not any(c.get("kind") in ("regression", "guard") for c in obs_checks):
        return {"status": "verification-failed", "verified": False, "historical_blockers": all_hist, "blockers": ["observed independent verification is missing criterion or regression/guard checks"]}
    if isinstance(child, dict):
        req_cids = {str(cr.get("id") or "AC").strip() for cr in (child.get("criteria") or ()) if isinstance(cr, dict)}
        exec_cids = {str(c.get("assesses") or "").strip() for c in obs_checks if c.get("kind") == "criterion"}
        if not req_cids or not req_cids.issubset(exec_cids):
            return {"status": "verification-failed", "verified": False, "historical_blockers": all_hist, "blockers": ["observed independent verification did not cover all child acceptance criteria"]}
    for c in obs_checks:
        if (chk_err := ir_pkg._verify_stored_check(c, candidate_sha, home)) is not None:
            return {"status": "verification-failed", "verified": False, "historical_blockers": all_hist, "blockers": [chk_err]}
    up = review_record.get("upstream_evidence")
    if not isinstance(up, dict) or not isinstance(up.get("automated_qa"), dict) or up["automated_qa"].get("verified") is not True or not isinstance(up.get("security_review"), dict) or up["security_review"].get("verified") is not True:
        return {"status": "prerequisite-unverified", "verified": False, "historical_blockers": all_hist, "blockers": ["independent review record has unverified upstream QA or security evidence"]}
    rec_findings, rec_blocking, rec_open_ids, rec_resolutions = review_record.get("findings"), review_record.get("blocking_findings"), review_record.get("open_finding_ids"), review_record.get("previous_findings_resolution")
    if not isinstance(rec_findings, list) or not isinstance(rec_blocking, list) or not isinstance(rec_open_ids, list) or not isinstance(rec_resolutions, list) or any(not isinstance(x, dict) for x in (*rec_findings, *rec_resolutions)):
        return {"status": "invalid-review", "verified": False, "historical_blockers": all_hist, "blockers": ["independent review findings or resolutions structure is invalid"]}
    if rec_blocking or rec_open_ids:
        return {"status": "changes-requested", "verified": False, "historical_blockers": all_hist, "blockers": [f"open blocking findings on {candidate_sha}: {', '.join(str(x) for x in rec_open_ids)}"]}
    findings_by_id = {str(f.get("finding_id")): f for f in rec_findings if f.get("finding_id")}
    res_by_id = {str(r.get("finding_id")): r for r in rec_resolutions if r.get("finding_id")}
    for f in rec_findings:
        if f.get("blocking") and (f.get("status") != "resolved" or f.get("resolution") not in ("fixed", "no-longer-applicable") or f.get("resolution_blocker") is not None or f.get("last_seen_revision") != candidate_sha):
            return {"status": "unresolved-historical-blockers", "verified": False, "historical_blockers": all_hist, "blockers": [f"blocking finding {f.get('finding_id')} is not verified resolved on {candidate_sha}"]}
    for pf in all_hist:
        fid = str(pf["finding_id"])
        cur_f, res_e = findings_by_id.get(fid), res_by_id.get(fid)
        if cur_f is None or res_e is None:
            return {"status": "unresolved-historical-blockers", "verified": False, "historical_blockers": all_hist, "blockers": [f"historical blocker {fid} was omitted from review reconciliation"]}
        if cur_f.get("status") != "resolved" or res_e.get("status") != "resolved" or cur_f.get("resolution") not in ("fixed", "no-longer-applicable") or res_e.get("resolution") not in ("fixed", "no-longer-applicable") or cur_f.get("resolution_blocker") is not None or res_e.get("resolution_blocker") is not None:
            return {"status": "unresolved-historical-blockers", "verified": False, "historical_blockers": all_hist, "blockers": [f"historical blocker {fid} is unresolved"]}
        if res_e.get("verified_on_revision") != candidate_sha or res_e.get("candidate_sha") != candidate_sha or not str(res_e.get("resolution_evidence") or "").strip():
            return {"status": "unresolved-historical-blockers", "verified": False, "historical_blockers": all_hist, "blockers": [f"historical blocker {fid} lacks verified resolution evidence on {candidate_sha}"]}
        source = str(pf.get("source") or cur_f.get("source") or "reviewer-agent")
        exp_vcmd = str(pf.get("verification_command") or cur_f.get("verification_command") or "").strip()
        f_ver = cur_f.get("reproducer_verification") or res_e.get("reproducer_verification") or (obs.get("finding_verifications") or {}).get(fid)
        if source == "reviewer-agent" or exp_vcmd or f_ver is not None:
            if (ver_err := ir_pkg._verify_stored_check(f_ver, candidate_sha, home, finding_id=fid, target=None if source == "reviewer-agent" else str(cur_f.get("target") or ""), expected_command=exp_vcmd or None)) is not None:
                return {"status": "unresolved-historical-blockers", "verified": False, "historical_blockers": all_hist, "blockers": [f"historical blocker {fid} failed trusted execution verification on {candidate_sha}: {ver_err}"]}
    _, recheck_blk, _, _ = ir_pkg.reconcile_review_findings(
        round_num=rec_round, candidate_sha=candidate_sha, base_sha=base_sha, agent_findings=p2_findings, det_findings=[],
        prior_findings=prior_entering, reconciliations=p2_reconcils, obs_ver=obs,
        qa_eval=up["automated_qa"], sec_eval=up["security_review"],
        scope_ok=True, changed_paths=tuple(scope_obj.get("changed_paths") or ()), deleted_paths=tuple(scope_obj.get("deleted_paths") or ()),
        role_sep_ok=True, home=home,
    )
    if recheck_blk:
        return {"status": "unresolved-historical-blockers", "verified": False, "historical_blockers": all_hist, "blockers": [f"reconciliation re-verification failed for {', '.join(f['finding_id'] for f in recheck_blk)}"]}
    if review_record.get("outcome") != "review-passed" or review_record.get("review_verified") is not True:
        return {"status": str(review_record.get("outcome") or "changes-requested"), "verified": False, "historical_blockers": all_hist, "blockers": ["independent review outcome is not review-passed"]}
    return {"status": "review-passed", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "reviewer_session_id": r_sid, "builder_session_id": b_sid, "historical_blockers": all_hist, "resolutions": rec_resolutions, "blockers": []}


def evaluate_approval_gate(
    *, candidate_sha: str, base_sha: str, ci_record: Any = None, qa_record: Any = None, security_record: Any = None,
    review_record: Any = None, repo: Path | None = None, home: Path | None = None, child_dir: Path | None = None,
    child: dict[str, Any] | None = None, conf: config_module.Config | None = None, builder_session_id: str | None = None,
    builder_summary: str = "", prior_findings: list[dict[str, Any]] | None = None, prior_approval: dict[str, Any] | None = None,
    round_num: int | None = None, agy_bin: str | None = None, load_from_child_dir: bool = False,
    deadline: float | None = None, limit_s: int = 30,
) -> dict[str, Any]:
    secrets = collect_redaction_secrets()
    if load_from_child_dir and child_dir is not None and home is not None:
        loaded = load_prerequisite_evidence(child_dir, home)
        ci_record = loaded["ci_record"] if ci_record is None else ci_record
        qa_record = loaded["qa_record"] if qa_record is None else qa_record
        security_record = loaded["security_record"] if security_record is None else security_record
        review_record = loaded["review_record"] if review_record is None else review_record
    if prior_approval is None and child_dir is not None and home is not None and (ap_p := child_dir / "approval-gate.json").is_file():
        try:
            loaded_ap = read_json(ap_p, home)
            if isinstance(loaded_ap, dict): prior_approval = loaded_ap
        except errors_module.FactoryError:
            pass
    if review_record is None and agy_bin is not None and repo is not None and home is not None and child_dir is not None and child is not None and conf is not None:
        review_record = ir_pkg.review_candidate_independently(
            repo=repo, home=home, child_dir=child_dir, child=child, conf=conf, base_sha=base_sha, candidate_sha=candidate_sha,
            builder_session_id=builder_session_id, builder_summary=builder_summary, qa_record=qa_record, security_record=security_record,
            prior_findings=prior_findings, round_num=round_num or 1, agy_bin=agy_bin, deadline=deadline or (time.monotonic() + 30.0), limit_s=limit_s,
        )
    eff_round = round_num or (review_record.get("round") if isinstance(review_record, dict) and isinstance(review_record.get("round"), int) else 1)
    ci_eval = evaluate_ci_prerequisite(candidate_sha, base_sha, ci_record, repo=repo, home=home, child=child, conf=conf, deadline=deadline, limit_s=limit_s)
    exp_tested = ci_eval.get("tested_sha") if ci_eval["verified"] else None
    exp_kind = ci_eval.get("revision_kind") if ci_eval["verified"] else None
    qa_eval = evaluate_qa_prerequisite(candidate_sha, base_sha, qa_record, child_dir=child_dir, home=home, repo=repo, child=child, expected_tested_sha=exp_tested, expected_revision_kind=exp_kind, deadline=deadline, limit_s=limit_s)
    sec_eval = evaluate_security_prerequisite(candidate_sha, base_sha, security_record, child_dir=child_dir, home=home)
    rev_eval = evaluate_independent_review_prerequisite(
        candidate_sha, base_sha, review_record, child_dir=child_dir, home=home, repo=repo, child=child, conf=conf,
        builder_session_id=builder_session_id, prior_findings=prior_findings, qa_eval=qa_eval, sec_eval=sec_eval, deadline=deadline, limit_s=limit_s,
    )
    prior_ap_rev = str(prior_approval.get("approved_revision") or prior_approval.get("candidate_sha") or "").strip() if isinstance(prior_approval, dict) else ""
    prior_ap_stale = bool(prior_ap_rev and prior_ap_rev != candidate_sha)
    all_verified = ci_eval["verified"] and qa_eval["verified"] and sec_eval["verified"] and rev_eval["verified"]
    blockers: list[str] = []
    if prior_ap_stale and not all_verified:
        blockers.append(f"previous approval for {prior_ap_rev} is rejected for subsequent candidate {candidate_sha}")
    for p_eval in (ci_eval, qa_eval, sec_eval, rev_eval):
        if not p_eval["verified"]:
            blockers.extend(p_eval.get("blockers") or [p_eval["status"]])
    if all_verified:
        gate_status = "approved"
    elif any(p["status"] == "authority-violation" for p in (ci_eval, qa_eval, sec_eval, rev_eval)):
        gate_status = "authority-violation"
    elif not rev_eval["verified"] and rev_eval["status"] in ("corrupt-prior-history", "reviewer-modified-worktree", "reused-builder-identity", "invalid-review-protocol", "unsupported-success-claim", "unresolved-historical-blockers"):
        gate_status = rev_eval["status"]
    elif prior_ap_stale and any("stale" in p["status"] for p in (ci_eval, qa_eval, sec_eval, rev_eval)):
        gate_status = "stale-candidate-revision"
    else:
        gate_status = next((p["status"] for p in (ci_eval, qa_eval, sec_eval, rev_eval) if not p["verified"]), "rejected")
    hist_list = rev_eval.get("historical_blockers") or []
    res_list = rev_eval.get("resolutions") or []
    res_ids = [str(r.get("finding_id")) for r in res_list if isinstance(r, dict) and r.get("status") == "resolved"]
    unres_ids = [str(pf.get("finding_id")) for pf in hist_list if str(pf.get("finding_id")) not in set(res_ids)] if not rev_eval["verified"] else []
    tested_sha = ci_eval.get("tested_sha") if ci_eval["verified"] else (qa_eval.get("tested_sha") if qa_eval["verified"] else None)
    rev_kind = ci_eval.get("revision_kind") if ci_eval["verified"] else (qa_eval.get("revision_kind") if qa_eval["verified"] else None)
    record = redact_value({
        "schema": 1, "role": "delivery-approval-gate", "verification_scope": APPROVAL_GATE_SCOPE_NOTE, "round": eff_round,
        "status": gate_status, "outcome": "approved" if all_verified else "rejected", "delivery_approved": bool(all_verified),
        "approved_revision": candidate_sha if all_verified else None, "candidate_sha": candidate_sha, "base_sha": base_sha,
        "tested_sha": tested_sha, "revision_kind": rev_kind,
        "superseded_approved_revision": prior_ap_rev if prior_ap_stale else None, "prior_approval_rejected": prior_ap_stale,
        "prerequisites": {
            "ci": {k: v for k, v in ci_eval.items()},
            "automated_qa": {k: v for k, v in qa_eval.items()},
            "security_review": {k: v for k, v in sec_eval.items()},
            "independent_review": {k: v for k, v in rev_eval.items() if k not in ("historical_blockers", "resolutions")},
        },
        "historical_blockers": {
            "total": len(hist_list), "resolved_ids": res_ids, "unresolved_ids": unres_ids,
            "all_verified_resolved": rev_eval["verified"], "resolutions": res_list,
        },
        "blockers": blockers, "recorded_at": now(),
    }, secrets)
    if child_dir is not None and home is not None:
        atomic_json(child_dir / "approval-gate.json", record, home)
        atomic_json(child_dir / f"approval-gate-round-{eff_round}.json", record, home)
    return record


def verify_candidate_approval(
    candidate_sha: str, base_sha: str, approval_record: Any, *, repo: Path | None = None, home: Path | None = None,
    child_dir: Path | None = None, child: dict[str, Any] | None = None, conf: config_module.Config | None = None,
    ci_record: Any = None, qa_record: Any = None, security_record: Any = None, review_record: Any = None,
    deadline: float | None = None, limit_s: int = 30,
) -> dict[str, Any]:
    if not isinstance(approval_record, dict) or not approval_record:
        return {"status": "approval-missing", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": [f"missing approval gate record for candidate {candidate_sha}"]}
    if approval_record.get("role") != "delivery-approval-gate" or approval_record.get("verification_scope") != APPROVAL_GATE_SCOPE_NOTE:
        return {"status": "authority-violation", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": [f"non-gate producer {approval_record.get('role')!r} cannot issue delivery_approved=True"]}
    ap_rev, ap_cand, ap_base = approval_record.get("approved_revision"), approval_record.get("candidate_sha"), approval_record.get("base_sha")
    if not (isinstance(candidate_sha, str) and ci_gate.SHA40_RE.fullmatch(candidate_sha) and isinstance(base_sha, str) and ci_gate.SHA40_RE.fullmatch(base_sha)):
        return {"status": "invalid-candidate-revision", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": ["candidate_sha and base_sha must be 40-char git SHAs"]}
    if ap_rev != candidate_sha or ap_cand != candidate_sha or ap_base != base_sha:
        return {"status": "stale-candidate-revision", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "stale_approved_revision": ap_rev or ap_cand, "blockers": [f"approval for ({ap_rev or ap_cand}, base={ap_base}) is rejected for candidate ({candidate_sha}, base={base_sha})"]}
    if approval_record.get("delivery_approved") is not True or approval_record.get("status") != "approved" or approval_record.get("outcome") != "approved" or bool(approval_record.get("blockers")):
        return {"status": str(approval_record.get("status") or "rejected"), "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": list(approval_record.get("blockers") or ["approval record is not approved"])}
    prereqs = approval_record.get("prerequisites")
    if not isinstance(prereqs, dict) or any(not isinstance(prereqs.get(k), dict) or prereqs[k].get("verified") is not True or prereqs[k].get("candidate_sha") != candidate_sha or prereqs[k].get("base_sha") != base_sha for k in ("ci", "automated_qa", "security_review", "independent_review")):
        return {"status": "prerequisite-unverified", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": ["approval record is missing verified candidate-bound prerequisites"]}
    t_sha, r_kind = approval_record.get("tested_sha"), approval_record.get("revision_kind")
    if not isinstance(t_sha, str) or not ci_gate.SHA40_RE.fullmatch(t_sha) or r_kind not in ("fast-forward-head", "integration-merge") or (t_sha == candidate_sha and r_kind != "fast-forward-head") or (t_sha != candidate_sha and r_kind != "integration-merge"):
        return {"status": "stale-candidate-revision", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": ["approval record has invalid tested_sha or revision_kind binding"]}
    if any(x is not None for x in (ci_record, qa_record, security_record, review_record)):
        return evaluate_approval_gate(
            candidate_sha=candidate_sha, base_sha=base_sha, ci_record=ci_record, qa_record=qa_record, security_record=security_record,
            review_record=review_record, repo=repo, home=home, child_dir=child_dir, child=child, conf=conf, deadline=deadline, limit_s=limit_s,
        )
    return approval_record
