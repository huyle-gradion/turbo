"""Exact-candidate final approval gate and prerequisite evidence adapters (Issue #58; Part 2b-a of #23)."""
from __future__ import annotations
import re, time
from pathlib import Path
from typing import Any
from factory import ci_gate, ci_selection, config as config_module, errors as errors_module, gitio, independent_review as ir_pkg, runner, security_review, worker as worker_module
from factory.config import now
from factory.deliver_checks import collect_redaction_secrets
from factory.intake import redact_value
from factory.paths import atomic_json, read_json

APPROVAL_GATE_SCOPE_NOTE = "exact-candidate-delivery-approval-gate (#58); not merge-approved (#24) or parent-accepted"

def _fail(status: str, msg: str | list[str], **extra: Any) -> dict[str, Any]:
    return {"status": status, "verified": False, **extra, "blockers": msg if isinstance(msg, list) else [msg]}

def _pos_int(v: Any) -> int | None:
    return v if type(v) is int and v >= 1 else None

def _scan_rounds(base_dir: Path | None, home: Path | None, pat: str, cur_r: int, inv_st: str, stale_st: str) -> tuple[list[tuple[int, dict[str, Any]]], dict[str, Any] | None]:
    if base_dir is None or not (base_dir.exists() or base_dir.is_symlink()): return [], None
    if base_dir.is_symlink() or not base_dir.is_dir(): return [], _fail(inv_st, f"invalid history directory {base_dir}")
    eff_home, out = home or base_dir, []
    for p in sorted(base_dir.iterdir()):
        if not (m := re.fullmatch(pat, p.name)): continue
        r_idx, rp = int(m.group(1)), p / "record.json"
        if r_idx < 1 or p.is_symlink() or not p.is_dir() or rp.is_symlink() or not rp.is_file(): return [], _fail(inv_st, f"corrupt or missing round record in {p}")
        try: r_obj = read_json(rp, eff_home)
        except (errors_module.FactoryError, OSError) as exc: return [], _fail(inv_st, f"unreadable round record {rp}: {exc}")
        if not isinstance(r_obj, dict) or (_pos_int(r_obj.get("round")) != r_idx if "round" in r_obj else False) or not isinstance(r_obj.get("findings", []), list): return [], _fail(inv_st, f"invalid round record in {rp}")
        if r_idx > cur_r: return [], _fail(stale_st, f"round {cur_r} is superseded by round {r_idx}")
        out.append((r_idx, r_obj))
    return out, None

def _verify_file_digest(path_val: Any, sha_val: Any, home: Path | None, label: str, *, rev_bind: tuple[str, str, str] | None = None) -> str | None:
    if not isinstance(path_val, str) or not path_val.strip() or not isinstance(sha_val, str) or not sha_val.strip(): return f"{label} is missing stored output_path or output_sha256"
    p = Path(path_val)
    try:
        if p.is_symlink() or not p.is_file() or (home is not None and not p.resolve().is_relative_to(home.resolve())): return f"{label} stored evidence file {p} is missing or outside runtime home"
        if runner.digest_text(txt := p.read_text(encoding="utf-8", errors="replace")) != sha_val: return f"{label} stored evidence file {p} sha256 mismatch"
        if rev_bind is not None:
            kv = dict(ci_gate.KEY_VAL_RE.findall(txt))
            if not all(ci_gate.SHA40_RE.fullmatch(str(kv.get(k) or "")) for k in ("candidate_sha", "base_sha", "tested_sha")): return f"{label} stored evidence {p} is missing revision provenance"
            if (kv["candidate_sha"], kv["base_sha"], kv["tested_sha"]) != rev_bind: return f"stale:{label} stored evidence {p} revision provenance mismatch"
            if (rp := p.resolve().parent / "record.json") != p.resolve() and rp.is_file() and not rp.is_symlink():
                if isinstance(drec := read_json(rp, home or rp.parent), dict) and any(drec.get(k) not in (None, exp) for k, exp in zip(("candidate_sha", "base_sha", "tested_sha"), rev_bind)):
                    return f"stale:{label} stored record {rp} revision provenance mismatch"
    except (errors_module.FactoryError, OSError): return f"{label} stored evidence file {p} is unreadable"
    return None

def load_prerequisite_evidence(child_dir: Path, home: Path, *, attempt_dir: Path | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"ci_record": None, "qa_record": None, "security_record": None, "review_record": None}
    att_dir = attempt_dir or (child_dir.parent.parent if child_dir.parent.name == "children" else None)
    if (ci_p := child_dir / "ci-verification.json").is_file(): out["ci_record"] = read_json(ci_p, home)
    elif att_dir is not None and (att_rec_p := att_dir / "record.json").is_file() and isinstance(att_rec := read_json(att_rec_p, home), dict) and isinstance(att_rec.get("child"), dict):
        out["ci_record"] = att_rec["child"].get("ci_verification")
    if (qa_dir := child_dir / "automated-qa").is_dir():
        rounds = sorted((int(m.group(1)), p / "record.json") for p in qa_dir.iterdir() if p.is_dir() and (m := re.fullmatch(r"round-(\d+)", p.name)) and (p / "record.json").is_file())
        if rounds: out["qa_record"] = read_json(rounds[-1][1], home)
        elif (qa_rec_p := qa_dir / "record.json").is_file(): out["qa_record"] = read_json(qa_rec_p, home)
    if (sec_p := child_dir / "security-review.json").is_file(): out["security_record"] = read_json(sec_p, home)
    if (rev_p := child_dir / "independent-review.json").is_file(): out["review_record"] = read_json(rev_p, home)
    return out

def evaluate_ci_prerequisite(candidate_sha: str, base_sha: str, ci_record: Any, *, repo: Path | None = None, home: Path | None = None, child: dict[str, Any] | None = None, conf: config_module.Config | None = None, deadline: float | None = None, limit_s: int = 30) -> dict[str, Any]:
    if hasattr(ci_record, "to_dict"): ci_record = ci_record.to_dict()
    if isinstance(ci_record, dict) and isinstance(ci_record.get("child"), dict) and isinstance(ci_record["child"].get("ci_verification"), dict): ci_record = ci_record["child"]
    if isinstance(ci_record, dict) and isinstance(ci_record.get("ci_verification"), dict):
        if ci_record.get("delivery_approved") is True: return _fail("authority-violation", "non-gate wrapper record cannot issue delivery_approved=True")
        if ci_record.get("verified") is False or ci_record.get("status") not in (None, "verified"): return _fail(str(ci_record.get("status") or "ci-failed"), "delivery wrapper marks CI as unverified")
        ci_record = ci_record["ci_verification"]
    if not isinstance(ci_record, dict) or not ci_record: return _fail("ci-missing", f"missing CI verification evidence for candidate {candidate_sha}")
    if ci_record.get("delivery_approved") is True: return _fail("authority-violation", "non-gate producer CI record cannot issue delivery_approved=True")
    if not (isinstance(candidate_sha, str) and ci_gate.SHA40_RE.fullmatch(candidate_sha) and isinstance(base_sha, str) and ci_gate.SHA40_RE.fullmatch(base_sha)): return _fail("ci-evidence-invalid", "candidate_sha and base_sha must be 40-char git SHAs")
    rec_cand, rec_base, rec_tested, rec_pol = ci_record.get("candidate_sha"), ci_record.get("base_sha"), ci_record.get("tested_sha"), ci_record.get("policy_sha")
    for val, exp, lbl in ((rec_cand, candidate_sha, "candidate_sha"), (rec_base, base_sha, "base_sha"), (rec_pol, base_sha, "policy_sha")):
        if isinstance(val, str) and ci_gate.SHA40_RE.fullmatch(val) and val != exp: return _fail("stale-ci-evidence", f"stale CI {lbl}={val} != {exp}")
    if ci_record.get("status") not in (None, "verified") and ci_record.get("verified") is False:
        st = "stale-ci-evidence" if ci_record.get("status") == "stale-revision" else str(ci_record.get("status") or "ci-failed")
        return _fail(st, list(ci_record.get("blockers") or [f"CI verification status is {st}"]))
    if not all(isinstance(x, str) and ci_gate.SHA40_RE.fullmatch(x) for x in (rec_cand, rec_base, rec_tested, rec_pol)): return _fail("ci-evidence-invalid", "CI record is missing valid 40-char candidate_sha, base_sha, policy_sha, or tested_sha")
    if (rev_kind := ci_record.get("revision_kind")) not in ("fast-forward-head", "integration-merge"): return _fail("ci-evidence-invalid", f"invalid CI revision_kind {rev_kind!r}")
    if rec_tested == candidate_sha:
        if rev_kind != "fast-forward-head": return _fail("stale-ci-evidence", "integration-merge CI record cannot have tested_sha == candidate_sha")
        if repo is not None and gitio.git(repo, "cat-file", "-t", candidate_sha).ok and gitio.git(repo, "cat-file", "-t", base_sha).ok and not gitio.is_ancestor(repo, base_sha, candidate_sha):
            return _fail("stale-ci-evidence", f"candidate_sha {candidate_sha} does not descend from base_sha {base_sha}")
    else:
        if rev_kind != "integration-merge": return _fail("stale-ci-evidence", f"tested_sha != candidate_sha requires integration-merge, got {rev_kind!r}")
        parents_ok = False
        if repo is not None:
            ok_git, git_kind, git_err = ci_gate._verify_tested_revision_in_git(repo, base_sha, candidate_sha, rec_tested, int(ci_record.get("pr_number") or 0), deadline or (time.monotonic() + 10.0), limit_s)
            if not ok_git or git_kind != "integration-merge": return _fail("stale-ci-evidence", f"invalid CI integration-merge tested_sha {rec_tested}: {git_err or git_kind}")
            parents_ok = True
        if (rec_parents := ci_record.get("merge_parents")) is not None:
            if not isinstance(rec_parents, (list, tuple)) or len(rec_parents) != 2 or not all(isinstance(p, str) for p in rec_parents) or set(rec_parents) != {base_sha, candidate_sha}:
                return _fail("stale-ci-evidence", f"CI integration-merge parents {rec_parents!r} do not match [base_sha, candidate_sha]")
            parents_ok = True
        if not parents_ok: return _fail("stale-ci-evidence", f"unverified CI integration-merge tested_sha {rec_tested}")
    if repo is not None and conf is not None and gitio.git(repo, "cat-file", "-t", rec_tested).ok and gitio.git(repo, "cat-file", "-t", base_sha).ok:
        if (pol_errs := ci_gate._verify_policy_revision_in_git(repo, base_sha, candidate_sha, rec_tested, ci_selection.protected_chain_paths(conf), deadline or (time.monotonic() + 10.0), limit_s)):
            return _fail("ci-untrusted-producer", pol_errs)
    producers, workflows, checks = ci_record.get("trusted_producers"), ci_record.get("trusted_workflows"), ci_record.get("checks")
    if not isinstance(producers, list) or not producers or any(not isinstance(p, str) or p not in ci_gate.TRUSTED_CHECK_PRODUCERS for p in producers): return _fail("ci-untrusted-producer", "CI record has missing or untrusted check producers")
    if not isinstance(workflows, list) or not workflows or any(not isinstance(w, str) or w not in ci_gate.TRUSTED_WORKFLOW_PATHS for w in workflows): return _fail("ci-untrusted-producer", "CI record has missing or untrusted workflow paths")
    if not isinstance(checks, list) or not checks or any(not isinstance(c, dict) for c in checks): return _fail("ci-evidence-invalid", "CI record is missing a non-empty list of check records")
    auth_reqs = {r["name"] for r in ci_selection.build_required_ci_checks(child, conf) if isinstance(r, dict) and r.get("name")} if (isinstance(child, dict) and conf is not None) else set()
    rec_reqs_raw = ci_record.get("required_checks")
    rec_reqs = {str(x["name"]).strip() if isinstance(x, dict) and x.get("name") else (x.strip() if isinstance(x, str) else "") for x in (rec_reqs_raw if isinstance(rec_reqs_raw, list) else ())} - {""}
    if not auth_reqs or (rec_reqs_raw is not None and (not isinstance(rec_reqs_raw, list) or not rec_reqs or not auth_reqs.issubset(rec_reqs))): return _fail("ci-evidence-invalid", "cannot establish non-empty authoritative required CI check set")
    req_names = auth_reqs | rec_reqs
    for c in checks:
        if not (cname := str(c.get("name") or "").strip()): return _fail("ci-evidence-invalid", "CI check record is missing name")
        if c.get("producer") not in ci_gate.TRUSTED_CHECK_PRODUCERS or c.get("workflow_path") not in ci_gate.TRUSTED_WORKFLOW_PATHS: return _fail("ci-untrusted-producer", f"CI check {cname!r} used untrusted producer or workflow")
        if bool(c.get("cached_result")) or (c.get("cached_from_sha") and c.get("cached_from_sha") != candidate_sha): return _fail("stale-ci-evidence", f"CI check {cname!r} reused cached result across revisions")
        if any(c.get(k) != exp for k, exp in (("candidate_sha", candidate_sha), ("base_sha", base_sha), ("policy_sha", base_sha), ("tested_sha", rec_tested), ("revision_kind", rev_kind))): return _fail("stale-ci-evidence", f"CI check {cname!r} revision binding mismatch")
        if c.get("status") != "completed": return _fail("ci-pending", f"CI check {cname!r} is not completed")
        if c.get("conclusion") != "success": return _fail("ci-skipped" if c.get("conclusion") in ("skipped", "neutral", "cancelled") else "ci-failed", f"CI check {cname!r} conclusion is {c.get('conclusion')!r}")
        if not str(c.get("html_url") or "").startswith(ci_gate._URL_PREFIXES) or not str(c.get("artifact_url") or "").startswith(ci_gate._URL_PREFIXES): return _fail("ci-evidence-invalid", f"CI check {cname!r} is missing accessible GitHub log or artifact URL")
        if (err := _verify_file_digest(c.get("output_path"), c.get("output_sha256"), home, f"CI check {cname!r}", rev_bind=(candidate_sha, base_sha, rec_tested))) is not None:
            return _fail("stale-ci-evidence" if err.startswith("stale:") else "ci-evidence-invalid", err.removeprefix("stale:"))
    if (missing_req := sorted(req_names - {str(c.get("name") or "").strip() for c in checks})): return _fail("ci-missing", f"missing required CI checks on {candidate_sha}: {', '.join(missing_req)}")
    if (pr := ci_record.get("pr")) is not None:
        if not isinstance(pr, dict): return _fail("ci-evidence-invalid", "CI record pr field must be an object")
        if pr.get("state") != "open" or pr.get("merged") is not False or pr.get("head_sha") != candidate_sha or pr.get("base_sha") != base_sha: return _fail("stale-ci-evidence", f"PR state or revision drifted from candidate {candidate_sha}")
        if pr.get("pr_confirmed") is not True or pr.get("ci_verified") is not True or pr.get("verified") is not True: return _fail("ci-failed", "CI record PR verification flags are not True")
    if repo is not None and (head_branch := str(ci_record.get("head_branch") or "").strip()):
        if (br_res := gitio.git(repo, "rev-parse", "--verify", f"refs/heads/{head_branch}")).ok and br_res.output.strip() != candidate_sha: return _fail("stale-ci-evidence", f"branch {head_branch} head {br_res.output.strip()} drifted from CI candidate {candidate_sha}")
    if ci_record.get("status") != "verified" or ci_record.get("verified") is not True or not isinstance(ci_record.get("blockers", []), list) or bool(ci_record.get("blockers")): return _fail("ci-failed", list(ci_record.get("blockers") or ["CI record is not verified"]))
    return {"status": "verified", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": rec_tested, "revision_kind": rev_kind, "blockers": []}

def evaluate_qa_prerequisite(candidate_sha: str, base_sha: str, qa_record: Any, *, child_dir: Path | None = None, home: Path | None = None, repo: Path | None = None, child: dict[str, Any] | None = None, expected_tested_sha: str | None = None, expected_revision_kind: str | None = None, deadline: float | None = None, limit_s: int = 30) -> dict[str, Any]:
    if hasattr(qa_record, "to_dict"): qa_record = qa_record.to_dict()
    prior_qa_fids: set[str] = set()
    if isinstance(qa_record, dict) and qa_record.get("delivery_approved") is True: return _fail("authority-violation", "non-gate producer automated-qa cannot issue delivery_approved=True")
    if isinstance(qa_record, dict) and isinstance(qa_record.get("automated_qa"), dict) and "criterion_coverage" not in qa_record: qa_record = qa_record["automated_qa"]
    if isinstance(qa_record, dict) and isinstance(qa_record.get("qa_rounds"), list):
        if qa_record.get("qa_verified") is not True or qa_record.get("ci_verified") is False or qa_record.get("status") not in (None, "qa-verified") or bool(qa_record.get("open_finding_ids")): return _fail(str(qa_record.get("status") or "qa-failed"), "QA delivery wrapper is not verified")
        if not (rounds_list := [r for r in qa_record["qa_rounds"] if isinstance(r, dict)]): return _fail("qa-missing", f"missing automated QA round records for {candidate_sha}")
        for pr_r in rounds_list[:-1]: prior_qa_fids.update(str(f["finding_id"]) for f in (pr_r.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id"))
        qa_record = rounds_list[-1]
    elif isinstance(qa_record, dict) and "criterion_coverage" not in qa_record and child_dir is not None:
        if qa_record.get("qa_verified") is not True or qa_record.get("status") not in (None, "qa-verified") or bool(qa_record.get("open_finding_ids")): return _fail(str(qa_record.get("status") or "qa-failed"), "QA summary record is not verified")
        if (r_count := _pos_int(qa_record.get("rounds"))) is not None and (r_path := child_dir / "automated-qa" / f"round-{r_count}" / "record.json").is_file(): qa_record = read_json(r_path, home or child_dir)
    if isinstance(qa_record, dict) and qa_record.get("delivery_approved") is True: return _fail("authority-violation", "non-gate producer automated-qa cannot issue delivery_approved=True")
    cur_qa_r = _pos_int(qa_record.get("round")) if isinstance(qa_record, dict) else None
    if isinstance(qa_record, dict) and qa_record and "criterion_coverage" in qa_record and cur_qa_r is None: return _fail("qa-invalid", f"QA record has missing or invalid round {qa_record.get('round')!r}")
    if cur_qa_r is not None:
        scanned_qa, qa_err = _scan_rounds(child_dir / "automated-qa" if child_dir is not None else None, home, r"round-(\d+)", cur_qa_r, "qa-invalid", "stale-qa-evidence")
        if qa_err is not None: return qa_err
        for r_idx, r_obj in scanned_qa:
            if r_idx <= cur_qa_r: prior_qa_fids.update(str(f["finding_id"]) for f in (r_obj.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id"))
    qa_eval = ir_pkg._validate_qa_record(candidate_sha, base_sha, qa_record, repo=repo, child=child, deadline=deadline, limit_s=limit_s)
    if not qa_eval["verified"]: return qa_eval
    cur_qa_fids = {str(f.get("finding_id")): f for f in (qa_record.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id")}
    if not prior_qa_fids.issubset(cur_qa_fids): return _fail("qa-findings-open", f"historical automated-qa findings omitted from reconciliation: {', '.join(sorted(prior_qa_fids - set(cur_qa_fids)))}")
    qa_tested, ci_reval = str(qa_record.get("tested_sha") or ""), qa_record.get("ci_revalidation") or {}
    for chk in (*(c for cov in (qa_record.get("criterion_coverage") or ()) if isinstance(cov, dict) for c in (cov.get("deterministic_check"), *(cov.get("evaluation_cases") or ()))), *(qa_record.get("regression_checks") or ())):
        if isinstance(chk, dict) and (err := _verify_file_digest(chk.get("output_path"), chk.get("output_sha256"), home, "QA check", rev_bind=(candidate_sha, base_sha, qa_tested))) is not None:
            return _fail("stale-qa-evidence" if err.startswith("stale:") else "qa-invalid", err.removeprefix("stale:"))
    qa_kind = str(qa_record.get("revision_kind") or ci_reval.get("revision_kind") or ("fast-forward-head" if qa_tested == candidate_sha else "integration-merge"))
    if expected_tested_sha and qa_tested != expected_tested_sha: return _fail("stale-qa-evidence", f"QA tested_sha {qa_tested} does not match CI tested_sha {expected_tested_sha}")
    if expected_revision_kind and qa_kind != expected_revision_kind: return _fail("stale-qa-evidence", f"QA revision_kind {qa_kind!r} does not match CI revision_kind {expected_revision_kind!r}")
    return {"status": "qa-verified", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": qa_tested, "revision_kind": qa_kind, "blockers": []}

def evaluate_security_prerequisite(candidate_sha: str, base_sha: str, security_record: Any, *, child_dir: Path | None = None, home: Path | None = None) -> dict[str, Any]:
    if hasattr(security_record, "to_dict"): security_record = security_record.to_dict()
    if isinstance(security_record, dict) and isinstance(security_record.get("child"), dict) and isinstance(security_record["child"].get("security_review"), dict): security_record = security_record["child"]
    if isinstance(security_record, dict) and isinstance(security_record.get("security_review"), dict):
        if security_record.get("delivery_approved") is True: return _fail("authority-violation", "non-gate security wrapper cannot issue delivery_approved=True")
        if isinstance(security_record.get("security_gate"), dict) and security_record["security_gate"].get("verified") is False:
            return _fail(str(security_record["security_gate"].get("status") or "security-blockers-unresolved"), list(security_record["security_gate"].get("blockers") or ["security gate unverified"]))
        security_record = security_record["security_review"]
    if isinstance(security_record, dict) and security_record.get("delivery_approved") is True: return _fail("authority-violation", "non-gate producer security-reviewer cannot issue delivery_approved=True")
    cur_sec_r = _pos_int(security_record.get("round")) if isinstance(security_record, dict) else None
    if isinstance(security_record, dict) and security_record and cur_sec_r is None: return _fail("security-review-invalid", f"security review record has missing or invalid round {security_record.get('round')!r}")
    sec_eval = security_review.evaluate_security_review_gate(candidate_sha, base_sha, security_record, home=home)
    if not sec_eval["verified"]: return sec_eval
    if cur_sec_r is not None and child_dir is not None:
        scanned_sec, sec_err = _scan_rounds(child_dir, home, r"security-round-(\d+)", cur_sec_r, "security-review-invalid", "stale-security-review")
        if sec_err is not None: return sec_err
        prior_sec_fids = {str(f["finding_id"]) for r_idx, r_obj in scanned_sec if r_idx < cur_sec_r for f in (r_obj.get("findings") or ()) if isinstance(f, dict) and f.get("blocking") and f.get("finding_id")}
        same_r_fids = {str(f["finding_id"]) for r_idx, r_obj in scanned_sec if r_idx == cur_sec_r for f in (r_obj.get("findings") or ()) if isinstance(f, dict) and f.get("blocking") and f.get("finding_id")}
        cur_f_map = {str(f.get("finding_id")): f for f in (security_record.get("findings") or ()) if isinstance(f, dict) and f.get("finding_id")}
        cur_r_map = {str(r.get("finding_id")): r for r in (security_record.get("previous_findings_resolution") or ()) if isinstance(r, dict) and r.get("finding_id")}
        for sfid in sorted(prior_sec_fids | same_r_fids):
            if sfid not in cur_f_map or cur_f_map[sfid].get("status") != "resolved" or (sfid in prior_sec_fids and (sfid not in cur_r_map or cur_r_map[sfid].get("status") != "resolved" or cur_r_map[sfid].get("verified_on_revision") != candidate_sha)):
                return _fail("security-blockers-unresolved", f"historical security blocker {sfid} was omitted or unresolved on {candidate_sha}")
    return {**sec_eval, "candidate_sha": candidate_sha, "base_sha": base_sha}

def _load_review_history_for_gate(child_dir: Path | None, home: Path | None, rec_round: int, candidate_sha: str, prior_findings: list[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None, str | None]:
    if prior_findings is not None and (not isinstance(prior_findings, list) or any(not isinstance(f, dict) for f in prior_findings)):
        return [], [], "corrupt-prior-history", "prior_findings must be a list of finding objects"
    if child_dir is not None:
        eff_home = home or child_dir
        _, rev_err = _scan_rounds(child_dir, eff_home, r"independent-review-round-(\d+)", rec_round, "corrupt-prior-history", "stale-independent-review")
        if rev_err is not None: return [], [], rev_err["status"], rev_err["blockers"][0]
        if (pb_p := child_dir / "prior-blockers.json").exists() or pb_p.is_symlink():
            try:
                pb_obj = read_json(pb_p, eff_home)
                if not isinstance(pb_obj, dict) or not isinstance(pb_obj.get("findings"), list) or any(not isinstance(x, dict) for x in pb_obj["findings"]) or ("updated_in_round" in pb_obj and _pos_int(pb_obj.get("updated_in_round")) is None):
                    return [], [], "corrupt-prior-history", f"corrupt prior review history structure in {pb_p}"
                if (up_r := _pos_int(pb_obj.get("updated_in_round"))) is not None and up_r > rec_round: return [], [], "stale-independent-review", f"prior-blockers.json updated_in_round {up_r} supersedes round {rec_round}"
            except (errors_module.FactoryError, OSError) as exc: return [], [], "corrupt-prior-history", f"unreadable or corrupt prior review history in {pb_p}: {exc}"
        try: all_hist = ir_pkg._normalize_prior_findings(child_dir, eff_home, rec_round + 1, prior_findings)
        except errors_module.FactoryError as exc: return [], [], "corrupt-prior-history", str(exc)
    else:
        try: all_hist = ir_pkg._normalize_prior_findings(Path("/nonexistent"), home or Path("/tmp"), 1, prior_findings)
        except errors_module.FactoryError as exc: return [], [], "corrupt-prior-history", str(exc)
    prior_entering: list[dict[str, Any]] = []
    for pf in all_hist:
        intro_r, intro_rev = _pos_int(pf.get("introduced_in_round") or pf.get("created_round")) or 1, str(pf.get("introduced_in_revision") or pf.get("created_candidate_sha") or "")
        prior_hist = [h for h in (pf.get("history") or ()) if isinstance(h, dict) and (_pos_int(h.get("round")) or 0) > 0 and int(h["round"]) < rec_round]
        if prior_hist:
            last_h = prior_hist[-1]
            prior_entering.append({**pf, "status": str(last_h.get("status") or "open"), "resolution": last_h.get("resolution"), "resolution_blocker": last_h.get("resolution_blocker"), "last_seen_round": int(last_h["round"]), "last_seen_revision": str(last_h.get("candidate_sha") or intro_rev), "resolved_in_round": int(last_h["round"]) if last_h.get("status") == "resolved" else None, "resolved_in_revision": str(last_h.get("candidate_sha") or "") if last_h.get("status") == "resolved" else None, "history": prior_hist})
        elif intro_r < rec_round or (intro_rev and intro_rev != candidate_sha) or (prior_findings and any(pf["finding_id"] == str(x.get("finding_id") or ir_pkg.compute_review_finding_id(str(x.get("category") or "bug"), str(x.get("target") or "repository"), str(x.get("rule") or "concern"))) for x in prior_findings)):
            prior_entering.append({**pf, "status": "open" if pf.get("resolved_in_round") in (None, rec_round) else str(pf.get("status") or "open"), "last_seen_round": min(intro_r, max(1, rec_round - 1)), "last_seen_revision": intro_rev, "resolved_in_round": None if pf.get("resolved_in_round") == rec_round else pf.get("resolved_in_round"), "resolved_in_revision": None if pf.get("resolved_in_round") == rec_round else pf.get("resolved_in_revision")})
    return all_hist, prior_entering, None, None

def evaluate_independent_review_prerequisite(candidate_sha: str, base_sha: str, review_record: Any, *, child_dir: Path | None = None, home: Path | None = None, repo: Path | None = None, child: dict[str, Any] | None = None, conf: config_module.Config | None = None, builder_session_id: str | None = None, prior_findings: list[dict[str, Any]] | None = None, qa_eval: dict[str, Any] | None = None, sec_eval: dict[str, Any] | None = None, deadline: float | None = None, limit_s: int = 30) -> dict[str, Any]:
    if not isinstance(review_record, dict) or not review_record: return _fail("independent-review-missing", f"missing independent review evidence for candidate {candidate_sha}", historical_blockers=[])
    if review_record.get("role") != "independent-reviewer" or review_record.get("delivery_approved") is not False or review_record.get("verification_scope") != ir_pkg.INDEPENDENT_REVIEW_SCOPE_NOTE:
        return _fail("authority-violation", "non-gate producer independent-reviewer cannot issue delivery_approved=True or alter role scope", historical_blockers=[])
    if (rec_round := _pos_int(review_record.get("round"))) is None: return _fail("invalid-review", f"independent review record has missing or invalid round {review_record.get('round')!r}", historical_blockers=[])
    all_hist, prior_entering, hist_st, hist_err = _load_review_history_for_gate(child_dir, home, rec_round, candidate_sha, prior_findings)
    if hist_st is not None: return _fail(hist_st, hist_err or hist_st, historical_blockers=all_hist)
    rev_cand, rev_base, std_sha = review_record.get("reviewed_revision"), review_record.get("base_sha"), review_record.get("standards_sha")
    if not all(isinstance(x, str) and ci_gate.SHA40_RE.fullmatch(x) for x in (rev_cand, rev_base, std_sha)): return _fail("invalid-review", "independent review record is missing valid 40-char reviewed_revision, base_sha, or standards_sha", historical_blockers=all_hist)
    if rev_cand != candidate_sha or rev_base != base_sha or std_sha != base_sha: return _fail("stale-independent-review", f"stale independent review: reviewed=({rev_cand}, base={rev_base}, std={std_sha}) != expected=({candidate_sha}, base={base_sha})", historical_blockers=all_hist)
    wt = review_record.get("worktree_integrity")
    if not isinstance(wt, dict) or wt.get("worktree_clean") is not True or wt.get("candidate_modified_by_reviewer") is not False or wt.get("head_before") != candidate_sha or wt.get("head_after") != candidate_sha or wt.get("status_porcelain") != "" or wt.get("mutation_evidence_path") is not None:
        return _fail("reviewer-modified-worktree", "independent reviewer modified the candidate worktree", historical_blockers=all_hist)
    b_sid, r_sid = str(review_record.get("builder_session_id") or "").strip(), str(review_record.get("reviewer_session_id") or "").strip()
    role_iss_txt = " ".join(str(x) for x in (review_record.get("role_issues") or ()))
    if not b_sid or r_sid == b_sid or "matches builder session" in role_iss_txt or (builder_session_id is not None and b_sid != str(builder_session_id).strip()):
        return _fail("reused-builder-identity", f"invalid or reused session identity: builder={b_sid!r}, reviewer={r_sid!r}", historical_blockers=all_hist)
    po, hyps = review_record.get("protocol_ordering"), review_record.get("failure_hypotheses")
    if not r_sid or not isinstance(po, dict) or not (po.get("enforced") is True and po.get("phase_1_executed") is True and po.get("phase_1_omitted_builder_summary") is True and po.get("phase_1_included_exact_diff") is True and po.get("hypotheses_persisted_before_summary") is True and po.get("phase_2_executed") is True and po.get("phase_2_continued_session_id") == r_sid):
        return _fail("invalid-review-protocol", "independent review two-phase protocol ordering was not enforced", historical_blockers=all_hist)
    if not isinstance(hyps, list) or not hyps or any(not isinstance(h, str) or not h.strip() for h in hyps): return _fail("invalid-review-protocol", "independent review is missing non-empty pre-summary failure hypotheses", historical_blockers=all_hist)
    if (hyp_err := _verify_file_digest(po.get("hypotheses_path"), po.get("hypotheses_sha256"), home, "phase-1 hypotheses")) is not None: return _fail("invalid-review-protocol", hyp_err, historical_blockers=all_hist)
    try:
        hyp_obj = read_json(Path(str(po["hypotheses_path"])), home)
        if not isinstance(hyp_obj, dict) or hyp_obj.get("reviewer_session_id") != r_sid or hyp_obj.get("candidate_sha") != candidate_sha or hyp_obj.get("base_sha") != base_sha or hyp_obj.get("hypotheses") != hyps:
            return _fail("invalid-review-protocol", "persisted phase-1 hypotheses metadata mismatch", historical_blockers=all_hist)
        p1_p, p1_out, p2_p, p2_out = (Path(str(po.get(k) or "")) for k in ("phase_1_prompt_path", "phase_1_stdout_path", "phase_2_prompt_path", "phase_2_stdout_path"))
        for fp in (p1_p, p1_out, p2_p, p2_out):
            if fp.is_symlink() or not fp.is_file() or (home is not None and not fp.resolve().is_relative_to(home.resolve())): return _fail("invalid-review-protocol", f"missing or untrusted protocol artifact {fp}", historical_blockers=all_hist)
        p1_prompt_txt, p2_prompt_txt = p1_p.read_text(encoding="utf-8", errors="replace"), p2_p.read_text(encoding="utf-8", errors="replace")
        _, p1_res, p1_perr = worker_module.parse_stream_events(p1_out.read_text(encoding="utf-8", errors="replace"))
        _, p2_res, p2_perr = worker_module.parse_stream_events(p2_out.read_text(encoding="utf-8", errors="replace"))
    except (errors_module.FactoryError, OSError) as exc: return _fail("invalid-review-protocol", f"unreadable protocol artifacts: {exc}", historical_blockers=all_hist)
    if "PHASE: 1" not in p1_prompt_txt or "Exact Base-to-Candidate Diff:" not in p1_prompt_txt: return _fail("invalid-review-protocol", "phase-1 prompt is missing required phase header or diff section", historical_blockers=all_hist)
    pre_diff_p1 = p1_prompt_txt.split("Exact Base-to-Candidate Diff:", 1)[0]
    if "Builder summary:" in pre_diff_p1 or "Builder Summary" in pre_diff_p1: return _fail("invalid-review-protocol", "phase-1 prompt leaked builder summary before hypotheses", historical_blockers=all_hist)
    if p1_perr is not None or not isinstance(p1_res, dict) or p1_res.get("status") != "SUCCESS" or str(p1_res.get("conversation_id") or "").strip() != r_sid: return _fail("invalid-review-protocol", "phase-1 stream output failed or session mismatched", historical_blockers=all_hist)
    parsed_hyps, p1_h_errs = ir_pkg._parse_phase1_hypotheses(str(p1_res.get("response") or ""))
    if p1_h_errs or parsed_hyps != hyps: return _fail("invalid-review-protocol", p1_h_errs or "phase-1 hypotheses do not match stream output", historical_blockers=all_hist)
    if p2_perr is not None or not isinstance(p2_res, dict) or p2_res.get("status") != "SUCCESS" or str(p2_res.get("conversation_id") or "").strip() != r_sid: return _fail("invalid-review-protocol", "phase-2 stream output failed or session drifted", historical_blockers=all_hist)
    p2_outcome, _, p2_findings, p2_reconcils, p2_issues = ir_pkg._parse_phase2_response_full(str(p2_res.get("response") or ""), has_prior_blockers=bool(prior_entering))
    if p2_issues or p2_outcome != "review-passed": return _fail("invalid-review-protocol" if p2_issues else "changes-requested", p2_issues or f"phase-2 reviewer outcome was {p2_outcome!r}", historical_blockers=all_hist)
    if review_record.get("reviewer_executed") is not True or review_record.get("role_separation_verified") is not True or review_record.get("role_issues") != []: return _fail("invalid-review", list(review_record.get("role_issues") or ["independent review role separation failed"]), historical_blockers=all_hist)
    safety = review_record.get("safety")
    if not isinstance(safety, dict) or safety.get("sandbox_flag") != "--sandbox" or safety.get("permission_mode") != "auto" or safety.get("bypass_permissions_used") is not False or not worker_module.probes_passed(safety.get("probes") or []):
        return _fail("invalid-review", "independent review safety probes or sandbox configuration failed", historical_blockers=all_hist)
    if repo is None or home is None or not isinstance(child, dict) or conf is None: return _fail("invalid-review", "missing required repo, home, child, or conf context for independent review verification", historical_blockers=all_hist)
    dl, secrets = deadline or (time.monotonic() + 10.0), collect_redaction_secrets()
    auth_diff_info = ir_pkg.inspect_diff_categories(repo, base_sha, candidate_sha, dl, limit_s)
    auth_scope_ok, _, auth_scope_det = ir_pkg.evaluate_scope(tuple(auth_diff_info["changed_paths"]), child, ci_selection.protected_chain_paths(conf))
    auth_diff_res = ir_pkg.git_timed(repo, dl, limit_s, "verify review diff", "diff", "--binary", base_sha, candidate_sha)
    auth_diff_txt = redact_value(auth_diff_res.output + ("\n" if not auth_diff_res.output.endswith("\n") else ""), secrets) if auth_diff_res.ok else ""
    auth_stds = redact_value(ir_pkg.load_project_standards(repo, base_sha, child, conf, dl, limit_s), secrets)
    scope_obj, stds = review_record.get("inspected_scope"), review_record.get("applicable_standards")
    if not isinstance(scope_obj, dict) or scope_obj.get("deterministic_ok") is not True or scope_obj.get("scope_status") in ("violation", "diff-failed", "operational-failure") or not auth_scope_ok or scope_obj.get("changed_paths") != auth_diff_info["changed_paths"] or scope_obj.get("scope_status") != auth_scope_det["status"]:
        return _fail("scope-violation", "candidate scope or diff inspection failed", historical_blockers=all_hist)
    if (diff_err := _verify_file_digest(scope_obj.get("diff_path"), scope_obj.get("diff_sha256"), home, "reviewed diff")) is not None: return _fail("invalid-review-protocol", diff_err, historical_blockers=all_hist)
    diff_txt = Path(str(scope_obj["diff_path"])).read_text(encoding="utf-8", errors="replace")
    if not auth_diff_res.ok or not diff_txt.strip() or diff_txt != auth_diff_txt or diff_txt.strip() not in p1_prompt_txt: return _fail("invalid-review-protocol", "phase-1 prompt or reviewed diff did not match authoritative base-to-candidate diff", historical_blockers=all_hist)
    if not isinstance(stds, list) or not stds or any(not isinstance(s, dict) or s.get("standard_sha") != base_sha or s.get("enforced") is not True for s in stds) or stds != auth_stds: return _fail("invalid-review", "applicable project standards missing or do not match authoritative base_sha standards", historical_blockers=all_hist)
    assess, b_claim, obs = review_record.get("assessment"), review_record.get("builder_summary_claim"), review_record.get("observed_verification")
    b_sum, obs_checks = str((b_claim if isinstance(b_claim, dict) else {}).get("summary") or ""), (obs if isinstance(obs, dict) else {}).get("checks")
    derived_contra = bool(b_sum.strip() and isinstance(obs_checks, list) and any(not isinstance(c, dict) or not (c.get("ok") is True and type(c.get("exit_code")) is int and c.get("exit_code") == 0 and not bool(c.get("timed_out"))) for c in obs_checks))
    if not isinstance(b_claim, dict) or b_claim.get("treated_as_execution_evidence") is not False or b_claim.get("contradicted_by_observed_execution") is not False or derived_contra:
        return _fail("unsupported-success-claim", "builder summary claim was contradicted by observed execution or treated as evidence", historical_blockers=all_hist)
    exp_p1 = redact_value(ir_pkg._render_phase1_prompt(child, base_sha, candidate_sha, auth_diff_txt, auth_stds), secrets)
    exp_hyps_sec, exp_bsum_sec = "Persisted Phase-1 Hypotheses:\n" + "\n".join(f"- {h}" for h in hyps) + "\n", f"Builder Summary (untrusted claim):\n{b_sum or '(none provided)'}\nExact Base-to-Candidate Diff:\n{auth_diff_txt}"
    if pre_diff_p1 != exp_p1.split("Exact Base-to-Candidate Diff:", 1)[0] or "PHASE: 2" not in p2_prompt_txt or exp_hyps_sec not in p2_prompt_txt or exp_bsum_sec not in p2_prompt_txt:
        return _fail("invalid-review-protocol", "phase-1 or phase-2 prompt does not match canonical protocol inputs", historical_blockers=all_hist)
    if not isinstance(assess, dict) or any(not isinstance(assess.get(k), dict) or assess[k].get("status") != "satisfied" or not str(assess[k].get("summary") or "").strip() for k in ir_pkg.ASSESSMENT_KEYS):
        return _fail("changes-requested", "one or more required assessment dimensions are unsatisfied or missing", historical_blockers=all_hist)
    if not isinstance(obs, dict) or obs.get("executed") is not True or obs.get("ok") is not True or obs.get("head_sha") != candidate_sha or bool(obs.get("verification_gaps")):
        return _fail("verification-failed", "observed independent verification did not pass on candidate", historical_blockers=all_hist)
    if not isinstance(obs_checks, list) or not obs_checks or any(not isinstance(c, dict) for c in obs_checks) or not any(c.get("kind") == "criterion" for c in obs_checks) or not any(c.get("kind") in ("regression", "guard") for c in obs_checks):
        return _fail("verification-failed", "observed independent verification is missing criterion or regression/guard checks", historical_blockers=all_hist)
    req_cids, exec_cids = {str(cr.get("id") or "AC").strip() for cr in (child.get("criteria") or ()) if isinstance(cr, dict)}, {str(c.get("assesses") or "").strip() for c in obs_checks if c.get("kind") == "criterion"}
    if not req_cids or not req_cids.issubset(exec_cids): return _fail("verification-failed", "observed independent verification did not cover all child acceptance criteria", historical_blockers=all_hist)
    for c in obs_checks:
        if (chk_err := ir_pkg._verify_stored_check(c, candidate_sha, home)) is not None: return _fail("verification-failed", chk_err, historical_blockers=all_hist)
    up = review_record.get("upstream_evidence")
    if not isinstance(up, dict) or not isinstance(up.get("automated_qa"), dict) or up["automated_qa"].get("verified") is not True or not isinstance(up.get("security_review"), dict) or up["security_review"].get("verified") is not True:
        return _fail("prerequisite-unverified", "independent review record has unverified upstream QA or security evidence", historical_blockers=all_hist)
    rec_findings, rec_blocking, rec_open_ids, rec_resolutions = review_record.get("findings"), review_record.get("blocking_findings"), review_record.get("open_finding_ids"), review_record.get("previous_findings_resolution")
    if not isinstance(rec_findings, list) or not isinstance(rec_blocking, list) or not isinstance(rec_open_ids, list) or not isinstance(rec_resolutions, list) or any(not isinstance(x, dict) for x in (*rec_findings, *rec_resolutions)):
        return _fail("invalid-review", "independent review findings or resolutions structure is invalid", historical_blockers=all_hist)
    findings_by_id, res_by_id = {str(f.get("finding_id")): f for f in rec_findings if f.get("finding_id")}, {str(r.get("finding_id")): r for r in rec_resolutions if r.get("finding_id")}
    for pf in all_hist:
        fid, cur_f, res_e = str(pf["finding_id"]), findings_by_id.get(str(pf["finding_id"])), res_by_id.get(str(pf["finding_id"]))
        if cur_f is None or res_e is None: return _fail("unresolved-historical-blockers", f"historical blocker {fid} was omitted from review reconciliation", historical_blockers=all_hist)
        if cur_f.get("status") != "resolved" or res_e.get("status") != "resolved" or cur_f.get("resolution") not in ("fixed", "no-longer-applicable") or res_e.get("resolution") not in ("fixed", "no-longer-applicable") or cur_f.get("resolution_blocker") is not None or res_e.get("resolution_blocker") is not None:
            return _fail("unresolved-historical-blockers", f"historical blocker {fid} is unresolved", historical_blockers=all_hist)
        if res_e.get("verified_on_revision") != candidate_sha or res_e.get("candidate_sha") != candidate_sha or not str(res_e.get("resolution_evidence") or "").strip():
            return _fail("unresolved-historical-blockers", f"historical blocker {fid} lacks verified resolution evidence on {candidate_sha}", historical_blockers=all_hist)
        source, exp_vcmd = str(pf.get("source") or cur_f.get("source") or "reviewer-agent"), str(pf.get("verification_command") or cur_f.get("verification_command") or "").strip()
        f_ver = cur_f.get("reproducer_verification") or res_e.get("reproducer_verification") or (obs.get("finding_verifications") or {}).get(fid)
        if source == "reviewer-agent" or exp_vcmd or f_ver is not None:
            if (ver_err := ir_pkg._verify_stored_check(f_ver, candidate_sha, home, finding_id=fid, target=None if source == "reviewer-agent" else str(cur_f.get("target") or ""), expected_command=exp_vcmd or None)) is not None:
                return _fail("unresolved-historical-blockers", f"historical blocker {fid} failed trusted execution verification on {candidate_sha}: {ver_err}", historical_blockers=all_hist)
    for f in rec_findings:
        if f.get("blocking") and (f.get("status") != "resolved" or f.get("resolution") not in ("fixed", "no-longer-applicable") or f.get("resolution_blocker") is not None or f.get("last_seen_revision") != candidate_sha):
            return _fail("changes-requested", f"blocking finding {f.get('finding_id')} is not verified resolved on {candidate_sha}", historical_blockers=all_hist)
    if rec_blocking or rec_open_ids: return _fail("changes-requested", f"open blocking findings on {candidate_sha}: {', '.join(str(x) for x in rec_open_ids)}", historical_blockers=all_hist)
    _, recheck_blk, _, _ = ir_pkg.reconcile_review_findings(round_num=rec_round, candidate_sha=candidate_sha, base_sha=base_sha, agent_findings=p2_findings, det_findings=[], prior_findings=prior_entering, reconciliations=p2_reconcils, obs_ver=obs, qa_eval=up["automated_qa"], sec_eval=up["security_review"], scope_ok=True, changed_paths=tuple(scope_obj.get("changed_paths") or ()), deleted_paths=tuple(scope_obj.get("deleted_paths") or ()), role_sep_ok=True, home=home)
    if recheck_blk: return _fail("unresolved-historical-blockers", f"reconciliation re-verification failed for {', '.join(f['finding_id'] for f in recheck_blk)}", historical_blockers=all_hist)
    if review_record.get("outcome") != "review-passed" or review_record.get("review_verified") is not True: return _fail(str(review_record.get("outcome") or "changes-requested"), "independent review outcome is not review-passed", historical_blockers=all_hist)
    return {"status": "review-passed", "verified": True, "candidate_sha": candidate_sha, "base_sha": base_sha, "reviewer_session_id": r_sid, "builder_session_id": b_sid, "historical_blockers": all_hist, "resolutions": rec_resolutions, "blockers": []}

def evaluate_approval_gate(*, candidate_sha: str, base_sha: str, ci_record: Any = None, qa_record: Any = None, security_record: Any = None, review_record: Any = None, repo: Path | None = None, home: Path | None = None, child_dir: Path | None = None, child: dict[str, Any] | None = None, conf: config_module.Config | None = None, builder_session_id: str | None = None, builder_summary: str = "", prior_findings: list[dict[str, Any]] | None = None, prior_approval: dict[str, Any] | None = None, round_num: int | None = None, agy_bin: str | None = None, load_from_child_dir: bool = False, _persist: bool = True, deadline: float | None = None, limit_s: int = 30) -> dict[str, Any]:
    secrets = collect_redaction_secrets()
    if load_from_child_dir and child_dir is not None and home is not None:
        loaded = load_prerequisite_evidence(child_dir, home)
        ci_record, qa_record = (loaded["ci_record"] if ci_record is None else ci_record), (loaded["qa_record"] if qa_record is None else qa_record)
        security_record, review_record = (loaded["security_record"] if security_record is None else security_record), (loaded["review_record"] if review_record is None else review_record)
    if prior_approval is None and child_dir is not None and home is not None and (ap_p := child_dir / "approval-gate.json").is_file():
        try:
            if isinstance(loaded_ap := read_json(ap_p, home), dict): prior_approval = loaded_ap
        except errors_module.FactoryError: pass
    bad_round_arg = round_num is not None and _pos_int(round_num) is None
    if not bad_round_arg and review_record is None and agy_bin is not None and repo is not None and home is not None and child_dir is not None and child is not None and conf is not None:
        review_record = ir_pkg.review_candidate_independently(repo=repo, home=home, child_dir=child_dir, child=child, conf=conf, base_sha=base_sha, candidate_sha=candidate_sha, builder_session_id=builder_session_id, builder_summary=builder_summary, qa_record=qa_record, security_record=security_record, prior_findings=prior_findings, round_num=_pos_int(round_num) or 1, agy_bin=agy_bin, deadline=deadline or (time.monotonic() + 30.0), limit_s=limit_s)
    rec_r_val = _pos_int(review_record.get("round")) if isinstance(review_record, dict) else None
    eff_round = _pos_int(round_num) or rec_r_val or 1
    ci_eval = evaluate_ci_prerequisite(candidate_sha, base_sha, ci_record, repo=repo, home=home, child=child, conf=conf, deadline=deadline, limit_s=limit_s)
    exp_tested, exp_kind = (ci_eval.get("tested_sha"), ci_eval.get("revision_kind")) if ci_eval["verified"] else (None, None)
    qa_eval = evaluate_qa_prerequisite(candidate_sha, base_sha, qa_record, child_dir=child_dir, home=home, repo=repo, child=child, expected_tested_sha=exp_tested, expected_revision_kind=exp_kind, deadline=deadline, limit_s=limit_s)
    sec_eval = evaluate_security_prerequisite(candidate_sha, base_sha, security_record, child_dir=child_dir, home=home)
    if bad_round_arg or (_pos_int(round_num) is not None and rec_r_val is not None and round_num != rec_r_val):
        rev_eval = _fail("invalid-review", f"invalid or mismatched round_num {round_num!r}", historical_blockers=[])
    else:
        rev_eval = evaluate_independent_review_prerequisite(candidate_sha, base_sha, review_record, child_dir=child_dir, home=home, repo=repo, child=child, conf=conf, builder_session_id=builder_session_id, prior_findings=prior_findings, qa_eval=qa_eval, sec_eval=sec_eval, deadline=deadline, limit_s=limit_s)
    prior_ap_rev = str(prior_approval.get("approved_revision") or prior_approval.get("candidate_sha") or "").strip() if isinstance(prior_approval, dict) else ""
    prior_ap_stale = bool(prior_ap_rev and prior_ap_rev != candidate_sha)
    all_verified = ci_eval["verified"] and qa_eval["verified"] and sec_eval["verified"] and rev_eval["verified"]
    blockers = ([f"previous approval for {prior_ap_rev} is rejected for subsequent candidate {candidate_sha}"] if (prior_ap_stale and not all_verified) else [])
    for p_eval in (ci_eval, qa_eval, sec_eval, rev_eval):
        if not p_eval["verified"]: blockers.extend(p_eval.get("blockers") or [p_eval["status"]])
    if all_verified: gate_status = "approved"
    elif any(p["status"] == "authority-violation" for p in (ci_eval, qa_eval, sec_eval, rev_eval)): gate_status = "authority-violation"
    elif not rev_eval["verified"] and rev_eval["status"] in ("corrupt-prior-history", "reviewer-modified-worktree", "reused-builder-identity", "invalid-review-protocol", "unsupported-success-claim", "unresolved-historical-blockers"): gate_status = rev_eval["status"]
    elif prior_ap_stale and (all(x is None for x in (ci_record, qa_record, security_record, review_record)) or all(not p["verified"] and "stale" in p["status"] for p in (ci_eval, qa_eval, sec_eval, rev_eval))): gate_status = "stale-candidate-revision"
    else: gate_status = next((p["status"] for p in (ci_eval, qa_eval, sec_eval, rev_eval) if not p["verified"]), "rejected")
    hist_list, res_list = rev_eval.get("historical_blockers") or [], rev_eval.get("resolutions") or []
    res_ids = [str(r.get("finding_id")) for r in res_list if isinstance(r, dict) and r.get("status") == "resolved"]
    unres_ids = [str(pf.get("finding_id")) for pf in hist_list if str(pf.get("finding_id")) not in set(res_ids)] if not rev_eval["verified"] else []
    tested_sha = ci_eval.get("tested_sha") if ci_eval["verified"] else (qa_eval.get("tested_sha") if qa_eval["verified"] else None)
    rev_kind = ci_eval.get("revision_kind") if ci_eval["verified"] else (qa_eval.get("revision_kind") if qa_eval["verified"] else None)
    prov = None
    if _persist and child_dir is not None and home is not None:
        inp_p = child_dir / f"approval-gate-inputs-round-{eff_round}.json"
        atomic_json(inp_p, {"candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": tested_sha, "revision_kind": rev_kind, "round": eff_round, "child_dir": str(child_dir), "child": child, "ci_record": ci_record, "qa_record": qa_record, "security_record": security_record, "review_record": review_record, "prior_findings": prior_findings, "builder_session_id": builder_session_id}, home)
        prov = {"child_dir": str(child_dir), "inputs_path": str(inp_p), "inputs_sha256": runner.digest_text(inp_p.read_text(encoding="utf-8", errors="replace"))}
    record = redact_value({
        "schema": 1, "role": "delivery-approval-gate", "verification_scope": APPROVAL_GATE_SCOPE_NOTE, "round": eff_round, "status": gate_status, "outcome": "approved" if all_verified else "rejected",
        "delivery_approved": bool(all_verified), "approved_revision": candidate_sha if all_verified else None, "candidate_sha": candidate_sha, "base_sha": base_sha, "tested_sha": tested_sha, "revision_kind": rev_kind,
        "provenance": prov, "superseded_approved_revision": prior_ap_rev if prior_ap_stale else None, "prior_approval_rejected": prior_ap_stale,
        "prerequisites": {"ci": dict(ci_eval), "automated_qa": dict(qa_eval), "security_review": dict(sec_eval), "independent_review": {k: v for k, v in rev_eval.items() if k not in ("historical_blockers", "resolutions")}},
        "historical_blockers": {"total": len(hist_list), "resolved_ids": res_ids, "unresolved_ids": unres_ids, "all_verified_resolved": rev_eval["verified"], "resolutions": res_list},
        "blockers": blockers, "recorded_at": now(),
    }, secrets)
    if _persist and child_dir is not None and home is not None:
        atomic_json(child_dir / "approval-gate.json", record, home); atomic_json(child_dir / f"approval-gate-round-{eff_round}.json", record, home)
    return record

def verify_candidate_approval(candidate_sha: str, base_sha: str, approval_record: Any, *, repo: Path | None = None, home: Path | None = None, child_dir: Path | None = None, child: dict[str, Any] | None = None, conf: config_module.Config | None = None, ci_record: Any = None, qa_record: Any = None, security_record: Any = None, review_record: Any = None, deadline: float | None = None, limit_s: int = 30) -> dict[str, Any]:
    def _rej(st: str, msg: str | list[str], **ex: Any) -> dict[str, Any]:
        return {"status": st, "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, **ex, "blockers": msg if isinstance(msg, list) else [msg]}
    if not isinstance(approval_record, dict) or not approval_record: return _rej("approval-missing", f"missing approval gate record for candidate {candidate_sha}")
    if approval_record.get("role") != "delivery-approval-gate" or approval_record.get("verification_scope") != APPROVAL_GATE_SCOPE_NOTE: return _rej("authority-violation", f"non-gate producer {approval_record.get('role')!r} cannot issue delivery_approved=True")
    ap_rev, ap_cand, ap_base = approval_record.get("approved_revision"), approval_record.get("candidate_sha"), approval_record.get("base_sha")
    if not (isinstance(candidate_sha, str) and ci_gate.SHA40_RE.fullmatch(candidate_sha) and isinstance(base_sha, str) and ci_gate.SHA40_RE.fullmatch(base_sha)): return _rej("invalid-candidate-revision", "candidate_sha and base_sha must be 40-char git SHAs")
    if ap_rev != candidate_sha or ap_cand != candidate_sha or ap_base != base_sha: return _rej("stale-candidate-revision", f"approval for ({ap_rev or ap_cand}, base={ap_base}) is rejected for candidate ({candidate_sha}, base={base_sha})", stale_approved_revision=ap_rev or ap_cand)
    if approval_record.get("delivery_approved") is not True or approval_record.get("status") != "approved" or approval_record.get("outcome") != "approved" or bool(approval_record.get("blockers")):
        return _rej(str(approval_record.get("status") or "rejected"), list(approval_record.get("blockers") or ["approval record is not approved"]))
    prereqs, hb = approval_record.get("prerequisites"), approval_record.get("historical_blockers")
    if not isinstance(prereqs, dict) or any(not isinstance(prereqs.get(k), dict) or prereqs[k].get("verified") is not True or prereqs[k].get("candidate_sha") != candidate_sha or prereqs[k].get("base_sha") != base_sha for k in ("ci", "automated_qa", "security_review", "independent_review")):
        return _rej("prerequisite-unverified", "approval record is missing verified candidate-bound prerequisites")
    if not isinstance(hb, dict) or hb.get("all_verified_resolved") is not True or hb.get("unresolved_ids") != [] or type(hb.get("total")) is not int or hb.get("total") < 0 or not isinstance(hb.get("resolved_ids"), list) or len(hb["resolved_ids"]) != hb["total"]:
        return _rej("unresolved-historical-blockers", "approval record has unverified or inconsistent historical_blockers")
    t_sha, r_kind = approval_record.get("tested_sha"), approval_record.get("revision_kind")
    if not isinstance(t_sha, str) or not ci_gate.SHA40_RE.fullmatch(t_sha) or r_kind not in ("fast-forward-head", "integration-merge") or (t_sha == candidate_sha) != (r_kind == "fast-forward-head"):
        return _rej("stale-candidate-revision", "approval record has invalid tested_sha or revision_kind binding")
    prior_f, b_sid, prov = None, None, approval_record.get("provenance")
    if isinstance(prov, dict) and home is not None and _verify_file_digest(prov.get("inputs_path"), prov.get("inputs_sha256"), home, "approval provenance") is None:
        inp = read_json(Path(str(prov["inputs_path"])), home)
        if isinstance(inp, dict) and (inp.get("candidate_sha"), inp.get("base_sha"), inp.get("tested_sha"), inp.get("revision_kind")) == (candidate_sha, base_sha, t_sha, r_kind):
            child_dir, child = (child_dir or (Path(str(inp["child_dir"])) if inp.get("child_dir") else None)), (child if child is not None else inp.get("child"))
            ci_record, qa_record = (ci_record if ci_record is not None else inp.get("ci_record")), (qa_record if qa_record is not None else inp.get("qa_record"))
            security_record, review_record = (security_record if security_record is not None else inp.get("security_record")), (review_record if review_record is not None else inp.get("review_record"))
            prior_f, b_sid = inp.get("prior_findings"), inp.get("builder_session_id")
    if conf is None and repo is not None and home is not None and (repo / ".factory" / "config.toml").is_file():
        conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
    reval = evaluate_approval_gate(candidate_sha=candidate_sha, base_sha=base_sha, ci_record=ci_record, qa_record=qa_record, security_record=security_record, review_record=review_record, repo=repo, home=home, child_dir=child_dir, child=child, conf=conf, builder_session_id=b_sid, prior_findings=prior_f, load_from_child_dir=True, _persist=False, deadline=deadline, limit_s=limit_s)
    if not reval["delivery_approved"] or reval.get("tested_sha") != t_sha or reval.get("revision_kind") != r_kind:
        return _rej(str(reval.get("status") if not reval["delivery_approved"] else "stale-candidate-revision"), list(reval.get("blockers") or ["underlying prerequisite revalidation failed"]))
    return approval_record
