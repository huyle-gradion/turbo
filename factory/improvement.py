"""Bounded factory-improvement proposals and comparison workflow (Issue #68, Part A of #32)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any

from factory import ci_selection, deliver_checks, gitio, runner, worker
from factory.config import now
from factory.errors import UsageError
from factory.paths import safe_dir

FACTORY_ROOT = Path(__file__).resolve().parents[1]
PROPOSAL_SCHEMA_VERSION = 1
REPORT_SCHEMA_VERSION = 1
SUPPORTED_RULES = frozenset({"baseline-failed-candidate-passed"})
VALID_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
AUTHORITY_NOTE = "improvement-eligible only; not approved, installed, merged, or parent-accepted"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def proposal_digest(proposal: dict[str, Any]) -> str:
    return hashlib.sha256((json.dumps(proposal, indent=2, sort_keys=True) + "\n").encode("utf-8")).hexdigest()


def _write_json(path: Path, data: dict[str, Any]) -> None:
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _is_safe_relative_path(p_str: str) -> bool:
    if not p_str or not isinstance(p_str, str):
        return False
    parts = p_str.replace("\\", "/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    p = Path(p_str)
    return not p.is_absolute() and ".." not in p.parts and "." not in p.parts


def _paths_overlap(p1_str: str, p2_str: str) -> bool:
    parts1 = Path(p1_str.replace("\\", "/")).parts
    parts2 = Path(p2_str.replace("\\", "/")).parts
    return parts1[:len(parts2)] == parts2 or parts2[:len(parts1)] == parts1


def _write_confined_file(worktree: Path, rel_path: str, content: bytes) -> Path:
    if not _is_safe_relative_path(rel_path):
        raise UsageError(f"unsafe or invalid target path: {rel_path!r}")
    parts = rel_path.replace("\\", "/").split("/")
    resolved_wt = worktree.resolve()
    curr = worktree
    for part in parts[:-1]:
        curr = curr / part
        if curr.is_symlink():
            raise UsageError(f"target path component is a symlink: {curr}")
        if curr.exists():
            if not curr.is_dir():
                raise UsageError(f"target path component exists and is not a directory: {curr}")
        else:
            curr.mkdir(mode=0o700)
        if not curr.resolve().is_relative_to(resolved_wt):
            raise UsageError(f"target path component escapes worktree: {rel_path!r}")
    target = curr / parts[-1]
    if target.is_symlink():
        raise UsageError(f"target path is a symlink: {target}")
    if target.is_dir():
        raise UsageError(f"target path is an existing directory: {target}")
    if not target.resolve().is_relative_to(resolved_wt):
        raise UsageError(f"target path escapes worktree: {rel_path!r}")
    target.write_bytes(content)
    return target


def _validate_case_structure(case: Any, seen_ids: set[str], label: str, prop_target: str | None = None) -> list[str]:
    if not isinstance(case, dict):
        return [f"{label} case must be a JSON object"]
    raw_id = case.get("case_id")
    if not isinstance(raw_id, str):
        return [f"{label} case has invalid case_id {raw_id!r}"]
    cid, issues = raw_id.strip(), []
    if not cid or not VALID_ID_RE.fullmatch(cid):
        issues.append(f"{label} case has invalid case_id {cid!r}")
    elif cid in seen_ids:
        issues.append(f"duplicate case_id {cid!r} in {label} cases")
    seen_ids.add(cid)
    cmd = str(case.get("command") or "").strip()
    argv = deliver_checks._verification_argv(cmd)
    if argv is None:
        issues.append(f"case {cid!r} command is unexecutable: {cmd!r}")
    elif ci_selection.WEAKENED_CMD_RE.search(cmd):
        issues.append(f"case {cid!r} command weakens verification: {cmd!r}")
    rub = case.get("rubric")
    if not isinstance(rub, dict):
        issues.append(f"case {cid!r} requires rubric dictionary")
    else:
        rid, raw_code = str(rub.get("rubric_id") or "").strip(), rub.get("expected_exit_code", 0)
        if not rid or not VALID_ID_RE.fullmatch(rid):
            issues.append(f"case {cid!r} invalid rubric_id: {rid!r}")
        if isinstance(raw_code, bool) or not isinstance(raw_code, int):
            issues.append(f"case {cid!r} expected_exit_code must be int")
        for k in ("required_output_tokens", "forbidden_output_tokens"):
            v = rub.get(k, [])
            if not isinstance(v, (list, tuple)) or any(not isinstance(t, str) for t in v):
                issues.append(f"case {cid!r} rubric {k} must be list of strings")
    raw_inputs = case.get("inputs")
    if raw_inputs is not None:
        if not isinstance(raw_inputs, (list, tuple)):
            issues.append(f"case {cid!r} inputs must be a list")
        else:
            seen_targets: list[str] = []
            for idx, inp in enumerate(raw_inputs):
                if not isinstance(inp, dict):
                    issues.append(f"case {cid!r} input {idx} must be a JSON object")
                    continue
                src = inp.get("path")
                if not isinstance(src, str) or not src.strip():
                    issues.append(f"case {cid!r} input requires path string")
                tgt = inp.get("target_path")
                if not isinstance(tgt, str) or not _is_safe_relative_path(tgt):
                    issues.append(f"case {cid!r} input requires valid relative target_path: {tgt!r}")
                else:
                    for prev_tgt in seen_targets:
                        if prev_tgt == tgt:
                            issues.append(f"case {cid!r} duplicate input target_path: {tgt!r}")
                        elif _paths_overlap(prev_tgt, tgt):
                            issues.append(f"case {cid!r} overlapping input target_paths: {tgt!r} and {prev_tgt!r}")
                    if prop_target and _is_safe_relative_path(prop_target):
                        if tgt == prop_target:
                            issues.append(f"case {cid!r} input target_path conflicts with proposed_change: {tgt!r}")
                        elif _paths_overlap(prop_target, tgt):
                            issues.append(f"case {cid!r} input target_path overlaps with proposed_change: {tgt!r}")
                    seen_targets.append(tgt)
                sha = inp.get("sha256")
                if not isinstance(sha, str) or not sha.strip():
                    issues.append(f"case {cid!r} input sha256 required")
    return issues


def validate_proposal_structure(proposal: Any) -> list[str]:
    if not isinstance(proposal, dict):
        return ["proposal must be a JSON object"]
    issues: list[str] = []
    if proposal.get("schema_version") != PROPOSAL_SCHEMA_VERSION:
        issues.append(f"unsupported schema_version: {proposal.get('schema_version')!r}")
    pid = str(proposal.get("proposal_id") or "").strip()
    if not pid or not VALID_ID_RE.fullmatch(pid):
        issues.append(f"invalid proposal_id: {pid!r}")
    obs = proposal.get("observed_failure")
    if not isinstance(obs, dict) or not str(obs.get("description") or "").strip():
        issues.append("observed_failure requires non-empty description")
    elif not isinstance(obs.get("artifacts"), list) or not obs.get("artifacts"):
        issues.append("observed_failure requires non-empty artifacts list")
    prop = proposal.get("proposed_change")
    if not isinstance(prop, dict) or prop.get("kind") not in ("skill", "tool", "check"):
        issues.append(f"proposed_change requires kind skill, tool, or check: {(prop or {}).get('kind')!r}")
    else:
        tgt = str(prop.get("target_path") or "").strip()
        if not _is_safe_relative_path(tgt):
            issues.append(f"invalid target_path: {tgt!r}")
        if not str(prop.get("content_sha256") or "").strip():
            issues.append("proposed_change content_sha256 required")
    base = proposal.get("baseline")
    if not isinstance(base, dict) or not str(base.get("identity") or "").strip():
        issues.append("baseline identity required")
    cand = proposal.get("candidate")
    if not isinstance(cand, dict) or not str(cand.get("identity") or "").strip():
        issues.append("candidate identity required")
    elif isinstance(prop, dict) and str(cand.get("content_sha256") or "") != str(prop.get("content_sha256") or ""):
        issues.append("candidate content_sha256 must match proposed_change content_sha256")
    exp_imp = proposal.get("expected_improvement")
    if not isinstance(exp_imp, dict) or not str(exp_imp.get("description") or "").strip():
        issues.append("expected_improvement requires description")
    elif exp_imp.get("rule") not in SUPPORTED_RULES:
        issues.append(f"unsupported rule: {exp_imp.get('rule')!r}")
    imp_cases, reg_cases = proposal.get("improvement_cases"), proposal.get("regression_cases")
    if not isinstance(imp_cases, list) or not imp_cases:
        issues.append("improvement_cases must be non-empty list")
    if not isinstance(reg_cases, list) or not reg_cases:
        issues.append("regression_cases must be non-empty list")
    seen_ids: set[str] = set()
    prop_tgt = str(prop.get("target_path") or "").strip() if isinstance(prop, dict) else None
    for cases, label in (((imp_cases if isinstance(imp_cases, list) else ()), "improvement"), ((reg_cases if isinstance(reg_cases, list) else ()), "regression")):
        for c in cases:
            issues.extend(_validate_case_structure(c, seen_ids, label, prop_target=prop_tgt))
    conds = proposal.get("execution_conditions")
    if not isinstance(conds, dict):
        issues.append("execution_conditions must be a JSON object")
    else:
        if not isinstance(conds.get("time_limit_seconds"), int) or conds.get("time_limit_seconds", 0) <= 0:
            issues.append("execution_conditions time_limit_seconds must be positive int")
        if conds.get("allow_network") is not False:
            issues.append("execution_conditions allow_network must be False")
        if conds.get("env_sanitized") is not True:
            issues.append("execution_conditions env_sanitized must be True")
        ps = conds.get("permitted_substitution")
        exp_c_sha = (prop or {}).get("content_sha256") if isinstance(prop, dict) else ""
        if not isinstance(ps, dict) or ps.get("target_path") != (prop or {}).get("target_path") or ps.get("content_sha256") != exp_c_sha:
            issues.append("execution_conditions permitted_substitution must match proposed_change")
    return issues


def canonicalize_draft_references(proposal: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    base = base_dir.resolve()
    obs = proposal.get("observed_failure")
    if isinstance(obs, dict) and isinstance(obs.get("artifacts"), list):
        for art in obs["artifacts"]:
            if isinstance(art, dict) and "path" in art and isinstance(art["path"], str):
                p = Path(art["path"])
                art["path"] = str((base / p).resolve() if not p.is_absolute() else p.resolve())
    prop = proposal.get("proposed_change")
    if isinstance(prop, dict) and "content_path" in prop and isinstance(prop["content_path"], str):
        cp = Path(prop["content_path"])
        prop["content_path"] = str((base / cp).resolve() if not cp.is_absolute() else cp.resolve())
    for cases_key in ("improvement_cases", "regression_cases"):
        cases = proposal.get(cases_key)
        if isinstance(cases, list):
            for case in cases:
                if isinstance(case, dict) and isinstance(case.get("inputs"), (list, tuple)):
                    for inp in case["inputs"]:
                        if isinstance(inp, dict) and "path" in inp and isinstance(inp["path"], str):
                            ip = Path(inp["path"])
                            inp["path"] = str((base / ip).resolve() if not ip.is_absolute() else ip.resolve())
    return proposal


def validate_proposal(proposal: dict[str, Any], *, base_dir: Path | None = None) -> list[str]:
    issues = validate_proposal_structure(proposal)
    if not isinstance(proposal, dict):
        return issues
    obs = proposal.get("observed_failure")
    if isinstance(obs, dict) and isinstance(obs.get("artifacts"), list):
        for art in obs["artifacts"]:
            if isinstance(art, dict):
                p = Path(str(art.get("path") or ""))
                if base_dir and not p.is_absolute():
                    p = base_dir / p
                if not p.is_file():
                    issues.append(f"observed_failure artifact not found: {p}")
                elif _sha256_file(p) != str(art.get("sha256") or ""):
                    issues.append(f"observed_failure artifact sha mismatch: {p}")
    prop = proposal.get("proposed_change")
    if isinstance(prop, dict):
        cp = Path(str(prop.get("content_path") or ""))
        if base_dir and not cp.is_absolute():
            cp = base_dir / cp
        if not cp.is_file():
            issues.append(f"proposed_change content_path not found: {cp}")
        else:
            exp_c_sha = _sha256_file(cp)
            if exp_c_sha != str(prop.get("content_sha256") or ""):
                issues.append("proposed_change content_sha256 mismatch")
    for cases_key in ("improvement_cases", "regression_cases"):
        cases = proposal.get(cases_key)
        if isinstance(cases, list):
            for c in cases:
                if isinstance(c, dict):
                    cid = c.get("case_id")
                    for inp in c.get("inputs") or ():
                        p = Path(str(inp.get("path") or "")) if isinstance(inp, dict) else Path()
                        if base_dir and not p.is_absolute():
                            p = base_dir / p
                        if not p.is_file():
                            issues.append(f"case {cid!r} input not found: {p}")
                        elif _sha256_file(p) != str(inp.get("sha256") or ""):
                            issues.append(f"case {cid!r} input sha mismatch: {p}")
    return issues


def create_proposal(
    *, proposal_id: str, failure_description: str, failure_artifacts: list[dict[str, str]],
    kind: str, target_path: str, content_path: str | Path, baseline_identity: str, candidate_identity: str,
    expected_improvement_description: str, improvement_cases: list[dict[str, Any]],
    regression_cases: list[dict[str, Any]], time_limit_seconds: int = 30,
    rule: str = "baseline-failed-candidate-passed",
) -> dict[str, Any]:
    cp, arts = Path(content_path).resolve(), []
    c_sha = _sha256_file(cp)
    for art in failure_artifacts:
        ap = Path(art["path"]).resolve()
        arts.append({"path": str(ap), "sha256": art.get("sha256") or _sha256_file(ap)})
    resolved_imp = json.loads(json.dumps(improvement_cases))
    resolved_reg = json.loads(json.dumps(regression_cases))
    canonicalize_draft_references({"improvement_cases": resolved_imp, "regression_cases": resolved_reg}, Path.cwd())
    for cases in (resolved_imp, resolved_reg):
        for case in cases:
            if isinstance(case, dict) and isinstance(case.get("inputs"), (list, tuple)):
                for inp in case["inputs"]:
                    if isinstance(inp, dict) and "path" in inp:
                        p = Path(inp["path"])
                        if "sha256" not in inp and p.is_file():
                            inp["sha256"] = _sha256_file(p)
    proposal = {
        "schema_version": PROPOSAL_SCHEMA_VERSION, "proposal_id": proposal_id,
        "observed_failure": {"description": failure_description, "artifacts": arts},
        "proposed_change": {"kind": kind, "target_path": target_path, "content_path": str(cp), "content_sha256": c_sha},
        "baseline": {"identity": baseline_identity}, "candidate": {"identity": candidate_identity, "content_sha256": c_sha},
        "expected_improvement": {"description": expected_improvement_description, "rule": rule},
        "improvement_cases": resolved_imp, "regression_cases": resolved_reg,
        "execution_conditions": {
            "time_limit_seconds": time_limit_seconds, "allow_network": False, "env_sanitized": True,
            "permitted_substitution": {"target_path": target_path, "content_sha256": c_sha},
        },
    }
    issues = validate_proposal(proposal)
    if issues: raise UsageError(f"invalid proposal: {'; '.join(issues)}")
    return proposal


def _execute_case(worktree: Path, case: dict[str, Any], side: str, proposal: dict[str, Any], attempt_dir: Path, timeout_s: int) -> dict[str, Any]:
    cid, argv = case["case_id"], deliver_checks._verification_argv(case["command"])
    isolated_home = safe_dir(attempt_dir / "homes" / side / cid, create=True)
    env, _ = worker.sanitized_env(dict(os.environ), worktree, isolated_home)
    env["TURBO_DISPOSABLE_SERVICES_ONLY"] = "1"
    env["PYTHONPATH"] = f"{worktree}:{worktree / 'tests'}" if (worktree / "tests").is_dir() else str(worktree)
    if argv is None:
        exit_code, out_s, err_s, duration_ms, timed_out, exec_err, executed = 1, "", f"unexecutable: {case['command']}", 0, False, "unexecutable command", False
    else:
        try:
            exit_code, out_s, err_s, duration_ms, timed_out = worker.execute_stream(worktree, argv, env, timeout_s, isolated_home=isolated_home, allow_network=False)
            executed, exec_err = not timed_out, None
        except Exception as exc:
            exit_code, out_s, err_s, duration_ms, timed_out, exec_err, executed = 1, "", str(exc), 0, False, str(exc), False
    out_text = out_s + err_s
    out_path = safe_dir(attempt_dir / side, create=True) / f"{cid}.txt"
    out_path.write_text(out_text, encoding="utf-8")
    os.chmod(out_path, 0o600)
    rub, failures = case["rubric"], []
    if not executed: failures.append(f"command not executed: {exec_err or 'unknown'}")
    if timed_out: failures.append("command timed out")
    if executed and not timed_out:
        if exit_code != rub.get("expected_exit_code", 0): failures.append(f"expected exit code {rub.get('expected_exit_code', 0)}, got {exit_code}")
        for t in rub.get("required_output_tokens", []):
            if t not in out_text: failures.append(f"missing required output token: {t!r}")
        for t in rub.get("forbidden_output_tokens", []):
            if t in out_text: failures.append(f"found forbidden output token: {t!r}")
    passed = len(failures) == 0 and executed and not timed_out
    is_launch_failure = (not executed) or timed_out or bool(exec_err) or (exit_code in (124, 126, 127))
    return {
        "case_id": cid, "subject_side": side, "subject_identity": proposal[side]["identity"],
        "command": case["command"], "argv": list(argv or ()), "executed": executed, "exit_code": exit_code,
        "timed_out": timed_out, "execution_error": exec_err, "duration_ms": duration_ms,
        "output_path": str(out_path), "output_sha256": runner.digest_text(out_text), "rubric": rub,
        "rubric_passed": passed, "rubric_failures": failures, "is_behavioral_failure": (not is_launch_failure and not passed),
    }


def _is_launch_failure(r: Any) -> bool:
    if not isinstance(r, dict):
        return True
    return (not r.get("executed")) or bool(r.get("timed_out")) or bool(r.get("execution_error")) or (r.get("exit_code") in (124, 126, 127))


def _candidate_case_success(r: Any) -> bool:
    if not isinstance(r, dict):
        return False
    rf = r.get("rubric_failures")
    if not isinstance(rf, list) or len(rf) != 0:
        return False
    return bool(r.get("rubric_passed")) and not _is_launch_failure(r)


def evaluate_proposal(
    proposal: dict[str, Any], evidence_dir: Path, *, repo: Path | None = None,
    telemetry: dict[str, Any] | None = None, rate_card: worker.RateCard | None = None,
) -> dict[str, Any]:
    issues = validate_proposal(proposal)
    if issues: raise UsageError(f"invalid proposal: {'; '.join(issues)}")
    prop_digest, factory_rev = proposal_digest(proposal), (gitio.git(FACTORY_ROOT, "rev-parse", "HEAD").output if gitio.git(FACTORY_ROOT, "rev-parse", "HEAD").ok else "unknown")
    attempts_dir, num = safe_dir(evidence_dir / "attempts", create=True), 1
    while True:
        attempt_dir = attempts_dir / f"attempt-{num}"
        try: attempt_dir.mkdir(parents=True, exist_ok=False); break
        except FileExistsError: num += 1
    manifest_path = attempt_dir / "attempt-manifest.json"
    manifest: dict[str, Any] = {
        "schema_version": PROPOSAL_SCHEMA_VERSION, "attempt_number": num, "proposal_digest": prop_digest,
        "candidate_content_digest": proposal["proposed_change"]["content_sha256"], "factory_revision": factory_rev,
        "status": "in-progress", "started_at": now(), "completed_at": None, "completed_cases": [], "eligibility": "ineligible",
    }
    _write_json(manifest_path, manifest)
    b_cases, c_cases, timeout_s = [], [], proposal["execution_conditions"]["time_limit_seconds"]
    staged_inputs: dict[str, list[tuple[str, bytes]]] = {}
    try:
        for case in proposal.get("improvement_cases", []) + proposal.get("regression_cases", []):
            cid = case.get("case_id")
            for inp in case.get("inputs") or ():
                if isinstance(inp, dict):
                    src = Path(str(inp.get("path") or ""))
                    if not src.is_file():
                        raise UsageError(f"case {cid!r} input not found: {src}")
                    data = src.read_bytes()
                    sha = hashlib.sha256(data).hexdigest()
                    if sha != str(inp.get("sha256") or ""):
                        raise UsageError(f"case {cid!r} input sha mismatch: expected {inp.get('sha256')}, got {sha}")
                    staged_inputs.setdefault(cid, []).append((str(inp["target_path"]), data))
        cand_path = Path(proposal["proposed_change"]["content_path"])
        if not cand_path.is_file():
            raise UsageError(f"proposed_change content_path not found: {cand_path}")
        cand_bytes = cand_path.read_bytes()
        if hashlib.sha256(cand_bytes).hexdigest() != proposal["proposed_change"]["content_sha256"]:
            raise UsageError("proposed_change content_sha256 mismatch")
        for side, store in (("baseline", b_cases), ("candidate", c_cases)):
            for kind, case in [("improvement", c) for c in proposal["improvement_cases"]] + [("regression", c) for c in proposal["regression_cases"]]:
                wt = attempt_dir / "worktrees" / f"{side}_{case['case_id']}"
                try:
                    if repo and (repo / ".git").is_dir(): worker.prepare_isolated_git_checkout(repo, wt, "HEAD")
                    elif repo and repo.is_dir(): shutil.copytree(repo, wt, dirs_exist_ok=True)
                    else: wt.mkdir(parents=True, exist_ok=True)
                    for target_rel, inp_bytes in staged_inputs.get(case["case_id"], []):
                        _write_confined_file(wt, target_rel, inp_bytes)
                    if side == "candidate":
                        target_rel = str(proposal["proposed_change"]["target_path"])
                        _write_confined_file(wt, target_rel, cand_bytes)
                    res = _execute_case(wt, case, side, proposal, attempt_dir, timeout_s)
                    res["case_kind"] = kind
                    store.append(res)
                    _write_json(attempt_dir / side / f"{case['case_id']}.json", res)
                    manifest["completed_cases"].append(f"{side}:{case['case_id']}")
                    _write_json(manifest_path, manifest)
                finally:
                    if wt.exists() or wt.is_symlink():
                        shutil.rmtree(wt, ignore_errors=True)
    except BaseException as exc:
        manifest["status"] = "interrupted" if isinstance(exc, (KeyboardInterrupt, TimeoutError)) else "failed"
        manifest["error"], manifest["completed_at"] = str(exc) or repr(exc), now()
        try:
            _write_json(manifest_path, manifest)
        except Exception:
            pass
        raise
    finally:
        worktrees_dir = attempt_dir / "worktrees"
        if worktrees_dir.exists():
            shutil.rmtree(worktrees_dir, ignore_errors=True)
    eligibility_reasons: list[str] = []
    b_by_id, c_by_id = {r["case_id"]: r for r in b_cases}, {r["case_id"]: r for r in c_cases}
    for ic in proposal["improvement_cases"]:
        cid = ic["case_id"]
        br, cr = b_by_id[cid], c_by_id[cid]
        if br["rubric_passed"]:
            eligibility_reasons.append(f"improvement case {cid!r} passed on baseline; no behavioral improvement demonstrated")
        elif not br["is_behavioral_failure"]:
            eligibility_reasons.append(f"baseline had execution error or timeout on {cid!r}; launch failure is not behavioral failure")
        if _is_launch_failure(cr):
            eligibility_reasons.append(f"candidate had launch failure or timeout on {cid!r}; launch failure cannot establish success")
        elif not cr["rubric_passed"]:
            eligibility_reasons.append(f"candidate failed improvement case {cid!r}: {'; '.join(cr['rubric_failures'])}")
    for rc in proposal["regression_cases"]:
        rid = rc["case_id"]
        cr = c_by_id[rid]
        if _is_launch_failure(cr):
            eligibility_reasons.append(f"candidate had launch failure or timeout on regression {rid!r}; launch failure cannot establish regression pass")
        elif not cr["rubric_passed"]:
            eligibility_reasons.append(f"candidate failed required regression {rid!r}: {'; '.join(cr['rubric_failures'])}")
    eligible = len(eligibility_reasons) == 0
    report = {
        "schema_version": REPORT_SCHEMA_VERSION, "proposal_digest": prop_digest, "factory_revision": factory_rev,
        "candidate_content_digest": proposal["proposed_change"]["content_sha256"],
        "baseline_identity": proposal["baseline"]["identity"], "candidate_identity": proposal["candidate"]["identity"],
        "proposal": proposal, "execution_conditions": proposal["execution_conditions"],
        "baseline_results": {"improvement_cases": [r for r in b_cases if r["case_kind"] == "improvement"], "regression_cases": [r for r in b_cases if r["case_kind"] == "regression"]},
        "candidate_results": {"improvement_cases": [r for r in c_cases if r["case_kind"] == "improvement"], "regression_cases": [r for r in c_cases if r["case_kind"] == "regression"]},
        "comparison": {
            "rule": proposal["expected_improvement"]["rule"], "rule_satisfied": eligible,
            "baseline_demonstrated_failure": all(r["is_behavioral_failure"] for r in b_cases if r["case_kind"] == "improvement"),
            "candidate_demonstrated_success": all(_candidate_case_success(r) for r in c_cases if r["case_kind"] == "improvement"),
            "candidate_regressions_passed": len(proposal["regression_cases"]) > 0 and all(_candidate_case_success(r) for r in c_cases if r["case_kind"] == "regression"),
            "reasons": eligibility_reasons,
        },
        "measurements": {
            "baseline": worker.extract_measurements((telemetry or {}).get("baseline"), sum(r["duration_ms"] for r in b_cases), spec=rate_card),
            "candidate": worker.extract_measurements((telemetry or {}).get("candidate"), sum(r["duration_ms"] for r in c_cases), spec=rate_card),
        },
        "eligibility": "improvement-eligible" if eligible else "ineligible", "eligibility_reasons": eligibility_reasons,
        "authority_note": AUTHORITY_NOTE, "recorded_at": now(),
    }
    report_path = attempt_dir / "report.json"
    _write_json(report_path, report)
    manifest["status"], manifest["completed_at"], manifest["eligibility"], manifest["report_path"] = "completed", now(), report["eligibility"], str(report_path)
    _write_json(manifest_path, manifest)
    return report


def validate_report_for_review(report: dict[str, Any], *, proposal_json: str | None = None) -> list[str]:
    issues: list[str] = []
    if not isinstance(report, dict):
        return ["report must be a JSON object"]
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        issues.append(f"unsupported schema_version: {report.get('schema_version')!r}")
    if report.get("authority_note") != AUTHORITY_NOTE:
        issues.append("invalid authority note on report")
    eligibility = report.get("eligibility")
    if eligibility not in ("improvement-eligible", "ineligible"):
        issues.append(f"invalid report eligibility: {eligibility!r}")

    emb_prop = report.get("proposal")
    prop_issues = validate_proposal_structure(emb_prop)
    if prop_issues:
        issues.extend(prop_issues)
    elif isinstance(emb_prop, dict):
        if report.get("proposal_digest") != proposal_digest(emb_prop):
            issues.append("report proposal_digest mismatch with embedded proposal")
        prop_c_sha = (emb_prop.get("proposed_change") if isinstance(emb_prop.get("proposed_change"), dict) else {}).get("content_sha256")
        cand_c_sha = (emb_prop.get("candidate") if isinstance(emb_prop.get("candidate"), dict) else {}).get("content_sha256")
        if report.get("candidate_content_digest") != prop_c_sha:
            issues.append("report candidate_content_digest mismatch with embedded proposal")
        if cand_c_sha != prop_c_sha:
            issues.append("embedded proposal candidate content_sha256 mismatch with proposed_change")

    if proposal_json is not None:
        expected_digest = hashlib.sha256(proposal_json.encode("utf-8")).hexdigest()
        if report.get("proposal_digest") != expected_digest:
            issues.append("report proposal_digest mismatch with external proposal_json")

    base_res = report.get("baseline_results")
    cand_res = report.get("candidate_results")
    if not isinstance(base_res, dict) or not isinstance(cand_res, dict):
        issues.append("report requires baseline_results and candidate_results dictionaries")
        return issues

    b_imp = base_res.get("improvement_cases")
    b_reg = base_res.get("regression_cases")
    c_imp = cand_res.get("improvement_cases")
    c_reg = cand_res.get("regression_cases")
    if not isinstance(b_imp, list) or not isinstance(b_reg, list) or not isinstance(c_imp, list) or not isinstance(c_reg, list):
        issues.append("case results in baseline_results and candidate_results must be lists")
        return issues

    p_imp = emb_prop.get("improvement_cases") if isinstance(emb_prop, dict) else None
    p_reg = emb_prop.get("regression_cases") if isinstance(emb_prop, dict) else None

    if isinstance(p_imp, list) and isinstance(p_reg, list):
        if len(p_reg) == 0:
            issues.append("report requires non-empty regression_cases")
        if len(p_imp) == 0:
            issues.append("report requires non-empty improvement_cases")

        for side_name, side_dict in (("baseline", base_res), ("candidate", cand_res)):
            for kind_name, prop_cases in (("improvement_cases", p_imp), ("regression_cases", p_reg)):
                actual_list = side_dict.get(kind_name)
                if not isinstance(actual_list, list):
                    continue
                if len(actual_list) != len(prop_cases):
                    issues.append(f"{side_name} {kind_name} count does not match proposal")
                    continue
                actual_by_id = {}
                for r in actual_list:
                    if not isinstance(r, dict):
                        issues.append(f"malformed case result in {side_name} {kind_name}")
                        continue
                    rcid = r.get("case_id")
                    if not isinstance(rcid, str) or not rcid or not VALID_ID_RE.fullmatch(rcid):
                        issues.append(f"malformed case_id in {side_name} {kind_name}: {rcid!r}")
                        continue
                    actual_by_id[rcid] = r
                    rf = r.get("rubric_failures")
                    if not isinstance(rf, list) or any(not isinstance(f, str) for f in rf):
                        issues.append(f"{side_name} case {rcid!r} missing or non-list rubric_failures")
                for pc in prop_cases:
                    if not isinstance(pc, dict):
                        continue
                    pcid = pc.get("case_id")
                    if not isinstance(pcid, str) or not pcid or not VALID_ID_RE.fullmatch(pcid):
                        continue
                    if pcid not in actual_by_id:
                        issues.append(f"missing {side_name} result for case {pcid!r}")
                    else:
                        cr = actual_by_id[pcid]
                        if cr.get("rubric") != pc.get("rubric"):
                            issues.append(f"{side_name} case {pcid!r} rubric does not match proposal")

    def _is_behavioral_failure(r: Any) -> bool:
        if not isinstance(r, dict):
            return False
        rf = r.get("rubric_failures")
        if not isinstance(rf, list):
            return False
        return (not _is_launch_failure(r)) and (not r.get("rubric_passed", False)) and bool(r.get("is_behavioral_failure"))

    raw_base_fail = bool(b_imp) and all(_is_behavioral_failure(r) for r in b_imp)
    raw_cand_succ = bool(c_imp) and all(_candidate_case_success(r) for r in c_imp)
    raw_cand_reg_pass = bool(c_reg) and all(_candidate_case_success(r) for r in c_reg)
    raw_rule_satisfied = raw_base_fail and raw_cand_succ and raw_cand_reg_pass

    comp = report.get("comparison")
    if not isinstance(comp, dict):
        issues.append("report missing comparison dictionary")
    else:
        if comp.get("rule") != "baseline-failed-candidate-passed":
            issues.append(f"unsupported comparison rule: {comp.get('rule')!r}")
        if bool(comp.get("baseline_demonstrated_failure")) != raw_base_fail:
            issues.append("comparison baseline_demonstrated_failure inconsistent with recorded outcomes")
        if bool(comp.get("candidate_demonstrated_success")) != raw_cand_succ:
            issues.append("comparison candidate_demonstrated_success inconsistent with recorded outcomes")
        if bool(comp.get("candidate_regressions_passed")) != raw_cand_reg_pass:
            issues.append("comparison candidate_regressions_passed inconsistent with recorded outcomes")
        if bool(comp.get("rule_satisfied")) != raw_rule_satisfied:
            issues.append("comparison rule_satisfied inconsistent with recorded outcomes")

    if eligibility == "improvement-eligible":
        if not raw_rule_satisfied:
            issues.append("eligible report contradicts recorded outcomes (rule not satisfied)")
        if isinstance(comp, dict):
            if not comp.get("rule_satisfied") or not comp.get("baseline_demonstrated_failure") or not comp.get("candidate_demonstrated_success") or not comp.get("candidate_regressions_passed"):
                issues.append("eligible report has unsatisfied comparison summary conditions")
        if report.get("eligibility_reasons"):
            issues.append("eligible report has non-empty eligibility_reasons")
    elif eligibility == "ineligible":
        if raw_rule_satisfied:
            issues.append("ineligible report contradicts recorded outcomes (rule was satisfied)")
        reasons = report.get("eligibility_reasons")
        if not isinstance(reasons, list) or not reasons:
            issues.append("ineligible report requires non-empty eligibility_reasons")

    return issues


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="factory.improvement", description="Factory improvement proposal and comparison workflow.")
    sub = p.add_subparsers(dest="action", required=True)
    prop = sub.add_parser("create-proposal", aliases=["propose"], help="create and validate a proposal")
    prop.add_argument("--out", required=True, help="output proposal JSON path")
    prop.add_argument("--from-file", help="input draft JSON file to validate and canonicalize")
    prop.add_argument("--proposal-id")
    prop.add_argument("--failure-desc")
    prop.add_argument("--failure-artifact", action="append", default=[])
    prop.add_argument("--kind", choices=("skill", "tool", "check"))
    prop.add_argument("--target-path")
    prop.add_argument("--content-file")
    prop.add_argument("--baseline-identity")
    prop.add_argument("--candidate-identity")
    prop.add_argument("--expected-improvement")
    prop.add_argument("--cases-file")
    prop.add_argument("--time-limit", type=int, default=30)
    eval_p = sub.add_parser("evaluate", help="evaluate baseline and candidate proposals")
    eval_p.add_argument("--proposal", required=True, help="proposal JSON path")
    eval_p.add_argument("--evidence-dir", required=True, help="evidence directory path")
    eval_p.add_argument("--repo", help="base repository path")
    eval_p.add_argument("--json", action="store_true", help="output report JSON to stdout")
    pkt_p = sub.add_parser("build-review-packet", aliases=["review-packet"], help="build an issue/PR review packet from evaluation report")
    pkt_p.add_argument("--report", required=True, help="evaluation report JSON path")
    pkt_p.add_argument("--out", required=True, help="output review packet JSON path")
    pkt_p.add_argument("--proposal-json", help="optional external proposal JSON path to verify against")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action in ("create-proposal", "propose"):
        if args.from_file:
            draft_path = Path(args.from_file).resolve()
            if not draft_path.is_file():
                sys.stderr.write(f"Error: draft file not found: {draft_path}\n")
                return 1
            try:
                proposal = json.loads(draft_path.read_text(encoding="utf-8"))
            except Exception as exc:
                sys.stderr.write(f"Error: failed to parse draft JSON: {exc}\n")
                return 1
            if not isinstance(proposal, dict):
                sys.stderr.write("Error: proposal draft must be a JSON object\n")
                return 1
            canonicalize_draft_references(proposal, draft_path.parent)
            issues = validate_proposal(proposal)
            if issues: sys.stderr.write(f"Error: {'; '.join(issues)}\n"); return 1
        else:
            if not all([args.proposal_id, args.failure_desc, args.kind, args.target_path, args.content_file, args.baseline_identity, args.candidate_identity, args.expected_improvement, args.cases_file]):
                sys.stderr.write("Error: missing required arguments for proposal creation\n"); return 1
            cases_data = json.loads(Path(args.cases_file).read_text(encoding="utf-8"))
            proposal = create_proposal(
                proposal_id=args.proposal_id, failure_description=args.failure_desc,
                failure_artifacts=[{"path": a} for a in args.failure_artifact],
                kind=args.kind, target_path=args.target_path, content_path=args.content_file,
                baseline_identity=args.baseline_identity, candidate_identity=args.candidate_identity,
                expected_improvement_description=args.expected_improvement,
                improvement_cases=cases_data.get("improvement_cases", []),
                regression_cases=cases_data.get("regression_cases", []),
                time_limit_seconds=args.time_limit,
            )
        out_p = Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        _write_json(out_p, proposal)
        sys.stdout.write(f"Proposal written to {out_p} (digest: {proposal_digest(proposal)})\n")
        return 0
    elif args.action == "evaluate":
        prop_data = json.loads(Path(args.proposal).read_text(encoding="utf-8"))
        report = evaluate_proposal(prop_data, Path(args.evidence_dir).resolve(), repo=(Path(args.repo).resolve() if args.repo else None))
        if args.json: sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        else: sys.stdout.write(f"Evaluation complete: {report['eligibility']}\n")
        return 0 if report["eligibility"] == "improvement-eligible" else 1
    elif args.action in ("build-review-packet", "review-packet"):
        report_data = json.loads(Path(args.report).read_text(encoding="utf-8"))
        prop_json = Path(args.proposal_json).read_text(encoding="utf-8") if args.proposal_json else None
        from factory.promotion import build_review_packet
        packet = build_review_packet(report_data, proposal_json=prop_json)
        out_p = Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        _write_json(out_p, packet)
        sys.stdout.write(f"Review packet written to {out_p}\n")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
