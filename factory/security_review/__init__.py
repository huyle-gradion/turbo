"""Separate security reviewer, revision-bound security gate, and bounded repair (Issue #22)."""

from __future__ import annotations

import argparse, json, math, os, re, shlex, shutil, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from factory import ci_selection, config as config_module, deliver_checks, gitio, runner, worker as worker_module
from factory.config import now
from factory.deliver_checks import collect_redaction_secrets, evaluate_scope, git_timed, inspect_diff_categories, remaining_seconds
from factory.errors import FactoryError
from factory.intake import redact_value
from factory.limits import parse_duration
from factory.paths import atomic_json, resolve_paths, safe_dir, write_evidence

SLUG_RE, LOC_PREFIX_RE = re.compile(r"[^a-z0-9]+"), re.compile(r"^[^:\s]+:\d+:\s*(.+)$")
INLINE_REPRO_PY = (
    "import pathlib, re, sys\nroot = pathlib.Path.cwd().resolve()\n"
    "if len(sys.argv) < 3 or '__UNVERIFIABLE__' in sys.argv[2:]: print('UNVERIFIABLE_REPRODUCER'); sys.exit(1)\n"
    "p = pathlib.Path(sys.argv[1])\n"
    "if p.is_symlink() or not p.resolve().is_relative_to(root) or not p.is_file(): print(f'MISSING_FILE {sys.argv[1]}'); sys.exit(1)\n"
    "try: regs = [re.compile(r) for r in sys.argv[2:]]\nexcept re.error: print('INVALID_REGEX'); sys.exit(1)\n"
    "hits = [f'{sys.argv[1]}:{i}: {ln.strip()}' for i, ln in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1) "
    "if ln.strip() and not ln.strip().startswith('#') and any(rg.search(ln) for rg in regs)]\n"
    "print('\\n'.join(hits) if hits else f'VERIFIED_ABSENT {sys.argv[1]}')\nsys.exit(1 if hits else 0)\n"
)


@dataclass(frozen=True, slots=True)
class DefectRule:
    policy_id: str
    rule: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    title: str
    correction: str


BASELINE_SECURITY_POLICIES: tuple[dict[str, str], ...] = (
    {"id": "SEC-POL-01", "name": "no-hardcoded-secrets", "source": "baseline-security-policy", "description": "Forbid hardcoded secrets, tokens, passwords, private keys, or backdoor credentials in code."},
    {"id": "SEC-POL-02", "name": "no-unsafe-execution", "source": "baseline-security-policy", "description": "Forbid unsafe dynamic execution or deserialization (eval, exec, shell=True, os.system, pickle.loads)."},
    {"id": "SEC-POL-03", "name": "no-injection-vectors", "source": "baseline-security-policy", "description": "Forbid unparameterized SQL interpolation and unsanitized command construction."},
    {"id": "SEC-POL-04", "name": "fail-closed-auth-validation", "source": "baseline-security-policy", "description": "Authentication and token validation must fail closed without bypass backdoors or secret leakage."},
    {"id": "SEC-POL-05", "name": "protected-policy-and-scope-integrity", "source": "baseline-security-policy", "description": "Preserve repository protections, protected paths, test coverage, and sub-task scope boundaries."},
)
DEFECT_PATTERNS: tuple[DefectRule, ...] = (
    DefectRule("SEC-POL-01", "hardcoded-secret", "security-vulnerability", "critical", re.compile(r"\b(?:BACKDOOR_SECRET|HARDCODED_SECRET|SECRET_KEY|API_SECRET|PRIVATE_KEY|BYPASS_TOKEN|ADMIN_BACKDOOR)\s*=\s*['\"][^'\"]+['\"]"), "Hardcoded secret or bypass credential literal in source", "Remove the hardcoded secret/bypass constant and validate credentials strictly against the expected contract."),
    DefectRule("SEC-POL-02", "unsafe-dynamic-execution", "security-vulnerability", "critical", re.compile(r"(?:\b(?:eval|exec)\s*\(|subprocess\.\w+\([^)\n]*shell\s*=\s*True|\bos\.system\s*\(|\bpickle\.loads\s*\()"), "Unsafe dynamic code or command execution primitive detected", "Delete the unsafe eval/exec/shell=True call and parse or validate inputs using safe deterministic logic."),
    DefectRule("SEC-POL-03", "sql-injection-interpolation", "security-vulnerability", "high", re.compile(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;\n]*(?:%s|\{[a-zA-Z0-9_]+\})", re.IGNORECASE), "Unparameterized SQL query string interpolation detected", "Use parameterized query placeholders instead of string formatting or interpolation."),
    DefectRule("SEC-POL-04", "auth-bypass-backdoor", "security-vulnerability", "critical", re.compile(r"(?:['\"]bypass['\"]\s*:\s*['\"]?true|\btoken\s*==\s*(?:BACKDOOR|BYPASS)|startswith\(\s*['\"]bypass:|allow_insecure\s*=\s*True)"), "Authentication or token validation bypass backdoor detected", "Remove the authentication bypass branch so token validation fails closed on invalid or expired tokens."),
)
KNOWN_RULES = frozenset(dr.rule for dr in DEFECT_PATTERNS)


def compute_finding_id(policy_id: str, file_path: str, rule: str) -> str:
    pol_slug = SLUG_RE.sub("-", policy_id.strip().lower()).strip("-").upper() or "POL"
    pol_slug = pol_slug if pol_slug.startswith("SEC-") else f"SEC-{pol_slug}"
    return f"{pol_slug}-{SLUG_RE.sub('-', file_path.strip().lower()).strip('-') or 'repo'}-{SLUG_RE.sub('-', rule.strip().lower()).strip('-') or 'defect'}"


def load_applicable_policies(
    repo: Path, base_sha: str, child: dict[str, Any], conf: config_module.Config, deadline: float, limit_s: int,
) -> list[dict[str, Any]]:
    policies = [{**p, "policy_sha": base_sha, "enforced": True} for p in BASELINE_SECURITY_POLICIES]
    for doc_name, pol_id in (("SECURITY.md", "SEC-DOC-SECURITY"), ("AGENTS.md", "SEC-DOC-AGENTS")):
        res = git_timed(repo, deadline, limit_s, f"read {doc_name}", "show", f"{base_sha}:{doc_name}")
        if res.ok and res.output.strip():
            first_line = next((ln.strip("# ").strip() for ln in res.output.splitlines() if ln.strip()), doc_name)
            policies.append({"id": pol_id, "name": doc_name.lower().replace(".", "-"), "source": f"{doc_name}@{base_sha[:12]}",
                             "policy_sha": base_sha, "enforced": True, "description": first_line[:160]})
    constraints = str((child.get("scope") or {}).get("constraints") or "").strip()
    if constraints and constraints.lower() != "none":
        policies.append({"id": "SEC-SUBTASK-CONSTRAINTS", "name": "subtask-security-constraints",
                         "source": f"asana-subtask:{child.get('gid')}", "policy_sha": base_sha, "enforced": True, "description": constraints[:200]})
    return policies


def build_security_reviewer_prompt(
    child: dict[str, Any], base_sha: str, candidate_sha: str, diff_info: dict[str, Any],
    policies: list[dict[str, Any]], prior_findings: list[dict[str, Any]] | None = None,
) -> str:
    scope = child.get("scope") or {}
    pol_lines = "\n".join(f"- {p['id']} ({p['name']}, source={p['source']}): {p['description']}" for p in policies)
    prior_lines = "\n".join(f"- {f.get('finding_id')}: {f.get('file_path')} ({f.get('rule')}) reproducer={f.get('verification_command')}"
                            for f in (prior_findings or []) if isinstance(f, dict) and f.get("blocking", True)) or "- None"
    schema = ('{"outcome":"approved|changes-requested","findings":[{"finding_id":"SEC-...","policy_id":"SEC-POL-01","rule":"...",'
              '"category":"security-vulnerability|non-blocking-suggestion","severity":"critical|high|medium|low","blocking":true,'
              '"title":"...","file_path":"...","line":1,"evidence":"...","actionable_correction":"...",'
              '"verification_command":"python3 -m factory.security_review --verify-file <path> --rule <rule> --forbidden-pattern <regex>"}]}')
    return (f"Role: security-reviewer (separate from builder). Do not edit files or commit.\n"
            f"Sub-task: {child.get('gid')} ({child.get('name')})\nCandidate revision: {candidate_sha} (base: {base_sha})\n"
            f"Inspected scope: {', '.join(diff_info.get('changed_paths') or ()) or 'none'}\n"
            f"In scope: {scope.get('in_scope') or 'as specified'}\nOut of scope: {scope.get('out_of_scope') or 'none'}\n"
            f"Sub-task constraints: {scope.get('constraints') or 'none'}\nApplicable security policies:\n{pol_lines}\n"
            f"Prior blocking findings:\n{prior_lines}\nRequired JSON response schema:\n{schema}\n")


def _make_finding(fid: str, pol_id: str, rule: str, category: str, severity: str, blocking: bool, title: str,
                  rel_path: str, line_no: int | None, evidence: str, correction: str, vcmd: str, round_num: int, candidate_sha: str) -> dict[str, Any]:
    return {"finding_id": fid, "policy_id": pol_id, "rule": rule, "category": category, "severity": severity, "blocking": blocking,
            "title": title, "file_path": rel_path, "line": line_no, "evidence": evidence, "actionable_correction": correction,
            "verification_command": vcmd, "status": "open" if blocking else "suggestion", "introduced_in_round": round_num,
            "last_seen_revision": candidate_sha, "resolved_in_revision": None, "resolution_evidence": None}


def _scan_candidate_files(worktree: Path, changed_paths: list[str], candidate_sha: str, round_num: int,
                          *, rule_filter: str | None = None, forbidden_pattern: str | None = None) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    wt_root = worktree.resolve()
    try:
        custom_re = re.compile(forbidden_pattern) if forbidden_pattern else None
    except re.error as exc:
        raise ValueError(f"invalid forbidden_pattern: {exc}") from exc
    for rel_path in changed_paths:
        target = worktree / rel_path
        try:
            if target.is_symlink() or not target.resolve().is_relative_to(wt_root) or not target.is_file():
                continue
        except OSError:
            continue
        for line_no, raw_line in enumerate(target.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            hit_line = f"{rel_path}:{line_no}: {stripped}"
            for dr in DEFECT_PATTERNS:
                if (not rule_filter or dr.rule == rule_filter) and dr.pattern.search(raw_line):
                    fid = compute_finding_id(dr.policy_id, rel_path, dr.rule)
                    if fid in by_id:
                        by_id[fid]["evidence"] += f"\n{hit_line}"
                    else:
                        vcmd = f"python3 -m factory.security_review --verify-file {shlex.quote(rel_path)} --rule {shlex.quote(dr.rule)}"
                        by_id[fid] = _make_finding(fid, dr.policy_id, dr.rule, dr.category, dr.severity, True, dr.title, rel_path,
                                                   line_no, hit_line, f"In `{rel_path}` (around line {line_no}): {dr.correction}", vcmd, round_num, candidate_sha)
            if custom_re and custom_re.search(raw_line):
                c_rule = rule_filter or "custom-finding"
                fid = compute_finding_id("SEC-POL-04", rel_path, c_rule)
                if fid in by_id:
                    by_id[fid]["evidence"] += f"\n{hit_line}"
                else:
                    vcmd = f"python3 -m factory.security_review --verify-file {shlex.quote(rel_path)} --rule {shlex.quote(c_rule)} --forbidden-pattern {shlex.quote(forbidden_pattern or '')}"
                    by_id[fid] = _make_finding(fid, "SEC-POL-04", c_rule, "security-vulnerability", "high", True, f"Forbidden security pattern ({c_rule})",
                                               rel_path, line_no, hit_line, f"Remediate {c_rule} in `{rel_path}`.", vcmd, round_num, candidate_sha)
    return list(by_id.values())


def _parse_reviewer_findings(response_text: str, candidate_sha: str, round_num: int) -> tuple[list[dict[str, Any]], list[str]]:
    text = (response_text or "").strip()
    if not (text.startswith("{") and text.endswith("}")):
        return [], ["reviewer response must be a raw JSON object without markdown fences"]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [f"reviewer response is not valid JSON: {exc}"]
    if not isinstance(parsed, dict):
        return [], ["reviewer response must be a JSON object"]
    rep_outcome, raw_list = parsed.get("outcome"), parsed.get("findings")
    if rep_outcome not in ("approved", "changes-requested"):
        return [], [f"reviewer response has invalid or missing outcome {rep_outcome!r}"]
    if not isinstance(raw_list, list) or not all(isinstance(r, dict) for r in raw_list):
        return [], ["reviewer response is missing a valid 'findings' list of objects"]
    items = []
    for raw in raw_list:
        pol_id, fpath = str(raw.get("policy_id") or "SEC-POL-04").strip(), str(raw.get("file_path") or "repository").strip()
        rule = str(raw.get("rule") or raw.get("title") or "finding").strip()
        sev = str(raw.get("severity") or "high").strip().lower()
        raw_blk = raw.get("blocking")
        blocking = (sev not in ("low", "info")) if raw_blk is None else bool(raw_blk)
        fid = str(raw.get("finding_id") or "").strip() or compute_finding_id(pol_id, fpath, rule)
        ev_str = str(raw.get("evidence") or f"Reported by security-reviewer on {fpath}@{candidate_sha[:12]}")
        pat = str(raw.get("forbidden_pattern") or "").strip()
        if not pat and raw.get("evidence"):
            first_ev = next((ln.strip() for ln in str(raw["evidence"]).splitlines() if ln.strip() and not ln.strip().startswith("#")), "")
            if first_ev:
                pat = re.escape(m.group(1) if (m := LOC_PREFIX_RE.match(first_ev)) else first_ev)
        try:
            if pat:
                re.compile(pat)
        except re.error:
            pat = ""
        vcmd = str(raw.get("verification_command") or "").strip()
        if not vcmd or ("factory.security_review" in vcmd and "--verify-file" in vcmd and "--forbidden-pattern" not in vcmd and rule not in KNOWN_RULES):
            vcmd = (f"python3 -m factory.security_review --verify-file {shlex.quote(fpath)} --rule {shlex.quote(rule)}" if rule in KNOWN_RULES
                    else f"python3 -m factory.security_review --verify-file {shlex.quote(fpath)} --rule {shlex.quote(rule)} --forbidden-pattern {shlex.quote(pat)}" if pat
                    else f"python3 -m factory.security_review --verify-file {shlex.quote(fpath)} --rule {shlex.quote(rule)}")
        items.append(_make_finding(
            fid, pol_id, rule, str(raw.get("category") or ("security-vulnerability" if blocking else "non-blocking-suggestion")),
            sev, blocking, str(raw.get("title") or rule), fpath, raw.get("line") if isinstance(raw.get("line"), int) else None, ev_str,
            str(raw.get("actionable_correction") or "Remediate the reported security finding within scope."), vcmd, round_num, candidate_sha))
    has_blocking = any(f["blocking"] for f in items)
    if rep_outcome == "approved" and has_blocking:
        return items, ["reviewer reported outcome='approved' despite blocking findings"]
    if rep_outcome == "changes-requested" and not has_blocking:
        return items, ["reviewer reported outcome='changes-requested' without any blocking findings"]
    return items, []


def _reconcile_findings(
    static_findings: list[dict[str, Any]], agent_findings: list[dict[str, Any]], prior_findings: list[dict[str, Any]] | None,
    finding_vers: dict[str, dict[str, Any]], ind_ver_ok: bool, candidate_sha: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    prior_blocking = {str(f["finding_id"]): dict(f) for f in (prior_findings or []) if isinstance(f, dict) and f.get("finding_id") and f.get("blocking", True)}
    cur_by_id: dict[str, dict[str, Any]] = {}
    for item in (*agent_findings, *static_findings):
        fid = str(item["finding_id"])
        if fid not in cur_by_id or item in static_findings or (item.get("blocking") and not cur_by_id[fid].get("blocking")):
            cur_by_id[fid] = {**cur_by_id.get(fid, {}), **item, "blocking": bool(item.get("blocking") or cur_by_id.get(fid, {}).get("blocking")),
                              "status": "open" if (item.get("blocking") or cur_by_id.get(fid, {}).get("blocking")) else "suggestion"}

    all_findings, resolutions = [], []
    for fid, cur in cur_by_id.items():
        f_ver = finding_vers.get(fid)
        if fid in prior_blocking:
            old_f = prior_blocking[fid]
            all_findings.append({
                **cur, **old_f, "blocking": True, "status": "open",
                "introduced_in_round": int(old_f.get("introduced_in_round") or 1),
                "last_seen_revision": candidate_sha, "resolved_in_revision": None,
                "resolution_evidence": None, "reproducer_verification": f_ver,
            })
            resolutions.append({"finding_id": fid, "previous_status": str(old_f.get("status") or "open"), "status": "open",
                                "verified_on_revision": candidate_sha, "reproducer_verification": f_ver, "resolution_evidence": None})
        elif cur.get("blocking"):
            all_findings.append({**cur, "status": "open", "reproducer_verification": f_ver})
        else:
            all_findings.append({**cur, "blocking": False, "status": "suggestion"})

    for fid, old_f in prior_blocking.items():
        if fid in cur_by_id:
            continue
        prev_st, f_ver = str(old_f.get("status") or "open"), finding_vers.get(fid)
        repro_passed = bool(isinstance(f_ver, dict) and f_ver.get("executed") and f_ver.get("ok") and f_ver.get("head_sha") == candidate_sha)
        if repro_passed and ind_ver_ok:
            res_rev = str(old_f["resolved_in_revision"]) if prev_st == "resolved" and old_f.get("resolved_in_revision") else candidate_sha
            ev_str = str(old_f.get("resolution_evidence") or f"Reproducer {f_ver['command']!r} exited 0 on {candidate_sha} ({f_ver['output_path']})")
            all_findings.append({**old_f, "blocking": True, "status": "resolved", "resolved_in_revision": res_rev,
                                 "reproducer_verification": f_ver, "resolution_evidence": ev_str})
            resolutions.append({"finding_id": fid, "previous_status": prev_st, "status": "resolved",
                                "verified_on_revision": candidate_sha, "reproducer_verification": f_ver, "resolution_evidence": ev_str})
        else:
            all_findings.append({**old_f, "blocking": True, "status": "open", "last_seen_revision": candidate_sha,
                                 "resolved_in_revision": None, "resolution_evidence": None, "reproducer_verification": f_ver})
            resolutions.append({"finding_id": fid, "previous_status": prev_st, "status": "open",
                                "verified_on_revision": candidate_sha, "reproducer_verification": f_ver, "resolution_evidence": None})
    blocking_findings = [f for f in all_findings if f.get("blocking") and f.get("status") != "resolved"]
    suggestions = [f for f in all_findings if not f.get("blocking")]
    return all_findings, blocking_findings, suggestions, resolutions


def _flag_val(argv: tuple[str, ...], flag: str) -> tuple[bool, str | None]:
    if flag not in argv:
        return False, None
    idx = argv.index(flag)
    val = argv[idx + 1] if idx + 1 < len(argv) else None
    return True, (val if val and not val.startswith("--") else None)


def _resolve_repro_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    if argv[:3] != ("python3", "-m", "factory.security_review") or "--verify-file" not in argv:
        return argv
    _, vfile = _flag_val(argv, "--verify-file")
    has_rule, rule = _flag_val(argv, "--rule")
    has_fpat, fpat = _flag_val(argv, "--forbidden-pattern")
    if not vfile or (has_rule and not rule) or (has_fpat and not fpat):
        return (sys.executable, "-c", INLINE_REPRO_PY, vfile or "__MISSING__", "__UNVERIFIABLE__")
    regexes = [dr.pattern.pattern for dr in DEFECT_PATTERNS if not rule or dr.rule == rule] + ([fpat] if fpat else [])
    return (sys.executable, "-c", INLINE_REPRO_PY, vfile, *(regexes or ["__UNVERIFIABLE__"]))


def _run_independent_verification(
    worktree: Path, verify_dir: Path, home: Path, child: dict[str, Any], conf: config_module.Config,
    changed_paths: tuple[str, ...], candidate_sha: str, secrets: tuple[str, ...],
    blocking_findings: list[dict[str, Any]], prior_blocking: dict[str, dict[str, Any]], deadline: float, limit_s: int,
) -> dict[str, Any]:
    plan = ci_selection.select_ci_test_plan(child, conf, changed_paths, repo=worktree)
    verify_home = safe_dir(verify_dir / "verify-home", create=True, root=home)
    safe_dir(verify_home / ".tmp", create=True, root=home)
    env, _ = worker_module.sanitized_env(dict(os.environ), worktree, verify_home)
    commands: list[tuple[str, tuple[str, ...]]] = []
    for guard in plan.get("essential_guards") or []:
        g_cfg = conf.gates.get(str(guard.get("id") or "").removeprefix("gate-"))
        if g_cfg is not None and g_cfg.kind == "command" and g_cfg.argv:
            commands.append((str(guard["name"]), tuple(g_cfg.argv)))
    for c in (plan.get("criterion_checks") or child.get("criteria") or []):
        if (a := deliver_checks._verification_argv(str(c.get("command") or c.get("verification") or ""))):
            commands.append((f"criterion/{str(c.get('id') or 'AC').strip()}", a))
    if plan.get("mode") == "affected-only" and plan.get("affected_tests"):
        commands.append(("regression/affected-tests", ("python3", "-m", "unittest", *plan["affected_tests"], "-v")))
    gate2 = conf.gates.get("2")
    if gate2 is not None and gate2.kind == "command" and gate2.argv:
        commands.append(("regression/gate-2", tuple(gate2.argv)))
    elif not commands:
        commands.append(("regression/unittest", ("python3", "-m", "unittest", "discover", "-s", "tests", "-v")))

    check_runs, all_ok = [], True
    for name, argv in commands:
        timeout_s = max(1, int(math.ceil(remaining_seconds(deadline, f"security verification {name}", limit_s))))
        code, out_s, err_s, elapsed_ms, timed_out = worker_module.execute_stream(worktree, argv, env, timeout_s, isolated_home=verify_home, allow_network=False)
        combined = redact_value((out_s + err_s).strip() + "\n", secrets)
        ev_path = write_evidence(verify_dir, f"sec-verify-{SLUG_RE.sub('-', name.lower()).strip('-')}", combined, home)
        ok = code == 0 and not timed_out
        all_ok = all_ok and ok
        check_runs.append({"name": name, "argv": list(argv), "exit_code": code, "ok": ok, "timed_out": timed_out,
                           "duration_ms": elapsed_ms, "head_sha": candidate_sha, "output_path": str(ev_path),
                           "output_sha256": runner.digest_text(combined), "provenance": "observed-security-verification"})

    repro_targets = {str(f["finding_id"]): f for f in (*blocking_findings, *prior_blocking.values()) if isinstance(f, dict) and f.get("finding_id")}
    finding_vers: dict[str, dict[str, Any]] = {}
    for fid, fobj in repro_targets.items():
        vcmd = str(fobj.get("verification_command") or "").strip()
        argv = deliver_checks._verification_argv(vcmd)
        if not argv:
            finding_vers[fid] = {"name": f"finding-reproducer/{fid}", "finding_id": fid, "command": vcmd, "executed": False,
                                 "ok": False, "reproduced": True, "exit_code": 1, "head_sha": candidate_sha}
            continue
        exec_argv = _resolve_repro_argv(argv)
        timeout_s = max(1, int(math.ceil(remaining_seconds(deadline, f"finding reproducer {fid}", limit_s))))
        code, out_s, err_s, elapsed_ms, timed_out = worker_module.execute_stream(worktree, exec_argv, env, timeout_s, isolated_home=verify_home, allow_network=False)
        combined = redact_value((out_s + err_s).strip() + "\n", secrets)
        ev_path = write_evidence(verify_dir, f"sec-repro-{SLUG_RE.sub('-', fid.lower()).strip('-')[:48]}", combined, home)
        ok = code == 0 and not timed_out
        finding_vers[fid] = {"name": f"finding-reproducer/{fid}", "finding_id": fid, "command": vcmd, "argv": list(exec_argv),
                             "requested_argv": list(argv), "executed": True, "exit_code": code, "ok": ok, "reproduced": not ok,
                             "timed_out": timed_out, "duration_ms": elapsed_ms, "head_sha": candidate_sha, "output_path": str(ev_path),
                             "output_sha256": runner.digest_text(combined), "provenance": "observed-finding-reproducer"}
    return {"executed": True, "ok": all_ok, "head_sha": candidate_sha, "selection_plan": plan,
            "security_probe_ok": len(blocking_findings) == 0 and all(finding_vers.get(fid, {}).get("ok", False) for fid in prior_blocking),
            "finding_verifications": finding_vers, "checks": check_runs, "provenance": "observed-security-verification"}


def _run_isolated_role_checkout(
    *, repo: Path, home: Path, role_dir: Path, candidate_sha: str, base_sha: str, agy_bin: str | None,
    evidence_prefix: str, secrets: tuple[str, ...], deadline: float, limit_s: int,
    build_prompt_fn: Callable[[Path, list[dict[str, Any]]], tuple[str, dict[str, Any]]],
    after_fn: Callable[[Path, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    safe_dir(role_dir, create=True, root=home)
    worktree = role_dir / "worktree"
    isolated_home = worker_module.prepare_isolated_home(role_dir, Path.home(), root=home)
    safe_dir(isolated_home / ".tmp", create=True, root=home)
    worker_env, stripped_keys = worker_module.sanitized_env(dict(os.environ), worktree, isolated_home)
    worker_module.prepare_isolated_git_checkout(repo, worktree, candidate_sha, deadline=deadline)
    try:
        fetch_res = git_timed(worktree, deadline, limit_s, "fetch base_sha", "fetch", "-q", "--no-tags", str(repo), base_sha)
        rev_res = git_timed(worktree, deadline, limit_s, "verify base_sha", "rev-parse", "--verify", f"{base_sha}^{{commit}}")
        (worktree / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
        probes, probes_ok, sandbox_error = [], False, None
        try:
            if agy_bin and str(agy_bin).strip():
                worker_module.validate_execution_options(worker_module.platform_info(), time_limit_seconds=limit_s, agy_bin=str(agy_bin))
            probes = worker_module.run_safety_probes(worker_env, worktree, role_dir, home, deadline=deadline)
            probes_ok = worker_module.probes_passed(probes)
        except worker_module.SandboxUnavailableError as exc:
            sandbox_error = str(exc)
        prompt, pre_ctx = build_prompt_fn(worktree, probes)
        executed, exit_code, elapsed_ms, timed_out = False, None, 0, False
        stdout_path, stderr_path, events, final_res, parse_err, perm_denied = None, None, [], None, None, False
        if probes_ok and agy_bin and str(agy_bin).strip():
            argv = (str(agy_bin), "--print", prompt, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
            t_out = max(1, int(math.ceil(remaining_seconds(deadline, f"{evidence_prefix} execution", limit_s))))
            try:
                exit_code, out_s, err_s, elapsed_ms, timed_out = worker_module.execute_stream(worktree, argv, worker_env, t_out, isolated_home=isolated_home)
                executed = True
                stdout_path = str(write_evidence(role_dir, f"{evidence_prefix}-stdout", redact_value(out_s, secrets), home))
                stderr_path = str(write_evidence(role_dir, f"{evidence_prefix}-stderr", redact_value(err_s, secrets), home))
                events, final_res, parse_err = worker_module.parse_stream_events(out_s)
                perm_denied = worker_module.has_permission_denial(events, final_res, err_s)
            except worker_module.SandboxUnavailableError as exc:
                sandbox_error, probes_ok = str(exc), False
        run_ctx = {
            **pre_ctx, "base_ok": fetch_res.ok and rev_res.ok, "sandbox_error": sandbox_error, "probes": probes,
            "probes_ok": probes_ok, "executed": executed, "exit_code": exit_code, "elapsed_ms": elapsed_ms,
            "timed_out": timed_out, "stdout_path": stdout_path, "stderr_path": stderr_path, "events": events,
            "final_res": final_res, "parse_err": parse_err, "perm_denied": perm_denied,
            "safety": {"sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False,
                       "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": probes},
        }
        return after_fn(worktree, run_ctx)
    finally:
        shutil.rmtree(worktree, ignore_errors=True)


def review_candidate_security(
    *, repo: Path, home: Path, child_dir: Path, child: dict[str, Any], conf: config_module.Config,
    base_sha: str, candidate_sha: str, round_num: int = 1, agy_bin: str | None = None,
    prior_findings: list[dict[str, Any]] | None = None, builder_session_id: str | None = None,
    deadline: float, limit_s: int,
) -> dict[str, Any]:
    round_dir = safe_dir(child_dir / f"security-round-{round_num}", create=True, root=home)
    secrets = collect_redaction_secrets()

    def _build_rev_prompt(rev_wt: Path, _probes: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        name_status = git_timed(rev_wt, deadline, limit_s, "diff name-status", "diff", "--find-renames", "--name-status", base_sha, candidate_sha)
        diff_info = inspect_diff_categories(rev_wt, base_sha, candidate_sha, deadline, limit_s)
        gate3 = conf.gates.get("3")
        protected = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
        scope_ok, scope_violations, scope_detail = evaluate_scope(tuple(diff_info["changed_paths"]), child, protected)
        diff_res = git_timed(rev_wt, deadline, limit_s, "security diff", "diff", "--binary", base_sha, candidate_sha)
        diff_text = redact_value(diff_res.output + "\n", secrets)
        diff_path = write_evidence(round_dir, "reviewed-diff", diff_text, home)
        policies = load_applicable_policies(repo, base_sha, child, conf, deadline, limit_s)
        prompt = build_security_reviewer_prompt(child, base_sha, candidate_sha, diff_info, policies, prior_findings)
        return prompt, {"diff_info": diff_info, "diff_cmds_ok": name_status.ok and diff_res.ok, "scope_ok": scope_ok,
                        "scope_violations": scope_violations, "scope_detail": scope_detail, "diff_path": diff_path,
                        "diff_sha256": runner.digest_text(diff_text), "policies": policies}

    def _after_rev(rev_wt: Path, rctx: dict[str, Any]) -> dict[str, Any]:
        diff_info, policies = rctx["diff_info"], rctx["policies"]
        diff_ok = bool(rctx.get("base_ok", True) and rctx.get("diff_cmds_ok", True))
        scope_ok, scope_detail = rctx["scope_ok"] and diff_ok, dict(rctx["scope_detail"])
        if not diff_ok:
            scope_detail["status"], scope_detail["deterministic_ok"] = "diff-failed", False
        role_issues = [f"sandbox unavailable: {rctx['sandbox_error']}"] if rctx.get("sandbox_error") else ([] if rctx["probes_ok"] else ["security reviewer safety probes failed"])
        if not diff_ok:
            role_issues.append("failed to resolve or diff base_sha against candidate_sha")
        reviewer_session_id, reviewer_executed, agent_findings = None, False, []
        if not (agy_bin and str(agy_bin).strip()):
            role_issues.append("security reviewer executable is required; missing reviewer execution fails closed")
        elif rctx["probes_ok"]:
            f_res = rctx["final_res"]
            if rctx["timed_out"] or rctx["parse_err"] is not None or rctx["perm_denied"] or rctx["exit_code"] != 0 or not isinstance(f_res, dict) or f_res.get("status") != "SUCCESS":
                role_issues.append(f"security reviewer execution failed (exit={rctx['exit_code']}, parse_error={rctx['parse_err']})")
            else:
                reviewer_session_id = str(f_res.get("conversation_id") or "").strip() or None
                if not reviewer_session_id:
                    role_issues.append("security reviewer did not record a conversation_id")
                else:
                    reviewer_executed = True
                    agent_findings, parse_issues = _parse_reviewer_findings(str(f_res.get("response") or ""), candidate_sha, round_num)
                    role_issues.extend(parse_issues)

        worktree_mutated = gitio.head(rev_wt) != candidate_sha or bool(gitio.status_porcelain(rev_wt))
        if worktree_mutated:
            role_issues.append("security reviewer mutated the candidate worktree; reviewer cannot approve its own edits")
        if builder_session_id and reviewer_session_id and reviewer_session_id == builder_session_id:
            role_issues.append(f"security reviewer session {reviewer_session_id!r} matches builder session; separate role required")

        static_findings = _scan_candidate_files(rev_wt, diff_info["changed_paths"], candidate_sha, round_num)
        for v in ([] if scope_ok else rctx["scope_violations"]):
            static_findings.append(_make_finding(
                compute_finding_id("SEC-POL-05", "scope", v[:40]), "SEC-POL-05", "scope-violation", "security-policy-violation",
                "high", True, f"Scope or protected-path violation: {v}", "repository", None, v,
                "Revert out-of-scope or protected-path changes.", "python3 -m unittest discover -s tests -v", round_num, candidate_sha))

        prior_blocking = {str(f["finding_id"]): f for f in (prior_findings or []) if isinstance(f, dict) and f.get("finding_id") and f.get("blocking", True)}
        pre_blocking = [f for f in (*agent_findings, *static_findings) if f.get("blocking") or f.get("finding_id") in prior_blocking]
        if rctx["probes_ok"] and not rctx["timed_out"] and not worktree_mutated and diff_ok:
            ind_ver = _run_independent_verification(
                rev_wt, round_dir, home, child, conf, tuple(diff_info["changed_paths"]),
                candidate_sha, secrets, pre_blocking, prior_blocking, deadline, limit_s,
            )
        else:
            ind_ver = {"executed": False, "ok": False, "head_sha": candidate_sha, "selection_plan": {},
                       "security_probe_ok": False, "finding_verifications": {}, "checks": [], "provenance": "skipped-due-to-role-or-probe-failure"}

        all_findings, current_blocking, suggestions, resolutions = _reconcile_findings(
            static_findings, agent_findings, prior_findings, ind_ver["finding_verifications"], ind_ver["ok"], candidate_sha,
        )
        ind_ver["security_probe_ok"] = len(current_blocking) == 0 and all(
            ind_ver["finding_verifications"].get(fid, {}).get("ok", False) for fid in prior_blocking
        )
        role_sep_ok = reviewer_executed and len(role_issues) == 0
        outcome = ("security-review-missing" if not (agy_bin and str(agy_bin).strip())
                   else "invalid-review" if not role_sep_ok
                   else "changes-requested" if current_blocking
                   else "missing-verification" if not ind_ver["ok"] else "approved")
        return {
            "schema": 1, "role": "security-reviewer", "builder_role": "builder",
            "reviewer_executed": reviewer_executed, "reviewer_session_id": reviewer_session_id,
            "reviewer_stdout_path": rctx["stdout_path"], "reviewer_stderr_path": rctx["stderr_path"],
            "reviewer_prompt_policies": [p["id"] for p in policies],
            "builder_session_id": builder_session_id, "role_separation_verified": role_sep_ok, "role_issues": role_issues,
            "round": round_num, "reviewed_revision": candidate_sha, "base_sha": base_sha, "policy_sha": base_sha,
            "inspected_scope": {"changed_paths": diff_info["changed_paths"], "implementation_paths": diff_info["implementation_paths"],
                                "test_paths": diff_info["test_paths"], "scope_status": scope_detail["status"],
                                "deterministic_ok": scope_detail["deterministic_ok"],
                                "diff_path": str(rctx["diff_path"]), "diff_sha256": rctx["diff_sha256"]},
            "applicable_policies": policies, "findings": all_findings, "blocking_findings": current_blocking,
            "non_blocking_suggestions": suggestions, "previous_findings_resolution": resolutions, "independent_verification": ind_ver,
            "safety": rctx["safety"], "outcome": outcome, "ready": outcome == "approved", "recorded_at": now(),
        }

    record = _run_isolated_role_checkout(
        repo=repo, home=home, role_dir=round_dir, candidate_sha=candidate_sha, base_sha=base_sha,
        agy_bin=agy_bin, evidence_prefix="reviewer", secrets=secrets, deadline=deadline, limit_s=limit_s,
        build_prompt_fn=_build_rev_prompt, after_fn=_after_rev,
    )
    redacted_rec = redact_value(record, secrets)
    atomic_json(round_dir / "record.json", redacted_rec, home); atomic_json(child_dir / "security-review.json", redacted_rec, home)
    return redacted_rec


def _verify_log_record(chk: Any, candidate_sha: str, home: Path | None) -> str | None:
    if (not isinstance(chk, dict) or not bool(chk.get("ok")) or bool(chk.get("timed_out"))
            or type(chk.get("exit_code")) is not int or chk.get("exit_code") != 0 or chk.get("head_sha") != candidate_sha):
        return f"check {chk.get('name') if isinstance(chk, dict) else chk!r} did not pass on {candidate_sha}"
    out_path = Path(str(chk.get("output_path") or ""))
    try:
        if out_path.is_symlink() or not out_path.is_file() or (home is not None and not out_path.resolve().is_relative_to(home.resolve())):
            return f"check {chk.get('name')!r} is missing stored log evidence"
    except OSError:
        return f"check {chk.get('name')!r} is missing stored log evidence"
    if runner.digest_text(out_path.read_text(encoding="utf-8", errors="replace")) != chk.get("output_sha256"):
        return f"check {chk.get('name')!r} log digest mismatch"
    return None


def evaluate_security_review_gate(
    candidate_sha: str, base_sha: str, security_review_record: dict[str, Any] | None,
    *, home: Path | None = None, builder_session_id: str | None = None,
) -> dict[str, Any]:
    def _fail(status: str, blockers: list[str], b_findings: list[dict[str, Any]] | None = None, suggs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {"status": status, "verified": False, "blockers": blockers, "blocking_findings": b_findings or [], "non_blocking_suggestions": suggs or []}

    if not isinstance(security_review_record, dict) or not security_review_record:
        return _fail("security-review-missing", [f"missing security review evidence for candidate {candidate_sha}"])
    raw_b = list(security_review_record.get("blocking_findings") or [])
    raw_s = [f for f in (security_review_record.get("non_blocking_suggestions") or []) if isinstance(f, dict) and not f.get("blocking", False)]
    rev_out = Path(str(security_review_record.get("reviewer_stdout_path") or ""))
    r_sid = str(security_review_record.get("reviewer_session_id") or "").strip()
    rec_bsid = str(security_review_record.get("builder_session_id") or "").strip()
    auth_bsid = str(builder_session_id or "").strip()
    b_sid = auth_bsid or rec_bsid
    if (not bool(security_review_record.get("reviewer_executed")) or not r_sid or rev_out.is_symlink()
            or not rev_out.is_file() or (home is not None and not rev_out.resolve().is_relative_to(home.resolve()))):
        return _fail("security-review-missing", list(security_review_record.get("role_issues") or ["missing actual security-reviewer execution evidence"]), raw_b, raw_s)
    if (security_review_record.get("role") != "security-reviewer" or not bool(security_review_record.get("role_separation_verified"))
            or bool(security_review_record.get("role_issues")) or not b_sid or r_sid == b_sid
            or (rec_bsid and r_sid == rec_bsid) or (auth_bsid and r_sid == auth_bsid)
            or not worker_module.probes_passed(((security_review_record.get("safety") or {}).get("probes")) or [])):
        return _fail("security-review-invalid", list(security_review_record.get("role_issues") or ["security reviewer role separation or safety probes not verified"]), raw_b, raw_s)
    rev_sha, rec_base, rec_pol = (str(security_review_record.get(k) or "").strip() for k in ("reviewed_revision", "base_sha", "policy_sha"))
    if rev_sha != candidate_sha or rec_base != base_sha or rec_pol != base_sha:
        return _fail("stale-security-review", [f"stale security review evidence: reviewed=({rev_sha}, base={rec_base}, policy={rec_pol}) does not match candidate=({candidate_sha}, base={base_sha})"], raw_b, raw_s)
    scope_obj = security_review_record.get("inspected_scope")
    if not isinstance(scope_obj, dict) or not (isinstance(security_review_record.get("applicable_policies"), list) and security_review_record.get("applicable_policies")):
        return _fail("security-review-missing", ["security review record is missing inspected_scope or applicable_policies"])
    if scope_obj.get("deterministic_ok") is not True:
        return _fail("security-review-invalid", ["security review inspected_scope deterministic_ok is not True"], raw_b, raw_s)
    blockers_list = [f for f in raw_b if isinstance(f, dict) and f.get("blocking", True) and f.get("status", "open") != "resolved"]
    for f in security_review_record.get("findings") or []:
        if isinstance(f, dict) and f.get("blocking", True) and f.get("status", "open") != "resolved" and not any(b.get("finding_id") == f.get("finding_id") for b in blockers_list):
            blockers_list.append(f)
    for res_entry in security_review_record.get("previous_findings_resolution") or []:
        if isinstance(res_entry, dict) and res_entry.get("status") != "resolved":
            fid = str(res_entry.get("finding_id") or "unknown")
            if not any(b.get("finding_id") == fid for b in blockers_list):
                blockers_list.append({"finding_id": fid, "title": f"Unresolved prior security finding {fid}", "status": "open", "blocking": True})
    if blockers_list:
        return _fail("security-blockers-unresolved", [f"unresolved blocking security finding {b.get('finding_id')}: {b.get('title')}" for b in blockers_list], blockers_list, raw_s)
    res_by_id = {str(r.get("finding_id")): r for r in (security_review_record.get("previous_findings_resolution") or []) if isinstance(r, dict) and r.get("finding_id")}
    for f in security_review_record.get("findings") or []:
        if isinstance(f, dict) and f.get("blocking", True) and f.get("status") == "resolved" and res_by_id.get(str(f.get("finding_id")), {}).get("status") != "resolved":
            return _fail("security-verification-missing", [f"resolved finding {f.get('finding_id')} is missing verified resolution evidence"], [], raw_s)
    for res_entry in security_review_record.get("previous_findings_resolution") or []:
        if not isinstance(res_entry, dict) or res_entry.get("verified_on_revision") != candidate_sha:
            return _fail("security-verification-missing", ["prior finding resolution is not bound to candidate revision"], [], raw_s)
        if (err := _verify_log_record(res_entry.get("reproducer_verification"), candidate_sha, home)):
            return _fail("security-verification-missing", [f"prior finding {res_entry.get('finding_id')} reproducer verification invalid: {err}"], [], raw_s)
    ind_ver = security_review_record.get("independent_verification")
    checks = ind_ver.get("checks") if isinstance(ind_ver, dict) else None
    if (not isinstance(ind_ver, dict) or not bool(ind_ver.get("executed")) or not bool(ind_ver.get("ok"))
            or str(ind_ver.get("head_sha") or "") != candidate_sha or not bool(ind_ver.get("security_probe_ok"))
            or not isinstance(checks, list) or not checks):
        return _fail("security-verification-missing", [f"missing or failing independent security verification for candidate {candidate_sha}"], [], raw_s)
    for chk in checks:
        if (err := _verify_log_record(chk, candidate_sha, home)):
            return _fail("security-verification-missing", [f"independent security verification {err}"], [], raw_s)
    if str(security_review_record.get("outcome") or "") != "approved":
        return _fail("security-review-invalid", [f"security review outcome is {security_review_record.get('outcome')!r}, expected 'approved'"], [], raw_s)
    return {"status": "verified", "verified": True, "blockers": [], "blocking_findings": [], "non_blocking_suggestions": raw_s}


try:
    from factory.security_review.delivery import (
        VERIFICATION_SCOPE_SECURITY_NOTE, DeliverSecuritySpec, _format_security_pr_section,
        build_security_repair_prompt, deliver_with_security_review, evaluate_child_pr_with_security_gate,
    )
except ImportError:  # pragma: no cover - standalone Slice 1 before delivery module is added
    DeliverSecuritySpec = None  # type: ignore[assignment,misc]
    deliver_with_security_review = None  # type: ignore[assignment]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="factory-security-review", description="Run child delivery with security review and bounded repair (#22).")
    for flag in ("--verify-file", "--rule", "--forbidden-pattern", "--repo", "--home", "--task", "--reviewer-agy-bin"):
        parser.add_argument(flag, default=None)
    parser.add_argument("--time-limit", default="15m"); parser.add_argument("--agy-bin", default="agy")
    parser.add_argument("--max-repair-rounds", type=int, default=2); parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.verify_file:
            root_dir = Path(args.repo or ".").resolve()
            target = root_dir / args.verify_file
            try:
                if target.is_symlink() or not target.resolve().is_relative_to(root_dir) or not target.is_file():
                    print(f"MISSING_FILE {args.verify_file}"); return 1
            except OSError:
                print(f"MISSING_FILE {args.verify_file}"); return 1
            if args.rule and args.rule not in KNOWN_RULES and not args.forbidden_pattern:
                print(f"UNVERIFIABLE_RULE {args.rule}"); return 1
            try:
                findings = _scan_candidate_files(root_dir, [args.verify_file], "HEAD", 1, rule_filter=args.rule, forbidden_pattern=args.forbidden_pattern)
            except ValueError as exc:
                print(f"INVALID_PATTERN {exc}"); return 1
            print(json.dumps({"file": args.verify_file, "ok": len(findings) == 0, "findings": findings}, indent=2, sort_keys=True) if args.json
                  else (f"VERIFIED_ABSENT {args.verify_file} {args.rule or 'all'}" if not findings else "\n".join(f["evidence"] for f in findings)))
            return 0 if not findings else 1
        if not (args.repo and args.home and args.task):
            parser.error("--repo, --home, and --task are required unless --verify-file is used")
        paths = resolve_paths(args.repo, args.home)
        if deliver_with_security_review is None or DeliverSecuritySpec is None:
            raise FactoryError("security delivery orchestration is not installed in this slice")
        res = deliver_with_security_review(
            paths,
            DeliverSecuritySpec(task_ref=args.task, time_limit_seconds=parse_duration(args.time_limit),
                                agy_bin=args.agy_bin, reviewer_agy_bin=args.reviewer_agy_bin, max_repair_rounds=max(0, args.max_repair_rounds)),
        )
        print(json.dumps(res.to_dict(), indent=2, sort_keys=True) if args.json else f"security-deliver {res.task_gid}: {res.status} (verified={res.verified})")
        return 0 if res.verified else 1
    except FactoryError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
