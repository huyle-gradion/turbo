"""Revision-bound child-PR CI and criterion-evidence gate (Issue #20)."""

from __future__ import annotations

from pathlib import Path
import re
import time
from typing import Any, Callable

from factory import config as config_module, gitio, runner
from factory.ci_selection import (
    DEFAULT_DEPENDENCY_RULES,
    ESSENTIAL_GUARD_TESTS,
    FULL_SUITE_TRIGGER_PATHS,
    PROTECTED_POLICY_PATHS,
    build_required_ci_checks,
    detect_spec_check_conflicts,
    evaluate_spec_check_policy,
    protected_chain_paths,
    select_ci_test_plan,
)
from factory.deliver_checks import (
    AttemptTimeoutError,
    GitHubError,
    KEY_VAL_RE,
    MAX_ARTIFACT_ZIP_BYTES,
    MAX_EVIDENCE_JSON_BYTES,
    RUN_URL_RE,
    _download_zip_bytes,
    _extract_check_run_attempt,
    _extract_wf_run_id,
    _fetch_all_check_runs,
    _fetch_run_evidence_artifacts,
    _fetch_workflow_run,
    _is_allowed_redirect_url,
    _read_bounded_bytes,
    _read_manifest_from_zip,
    _sanitize_url_for_log,
    _select_authoritative_check_run,
    git_timed,
    github_request,
    remaining_seconds,
)
from factory.paths import write_evidence

TRUSTED_CHECK_PRODUCERS = ("github-actions",)
TRUSTED_WORKFLOW_PATHS = (".github/workflows/ci.yml",)
TRUSTED_WORKFLOW_EVENTS = ("pull_request", "push", "workflow_dispatch")
VERIFICATION_SCOPE_NOTE = "ci-and-criterion-only; not independently reviewed, merge-approved, or complete"

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_URL_PREFIXES = ("https://github.com/", "http://127.0.0.1:", "http://localhost:")


def _norm_check_name(raw_name: str, expected_names: set[str]) -> str:
    stripped = raw_name.strip()
    for expected in expected_names:
        if stripped == expected or stripped.endswith(f" / {expected}"):
            return expected
    return stripped


def _norm_wf_path(raw_path: object) -> str:
    return str(raw_path or "").split("@", 1)[0].strip().lstrip("/")


def _protected_chain_paths(conf: config_module.Config | None) -> tuple[str, ...]:
    return protected_chain_paths(conf)


def _verify_tested_revision_in_git(
    repo: Path, base_sha: str, candidate_sha: str, tested_sha: str, pr_number: int, deadline: float, limit_s: int,
) -> tuple[bool, str, str]:
    if not (SHA40_RE.fullmatch(base_sha) and SHA40_RE.fullmatch(candidate_sha) and SHA40_RE.fullmatch(tested_sha)):
        return False, "invalid-sha", "candidate_sha, base_sha, and tested_sha must be 40-char commit SHAs"
    if tested_sha == candidate_sha:
        if gitio.is_ancestor(repo, base_sha, candidate_sha):
            return True, "fast-forward-head", ""
        return False, "non-ancestor-head", f"tested_sha equals candidate_sha ({candidate_sha}), which does not descend from base_sha ({base_sha})"
    if not git_timed(repo, deadline, limit_s, "inspect tested_sha", "cat-file", "-t", tested_sha).ok:
        git_timed(repo, deadline, limit_s, "fetch PR merge ref", "fetch", "-q", "--no-tags", "origin", f"refs/pull/{pr_number}/merge")
    parents_res = git_timed(repo, deadline, limit_s, "verify integration parents", "rev-list", "--parents", "-n", "1", tested_sha)
    if not parents_res.ok:
        return False, "missing-tested-commit", f"cannot resolve tested integration revision {tested_sha} in repository"
    parents = parents_res.output.strip().split()[1:]
    if parents == [base_sha, candidate_sha] or (base_sha in parents and candidate_sha in parents and len(parents) == 2):
        return True, "integration-merge", ""
    return False, "mismatched-integration-parents", f"tested_sha {tested_sha} parents {parents} do not match [base_sha={base_sha}, candidate_sha={candidate_sha}]"


def _verify_policy_revision_in_git(
    repo: Path, base_sha: str, candidate_sha: str, tested_sha: str,
    protected: tuple[str, ...], deadline: float, limit_s: int,
) -> list[str]:
    errors: list[str] = []
    seen_revs: set[str] = set()
    for label, rev in (("candidate_sha", candidate_sha), ("tested_sha", tested_sha)):
        if rev in seen_revs:
            continue
        seen_revs.add(rev)
        if SHA40_RE.fullmatch(rev) and git_timed(repo, deadline, limit_s, f"verify {label}", "cat-file", "-t", rev).ok:
            diff_res = git_timed(repo, deadline, limit_s, f"policy diff {label}", "diff", "--name-only", base_sha, rev, "--", *protected)
            if diff_res.ok and (modified := [ln.strip() for ln in diff_res.output.splitlines() if ln.strip()]):
                errors.append(f"PR-controlled revision {label} ({rev}) modified protected CI/verification chain relative to base_sha ({base_sha}): {modified}")
    return errors


def _format_pr_evidence_body(
    parent: dict[str, Any], child: dict[str, Any], head_branch: str, candidate_sha: str,
    base_branch: str, base_sha: str, tested_sha: str, revision_kind: str, scope_detail: dict[str, Any],
    check_records: list[dict[str, Any]], gate_status: str,
) -> str:
    parent_gid, child_gid = str(parent["gid"]), str(child["gid"])
    crit_lines: list[str] = []
    guard_lines: list[str] = []
    for rec in check_records:
        outcome = str(rec.get("conclusion") or rec.get("status") or "missing").upper()
        line = (
            f"- `{rec['id']}` -> `{rec['name']}`: **{outcome}** "
            f"(run `{rec.get('run_id') or 'none'}`, workflow `{rec.get('workflow_path') or 'unavailable'}`, "
            f"policy `{rec.get('policy_sha') or 'unavailable'}`, candidate `{candidate_sha}`, "
            f"base `{base_sha}`, tested `{rec.get('tested_sha') or 'unavailable'}`) "
            f"[CI Check Log]({rec.get('html_url') or 'unavailable'}) | "
            f"[CI Artifact]({rec.get('artifact_url') or 'unavailable'})"
        )
        if rec["kind"] == "criterion":
            coverage = ", ".join(rec.get("parent_coverage") or []) or "none"
            crit_lines.append(f"{line} (Parent coverage: `{coverage}`)")
        else:
            guard_lines.append(line)
    if gate_status == "verified":
        status_line = f"`verified` for candidate `{candidate_sha}` against base `{base_sha}` (tested `{tested_sha}`, {VERIFICATION_SCOPE_NOTE})"
    else:
        status_line = f"`{gate_status}` (not verified; candidate `{candidate_sha}`, base `{base_sha}`, tested `{tested_sha}`; {VERIFICATION_SCOPE_NOTE})"
    return (
        f"## Summary\n\n{child.get('outcome') or child['name']}\n\n"
        f"## Asana Links\n- Parent task: https://app.asana.com/0/0/{parent_gid} (`{parent_gid}`)\n"
        f"- Sub-task: https://app.asana.com/0/0/{child_gid} (`{child_gid}`)\n\n"
        f"## Revision & Provenance\n- Candidate revision: `{candidate_sha}`\n"
        f"- Base/Policy revision (`{base_branch}`): `{base_sha}`\n"
        f"- Tested revision (`{revision_kind}`): `{tested_sha}`\n"
        f"- Head branch: `{head_branch}`\n"
        f"- CI gate status: {status_line}\n"
        f"- Scope check: `{scope_detail.get('status')}` ({scope_detail.get('provenance')})\n\n"
        f"## Criterion-to-Check CI Evidence\n" + ("\n".join(crit_lines) or "- None")
        + "\n\n## Required Guards CI Evidence\n" + ("\n".join(guard_lines) or "- None") + "\n"
    )


def _build_observed_check_records(
    required: list[dict[str, Any]], selected_by_name: dict[str, dict[str, Any]],
    untrusted_by_name: dict[str, dict[str, Any]], rerun_metadata: dict[str, dict[str, Any]],
    wf_by_check: dict[str, int], wf_cache: dict[int, dict[str, Any]], candidate_sha: str, base_sha: str,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for req in required:
        rname = req["name"]
        cr = selected_by_name.get(rname) or untrusted_by_name.get(rname) or {}
        wf_id = wf_by_check.get(rname) or _extract_wf_run_id(cr)
        wf_path = _norm_wf_path(wf_cache.get(wf_id or 0, {}).get("path")) if wf_id else ""
        default_reruns = {"run_count": 1 if cr else 0, "selected_run_id": cr.get("id"), "superseded_run_ids": []}
        records.append({
            **req, "run_id": cr.get("id"), "workflow_run_id": wf_id, "workflow_path": wf_path or None,
            "policy_sha": None, "artifact_id": None,
            "producer": str((cr.get("app") if isinstance(cr.get("app"), dict) else {}).get("slug") or ""),
            "status": str(cr.get("status") or "missing"), "conclusion": str(cr.get("conclusion") or ""),
            "candidate_sha": str(cr.get("head_sha") or candidate_sha), "base_sha": base_sha,
            "tested_sha": None, "revision_kind": None,
            "html_url": str(cr.get("html_url") or cr.get("details_url") or "") or None,
            "artifact_url": None, "output_path": None, "output_sha256": None,
            "reruns": rerun_metadata.get(rname, default_reruns),
        })
    return records


def evaluate_child_pr_ci_gate(
    *, repo: Path, home: Path, child_dir: Path, base_url: str, token: str, repo_slug: str,
    parent: dict[str, Any], child: dict[str, Any], conf: config_module.Config, pr_info: dict[str, Any],
    head_branch: str, candidate_sha: str, base_branch: str, base_sha: str, scope_detail: dict[str, Any],
    trace: list[dict[str, Any]], deadline: float, limit_s: int, changed_paths: tuple[str, ...] = (),
    deleted_paths: tuple[str, ...] = (), trusted_producers: tuple[str, ...] = TRUSTED_CHECK_PRODUCERS,
    trusted_workflows: tuple[str, ...] = TRUSTED_WORKFLOW_PATHS, poll_interval_s: float = 1.0,
    max_missing_polls: int = 15, max_polls: int | None = None, artifact_retry_delay_s: float = 2.0,
    sleep_fn: Callable[[float], None] = time.sleep, cancel_superseded: bool = False,
) -> dict[str, Any]:
    required = build_required_ci_checks(child, conf)
    selection_plan = select_ci_test_plan(child, conf, changed_paths, deleted_paths=deleted_paths)
    protected_chain = _protected_chain_paths(conf)
    expected_names = {item["name"] for item in required}
    pr_number, missing_polls, polls = int(pr_info["number"]), 0, 0
    raw_runs: list[dict[str, Any]] = []
    untrusted_hits: list[str] = []
    aggregate_runs: list[dict[str, Any]] = []
    trusted_by_name: dict[str, list[dict[str, Any]]] = {name: [] for name in expected_names}
    untrusted_by_name: dict[str, dict[str, Any]] = {}

    while True:
        try:
            raw_runs = _fetch_all_check_runs(base_url, token, repo_slug, candidate_sha, trace, deadline, limit_s)
        except AttemptTimeoutError:
            break
        polls += 1
        trusted_by_name = {name: [] for name in expected_names}
        untrusted_by_name = {}
        untrusted_hits = []
        aggregate_runs = []
        for cr in raw_runs:
            norm_name = _norm_check_name(str(cr.get("name") or ""), expected_names)
            if norm_name == "turbo/child-gate" or norm_name.startswith("turbo/"):
                aggregate_runs.append({"id": cr.get("id"), "name": norm_name, "kind": "turbo-aggregate"})
            elif norm_name in expected_names:
                app_obj = cr.get("app") if isinstance(cr.get("app"), dict) else {}
                producer = str(app_obj.get("slug") or "").strip()
                if producer not in trusted_producers:
                    untrusted_by_name[norm_name] = cr
                    untrusted_hits.append(f"required check {norm_name!r} (run {cr.get('id')}) came from untrusted producer {producer!r}")
                else:
                    trusted_by_name[norm_name].append(cr)
        any_pending = False
        any_missing = False
        for req in required:
            runs = trusted_by_name[req["name"]]
            if not runs:
                any_missing = True
            elif any(str(r.get("status") or "") != "completed" for r in runs):
                any_pending = True
        if not any_pending and (not any_missing or untrusted_hits):
            break
        if not any_pending and any_missing and raw_runs:
            missing_polls += 1
            if missing_polls >= max_missing_polls:
                break
        if max_polls is not None and polls >= max_polls:
            break
        if time.monotonic() + poll_interval_s >= deadline:
            break
        sleep_fn(min(poll_interval_s, max(0.01, deadline - time.monotonic())))

    wf_cache: dict[int, dict[str, Any]] = {}
    run_attempts_by_id: dict[int, int] = {}
    wf_by_check: dict[str, int] = {}
    superseded_wf_runs: set[int] = set()
    selected_by_name: dict[str, dict[str, Any]] = {}
    rerun_metadata: dict[str, dict[str, Any]] = {}
    pending_names, missing_names, skipped_names, failed_names, ordering_issues = [], [], [], [], []
    post_poll_timed_out = False

    for req in required:
        rname = req["name"]
        runs = trusted_by_name.get(rname) or []
        if not runs:
            missing_names.append(rname)
            continue
        try:
            selected, sup_runs, sup_wf_ids, ord_err = _select_authoritative_check_run(
                rname, runs, base_url, token, repo_slug, wf_cache, trace, deadline, limit_s,
            )
        except AttemptTimeoutError:
            non_comp = [r for r in runs if str(r.get("status") or "") != "completed"]
            selected = non_comp[-1] if non_comp else runs[-1]
            sup_runs = [r for r in runs if r is not selected]
            sup_wf_ids, ord_err, post_poll_timed_out = set(), None, True
        if ord_err is not None:
            ordering_issues.append(ord_err)
        if selected is None:
            missing_names.append(rname)
            continue
        selected_by_name[rname] = selected
        superseded_wf_runs.update(sup_wf_ids)
        for old_r in sup_runs:
            old_wf_id = _extract_wf_run_id(old_r)
            if old_wf_id is not None and str(old_r.get("status") or "") != "completed":
                superseded_wf_runs.add(old_wf_id)
        rerun_metadata[rname] = {
            "run_count": len(runs), "selected_run_id": selected.get("id"),
            "superseded_run_ids": [r.get("id") for r in sup_runs],
        }
        wf_id = _extract_wf_run_id(selected)
        if wf_id is not None:
            wf_by_check[rname] = wf_id
        st = str(selected.get("status") or "")
        conc = str(selected.get("conclusion") or "") if selected.get("conclusion") is not None else ""
        if st != "completed":
            pending_names.append(rname)
        elif conc in ("skipped", "neutral", "cancelled"):
            skipped_names.append(f"{rname} ({conc})")
        elif conc != "success":
            failed_names.append(f"{rname} ({conc or 'unknown'})")

    def _early_return(status: str, blockers: list[str], cancelled_runs: list[int] | None = None) -> dict[str, Any]:
        obs_checks = _build_observed_check_records(
            required, selected_by_name, untrusted_by_name, rerun_metadata, wf_by_check, wf_cache, candidate_sha, base_sha,
        )
        return {
            "status": status, "verified": False, "verification_scope": VERIFICATION_SCOPE_NOTE,
            "candidate_sha": candidate_sha, "base_sha": base_sha, "policy_sha": None,
            "tested_sha": None, "revision_kind": None,
            "trusted_producers": list(trusted_producers), "trusted_workflows": list(trusted_workflows),
            "selection_plan": selection_plan, "cancelled_workflow_runs": cancelled_runs or [],
            "checks": obs_checks, "aggregate_checks": aggregate_runs, "blockers": blockers,
            "pr": {**pr_info, "pr_confirmed": bool(pr_info.get("pr_confirmed", True)), "ci_verified": False, "verified": False},
        }

    if untrusted_hits:
        return _early_return("ci-untrusted-producer", list(dict.fromkeys(untrusted_hits)))

    cancelled_runs: list[int] = []
    if cancel_superseded:
        for sup_run_id in sorted(superseded_wf_runs - set(wf_by_check.values())):
            try:
                sup_wf = _fetch_workflow_run(base_url, token, repo_slug, sup_run_id, wf_cache, trace, deadline, limit_s)
                sup_path = _norm_wf_path(sup_wf.get("path"))
                sup_branch = str(sup_wf.get("head_branch") or "").strip()
                sup_ev = str(sup_wf.get("event") or "").strip()
                sup_prs = [int(p.get("number") or 0) for p in (sup_wf.get("pull_requests") or []) if isinstance(p, dict) and int(p.get("number") or 0) > 0]
                if sup_path in trusted_workflows and sup_ev == "pull_request" and sup_branch == head_branch and sup_prs == [pr_number]:
                    github_request("POST", f"{base_url}/repos/{repo_slug}/actions/runs/{sup_run_id}/cancel", token, base_url, trace, deadline, limit_s, {})
                    cancelled_runs.append(sup_run_id)
            except (GitHubError, AttemptTimeoutError):
                pass

    if post_poll_timed_out or pending_names or (missing_names and not raw_runs):
        pending_list = pending_names or missing_names or [req["name"] for req in required]
        return _early_return("ci-pending", [f"CI checks still pending when time allowance expired: {', '.join(pending_list)}"], cancelled_runs)
    if missing_names:
        return _early_return("ci-missing", [f"missing required CI checks on {candidate_sha}: {', '.join(missing_names)}"], cancelled_runs)

    try:
        for rname, wf_id in wf_by_check.items():
            wf_info = _fetch_workflow_run(base_url, token, repo_slug, wf_id, wf_cache, trace, deadline, limit_s)
            run_attempts_by_id[wf_id] = _extract_check_run_attempt(selected_by_name[rname], wf_info) or 1
            wf_path = _norm_wf_path(wf_info.get("path"))
            wf_event = str(wf_info.get("event") or "").strip()
            wf_head = str(wf_info.get("head_sha") or "").strip()
            if not wf_path or wf_path not in trusted_workflows:
                untrusted_hits.append(f"required check {rname!r} (workflow run {wf_id}) ran from untrusted or missing workflow {wf_path!r}; expected {list(trusted_workflows)}")
            if not wf_event or wf_event not in TRUSTED_WORKFLOW_EVENTS:
                untrusted_hits.append(f"required check {rname!r} (workflow run {wf_id}) triggered by untrusted or missing event {wf_event!r}")
            if not wf_head or wf_head != candidate_sha:
                untrusted_hits.append(f"workflow run {wf_id} head_sha {wf_head!r} does not match candidate_sha {candidate_sha!r}")

        artifact_checks, artifact_issues = _fetch_run_evidence_artifacts(
            base_url, token, repo_slug, run_attempts_by_id, trace, deadline, limit_s,
        )
        if artifact_retry_delay_s > 0 and (artifact_issues or len(artifact_checks) < len(required)) and time.monotonic() + artifact_retry_delay_s < deadline:
            sleep_fn(artifact_retry_delay_s)
            artifact_checks, artifact_issues = _fetch_run_evidence_artifacts(
                base_url, token, repo_slug, run_attempts_by_id, trace, deadline, limit_s,
            )
    except AttemptTimeoutError as exc:
        return _early_return("ci-pending", [f"CI checks still pending when time allowance expired: {exc}"], cancelled_runs)

    evidence_issues: list[str] = [*ordering_issues, *artifact_issues]
    check_records: list[dict[str, Any]] = []
    observed_tested_shas: set[str] = set()
    observed_rev_kinds: set[str] = set()
    observed_policy_shas: set[str] = set()
    git_rev_cache: dict[str, tuple[bool, str, str, list[str]]] = {}

    for req in required:
        rname = req["name"]
        cr = selected_by_name[rname]
        wf_id = wf_by_check.get(rname)
        wf_path = _norm_wf_path(wf_cache.get(wf_id or 0, {}).get("path"))
        art_rec = artifact_checks.get(rname) or {}
        if not art_rec:
            evidence_issues.append(f"missing CI artifact evidence entry for required check {rname!r}")
        elif wf_id is not None and art_rec.get("run_id") != wf_id:
            evidence_issues.append(f"check {rname!r} artifact run_id {art_rec.get('run_id')} does not match selected workflow run {wf_id}")
        art_wf = _norm_wf_path(art_rec.get("workflow_path"))
        if not art_wf:
            evidence_issues.append(f"check {rname!r} artifact is missing workflow_path provenance")
        elif art_wf not in trusted_workflows:
            untrusted_hits.append(f"artifact for {rname!r} came from untrusted workflow {art_wf!r}")
        elif wf_path and art_wf != wf_path:
            evidence_issues.append(f"check {rname!r} artifact workflow_path {art_wf!r} != workflow run path {wf_path!r}")
        art_pol = str(art_rec.get("policy_sha") or "").strip()
        if not art_pol:
            evidence_issues.append(f"check {rname!r} artifact is missing policy_sha provenance")
        elif art_pol != base_sha:
            untrusted_hits.append(f"check {rname!r} policy_sha {art_pol!r} does not match trusted base policy revision {base_sha!r}")
        else:
            observed_policy_shas.add(art_pol)
        if bool(art_rec.get("cached_result")) or (art_rec.get("cached_from_sha") and art_rec.get("cached_from_sha") != candidate_sha):
            evidence_issues.append(f"check {rname!r} reused cached verification results across revisions (forbidden by CI policy)")
        obs_head = str(cr.get("head_sha") or "").strip()
        prov_cand = str(art_rec.get("candidate_sha") or "").strip()
        prov_base = str(art_rec.get("base_sha") or "").strip()
        prov_tested = str(art_rec.get("tested_sha") or "").strip()
        prov_rev_kind = str(art_rec.get("revision_kind") or "").strip()
        html_url = str(cr.get("html_url") or cr.get("details_url") or "").strip()
        artifact_url = str(art_rec.get("artifact_url") or "").strip()
        raw_log = str(art_rec.get("log_text") or "").strip()
        cr_conc = str(cr.get("conclusion") or "").strip()
        art_conc = str(art_rec.get("conclusion") or "").strip()
        art_exit = art_rec.get("exit_code")
        if obs_head != candidate_sha or prov_cand != candidate_sha:
            evidence_issues.append(f"check {rname!r} candidate_sha mismatch: expected {candidate_sha!r}, got head={obs_head!r} artifact={prov_cand!r}")
        if prov_base != base_sha:
            evidence_issues.append(f"check {rname!r} base_sha mismatch: expected {base_sha!r}, got {prov_base!r}")
        if cr_conc == "success":
            if isinstance(art_exit, bool) or not isinstance(art_exit, int) or art_exit != 0 or art_conc != "success":
                evidence_issues.append(f"check {rname!r} artifact lacks successful execution evidence (exit_code={art_exit!r}, conclusion={art_conc!r})")
        if not html_url.startswith(_URL_PREFIXES):
            evidence_issues.append(f"check {rname!r} is missing an accessible GitHub CI log URL: {html_url!r}")
        if not artifact_url.startswith(_URL_PREFIXES):
            evidence_issues.append(f"check {rname!r} is missing an accessible GitHub CI artifact URL: {artifact_url!r}")
        ev_path = write_evidence(child_dir, f"ci-{rname.replace('/', '-').lower()}", raw_log + "\n", home) if raw_log else None
        if not raw_log:
            evidence_issues.append(f"check {rname!r} is missing raw CI execution output in artifact")
        if prov_tested:
            if prov_tested not in git_rev_cache:
                try:
                    ok_git, r_kind, g_err = _verify_tested_revision_in_git(repo, base_sha, candidate_sha, prov_tested, pr_number, deadline, limit_s)
                    pol_errs = _verify_policy_revision_in_git(repo, base_sha, candidate_sha, prov_tested, protected_chain, deadline, limit_s) if ok_git else []
                except AttemptTimeoutError as exc:
                    return _early_return("ci-pending", [f"CI checks still pending when time allowance expired: {exc}"], cancelled_runs)
                git_rev_cache[prov_tested] = (ok_git, r_kind, g_err, pol_errs)
            ok_git, rev_kind, git_err, policy_errs = git_rev_cache[prov_tested]
            if not ok_git:
                evidence_issues.append(f"check {rname!r} invalid tested revision {prov_tested!r}: {git_err}")
            else:
                if prov_rev_kind and prov_rev_kind != rev_kind:
                    evidence_issues.append(f"check {rname!r} artifact revision_kind {prov_rev_kind!r} does not match git-verified {rev_kind!r}")
                observed_tested_shas.add(prov_tested)
                observed_rev_kinds.add(rev_kind)
                untrusted_hits.extend(policy_errs)
        else:
            evidence_issues.append(f"check {rname!r} is missing tested_sha provenance")
            rev_kind = "unavailable"
        check_records.append({
            **req, "run_id": cr.get("id"), "workflow_run_id": wf_id or art_rec.get("run_id"),
            "run_attempt": art_rec.get("run_attempt"), "workflow_path": art_wf or wf_path or None,
            "policy_sha": art_pol or None, "artifact_id": art_rec.get("artifact_id"),
            "producer": str((cr.get("app") if isinstance(cr.get("app"), dict) else {}).get("slug") or ""),
            "status": str(cr.get("status") or ""), "conclusion": cr_conc,
            "candidate_sha": prov_cand or None, "base_sha": prov_base or None,
            "tested_sha": prov_tested or None, "revision_kind": rev_kind,
            "html_url": html_url, "artifact_url": artifact_url,
            "output_path": str(ev_path) if ev_path else None,
            "output_sha256": runner.digest_text(raw_log + "\n") if raw_log else None,
            "reruns": rerun_metadata[rname],
        })

    if untrusted_hits:
        return {
            "status": "ci-untrusted-producer", "verified": False, "verification_scope": VERIFICATION_SCOPE_NOTE,
            "candidate_sha": candidate_sha, "base_sha": base_sha, "policy_sha": None,
            "tested_sha": None, "revision_kind": None,
            "trusted_producers": list(trusted_producers), "trusted_workflows": list(trusted_workflows),
            "selection_plan": selection_plan, "cancelled_workflow_runs": cancelled_runs,
            "checks": check_records, "aggregate_checks": aggregate_runs,
            "blockers": list(dict.fromkeys(untrusted_hits)),
            "pr": {**pr_info, "pr_confirmed": bool(pr_info.get("pr_confirmed", True)), "ci_verified": False, "verified": False},
        }

    if len(observed_tested_shas) > 1:
        evidence_issues.append(f"inconsistent tested_sha across required checks: {sorted(observed_tested_shas)}")
    tested_sha_final = next(iter(observed_tested_shas)) if len(observed_tested_shas) == 1 else "unavailable"
    rev_kind_final = next(iter(observed_rev_kinds)) if len(observed_rev_kinds) == 1 else "unavailable"
    policy_sha_final = next(iter(observed_policy_shas)) if len(observed_policy_shas) == 1 else None

    try:
        _, pre_stale_reasons = _check_pr_revision_drift(
            repo, base_url, token, repo_slug, pr_number, head_branch, candidate_sha, base_branch, base_sha, trace, deadline, limit_s,
        )
        if pre_stale_reasons:
            gate_status, blockers = "stale-revision", pre_stale_reasons
        elif skipped_names:
            gate_status, blockers = "ci-skipped", [f"required CI checks were skipped or neutral: {', '.join(skipped_names)}"]
        elif failed_names:
            gate_status, blockers = "ci-failed", [f"required CI checks failed: {', '.join(failed_names)}"]
        elif evidence_issues:
            gate_status, blockers = "ci-evidence-invalid", evidence_issues
        else:
            gate_status, blockers = "verified", []

        updated_body = _format_pr_evidence_body(
            parent, child, head_branch, candidate_sha, base_branch, base_sha,
            tested_sha_final, rev_kind_final, scope_detail, check_records, gate_status,
        )
        github_request("PATCH", f"{base_url}/repos/{repo_slug}/pulls/{pr_number}", token, base_url, trace, deadline, limit_s, {"body": updated_body})
        live_fields, post_stale_reasons = _check_pr_revision_drift(
            repo, base_url, token, repo_slug, pr_number, head_branch, candidate_sha, base_branch, base_sha, trace, deadline, limit_s,
        )
        r_body = live_fields["body"]
        for req in required:
            if req["name"] not in r_body or candidate_sha not in r_body or base_sha not in r_body:
                evidence_issues.append(f"PR #{pr_number} body is missing inspectable criterion-to-check evidence for {req['name']}")
        if post_stale_reasons:
            if gate_status != "stale-revision":
                gate_status = "stale-revision"
                blockers = post_stale_reasons
                invalidated_body = _format_pr_evidence_body(
                    parent, child, head_branch, candidate_sha, base_branch, base_sha,
                    tested_sha_final, rev_kind_final, scope_detail, check_records, "stale-revision",
                )
                github_request("PATCH", f"{base_url}/repos/{repo_slug}/pulls/{pr_number}", token, base_url, trace, deadline, limit_s, {"body": invalidated_body})
                live_fields["body"] = invalidated_body
            else:
                blockers = post_stale_reasons
        elif gate_status == "verified" and evidence_issues:
            gate_status, blockers = "ci-evidence-invalid", evidence_issues
    except AttemptTimeoutError as exc:
        return _early_return("ci-pending", [f"CI checks still pending when time allowance expired: {exc}"], cancelled_runs)

    is_verified = gate_status == "verified"
    pr_confirmed_ok = bool(pr_info.get("pr_confirmed", True)) and gate_status != "stale-revision"
    return {
        "status": gate_status, "verified": is_verified, "verification_scope": VERIFICATION_SCOPE_NOTE,
        "candidate_sha": candidate_sha, "base_sha": base_sha, "policy_sha": policy_sha_final,
        "tested_sha": tested_sha_final, "revision_kind": rev_kind_final,
        "trusted_producers": list(trusted_producers), "trusted_workflows": list(trusted_workflows),
        "selection_plan": selection_plan, "cancelled_workflow_runs": cancelled_runs,
        "checks": check_records, "aggregate_checks": aggregate_runs, "blockers": blockers,
        "pr": {**pr_info, **live_fields, "pr_confirmed": pr_confirmed_ok, "ci_verified": is_verified, "verified": is_verified},
    }


def _check_pr_revision_drift(
    repo: Path, base_url: str, token: str, repo_slug: str, pr_number: int,
    head_branch: str, candidate_sha: str, base_branch: str, base_sha: str,
    trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> tuple[dict[str, Any], list[str]]:
    fetch_res = git_timed(repo, deadline, limit_s, "recheck origin refs", "fetch", "origin")
    remote_base, remote_head = gitio.remote_ref(repo, base_branch), gitio.remote_ref(repo, head_branch)
    live_pr = github_request("GET", f"{base_url}/repos/{repo_slug}/pulls/{pr_number}", token, base_url, trace, deadline, limit_s)
    head_obj = live_pr.get("head") if isinstance(live_pr.get("head"), dict) else {}
    base_obj = live_pr.get("base") if isinstance(live_pr.get("base"), dict) else {}
    r_head_sha, r_base_sha = str(head_obj.get("sha") or "").strip(), str(base_obj.get("sha") or "").strip()
    r_head_ref, r_base_ref = str(head_obj.get("ref") or "").strip(), str(base_obj.get("ref") or "").strip()
    r_state, r_merged, r_body = str(live_pr.get("state") or ""), bool(live_pr.get("merged")), str(live_pr.get("body") or "")
    reasons: list[str] = []
    if not fetch_res.ok:
        reasons.append(f"failed to fetch origin during revision recheck: {fetch_res.output}")
    if r_state != "open" or r_merged:
        reasons.append(f"PR #{pr_number} is no longer open and unmerged (state={r_state!r}, merged={r_merged})")
    if r_head_sha != candidate_sha or (remote_head is not None and remote_head != candidate_sha):
        reasons.append(f"PR head revision changed during verification: expected {candidate_sha}, got PR={r_head_sha} origin={remote_head}")
    if r_base_sha != base_sha or (remote_base is not None and remote_base != base_sha):
        reasons.append(f"PR base revision on {base_branch} changed during verification: expected {base_sha}, got PR={r_base_sha} origin={remote_base}")
    if (head_branch and r_head_ref != head_branch) or (base_branch and r_base_ref != base_branch):
        reasons.append(f"PR branch refs changed during verification: expected {head_branch}->{base_branch}, got {r_head_ref}->{r_base_ref}")
    return {
        "body": r_body, "state": r_state, "merged": r_merged,
        "base_ref": r_base_ref, "base_sha": r_base_sha, "head_ref": r_head_ref, "head_sha": r_head_sha,
    }, reasons


def revalidate_child_verification(
    *, repo: Path, base_url: str, token: str, repo_slug: str,
    child_record: dict[str, Any], trace: list[dict[str, Any]], deadline: float, limit_s: int,
) -> dict[str, Any]:
    if not child_record.get("verified") or child_record.get("status") != "verified":
        return {"status": str(child_record.get("status") or "unverified"), "verified": False, "blockers": ["child does not hold verified status"]}
    pr = child_record.get("pr") if isinstance(child_record.get("pr"), dict) else {}
    ci_ver = child_record.get("ci_verification") if isinstance(child_record.get("ci_verification"), dict) else {}
    pr_number = int(pr.get("number") or 0)
    candidate_sha, base_sha = str(child_record.get("candidate_sha") or ""), str(child_record.get("base_sha") or "")
    head_branch, base_branch = str(child_record.get("head_branch") or ""), str(child_record.get("base_branch") or "")
    if pr_number <= 0 or not SHA40_RE.fullmatch(candidate_sha) or not SHA40_RE.fullmatch(base_sha):
        return {"status": "stale-revision", "verified": False, "blockers": ["incomplete revision binding on child record"]}
    if ci_ver.get("candidate_sha") != candidate_sha or ci_ver.get("base_sha") != base_sha:
        return {"status": "stale-revision", "verified": False, "blockers": ["recorded CI verification does not match child revisions"]}
    _, reasons = _check_pr_revision_drift(
        repo, base_url, token, repo_slug, pr_number, head_branch, candidate_sha, base_branch, base_sha, trace, deadline, limit_s,
    )
    return {"status": "stale-revision" if reasons else "verified", "verified": not reasons, "blockers": reasons}
