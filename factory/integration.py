"""Protected child-integration ownership and revision safety (#65)."""
from __future__ import annotations

from dataclasses import dataclass, field
import json, time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, build_opener

from factory import config as config_module, gitio
from factory.ci_gate import SHA40_RE
from factory.deliver_checks import (
    AttemptTimeoutError, collect_redaction_secrets, git_timed, parse_repo_slug,
    remaining_seconds, resolve_github_api, resolve_github_token, verify_origin_remote,
)
from factory.independent_review import approval as approval_mod
from factory.intake import NoRedirectHandler, same_api_origin
from factory.paths import atomic_json, read_json

FACTORY_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class IntegrationResult:
    status: str
    outcome: str
    landed_sha: str | None
    repo_slug: str
    pr_number: int
    candidate_sha: str
    base_sha: str
    head_branch: str
    base_branch: str
    blockers: list[str] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    protection_observed: dict[str, Any] = field(default_factory=dict)
    record_path: str | None = None
    request_path: str | None = None
    factory_revision: str = "unavailable"
    approval_status: str | None = None
    mutation_outcome: str | None = None
    confirmation_status: str | None = None
    tested_sha: str | None = None
    reconciled: bool = False


def _factory_rev() -> str:
    res = gitio.git(FACTORY_ROOT, "rev-parse", "HEAD")
    return res.output.strip() if res.ok and SHA40_RE.fullmatch(res.output.strip()) else "unavailable"


def _http_req(
    method: str, url: str, token: str, base_url: str, trace: list[dict[str, Any]],
    dl: float, limit_s: int, payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], str]:
    rem = remaining_seconds(dl, "GitHub API integration request", limit_s)
    target_parsed = urlparse(url)
    if not same_api_origin(url, base_url):
        trace.append({"method": method, "url": url, "status": "blocked-origin"})
        return 0, {}, "refused to send credentials to untrusted destination"
    if not token:
        trace.append({"method": method, "url": url, "status": "missing-token"})
        return 0, {}, "missing GitHub authentication token"
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"}
    req = Request(url, data=json.dumps(payload).encode("utf-8") if payload is not None else None, headers=headers, method=method)
    try:
        with build_opener(NoRedirectHandler).open(req, timeout=min(15.0, rem)) as resp:
            code, body = getattr(resp, "status", 200), resp.read().decode("utf-8", "replace")
    except HTTPError as exc:
        trace.append({"method": method, "url": url, "status": exc.code})
        raw = exc.read().decode("utf-8", "replace") if hasattr(exc, "read") else ""
        exc.close()
        try: parsed = json.loads(raw) if raw else {}
        except Exception: parsed = {}
        return exc.code, parsed, str(parsed.get("message") or exc.reason or f"HTTP {exc.code}")
    except (TimeoutError, URLError, OSError) as exc:
        is_t = isinstance(exc, TimeoutError) or time.monotonic() >= dl or isinstance(getattr(exc, "reason", None), TimeoutError)
        trace.append({"method": method, "url": url, "status": "timeout" if is_t else "network-error"})
        if is_t: raise AttemptTimeoutError(f"timed out during GitHub API request after {limit_s}s") from exc
        return 0, {}, f"network error on {target_parsed.path}: {exc}"
    trace.append({"method": method, "url": url, "status": code})
    try: parsed = json.loads(body)
    except Exception: parsed = {}
    return code, parsed if isinstance(parsed, dict) else {}, ""


def _confirm_landing(
    *, repo: Path, eff_base_url: str, eff_token: str, repo_slug: str, pr_number: int,
    candidate_sha: str, base_sha: str, tested_sha: str | None, head_branch: str, base_branch: str,
    merge_method: str, trace: list[dict[str, Any]], dl: float, limit_s: int,
) -> tuple[bool, str, str, str | None]:
    code, pr_data, err_msg = _http_req(
        "GET", f"{eff_base_url}/repos/{repo_slug}/pulls/{pr_number}",
        eff_token, eff_base_url, trace, dl, limit_s,
    )
    if code != 200 or not pr_data:
        st = "denied-permissions" if code in (401, 403) else ("pr-not-found" if code == 404 else "provider-error")
        return False, st, f"authoritative PR verification failed: {err_msg or f'HTTP {code}'}", None

    if pr_data.get("state") != "closed" or pr_data.get("merged") is not True:
        return False, "misleading-merge-response", f"PR #{pr_number} is not closed and merged (state={pr_data.get('state')!r}, merged={pr_data.get('merged')})", None

    head_obj, base_obj = pr_data.get("head") or {}, pr_data.get("base") or {}
    r_head_sha = str(head_obj.get("sha") or "").strip()
    r_head_ref, r_base_ref = str(head_obj.get("ref") or "").strip(), str(base_obj.get("ref") or "").strip()
    r_head_repo = str((head_obj.get("repo") or {}).get("full_name") or "").strip()
    r_base_repo = str((base_obj.get("repo") or {}).get("full_name") or "").strip()

    if r_head_repo.lower() != repo_slug.lower() or r_base_repo.lower() != repo_slug.lower():
        return False, "repo-slug-mismatch", f"PR #{pr_number} repository ({r_head_repo}/{r_base_repo}) does not match {repo_slug!r}", None
    if r_head_ref != head_branch or r_base_ref != base_branch:
        return False, "branch-ref-mismatch", f"PR #{pr_number} refs ({r_head_ref}->{r_base_ref}) do not match expected ({head_branch}->{base_branch})", None
    if r_head_sha != candidate_sha:
        return False, "stale-candidate-revision", f"PR #{pr_number} head SHA {r_head_sha} does not match candidate {candidate_sha}", None
    if base_branch in ("main", "master") or not base_branch.startswith("feature/"):
        return False, "unintended-target", f"PR #{pr_number} target branch {base_branch!r} is invalid", None

    landed_sha = str(pr_data.get("merge_commit_sha") or "").strip()
    if not (landed_sha and SHA40_RE.fullmatch(landed_sha)):
        return False, "invalid-landed-sha", f"PR #{pr_number} merge_commit_sha {landed_sha!r} is missing or invalid", None

    fetch_res = git_timed(repo, dl, limit_s, "git fetch origin", "fetch", "origin")
    if not fetch_res.ok:
        return False, "remote-git-drift", f"git fetch origin failed during confirmation: {fetch_res.output}", None

    cat_res = git_timed(repo, dl, limit_s, "inspect landed commit", "cat-file", "-t", landed_sha)
    if not cat_res.ok or cat_res.output.strip() != "commit":
        return False, "missing-landed-commit", f"landed commit {landed_sha} not found in repository", None

    if merge_method != "merge":
        return False, "unsupported-merge-method", f"unsupported integration method: {merge_method!r}; only 'merge' is supported", None

    parents_res = git_timed(repo, dl, limit_s, "verify landed parents", "rev-list", "--parents", "-n", "1", landed_sha)
    if not parents_res.ok:
        return False, "missing-landed-commit", f"failed to resolve landed commit parents: {parents_res.output}", None
    parents = parents_res.output.strip().split()[1:]
    if parents != [base_sha, candidate_sha]:
        return False, "invalid-landing-relationship", f"landed commit {landed_sha} parents {parents} do not match [base_sha={base_sha}, candidate_sha={candidate_sha}]", None

    if not (tested_sha and tested_sha.strip()):
        return False, "unverifiable-landing-relationship", "missing tested_sha for landing proof", None

    if not git_timed(repo, dl, limit_s, "inspect tested_sha", "cat-file", "-t", tested_sha).ok:
        git_timed(repo, dl, limit_s, "fetch PR merge ref", "fetch", "-q", "--no-tags", "origin", f"refs/pull/{pr_number}/merge")
    landed_tree_res = git_timed(repo, dl, limit_s, "landed tree", "rev-parse", f"{landed_sha}^{{tree}}")
    tested_tree_res = git_timed(repo, dl, limit_s, "tested tree", "rev-parse", f"{tested_sha}^{{tree}}")
    if not (landed_tree_res.ok and tested_tree_res.ok):
        return False, "tree-resolution-failed", "failed to resolve landed or tested tree in git", None
    if landed_tree_res.output.strip() != tested_tree_res.output.strip():
        return False, "invalid-landing-relationship", f"landed tree {landed_tree_res.output.strip()} does not match tested tree {tested_tree_res.output.strip()}", None

    rem_base = gitio.remote_ref(repo, base_branch)
    if not rem_base or not SHA40_RE.fullmatch(rem_base):
        return False, "missing-remote-base", f"remote origin/{base_branch} not found", None
    if not gitio.is_ancestor(repo, landed_sha, rem_base):
        return False, "landed-commit-not-on-base", f"landed commit {landed_sha} is not an ancestor of origin/{base_branch} ({rem_base})", None

    return True, "confirmed", "", landed_sha


def integrate_approved_child(
    *, repo: Path, home: Path, child_dir: Path, child: dict[str, Any], conf: config_module.Config | None = None,
    pr_number: int, candidate_sha: str, base_sha: str, head_branch: str, base_branch: str,
    approval_record: Any = None, ci_record: Any = None, qa_record: Any = None, security_record: Any = None,
    review_record: Any = None, repo_slug: str | None = None, base_url: str | None = None, token: str | None = None,
    merge_method: str = "merge", commit_title: str | None = None, commit_message: str | None = None,
    on_before_merge: Callable[[], None] | None = None, deadline: float | None = None, limit_s: int = 30,
) -> IntegrationResult:
    secrets: list[str] = list(collect_redaction_secrets())
    if token:
        for t in (token, quote(token, safe="")):
            if t and t not in secrets: secrets.append(t)
    trace, blockers, prot_obs = [], [], {}
    f_rev, dl = _factory_rev(), deadline or (time.monotonic() + float(limit_s))
    ap_status = "unverified"
    mut_outcome = "not-attempted"
    conf_status = "not-attempted"
    tested_sha_val: str | None = None
    is_reconciled = False

    def _make(st: str, out: str, landed: str | None = None, req_p: str | None = None, rec_p: str | None = None) -> IntegrationResult:
        return IntegrationResult(
            st, out, landed, repo_slug or "", pr_number, candidate_sha, base_sha, head_branch, base_branch,
            list(blockers), trace, prot_obs, rec_p, req_p, f_rev,
            approval_status=ap_status, mutation_outcome=mut_outcome,
            confirmation_status=conf_status, tested_sha=tested_sha_val, reconciled=is_reconciled,
        )

    def _fail(st: str, msg: str | list[str], *, req_p: str | None = None, persist_result: bool = True) -> IntegrationResult:
        nonlocal conf_status
        conf_status = conf_status if conf_status != "not-attempted" else "unconfirmed"
        blockers.extend(msg if isinstance(msg, list) else [msg])
        rec_path: str | None = None
        if persist_result and child_dir.exists():
            rec_p = child_dir / "integration-record.json"
            rec_data = approval_mod.redact_value({
                "schema": 1, "role": "child-integration-result", "factory_revision": f_rev, "status": st,
                "outcome": "rejected", "repo_slug": repo_slug or "", "pr_number": pr_number,
                "candidate_sha": candidate_sha, "base_sha": base_sha, "head_branch": head_branch, "base_branch": base_branch,
                "landed_sha": None, "merge_method": merge_method, "protection_observed": prot_obs,
                "approval_status": ap_status, "mutation_outcome": mut_outcome,
                "confirmation_status": conf_status, "tested_sha": tested_sha_val, "reconciled": is_reconciled,
                "blockers": list(blockers), "trace": trace, "recorded_at": approval_mod.now(),
            }, secrets)
            try: atomic_json(rec_p, rec_data, home); rec_path = str(rec_p)
            except Exception as exc:
                blockers.append(str(approval_mod.redact_value(f"failed to persist integration record: {exc}", secrets)))
                rec_path = None
        return _make(st, "rejected", req_p=req_p, rec_p=rec_path)

    # 1. Target validation (AC7)
    if base_branch in ("main", "master") or not base_branch.startswith("feature/"):
        return _fail("unintended-target", f"target branch must be a feature/<name> branch; got {base_branch!r}")
    if head_branch in ("main", "master") or head_branch == base_branch:
        return _fail("unintended-target", f"head branch cannot be main, master, or match target {head_branch!r}")

    # 2. Revisions & PR format validation (AC2)
    if not isinstance(pr_number, int) or pr_number <= 0:
        return _fail("invalid-pr-number", f"pr_number must be a positive integer, got {pr_number!r}")
    if not (isinstance(candidate_sha, str) and SHA40_RE.fullmatch(candidate_sha) and isinstance(base_sha, str) and SHA40_RE.fullmatch(base_sha)):
        return _fail("invalid-revisions", "candidate_sha and base_sha must be 40-character git commit SHAs")

    # 3. Provider API & origin verification (AC2)
    try:
        resolved_api, is_loopback = resolve_github_api() if base_url is None else (base_url, any(h in base_url for h in ("127.0.0.1", "localhost", "::1")))
        eff_base_url = resolved_api.rstrip("/")
        eff_token = token if token is not None else resolve_github_token(is_loopback)
        if eff_token:
            for t in (eff_token, quote(eff_token, safe="")):
                if t and t not in secrets: secrets.append(t)
    except Exception as exc:
        return _fail("provider-config-error", f"failed to resolve GitHub API or token: {exc}")

    if repo_slug is None:
        rem_res = git_timed(repo, dl, limit_s, "origin remote get-url", "remote", "get-url", "origin")
        if not rem_res.ok or not rem_res.output:
            return _fail("missing-origin-remote", f"cannot resolve origin remote: {rem_res.output}")
        try: repo_slug = parse_repo_slug(rem_res.output.strip())
        except Exception as exc: return _fail("missing-origin-remote", str(exc))

    orig_err = verify_origin_remote(repo, repo_slug, dl, limit_s)
    if orig_err is not None:
        return _fail("origin-remote-mismatch", orig_err)

    req_file = child_dir / "integration-request.json" if child_dir.exists() else None
    rec_file = child_dir / "integration-record.json" if child_dir.exists() else None

    # Check if confirmed landing already exists (AC5, AC6, AC7)
    if rec_file and rec_file.is_file():
        try: prior_rec = read_json(rec_file, home)
        except Exception: prior_rec = {}
        if isinstance(prior_rec, dict) and prior_rec.get("status") == "confirmed" and prior_rec.get("outcome") == "confirmed":
            if repo_slug and str(prior_rec.get("repo_slug") or "").lower() != repo_slug.lower():
                return _fail("repo-slug-mismatch", f"repo_slug {repo_slug!r} does not match confirmed landing repo {prior_rec.get('repo_slug')!r}", persist_result=False)
            if prior_rec.get("pr_number") is not None and prior_rec.get("pr_number") != pr_number:
                return _fail("branch-ref-mismatch", f"PR #{pr_number} does not match confirmed landing PR #{prior_rec.get('pr_number')}", persist_result=False)
            if prior_rec.get("base_branch") and prior_rec.get("base_branch") != base_branch:
                return _fail("branch-ref-mismatch", f"target branch {base_branch!r} does not match confirmed landing target branch {prior_rec.get('base_branch')!r}", persist_result=False)
            if prior_rec.get("head_branch") and prior_rec.get("head_branch") != head_branch:
                return _fail("branch-ref-mismatch", f"head branch {head_branch!r} does not match confirmed landing head branch {prior_rec.get('head_branch')!r}", persist_result=False)
            if prior_rec.get("candidate_sha") != candidate_sha:
                return _fail("stale-candidate-revision", f"candidate {candidate_sha} does not match confirmed landing candidate {prior_rec.get('candidate_sha')}", persist_result=False)
            if prior_rec.get("base_sha") != base_sha:
                return _fail("stale-base-revision", f"base {base_sha} does not match original authorized base {prior_rec.get('base_sha')}; cannot recover with substituted post-merge base", persist_result=False)
            ap_status, mut_outcome, conf_status = "approved", str(prior_rec.get("mutation_outcome") or "already-merged"), "confirmed"
            tested_sha_val, is_reconciled = prior_rec.get("tested_sha"), True
            return IntegrationResult(
                "confirmed", "confirmed", prior_rec.get("landed_sha"), repo_slug or "", pr_number,
                candidate_sha, base_sha, head_branch, base_branch, [], trace,
                prior_rec.get("protection_observed", {}), str(rec_file),
                str(req_file) if req_file and req_file.is_file() else None, f_rev,
                approval_status="approved", mutation_outcome=mut_outcome,
                confirmation_status="confirmed", tested_sha=tested_sha_val, reconciled=True,
            )

    # Check prior initiated request for reconciliation (AC4, AC5, AC6, AC8)
    reconciling = False
    if req_file and req_file.is_file():
        try: prior_req = read_json(req_file, home)
        except Exception: prior_req = {}
        if isinstance(prior_req, dict) and prior_req.get("role") == "child-integration-request":
            if repo_slug and str(prior_req.get("repo_slug") or "").lower() != repo_slug.lower():
                return _fail("repo-slug-mismatch", f"repo_slug {repo_slug!r} does not match initiated integration request repo {prior_req.get('repo_slug')!r}", req_p=str(req_file))
            if prior_req.get("pr_number") is not None and prior_req.get("pr_number") != pr_number:
                return _fail("branch-ref-mismatch", f"PR #{pr_number} does not match initiated integration request PR #{prior_req.get('pr_number')}", req_p=str(req_file))
            if prior_req.get("base_branch") and prior_req.get("base_branch") != base_branch:
                return _fail("branch-ref-mismatch", f"target branch {base_branch!r} does not match initiated integration request target branch {prior_req.get('base_branch')!r}", req_p=str(req_file))
            if prior_req.get("head_branch") and prior_req.get("head_branch") != head_branch:
                return _fail("branch-ref-mismatch", f"head branch {head_branch!r} does not match initiated integration request head branch {prior_req.get('head_branch')!r}", req_p=str(req_file))
            if prior_req.get("candidate_sha") != candidate_sha:
                return _fail("stale-candidate-revision", f"candidate {candidate_sha} does not match initiated integration request candidate {prior_req.get('candidate_sha')}", req_p=str(req_file))
            if prior_req.get("base_sha") != base_sha:
                return _fail("stale-base-revision", f"base {base_sha} does not match initiated integration request base {prior_req.get('base_sha')}; cannot recover with substituted post-merge base", req_p=str(req_file))
            reconciling = True

    # 4. Exact-candidate approval verification (AC3, AC4)
    if conf is None:
        try: conf = config_module.load(config_module.RuntimePaths(repo=repo, home=home))
        except Exception: pass
    ap_res = approval_mod.verify_candidate_approval(
        candidate_sha, base_sha, approval_record, repo=repo, home=home, child_dir=child_dir, child=child,
        conf=conf, ci_record=ci_record, qa_record=qa_record, security_record=security_record,
        review_record=review_record, deadline=dl, limit_s=limit_s,
    )
    if ap_res.get("delivery_approved") is not True or ap_res.get("status") != "approved":
        ap_status = str(ap_res.get("status") or "approval-unverified")
        return _fail(ap_status, list(ap_res.get("blockers") or [f"approval gate verification failed: {ap_status}"]), req_p=str(req_file) if reconciling else None)

    ap_status = "approved"
    tested_sha_val = str(ap_res.get("tested_sha") or "")

    # Reconcile previously initiated integration before any new mutation (AC4, AC5, AC8)
    if reconciling:
        r_code, r_pr, r_err = _http_req("GET", f"{eff_base_url}/repos/{repo_slug}/pulls/{pr_number}", eff_token, eff_base_url, trace, dl, limit_s)
        if r_code == 0 or r_code >= 500:
            mut_outcome, conf_status = "uncertain", "uncertain"
            blockers.append(f"reconciliation failed; remote integration state is unresolved: {r_err or f'HTTP {r_code}'}")
            return _make("uncertain", "uncertain", req_p=str(req_file))
        if r_code in (401, 403):
            mut_outcome = "denied"
            return _fail("denied-permissions", f"insufficient permissions to reconcile PR #{pr_number}: {r_err}", req_p=str(req_file))
        if r_code == 404:
            return _fail("pr-not-found", f"PR #{pr_number} not found during reconciliation: {r_err}", req_p=str(req_file))

        if r_pr.get("state") == "closed" and r_pr.get("merged") is True:
            mut_outcome, is_reconciled = "already-merged", True
            try:
                ok_conf, st_conf, msg_conf, landed_sha = _confirm_landing(
                    repo=repo, eff_base_url=eff_base_url, eff_token=eff_token, repo_slug=repo_slug,
                    pr_number=pr_number, candidate_sha=candidate_sha, base_sha=base_sha,
                    tested_sha=tested_sha_val, head_branch=head_branch, base_branch=base_branch,
                    merge_method=merge_method, trace=trace, dl=dl, limit_s=limit_s,
                )
            except AttemptTimeoutError as exc:
                status, outcome, conf_status = "uncertain", "uncertain", "uncertain"
                landed_sha = None
                blockers.append(str(approval_mod.redact_value(f"confirmation timed out: {exc}", secrets)))
            else:
                if not ok_conf:
                    conf_status = st_conf
                    return _fail(st_conf, msg_conf, req_p=str(req_file))
                status, outcome, conf_status = "confirmed", "confirmed", "confirmed"

            rec_path_str: str | None = None
            if child_dir.exists():
                rec_target = child_dir / "integration-record.json"
                rec_data = approval_mod.redact_value({
                    "schema": 1, "role": "child-integration-result", "factory_revision": f_rev, "status": status,
                    "outcome": outcome, "repo_slug": repo_slug, "pr_number": pr_number,
                    "candidate_sha": candidate_sha, "base_sha": base_sha, "head_branch": head_branch, "base_branch": base_branch,
                    "landed_sha": landed_sha, "merge_method": merge_method, "protection_observed": prot_obs,
                    "approval_status": ap_status, "mutation_outcome": mut_outcome,
                    "confirmation_status": conf_status, "tested_sha": tested_sha_val, "reconciled": is_reconciled,
                    "blockers": list(blockers), "trace": trace, "recorded_at": approval_mod.now(),
                }, secrets)
                try:
                    atomic_json(rec_target, rec_data, home)
                    rec_path_str = str(rec_target)
                except Exception as exc:
                    blockers.append(str(approval_mod.redact_value(f"failed to persist integration record: {exc}", secrets)))
                    rec_path_str = None
                    if status == "confirmed":
                        return _make("persistence-failed", "rejected", landed=None, req_p=str(req_file), rec_p=None)

            return _make(status, outcome, landed=landed_sha, req_p=str(req_file), rec_p=rec_path_str)

    # 5. Authoritative Provider PR state & revision check (AC2, AC4)
    code, pr_data, err_msg = _http_req("GET", f"{eff_base_url}/repos/{repo_slug}/pulls/{pr_number}", eff_token, eff_base_url, trace, dl, limit_s)
    if code != 200 or not pr_data:
        st = "denied-permissions" if code in (401, 403) else ("pr-not-found" if code == 404 else "provider-error")
        return _fail(st, f"failed to fetch PR #{pr_number} from provider: {err_msg or f'HTTP {code}'}")

    pr_state, pr_merged = str(pr_data.get("state") or ""), bool(pr_data.get("merged"))
    if pr_state != "open" or pr_merged:
        return _fail("pr-closed-or-merged", f"PR #{pr_number} is not open and unmerged (state={pr_state!r}, merged={pr_merged})")

    head_obj, base_obj = pr_data.get("head") or {}, pr_data.get("base") or {}
    r_head_sha, r_base_sha = str(head_obj.get("sha") or "").strip(), str(base_obj.get("sha") or "").strip()
    r_head_ref, r_base_ref = str(head_obj.get("ref") or "").strip(), str(base_obj.get("ref") or "").strip()
    r_head_repo = str((head_obj.get("repo") or {}).get("full_name") or "").strip()
    r_base_repo = str((base_obj.get("repo") or {}).get("full_name") or "").strip()

    if r_head_repo.lower() != repo_slug.lower() or r_base_repo.lower() != repo_slug.lower():
        return _fail("repo-slug-mismatch", f"PR #{pr_number} repository {r_base_repo!r} does not match {repo_slug!r}")
    if r_head_ref != head_branch or r_base_ref != base_branch:
        return _fail("branch-ref-mismatch", f"PR #{pr_number} refs ({r_head_ref}->{r_base_ref}) do not match expected ({head_branch}->{base_branch})")
    if r_head_sha != candidate_sha:
        return _fail("stale-candidate-revision", f"PR #{pr_number} head SHA {r_head_sha} does not match candidate {candidate_sha}")
    if r_base_sha != base_sha:
        return _fail("stale-base-revision", f"PR #{pr_number} base SHA {r_base_sha} does not match base {base_sha}")

    # 6. Remote Git state verification (AC2)
    fetch_res = git_timed(repo, dl, limit_s, "git fetch origin", "fetch", "origin")
    if not fetch_res.ok:
        return _fail("remote-git-drift", f"git fetch origin failed during preflight: {fetch_res.output}")
    rem_head, rem_base = gitio.remote_ref(repo, head_branch), gitio.remote_ref(repo, base_branch)
    if rem_head != candidate_sha:
        return _fail("stale-candidate-revision", f"remote origin/{head_branch} ({rem_head}) does not match candidate {candidate_sha}")
    if rem_base != base_sha:
        return _fail("stale-base-revision", f"remote origin/{base_branch} ({rem_base}) does not match base {base_sha}")

    # 7. Repository protection verification (AC6)
    quoted_branch = quote(base_branch, safe="")
    p_code, prot_data, p_msg = _http_req("GET", f"{eff_base_url}/repos/{repo_slug}/branches/{quoted_branch}/protection", eff_token, eff_base_url, trace, dl, limit_s)
    if p_code in (401, 403):
        return _fail("denied-permissions", f"insufficient permissions to verify branch protection on {base_branch}: {p_msg}")
    if p_code != 200 or not prot_data:
        return _fail("unsupported-protection", f"branch protection is not enabled on {base_branch}")

    prot_obs.update(prot_data)
    rsc, admins = prot_data.get("required_status_checks") or {}, prot_data.get("enforce_admins") or {}
    allow_fp, allow_del = prot_data.get("allow_force_pushes") or {}, prot_data.get("allow_deletions") or {}
    if not isinstance(rsc, dict) or not rsc.get("strict"):
        return _fail("unsupported-protection", f"branch protection on {base_branch} must require strict status checks")
    if not isinstance(admins, dict) or not admins.get("enabled"):
        return _fail("unsupported-protection", f"branch protection on {base_branch} must enforce admins to prevent bypass")
    if isinstance(allow_fp, dict) and allow_fp.get("enabled"):
        return _fail("unsupported-protection", f"branch protection on {base_branch} forbids force pushes")
    if isinstance(allow_del, dict) and allow_del.get("enabled"):
        return _fail("unsupported-protection", f"branch protection on {base_branch} forbids branch deletions")

    # 8. Redacted pre-mutation request persistence (AC9)
    req_path_str: str | None = None
    if child_dir.exists():
        req_p = child_dir / "integration-request.json"
        req_data = approval_mod.redact_value({
            "schema": 1, "role": "child-integration-request", "factory_revision": f_rev, "repo_slug": repo_slug,
            "pr_number": pr_number, "candidate_sha": candidate_sha, "base_sha": base_sha,
            "head_branch": head_branch, "base_branch": base_branch, "merge_method": merge_method,
            "initiated_at": approval_mod.now(),
        }, secrets)
        try: atomic_json(req_p, req_data, home); req_path_str = str(req_p)
        except Exception as exc: return _fail("persistence-failed", f"failed to persist pre-mutation request: {exc}", persist_result=False)

    # 9. Test barrier / fault injection hook (AC8)
    if on_before_merge is not None:
        try: on_before_merge()
        except Exception as exc: return _fail("hook-failure", f"on_before_merge hook failed: {exc}", req_p=req_path_str)

    # 10. Provider mutation call (AC5)
    payload = {"sha": candidate_sha, "merge_method": merge_method}
    if commit_title: payload["commit_title"] = commit_title
    if commit_message: payload["commit_message"] = commit_message

    outcome, status, landed_sha = "rejected", "rejected", None
    try:
        m_code, m_data, m_msg = _http_req("PUT", f"{eff_base_url}/repos/{repo_slug}/pulls/{pr_number}/merge", eff_token, eff_base_url, trace, dl, limit_s, payload=payload)
    except (AttemptTimeoutError, Exception) as exc:
        status, outcome, mut_outcome = "uncertain", "uncertain", "uncertain"
        conf_status = "uncertain"
        blockers.append(f"merge communication failure; remote integration state is uncertain: {exc}")
    else:
        if m_code in (200, 201) and m_data.get("merged") is True:
            mut_outcome = "succeeded"
            try:
                ok_conf, st_conf, msg_conf, landed_sha = _confirm_landing(
                    repo=repo, eff_base_url=eff_base_url, eff_token=eff_token, repo_slug=repo_slug,
                    pr_number=pr_number, candidate_sha=candidate_sha, base_sha=base_sha,
                    tested_sha=tested_sha_val, head_branch=head_branch, base_branch=base_branch,
                    merge_method=merge_method, trace=trace, dl=dl, limit_s=limit_s,
                )
            except AttemptTimeoutError as exc:
                status, outcome, conf_status = "uncertain", "uncertain", "uncertain"
                landed_sha = None
                blockers.append(str(approval_mod.redact_value(f"confirmation timed out: {exc}", secrets)))
            else:
                if ok_conf:
                    status, outcome, conf_status = "confirmed", "confirmed", "confirmed"
                else:
                    status, outcome, conf_status = st_conf, "rejected", st_conf
                    landed_sha = None
                    blockers.append(msg_conf)
        elif m_code == 405:
            status, outcome, mut_outcome = "rejected-competing-base", "rejected", "rejected"
            conf_status = "unconfirmed"
            blockers.append(f"provider rejected merge: base branch was modified ({m_msg})")
        elif m_code == 409:
            status, outcome, mut_outcome = "rejected-head-mismatch", "rejected", "rejected"
            conf_status = "unconfirmed"
            blockers.append(f"provider rejected merge: head commit mismatch or conflict ({m_msg})")
        elif m_code in (401, 403):
            status, outcome, mut_outcome = "denied-permissions", "rejected", "denied"
            conf_status = "unconfirmed"
            blockers.append(f"provider denied merge permissions (HTTP {m_code}): {m_msg}")
        elif m_code >= 500 or m_code == 0:
            status, outcome, mut_outcome = "uncertain", "uncertain", "uncertain"
            conf_status = "uncertain"
            blockers.append(f"merge communication failure (HTTP {m_code}): {m_msg or 'transport failure'}; remote integration state is uncertain")
        else:
            status, outcome, mut_outcome = "rejected-provider-error", "rejected", "rejected"
            conf_status = "unconfirmed"
            blockers.append(f"provider rejected merge (HTTP {m_code}): {m_msg}")

    # 11. Result evidence persistence (AC8, AC9)
    rec_path_str: str | None = None
    if child_dir.exists():
        rec_p = child_dir / "integration-record.json"
        rec_data = approval_mod.redact_value({
            "schema": 1, "role": "child-integration-result", "factory_revision": f_rev, "status": status,
            "outcome": outcome, "repo_slug": repo_slug, "pr_number": pr_number,
            "candidate_sha": candidate_sha, "base_sha": base_sha, "head_branch": head_branch, "base_branch": base_branch,
            "landed_sha": landed_sha, "merge_method": merge_method, "protection_observed": prot_obs,
            "approval_status": ap_status, "mutation_outcome": mut_outcome,
            "confirmation_status": conf_status, "tested_sha": tested_sha_val, "reconciled": is_reconciled,
            "blockers": list(blockers), "trace": trace, "recorded_at": approval_mod.now(),
        }, secrets)
        try:
            atomic_json(rec_p, rec_data, home)
            rec_path_str = str(rec_p)
        except Exception as exc:
            blockers.append(str(approval_mod.redact_value(f"failed to persist integration record: {exc}", secrets)))
            rec_path_str = None
            if status == "confirmed":
                status, outcome = "persistence-failed", "rejected"
                landed_sha = None

    return _make(status, outcome, landed=landed_sha, req_p=req_path_str, rec_p=rec_path_str)
