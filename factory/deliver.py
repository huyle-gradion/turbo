"""Single-child feature delivery orchestration and child PR creation (Issue #19)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib, json, math, os, re, shutil, subprocess, sys, time
from pathlib import Path
from typing import Any

from factory import ci_gate, config as config_module, gitio, intake as intake_module, runner, worker as worker_module
from factory.ci_gate import SHA40_RE
from factory.config import now
from factory.deliver_checks import (
    AttemptTimeoutError, GitHubError, collect_redaction_secrets, evaluate_scope, git_timed,
    inspect_diff_categories, open_and_confirm_pr, parse_repo_slug, remaining_seconds,
    resolve_github_api, resolve_github_token, verify_origin_remote,
)
from factory.errors import UsageError
from factory.integration import integrate_approved_child
from factory.intake import redact_value
from factory.limits import parse_duration
from factory.paths import RuntimePaths, atomic_json, safe_dir, write_evidence

FACTORY_ROOT = Path(__file__).resolve().parents[1]
SLUG_TOKEN_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class DeliverSpec:
    task_ref: str
    time_limit_seconds: int
    agy_bin: str = "agy"
    rates: worker_module.RateCard | None = None
    policy_report: str | Path | dict[str, Any] | None = None
    policy_proof: str | Path | dict[str, Any] | None = None
    policy_proposal: str | Path | dict[str, Any] | None = None
    policy_repo: str | Path | None = None


@dataclass(frozen=True, slots=True)
class DeliverResult:
    schema: int
    task_gid: str
    attempt: int
    status: str
    pr_opened: bool
    verified: bool
    verification_scope: str
    merged: bool
    factory_revision: str
    feature_branch: str
    parent: dict[str, Any]
    child: dict[str, Any] | None
    blockers: list[str]
    measurements: dict[str, Any]
    evidence: dict[str, Any]
    recorded_at: str
    ci_verified: bool = False
    delivery_approved: bool = False
    approval_outcome: str = "rejected"
    approved_revision: str | None = None
    candidate_sha: str | None = None
    base_sha: str | None = None
    tested_sha: str | None = None
    revision_kind: str | None = None
    approval: dict[str, Any] | None = None
    policy_consumption: dict[str, Any] | None = None
    integration: dict[str, Any] | None = None
    landed_sha: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _child_branch_name(repo: Path, child_gid: str, child_name: str, attempt: int) -> str:
    slug = SLUG_TOKEN_RE.sub("-", child_name.strip().lower()).strip("-")[:40].strip("-") or "slice"
    base = f"task/{child_gid}-{slug}"
    if not gitio.branch_exists(repo, base) and gitio.remote_ref(repo, base) is None:
        return base
    n = max(1, attempt)
    while True:
        candidate = f"{base}-attempt-{n}"
        if not gitio.branch_exists(repo, candidate) and gitio.remote_ref(repo, candidate) is None:
            return candidate
        n += 1


def _ensure_feature_branch(repo: Path, feature_branch: str, deadline: float, limit_s: int) -> tuple[str, list[str]]:
    if feature_branch in ("main", "master") or not feature_branch.startswith("feature/"):
        return "", [f"target feature branch must be a feature/<name> branch, got {feature_branch!r}"]
    fetch_res = git_timed(repo, deadline, limit_s, "git fetch origin", "fetch", "origin")
    if not fetch_res.ok:
        return "", [f"cannot fetch origin before branch setup: {fetch_res.output}"]
    remote_sha = gitio.remote_ref(repo, feature_branch)
    local_exists = gitio.branch_exists(repo, feature_branch)
    if remote_sha and local_exists:
        local_sha = gitio.commit_sha(repo, f"refs/heads/{feature_branch}")
        if local_sha != remote_sha:
            if gitio.is_ancestor(repo, local_sha, remote_sha):
                if gitio.branch(repo) == feature_branch:
                    return "", [f"local {feature_branch} ({local_sha}) is checked out and behind origin/{feature_branch} ({remote_sha}); refusing to update checked-out branch"]
                ff_res = git_timed(repo, deadline, limit_s, "feature branch fast-forward", "update-ref", f"refs/heads/{feature_branch}", remote_sha, local_sha)
                if not ff_res.ok:
                    return "", [f"cannot fast-forward {feature_branch}: {ff_res.output}"]
                return remote_sha, []
            if not gitio.is_ancestor(repo, remote_sha, local_sha):
                return "", [f"existing local {feature_branch} ({local_sha}) diverged from origin/{feature_branch} ({remote_sha}); refusing to reset"]
        return local_sha, []
    if remote_sha and not local_exists:
        br_res = git_timed(repo, deadline, limit_s, "feature branch creation", "branch", feature_branch, remote_sha)
        if not br_res.ok:
            return "", [f"cannot create feature branch {feature_branch}: {br_res.output}"]
        return remote_sha, []
    if local_exists:
        return gitio.commit_sha(repo, f"refs/heads/{feature_branch}"), []
    base_ref = "refs/remotes/origin/main" if gitio.remote_ref(repo, "main") else "HEAD"
    base_sha = gitio.commit_sha(repo, base_ref)
    br_res = git_timed(repo, deadline, limit_s, "feature branch creation", "branch", feature_branch, base_sha)
    if not br_res.ok:
        return "", [f"cannot create feature branch {feature_branch}: {br_res.output}"]
    return base_sha, []


def _build_worker_prompt(
    parent: dict[str, Any],
    child: dict[str, Any],
    feature_branch: str,
    approved_lessons: tuple[tuple[str, str], ...] = (),
) -> str:
    criteria_lines = "\n".join(
        f"- {c['id']}: {c['description']} (Verification: {c['verification']})"
        for c in (child.get("criteria") or [])
    )
    scope = child.get("scope") or {}
    lessons_section = ""
    if approved_lessons:
        lesson_blocks = [f"- {path}:\n{text.strip()}" for path, text in approved_lessons]
        lessons_section = "\nApproved factory lessons:\n" + "\n".join(lesson_blocks) + "\n"
    return (
        f"Implement prepared Asana sub-task {child['gid']} ({child['name']}) "
        f"for parent feature {parent['gid']} ({parent['name']}).\n"
        f"Target feature branch: {feature_branch}\n"
        f"Outcome: {child.get('outcome') or child['name']}\n"
        f"In scope: {scope.get('in_scope') or 'as specified'}\n"
        f"Out of scope: {scope.get('out_of_scope') or 'none'}\n"
        f"Constraints: {scope.get('constraints') or 'none'}\n"
        f"Acceptance criteria:\n{criteria_lines}\n"
        f"{lessons_section}"
        "Implement the bounded change and relevant tests within scope, run verification checks, "
        "and commit your changes to the current worktree HEAD. Do not push or touch main.\n"
    )


def resolve_delivery_policy(spec: DeliverSpec, factory_root: Path) -> tuple[Any, list[str]]:
    if spec.policy_report is None and spec.policy_proof is None:
        return None, []
    if spec.policy_report is None or spec.policy_proof is None:
        return None, ["approved policy selection requires both policy report and approval proof"]
    try:
        report_data = spec.policy_report if isinstance(spec.policy_report, dict) else json.loads(Path(spec.policy_report).read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"failed to read policy report: {exc}"]
    try:
        proof_data = spec.policy_proof if isinstance(spec.policy_proof, dict) else json.loads(Path(spec.policy_proof).read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"failed to read policy proof: {exc}"]
    prop_data = None
    if spec.policy_proposal is not None:
        try:
            prop_data = spec.policy_proposal if isinstance(spec.policy_proposal, dict) else json.loads(Path(spec.policy_proposal).read_text(encoding="utf-8"))
        except Exception as exc:
            return None, [f"failed to read policy proposal: {exc}"]
    repo_path = Path(spec.policy_repo).resolve() if spec.policy_repo else factory_root
    from factory.promotion import resolve_approved_version
    res = resolve_approved_version(
        repo=repo_path,
        report=report_data,
        approval_proof=proof_data,
        proposal=prop_data,
    )
    if not res.verified:
        return res, [f"approved policy selection refused ({res.status}): {'; '.join(res.blockers)}"]
    return res, []


def validate_resume_policy(prev_rec: dict[str, Any], current_policy: dict[str, Any]) -> tuple[bool, str]:
    prev_policy = prev_rec.get("policy_consumption")
    if prev_policy is None:
        if current_policy.get("selected"):
            return False, "cannot reuse prior attempt: current run selected approved policy but prior attempt had none"
        return True, ""
    if not isinstance(prev_policy, dict):
        return False, "cannot reuse prior attempt: corrupt prior policy consumption record"
    if prev_policy.get("selected") != current_policy.get("selected"):
        return False, "cannot reuse prior attempt: policy selection toggled between runs"
    if current_policy.get("selected"):
        for f in ("selected_version", "target_path", "kind", "content_sha256"):
            if prev_policy.get(f) != current_policy.get(f):
                return False, f"cannot reuse prior attempt: policy {f} changed ({prev_policy.get(f)} != {current_policy.get(f)})"
        ret_path_str = prev_policy.get("retained_artifact_path")
        if not ret_path_str or not Path(ret_path_str).is_file():
            return False, "cannot reuse prior attempt: retained policy artifact missing"
        try:
            actual_sha = hashlib.sha256(Path(ret_path_str).read_bytes()).hexdigest()
        except OSError:
            return False, "cannot reuse prior attempt: retained policy artifact unreadable"
        if actual_sha != prev_policy.get("content_sha256"):
            return False, "cannot reuse prior attempt: retained policy artifact altered"
    if prev_rec.get("factory_revision") and current_policy.get("factory_revision"):
        if prev_rec.get("factory_revision") != current_policy.get("factory_revision"):
            return False, f"cannot reuse prior attempt: factory revision changed ({prev_rec.get('factory_revision')} != {current_policy.get('factory_revision')})"
    return True, ""


def _latest_attempt_num(deliveries_root: Path) -> int:
    safe_dir(deliveries_root, create=True)
    return max((int(m.group(1)) for p in deliveries_root.iterdir() if p.is_dir() and (m := re.fullmatch(r"attempt-(\d+)", p.name)) and (p / "record.json").is_file()), default=0)


def _next_attempt_dir(deliveries_root: Path, home: Path) -> tuple[int, Path]:
    safe_dir(deliveries_root, create=True, root=home)
    attempt = 1
    while (deliveries_root / f"attempt-{attempt}").exists():
        attempt += 1
    return attempt, safe_dir(deliveries_root / f"attempt-{attempt}", create=True, root=home)


def _session_id_from_file(p: Path) -> str | None:
    if not p.is_file():
        return None
    try:
        _, final_res, _ = worker_module.parse_stream_events(p.read_text(encoding="utf-8", errors="replace"))
        return (str(final_res.get("conversation_id") or final_res.get("session_id") or "").strip() if isinstance(final_res, dict) else "") or None
    except Exception:
        return None


def detect_candidate_builder_session_id(child_dir: Path, candidate_sha: str | None = None) -> str | None:
    if not child_dir.is_dir():
        return None
    sec_dirs = sorted([d for d in child_dir.iterdir() if d.is_dir() and d.name.startswith("security-repair-")],
                      key=lambda d: int(d.name.split("-")[-1]) if d.name.split("-")[-1].isdigit() else 0, reverse=True)
    for sd in sec_dirs:
        for fn in ("repair-stdout.txt", "repair-stdout-1.txt"):
            if (sid := _session_id_from_file(sd / fn)):
                if candidate_sha is not None:
                    rec_p = sd / "record.json"
                    if rec_p.is_file():
                        try:
                            rec = json.loads(rec_p.read_text(encoding="utf-8"))
                            if rec.get("to_sha") and rec.get("to_sha") != candidate_sha:
                                continue
                        except Exception:
                            pass
                return sid

    qa_root = child_dir / "automated-qa"
    if qa_root.is_dir():
        qa_rep_dirs = sorted([d for d in qa_root.iterdir() if d.is_dir() and (d.name.startswith("repair-") or d.name.startswith("round-"))],
                             key=lambda d: int(d.name.split("-")[-1]) if d.name.split("-")[-1].isdigit() else 0, reverse=True)
        for qd in qa_rep_dirs:
            target_dirs = [qd / "repair", qd] if (qd / "repair").is_dir() else [qd]
            for td in target_dirs:
                for fn in ("repair-stdout.txt", "repair-stdout-1.txt"):
                    if (sid := _session_id_from_file(td / fn)):
                        if candidate_sha is not None:
                            rec_p = td / "record.json"
                            if rec_p.is_file():
                                try:
                                    rec = json.loads(rec_p.read_text(encoding="utf-8"))
                                    if rec.get("candidate_sha") and rec.get("candidate_sha") != candidate_sha:
                                        continue
                                except Exception:
                                    pass
                        return sid

    for p in (
        child_dir / "builder-stdout.txt", child_dir / "builder-stdout-1.txt",
        child_dir / "evidence" / "builder-stdout.txt",
    ):
        if (sid := _session_id_from_file(p)):
            return sid
    if child_dir.parent.name == "children":
        att_dir = child_dir.parent.parent
        for p in (att_dir / "evidence" / "builder-stdout.txt", att_dir / "builder-stdout.txt"):
            if (sid := _session_id_from_file(p)):
                return sid
    return None


_detect_builder_session_id = detect_candidate_builder_session_id


def enforce_delivery_approval(
    *, candidate_sha: str, base_sha: str, repo: Path, home: Path, child_dir: Path,
    child: dict[str, Any], conf: config_module.Config, ci_record: Any = None, qa_record: Any = None,
    security_record: Any = None, review_record: Any = None, approval_record: Any = None,
    builder_session_id: str | None = None, builder_summary: str = "",
    deadline: float | None = None, limit_s: int = 30,
) -> dict[str, Any]:
    from factory.independent_review import approval as approval_mod
    att_dir = child_dir.parent.parent if child_dir.parent.name == "children" else None
    loaded = approval_mod.load_prerequisite_evidence(child_dir, home, attempt_dir=att_dir)
    eff_ci = ci_record if ci_record is not None else loaded["ci_record"]
    eff_qa = qa_record if qa_record is not None else loaded["qa_record"]
    eff_sec = security_record if security_record is not None else loaded["security_record"]
    eff_rev = review_record if review_record is not None else loaded["review_record"]
    actual_bsid = detect_candidate_builder_session_id(child_dir, candidate_sha)
    b_sid = actual_bsid or builder_session_id
    gate_p = child_dir / "approval-gate.json"
    disk_gate, corrupt_gate = approval_record, False
    if disk_gate is None and gate_p.is_file():
        try:
            disk_gate = approval_mod.read_json(gate_p, home)
        except Exception:
            disk_gate, corrupt_gate = {}, True
    if approval_record is not None or corrupt_gate or (disk_gate is not None and not isinstance(disk_gate, dict)):
        ver_res = approval_mod.verify_candidate_approval(
            candidate_sha, base_sha, disk_gate if disk_gate is not None else approval_record,
            repo=repo, home=home, child_dir=child_dir, child=child, conf=conf,
            ci_record=eff_ci or {}, qa_record=eff_qa or {}, security_record=eff_sec or {}, review_record=eff_rev or {},
            deadline=deadline, limit_s=limit_s,
        )
        if gate_p.parent.exists():
            atomic_json(gate_p, ver_res, home)
        return ver_res

    is_same_cand_approval = (
        isinstance(disk_gate, dict)
        and disk_gate.get("delivery_approved") is True
        and disk_gate.get("candidate_sha") == candidate_sha
        and disk_gate.get("base_sha") == base_sha
    )
    if is_same_cand_approval:
        ver_res = approval_mod.verify_candidate_approval(
            candidate_sha, base_sha, disk_gate, repo=repo, home=home, child_dir=child_dir, child=child, conf=conf,
            ci_record=eff_ci or {}, qa_record=eff_qa or {}, security_record=eff_sec or {}, review_record=eff_rev or {},
            deadline=deadline, limit_s=limit_s,
        )
        if ver_res.get("delivery_approved") is True:
            return ver_res
        if gate_p.parent.exists():
            atomic_json(gate_p, ver_res, home)
        return ver_res

    eval_res = approval_mod.evaluate_approval_gate(
        candidate_sha=candidate_sha, base_sha=base_sha, repo=repo, home=home, child_dir=child_dir, child=child, conf=conf,
        ci_record=eff_ci, qa_record=eff_qa, security_record=eff_sec, review_record=eff_rev,
        prior_approval=disk_gate if isinstance(disk_gate, dict) else None, builder_session_id=b_sid,
        builder_summary=builder_summary, deadline=deadline, limit_s=limit_s, load_from_child_dir=False, _persist=True,
    )
    if eval_res.get("delivery_approved") is not True:
        return eval_res
    ver_res = approval_mod.verify_candidate_approval(
        candidate_sha, base_sha, eval_res, repo=repo, home=home, child_dir=child_dir, child=child, conf=conf,
        ci_record=eff_ci or {}, qa_record=eff_qa or {}, security_record=eff_sec or {}, review_record=eff_rev or {},
        deadline=deadline, limit_s=limit_s,
    )
    if ver_res.get("delivery_approved") is not True and gate_p.parent.exists():
        atomic_json(gate_p, ver_res, home)
    return ver_res


def deliver_ci_prerequisite(paths: RuntimePaths, spec: DeliverSpec, *, pending_status: str = "ci-verified") -> DeliverResult:
    if pending_status not in ("ci-verified", "security-review-pending"):
        raise UsageError(f"unsupported prerequisite pending_status {pending_status!r}")
    return _execute_delivery(paths, spec, require_final_approval=False, pending_status=pending_status)


def deliver_feature(paths: RuntimePaths, spec: DeliverSpec) -> DeliverResult:
    return _execute_delivery(paths, spec, require_final_approval=True, pending_status="ci-verified")


def _execute_delivery(paths: RuntimePaths, spec: DeliverSpec, *, require_final_approval: bool, pending_status: str) -> DeliverResult:
    from factory.independent_review import approval as approval_mod
    started = time.monotonic()
    limit_s = spec.time_limit_seconds
    deadline = started + limit_s
    plat = worker_module.platform_info()
    worker_module.validate_execution_options(plat, time_limit_seconds=limit_s, agy_bin=spec.agy_bin, rates=spec.rates)
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    secrets = collect_redaction_secrets()
    gh_api_url, gh_is_loopback = resolve_github_api()
    intake_args = type("IntakeArgs", (), {"task": spec.task_ref, "deadline": deadline})()
    intake_res = intake_module.run_from_cli(paths, intake_args)
    task_gid = intake_res.task_gid
    parent_root = safe_dir(paths.home / "deliveries" / task_gid, create=True, root=paths.home)
    rev_res = gitio.git(FACTORY_ROOT, "rev-parse", "HEAD")
    factory_rev = rev_res.output if rev_res.ok and re.fullmatch(r"[0-9a-f]{40}", rev_res.output) else "unavailable"
    feature_branch = str(intake_res.parent.get("target_feature_branch") or "")

    eff_factory_repo = Path(spec.policy_repo).resolve() if spec.policy_repo else FACTORY_ROOT
    policy_res, policy_blockers = resolve_delivery_policy(spec, eff_factory_repo)
    factory_dirty = bool(gitio.status_porcelain(eff_factory_repo))
    if policy_blockers:
        st = f"policy-{policy_res.status}" if policy_res is not None else "policy-selection-failed"
        fail_policy = {
            "selected": True, "status": policy_res.status if policy_res is not None else "unresolved",
            "verified": False, "selected_version": None, "target_path": None, "kind": None,
            "content_sha256": None, "provenance": {}, "factory_revision": factory_rev,
            "factory_dirty": factory_dirty, "local_source_drift": False,
            "retained_artifact_path": None, "retained_artifact_sha256": None, "blockers": policy_blockers,
        }
        attempt, attempt_dir = _next_attempt_dir(parent_root, paths.home)
        base_ev = {
            "attempt_dir": str(attempt_dir),
            "intake_record_path": str(paths.home / "intake" / task_gid / "record.json"),
            "intake_status": intake_res.status,
            "policy_consumption": fail_policy,
        }
        meas = {
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "usage": {"state": "unavailable", "provenance": "unavailable; policy selection failed"},
            "cost": {"state": "unavailable", "usd": None, "provenance": "unavailable; policy selection failed"},
        }
        res = DeliverResult(
            schema=1, task_gid=task_gid, attempt=attempt, status=st, pr_opened=False,
            verified=False, verification_scope=ci_gate.VERIFICATION_SCOPE_NOTE, merged=False,
            factory_revision=factory_rev, feature_branch=feature_branch, parent=intake_res.parent,
            child=None, blockers=policy_blockers, measurements=meas, evidence=base_ev,
            recorded_at=now(), policy_consumption=fail_policy,
        )
        atomic_json(attempt_dir / "record.json", res.to_dict(), paths.home)
        atomic_json(parent_root / "record.json", res.to_dict(), paths.home)
        return res

    if policy_res is not None:
        local_p = eff_factory_repo / policy_res.target_path
        local_drift = local_p.is_file() and hashlib.sha256(local_p.read_bytes()).hexdigest() != policy_res.content_sha256
        policy_consumption = {
            "selected": True, "status": "consumed", "verified": True,
            "selected_version": policy_res.selected_version, "target_path": policy_res.target_path,
            "kind": policy_res.kind, "content_sha256": policy_res.content_sha256,
            "provenance": policy_res.provenance, "factory_revision": factory_rev,
            "factory_dirty": factory_dirty, "local_source_drift": local_drift,
            "retained_artifact_path": None, "retained_artifact_sha256": policy_res.content_sha256,
        }
    else:
        policy_consumption = {
            "selected": False, "status": "none", "verified": True,
            "selected_version": None, "target_path": None, "kind": None,
            "content_sha256": None, "provenance": {}, "factory_revision": factory_rev,
            "factory_dirty": factory_dirty, "local_source_drift": False,
            "retained_artifact_path": None, "retained_artifact_sha256": None,
        }

    if require_final_approval and intake_res.delivery_ready and len(intake_res.children) == 1 and not intake_res.children[0].get("blocked_by"):
        child0, child0_gid = intake_res.children[0], str(intake_res.children[0]["gid"])
        if (latest_num := _latest_attempt_num(parent_root)) > 0:
            latest_dir = parent_root / f"attempt-{latest_num}"
            try:
                prev_rec = json.loads((latest_dir / "record.json").read_text(encoding="utf-8"))
            except Exception:
                prev_rec = {}
            prev_child = prev_rec.get("child") if isinstance(prev_rec, dict) else None
            prev_cdir = latest_dir / "children" / child0_gid
            gate_p = prev_cdir / "approval-gate.json"
            gate_changed = False
            if gate_p.is_file():
                try:
                    gate_changed = json.loads(gate_p.read_text(encoding="utf-8")) != prev_rec.get("approval")
                except Exception:
                    gate_changed = True
            has_prereq_activity = (
                prev_rec.get("status") in ("ci-verified", "qa-verified", "security-verified", "security-review-pending", "completed", "confirmed")
                or (prev_cdir / "automated-qa").exists() or (prev_cdir / "security-review.json").is_file()
                or (prev_cdir / "independent-review.json").is_file() or gate_changed or prev_rec.get("delivery_approved") is True
                or (prev_cdir / "integration-request.json").is_file() or (prev_cdir / "integration-record.json").is_file()
            )
            compat, compat_msg = validate_resume_policy(prev_rec, policy_consumption)
            if (
                compat
                and isinstance(prev_child, dict) and prev_rec.get("pr_opened") is True and str(prev_child.get("gid") or "") == child0_gid
                and bool(prev_rec.get("ci_verified") or prev_child.get("ci_verified") or (prev_child.get("ci_verification") or {}).get("verified"))
                and has_prereq_activity
            ):
                repo_slug = parse_repo_slug(str(intake_res.parent.get("repository") or child0.get("repository") or ""))
                origin_issue = verify_origin_remote(paths.repo, repo_slug, deadline, limit_s)
                live_feat_sha, branch_issues = ("", [origin_issue]) if origin_issue else _ensure_feature_branch(paths.repo, feature_branch, deadline, limit_s)
                if not branch_issues:
                    head_branch, prev_cand = str(prev_child.get("head_branch") or ""), str(prev_child.get("candidate_sha") or "")
                    rem_cand = gitio.remote_ref(paths.repo, head_branch) if head_branch else None
                    loc_cand = gitio.commit_sha(paths.repo, f"refs/heads/{head_branch}") if (head_branch and gitio.branch_exists(paths.repo, head_branch)) else None
                    cand_sha = rem_cand or loc_cand or prev_cand
                    orig_base = str(prev_child.get("base_sha") or prev_rec.get("base_sha") or "")
                    is_recovering = False
                    if (prev_cdir / "integration-record.json").is_file():
                        try:
                            _pr_rec = json.loads((prev_cdir / "integration-record.json").read_text(encoding="utf-8"))
                            is_recovering = bool(_pr_rec.get("candidate_sha") == cand_sha and _pr_rec.get("status") in ("confirmed", "uncertain"))
                        except Exception:
                            is_recovering = False
                    elif (prev_cdir / "integration-request.json").is_file():
                        try:
                            _pr_req = json.loads((prev_cdir / "integration-request.json").read_text(encoding="utf-8"))
                            is_recovering = bool(_pr_req.get("candidate_sha") == cand_sha)
                        except Exception:
                            is_recovering = False
                    auth_base_sha = (orig_base if (orig_base and SHA40_RE.fullmatch(orig_base)) else live_feat_sha) if is_recovering else live_feat_sha
                    try:
                        app_rec = enforce_delivery_approval(
                            candidate_sha=cand_sha, base_sha=auth_base_sha, repo=paths.repo, home=paths.home,
                            child_dir=prev_cdir, child=child0, conf=conf, deadline=deadline, limit_s=limit_s,
                        )
                    except (AttemptTimeoutError, TimeoutError) as exc:
                        t_msg = f"delivery approval timed out: {exc}"
                        app_rec = {"schema": 1, "role": "delivery-approval-gate", "status": "timed-out", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": cand_sha, "base_sha": auth_base_sha, "blockers": [t_msg]}
                        if prev_cdir.exists(): atomic_json(gate_p, app_rec, paths.home)
                    approved = bool(app_rec.get("delivery_approved") is True and app_rec.get("status") == "approved" and app_rec.get("outcome") == "approved" and app_rec.get("approved_revision") == cand_sha)
                    ci_eval = (app_rec.get("prerequisites") or {}).get("ci") or {}
                    ci_ok = bool(ci_eval.get("verified") is True) if ci_eval else bool(prev_child.get("ci_verified"))
                    t_sha = app_rec.get("tested_sha") or (ci_eval.get("tested_sha") if ci_ok else None)
                    r_kind = app_rec.get("revision_kind") or (ci_eval.get("revision_kind") if ci_ok else None)
                    app_rev, app_out = (cand_sha if approved else None), ("approved" if approved else "rejected")

                    merged = False
                    landed_sha: str | None = None
                    integration_rec: dict[str, Any] | None = None
                    blks: list[str] = []
                    full_ci_rec: dict[str, Any] | None = None
                    if (prev_cdir / "ci-verification.json").is_file():
                        try:
                            full_ci_rec = json.loads((prev_cdir / "ci-verification.json").read_text(encoding="utf-8"))
                        except Exception:
                            full_ci_rec = None
                    if full_ci_rec is None and isinstance(prev_child.get("ci_verification"), dict):
                        full_ci_rec = prev_child["ci_verification"]

                    if approved:
                        try:
                            gh_token = resolve_github_token(gh_is_loopback)
                            pr_num = int((prev_child.get("pr") or {}).get("number") or 1)
                            int_res = integrate_approved_child(
                                repo=paths.repo, home=paths.home, child_dir=prev_cdir, child=child0, conf=conf,
                                pr_number=pr_num, candidate_sha=cand_sha, base_sha=auth_base_sha,
                                head_branch=head_branch, base_branch=feature_branch, approval_record=app_rec,
                                ci_record=full_ci_rec,
                                repo_slug=repo_slug, base_url=gh_api_url, token=gh_token,
                                deadline=deadline, limit_s=limit_s,
                            )
                            integration_rec = {
                                "status": int_res.status, "outcome": int_res.outcome,
                                "landed_sha": int_res.landed_sha, "reconciled": int_res.reconciled,
                                "record_path": int_res.record_path, "request_path": int_res.request_path,
                            }
                            if int_res.status == "confirmed" and int_res.landed_sha:
                                st = "completed"
                                merged = True
                                landed_sha = int_res.landed_sha
                            else:
                                st = int_res.status
                                blks.extend(b for b in int_res.blockers if b not in blks)
                        except (AttemptTimeoutError, TimeoutError) as exc:
                            st, blks = "timed-out", [f"integration timed out: {exc}"]
                        except Exception as exc:
                            st, blks = "integration-failed", [f"integration error: {exc}"]
                    else:
                        st = str(app_rec.get("status") or "approval-rejected")
                        blks = list(dict.fromkeys(app_rec.get("blockers") or []))

                    is_completed = bool(approved and merged and st == "completed")
                    is_verified = bool(is_completed or (approved and st == "verified"))
                    v_scope = approval_mod.APPROVAL_GATE_SCOPE_NOTE if (is_verified or approved) else ci_gate.VERIFICATION_SCOPE_NOTE

                    upd_pr = {
                        **(prev_child.get("pr") or {}), "head_sha": cand_sha, "base_sha": auth_base_sha,
                        "ci_verified": ci_ok, "verified": is_completed, "delivery_approved": approved,
                        "approved_revision": app_rev, "merged": merged, "landed_sha": landed_sha,
                    }
                    upd_child = {
                        **prev_child, "status": st, "ci_verified": ci_ok, "verified": is_completed, "delivery_approved": approved,
                        "approval_outcome": app_out, "approved_revision": app_rev, "verification_scope": v_scope,
                        "base_sha": auth_base_sha, "candidate_sha": cand_sha, "tested_sha": t_sha, "revision_kind": r_kind,
                        "ci_verification": full_ci_rec or prev_child.get("ci_verification"),
                        "approval": app_rec, "integration": integration_rec, "pr": upd_pr,
                        "merged": merged, "landed_sha": landed_sha,
                    }
                    upd_ev = {**(prev_rec.get("evidence") or {}), "approval_gate_path": str(gate_p)}
                    if (prev_cdir / "ci-verification.json").is_file():
                        upd_ev["ci_verification_path"] = str(prev_cdir / "ci-verification.json")
                    if (prev_cdir / "integration-request.json").is_file():
                        upd_ev["integration_request_path"] = str(prev_cdir / "integration-request.json")
                    if (prev_cdir / "integration-record.json").is_file():
                        upd_ev["integration_record_path"] = str(prev_cdir / "integration-record.json")
                    if landed_sha:
                        upd_ev["landed_sha"] = landed_sha
                        upd_ev["completion_confirmed"] = True
                    upd_ev["task_gid"] = task_gid
                    upd_ev["parent_task_url"] = f"https://app.asana.com/0/0/{task_gid}"
                    upd_ev["child_task_url"] = f"https://app.asana.com/0/{task_gid}/{child0_gid}"
                    pr_url = str(upd_pr.get("url") or upd_pr.get("html_url") or (prev_rec.get("evidence") or {}).get("pr_url") or "").strip()
                    if pr_url:
                        upd_ev["pr_url"] = pr_url
                    upd_ev["reviewed_revision"] = app_rev
                    upd_ev["tested_revision"] = t_sha
                    upd_ev["original_base_sha"] = auth_base_sha

                    res = DeliverResult(
                        schema=1, task_gid=task_gid, attempt=latest_num, status=st, pr_opened=True, verified=is_verified,
                        verification_scope=v_scope, merged=merged, factory_revision=factory_rev, feature_branch=feature_branch,
                        parent=redact_value(intake_res.parent, secrets), child=redact_value(upd_child, secrets),
                        blockers=redact_value(blks, secrets), measurements=prev_rec.get("measurements") or {},
                        evidence=redact_value(upd_ev, secrets), recorded_at=now(), ci_verified=ci_ok, delivery_approved=approved,
                        approval_outcome=app_out, approved_revision=app_rev, candidate_sha=cand_sha, base_sha=auth_base_sha,
                        tested_sha=t_sha, revision_kind=r_kind, approval=redact_value(app_rec, secrets),
                        policy_consumption=prev_rec.get("policy_consumption") or policy_consumption,
                        integration=redact_value(integration_rec, secrets), landed_sha=landed_sha,
                    )
                    atomic_json(latest_dir / "record.json", res.to_dict(), paths.home)
                    atomic_json(parent_root / "record.json", res.to_dict(), paths.home)
                    return res

    attempt, attempt_dir = _next_attempt_dir(parent_root, paths.home)
    intake_src = paths.home / "intake" / task_gid / "record.json"
    intake_snap = attempt_dir / "intake-record.json"
    if intake_src.exists():
        shutil.copy2(intake_src, intake_snap)

    def _finish(
        status: str, blockers: list[str], child_payload: dict[str, Any] | None,
        measurements: dict[str, Any], evidence: dict[str, Any], active_secrets: tuple[str, ...] = secrets,
        *, pr_opened: bool = False, ci_verified: bool = False, delivery_approved: bool = False,
        approval_outcome: str = "rejected", approved_revision: str | None = None,
        candidate_sha: str | None = None, base_sha: str | None = None,
        tested_sha: str | None = None, revision_kind: str | None = None,
        approval: dict[str, Any] | None = None,
        merged: bool = False, landed_sha: str | None = None,
        integration: dict[str, Any] | None = None,
        policy_consumption: dict[str, Any] | None = None,
    ) -> DeliverResult:
        is_completed = bool(delivery_approved and merged and status == "completed")
        is_verified = bool(is_completed or (delivery_approved and status == "verified"))
        v_scope = approval_mod.APPROVAL_GATE_SCOPE_NOTE if (is_verified or delivery_approved) else ci_gate.VERIFICATION_SCOPE_NOTE
        eff_policy = policy_consumption if policy_consumption is not None else evidence.get("policy_consumption")
        res = DeliverResult(
            schema=1, task_gid=task_gid, attempt=attempt, status=status,
            pr_opened=pr_opened, verified=is_verified, verification_scope=v_scope,
            merged=merged, factory_revision=factory_rev,
            feature_branch=feature_branch, parent=redact_value(intake_res.parent, active_secrets),
            child=redact_value(child_payload, active_secrets) if child_payload is not None else None,
            blockers=redact_value(blockers, active_secrets), measurements=measurements,
            evidence=redact_value({**evidence, "policy_consumption": eff_policy}, active_secrets), recorded_at=now(),
            ci_verified=ci_verified, delivery_approved=delivery_approved,
            approval_outcome=approval_outcome,
            approved_revision=approved_revision,
            candidate_sha=candidate_sha, base_sha=base_sha,
            tested_sha=tested_sha, revision_kind=revision_kind,
            approval=redact_value(approval, active_secrets) if approval is not None else None,
            integration=redact_value(integration, active_secrets) if integration is not None else None,
            landed_sha=landed_sha,
            policy_consumption=eff_policy,
        )
        atomic_json(attempt_dir / "record.json", res.to_dict(), paths.home)
        atomic_json(parent_root / "record.json", res.to_dict(), paths.home)
        return res

    def _default_meas() -> dict[str, Any]:
        return {
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "usage": {"state": "unavailable", "provenance": "unavailable; builder did not run"},
            "cost": {"state": "unavailable", "usd": None, "provenance": "unavailable; builder did not run"},
        }

    base_evidence: dict[str, Any] = {
        "attempt_dir": str(attempt_dir),
        "intake_record_path": str(intake_snap if intake_snap.exists() else intake_src),
        "intake_status": intake_res.status,
        "policy_consumption": policy_consumption,
    }
    intake_reqs = intake_res.evidence.get("requests") if isinstance(intake_res.evidence, dict) else []
    intake_timed_out = time.monotonic() >= deadline or any(
        isinstance(r, dict) and r.get("status") == "timeout" for r in (intake_reqs or [])
    )
    if intake_timed_out:
        return _finish("timed-out", [f"attempt timed out during intake after {limit_s}s", *intake_res.blockers], None, _default_meas(), base_evidence)
    if len(intake_res.children) > 1:
        gids = ", ".join(c["gid"] for c in intake_res.children)
        return _finish("unsupported-topology", [f"slice #19 supports exactly 1 prepared child sub-task, found {len(intake_res.children)} ({gids})", *intake_res.blockers], None, _default_meas(), base_evidence)
    if len(intake_res.children) == 1 and intake_res.children[0].get("blocked_by"):
        c0 = intake_res.children[0]
        return _finish("unsupported-topology", [f"child {c0['gid']} declares dependencies ({c0.get('blocked_by')}), which is outside slice #19 single-child delivery", *intake_res.blockers], c0, _default_meas(), base_evidence)
    if not intake_res.delivery_ready:
        return _finish(f"intake-{intake_res.status}", list(intake_res.blockers), None, _default_meas(), base_evidence)
    child = intake_res.children[0]
    child_gid = str(child["gid"])
    pre_policy_detail = ci_gate.evaluate_spec_check_policy(child, conf)
    if pre_conflicts := pre_policy_detail["conflicts"]:
        return _finish(
            "spec-check-conflict", pre_conflicts,
            {
                "gid": child_gid, "name": child["name"], "status": "spec-check-conflict",
                "verified": False, "spec_check_policy": pre_policy_detail, "pr": None,
            },
            _default_meas(), base_evidence,
        )
    child_dir = safe_dir(attempt_dir / "children" / child_gid, create=True, root=paths.home)
    worktree_dir = child_dir / "worktree"
    gh_trace: list[dict[str, Any]] = []
    measurements = _default_meas()
    pr_info: dict[str, Any] | None = None
    retained_file = None
    if policy_res is not None:
        retained_dir = safe_dir(child_dir / "consumed-policy", create=True, root=paths.home)
        retained_file = retained_dir / policy_res.target_path
        retained_file.parent.mkdir(parents=True, exist_ok=True)
        retained_file.write_bytes(policy_res.content_bytes)
        policy_consumption["retained_artifact_path"] = str(retained_file)

    try:
        repo_slug = parse_repo_slug(str(intake_res.parent.get("repository") or child.get("repository") or ""))
        if (origin_issue := verify_origin_remote(paths.repo, repo_slug, deadline, limit_s)) is not None:
            return _finish("branch-failed", [origin_issue], child, _default_meas(), base_evidence)
        main_before = gitio.commit_sha(paths.repo, "refs/heads/main") if gitio.branch_exists(paths.repo, "main") else gitio.head(paths.repo)
        remote_main_before = gitio.remote_ref(paths.repo, "main")
        base_sha, branch_issues = _ensure_feature_branch(paths.repo, feature_branch, deadline, limit_s)
        if branch_issues:
            return _finish("branch-failed", branch_issues, child, _default_meas(), base_evidence)

        isolated_home = worker_module.prepare_isolated_home(child_dir, Path.home(), root=paths.home)
        worker_env, stripped_keys = worker_module.sanitized_env(dict(os.environ), worktree_dir, isolated_home)
        host_version = worker_module.detect_host_version(spec.agy_bin, (), worker_env)
        head_branch = _child_branch_name(paths.repo, child_gid, str(child.get("name") or ""), attempt)
        try:
            worker_module.prepare_isolated_git_checkout(paths.repo, worktree_dir, base_sha, deadline=deadline)
        except TimeoutError as exc:
            raise AttemptTimeoutError(f"worktree preparation timed out after {limit_s}s") from exc
        except RuntimeError as exc:
            return _finish("branch-failed", [str(exc)], child, _default_meas(), base_evidence)

        remaining_seconds(deadline, "safety probes", limit_s)
        try:
            probes = worker_module.run_safety_probes(worker_env, worktree_dir, child_dir, paths.home, deadline=deadline)
        except TimeoutError as exc:
            raise AttemptTimeoutError(f"safety probes timed out after {limit_s}s") from exc
        if time.monotonic() >= deadline:
            raise AttemptTimeoutError(f"safety probes timed out after {limit_s}s")
        approved_lessons = ()
        if policy_res is not None and policy_res.kind == "lesson":
            approved_lessons = ((policy_res.target_path, policy_res.content_bytes.decode("utf-8", errors="replace")),)
        prompt_text = _build_worker_prompt(intake_res.parent, child, feature_branch, approved_lessons=approved_lessons)
        argv = (spec.agy_bin, "--print", prompt_text, "--output-format", "stream-json", "--sandbox", "--mode", "auto")
        if policy_res is not None and policy_res.kind == "skill":
            skill_dest = isolated_home / ".gemini" / "antigravity-cli" / policy_res.target_path
            skill_dest.parent.mkdir(parents=True, exist_ok=True)
            skill_dest.write_bytes(policy_res.content_bytes)
        elif policy_res is not None and policy_res.kind == "tool":
            tool_bin = safe_dir(isolated_home / "bin", create=True, root=paths.home)
            tool_dest = tool_bin / Path(policy_res.target_path).name
            tool_dest.write_bytes(policy_res.content_bytes)
            tool_dest.chmod(0o755)
            worker_env["PATH"] = f"{tool_bin}:{worker_env.get('PATH', '')}"
        if worker_module.probes_passed(probes):
            builder_timeout = max(1, int(math.ceil(remaining_seconds(deadline, "builder execution", limit_s))))
            try:
                exit_code, stdout_text, stderr_text, worker_ms, timed_out = worker_module.execute_stream(
                    worktree_dir, argv, worker_env, builder_timeout, isolated_home=isolated_home
                )
            except worker_module.SandboxUnavailableError:
                exit_code, stdout_text, stderr_text, timed_out = None, "", "", False
                events, final_result, parse_error, probes = [], None, None, []
            else:
                events, final_result, parse_error = worker_module.parse_stream_events(stdout_text)
                measurements = worker_module.extract_measurements(final_result, int((time.monotonic() - started) * 1000), spec.rates)
                measurements["builder_elapsed_ms"] = worker_ms
                if timed_out or time.monotonic() >= deadline:
                    raise AttemptTimeoutError(f"builder timed out after {limit_s}s")
        else:
            exit_code, stdout_text, stderr_text, timed_out = None, "", "", False
            events, final_result, parse_error = [], None, None

        stdout_path = write_evidence(child_dir, "builder-stdout", stdout_text, paths.home)
        stderr_path = write_evidence(child_dir, "builder-stderr", stderr_text, paths.home)
        candidate_sha = gitio.head(worktree_dir)
        dirty_after = gitio.status_porcelain(worktree_dir)
        cand_diff_text = (
            git_timed(worktree_dir, deadline, limit_s, "candidate diff", "diff", "--binary", base_sha, candidate_sha).output
            if candidate_sha != base_sha else ""
        )
        cand_diff_path = write_evidence(child_dir, "candidate-diff", redact_value(cand_diff_text, secrets), paths.home)
        wt_status_path = write_evidence(child_dir, "worktree-status", redact_value(dirty_after, secrets), paths.home)
        diff_info = (
            inspect_diff_categories(worktree_dir, base_sha, candidate_sha, deadline, limit_s)
            if candidate_sha != base_sha
            else {"changed_paths": [], "implementation_paths": [], "test_paths": [], "has_implementation_changes": False, "has_test_changes": False}
        )
        gate3 = conf.gates.get("3")
        protected_paths = gate3.paths if gate3 is not None and gate3.kind == "protected-paths" else ()
        scope_ok, scope_violations, scope_detail = evaluate_scope(tuple(diff_info["changed_paths"]), child, protected_paths)
        post_policy_detail = ci_gate.evaluate_spec_check_policy(
            child, conf, tuple(diff_info["changed_paths"]), repo=worktree_dir,
        )
        post_conflicts = post_policy_detail["conflicts"]
        scope_detail["spec_check_policy"] = post_policy_detail

        fetch_after = git_timed(paths.repo, deadline, limit_s, "git fetch origin", "fetch", "origin")
        main_after = gitio.commit_sha(paths.repo, "refs/heads/main") if gitio.branch_exists(paths.repo, "main") else main_before
        remote_main_after = gitio.remote_ref(paths.repo, "main")
        feature_after = gitio.commit_sha(paths.repo, f"refs/heads/{feature_branch}") if gitio.branch_exists(paths.repo, feature_branch) else ""
        if (
            not fetch_after.ok or main_after != main_before
            or (remote_main_before is not None and remote_main_after != remote_main_before)
            or feature_after != base_sha
        ):
            scope_ok = False
            scope_violations.append("unauthorized repository or remote branch mutation detected")

        builder_status, blockers = "completed", []
        if not worker_module.probes_passed(probes):
            builder_status, blockers = "unsafe-environment", ["worker environment safety probes failed"]
        elif parse_error is not None:
            builder_status, blockers = "malformed-output", [f"builder produced malformed structured output: {parse_error}"]
        elif worker_module.has_permission_denial(events, final_result, stderr_text):
            builder_status, blockers = "permission-denied", ["builder encountered sandbox or tool permission denial"]
        elif exit_code != 0 or not isinstance(final_result, dict) or final_result.get("status") != "SUCCESS":
            res_status = final_result.get("status") if isinstance(final_result, dict) else None
            builder_status, blockers = "builder-failed", [f"builder exited with code {exit_code} and result status {res_status!r}"]
        elif dirty_after:
            builder_status, blockers = "uncommitted-changes", [f"builder left uncommitted changes in worktree: {dirty_after}"]
        elif candidate_sha == base_sha or not diff_info["changed_paths"]:
            builder_status, blockers = "missing-implementation", ["builder produced no committed changes relative to the feature branch base"]
        elif not gitio.is_ancestor(worktree_dir, base_sha, candidate_sha):
            builder_status, blockers = "scope-violation", ["builder rewrote history or diverged from the feature branch base"]
        elif post_conflicts:
            builder_status, blockers = "spec-check-conflict", post_conflicts
        elif not scope_ok:
            builder_status, blockers = "scope-violation", list(scope_violations)
        elif not diff_info["has_implementation_changes"]:
            builder_status, blockers = "missing-implementation", ["builder committed test changes only without implementation changes"]
        elif not diff_info["has_test_changes"]:
            builder_status, blockers = "missing-tests", ["builder committed implementation changes without relevant test changes"]

        if policy_res is not None and policy_res.kind == "check" and builder_status == "completed":
            try:
                check_cmd = [sys.executable, str(retained_file)]
                check_res = subprocess.run(check_cmd, cwd=str(worktree_dir), capture_output=True, text=True, timeout=30)
                if check_res.returncode != 0:
                    builder_status = "approved-policy-check-failed"
                    check_out = (check_res.stderr or check_res.stdout).strip()
                    blockers.append(f"approved policy check {policy_res.target_path} failed: {check_out}")
            except Exception as exc:
                builder_status = "approved-policy-check-failed"
                blockers.append(f"approved policy check {policy_res.target_path} execution error: {exc}")

        ci_verification: dict[str, Any] | None = None
        approval_rec: dict[str, Any] | None = None
        ci_ok = False
        delivery_approved = False
        merged = False
        landed_sha: str | None = None
        integration_rec: dict[str, Any] | None = None
        if builder_status == "completed":
            try:
                gh_token = resolve_github_token(gh_is_loopback)
                if not gh_token:
                    raise GitHubError("missing GitHub authentication token (GITHUB_TOKEN, GH_TOKEN, or TURBO_GITHUB_TOKEN)")
                fetch_cand = git_timed(paths.repo, deadline, limit_s, "fetch candidate commit", "fetch", "-q", "--no-tags", str(worktree_dir), candidate_sha)
                if not fetch_cand.ok or gitio.commit_sha(paths.repo, "FETCH_HEAD") != candidate_sha:
                    raise GitHubError(f"failed to import verified candidate commit {candidate_sha}: {fetch_cand.output}")
                (paths.repo / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
                head_branch = _child_branch_name(paths.repo, child_gid, str(child.get("name") or ""), attempt)
                br_child = git_timed(paths.repo, deadline, limit_s, "branch child head", "branch", head_branch, candidate_sha)
                if not br_child.ok:
                    raise GitHubError(f"failed to create child branch {head_branch}: {br_child.output}")
                push_feat = git_timed(paths.repo, deadline, limit_s, "push feature branch", "push", "origin", f"{base_sha}:refs/heads/{feature_branch}")
                if not push_feat.ok:
                    raise GitHubError(f"failed to push feature branch {feature_branch} to origin: {push_feat.output}")
                push_child = git_timed(paths.repo, deadline, limit_s, "push child branch", "push", "origin", f"{candidate_sha}:refs/heads/{head_branch}")
                if not push_child.ok:
                    raise GitHubError(f"failed to push child branch {head_branch} to origin: {push_child.output}")
                pr_info = open_and_confirm_pr(
                    gh_api_url, gh_token, repo_slug, intake_res.parent, child, head_branch,
                    candidate_sha, feature_branch, [], scope_detail, gh_trace, deadline, limit_s,
                )
                ci_verification = ci_gate.evaluate_child_pr_ci_gate(
                    repo=paths.repo, home=paths.home, child_dir=child_dir, base_url=gh_api_url, token=gh_token,
                    repo_slug=repo_slug, parent=intake_res.parent, child=child, conf=conf, pr_info=pr_info,
                    head_branch=head_branch, candidate_sha=candidate_sha, base_branch=feature_branch,
                    base_sha=base_sha, scope_detail=scope_detail, trace=gh_trace, deadline=deadline, limit_s=limit_s,
                    changed_paths=tuple(diff_info["changed_paths"]),
                    poll_interval_s=0.05 if gh_is_loopback else 2.0,
                    max_missing_polls=3 if gh_is_loopback else 15,
                    artifact_retry_delay_s=0.0 if gh_is_loopback else 2.0,
                )
                atomic_json(child_dir / "ci-verification.json", redact_value(ci_verification, secrets), paths.home)
                ci_ok = str(ci_verification["status"]) == "verified" and bool(ci_verification.get("verified"))
                pr_info = dict(ci_verification.get("pr") or pr_info or {})
                blockers.extend(ci_verification.get("blockers") or [])
                if ci_ok and require_final_approval:
                    try:
                        approval_rec = enforce_delivery_approval(
                            candidate_sha=candidate_sha, base_sha=base_sha, repo=paths.repo, home=paths.home,
                            child_dir=child_dir, child=child, conf=conf, ci_record=ci_verification,
                            deadline=deadline, limit_s=limit_s,
                        )
                        delivery_approved = bool(
                            approval_rec.get("delivery_approved") is True
                            and approval_rec.get("status") == "approved"
                            and approval_rec.get("outcome") == "approved"
                            and approval_rec.get("approved_revision") == candidate_sha
                        )
                        if delivery_approved:
                            app_out, app_rev = "approved", candidate_sha
                            int_res = integrate_approved_child(
                                repo=paths.repo, home=paths.home, child_dir=child_dir, child=child, conf=conf,
                                pr_number=int(pr_info["number"]), candidate_sha=candidate_sha, base_sha=base_sha,
                                head_branch=head_branch, base_branch=feature_branch, approval_record=approval_rec,
                                ci_record=ci_verification, repo_slug=repo_slug, base_url=gh_api_url, token=gh_token,
                                deadline=deadline, limit_s=limit_s,
                            )
                            integration_rec = {
                                "status": int_res.status, "outcome": int_res.outcome,
                                "landed_sha": int_res.landed_sha, "reconciled": int_res.reconciled,
                                "record_path": int_res.record_path, "request_path": int_res.request_path,
                            }
                            if int_res.status == "confirmed" and int_res.landed_sha:
                                final_status = "completed"
                                merged = True
                                landed_sha = int_res.landed_sha
                            else:
                                final_status = int_res.status
                                blockers.extend(b for b in int_res.blockers if b not in blockers)
                        else:
                            final_status = str(approval_rec.get("status") or "approval-rejected")
                            blockers.extend(b for b in (approval_rec.get("blockers") or []) if b not in blockers)
                    except (AttemptTimeoutError, TimeoutError) as exc:
                        delivery_approved, final_status = False, "timed-out"
                        t_msg = f"delivery approval timed out: {exc}"
                        blockers.append(t_msg)
                        approval_rec = {"schema": 1, "role": "delivery-approval-gate", "status": "timed-out", "outcome": "rejected", "delivery_approved": False, "approved_revision": None, "candidate_sha": candidate_sha, "base_sha": base_sha, "blockers": [t_msg]}
                        if child_dir.exists(): atomic_json(child_dir / "approval-gate.json", approval_rec, paths.home)
                elif ci_ok:
                    final_status = pending_status
                else:
                    final_status = str(ci_verification["status"])
                pr_info = {
                    **pr_info, "ci_verified": ci_ok, "verified": merged,
                    "delivery_approved": delivery_approved,
                    "approved_revision": candidate_sha if delivery_approved else None,
                    "merged": merged, "landed_sha": landed_sha,
                }
            except AttemptTimeoutError as exc:
                if pr_info is not None:
                    pr_info = {**pr_info, "pr_confirmed": True, "ci_verified": False, "verified": False, "delivery_approved": False, "merged": False, "landed_sha": None}
                    final_status = "ci-pending"
                    blockers.append(f"CI verification still pending when time allowance expired: {exc}")
                else:
                    raise
            except GitHubError as exc:
                final_status = "pr-failed"
                blockers.append(str(exc))
        else:
            final_status = builder_status

        measurements["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        gh_trace_text = json.dumps(
            redact_value({"requests": gh_trace, "pr": pr_info, "ci_verification": ci_verification}, secrets),
            indent=2, sort_keys=True,
        ) + "\n"
        gh_evidence_path = write_evidence(child_dir, "github-pr", gh_trace_text, paths.home)
        tested_sha = (approval_rec or {}).get("tested_sha") or (ci_verification.get("tested_sha") if isinstance(ci_verification, dict) else None)
        rev_kind = (approval_rec or {}).get("revision_kind") or (ci_verification.get("revision_kind") if isinstance(ci_verification, dict) else None)
        app_out = "approved" if delivery_approved else "rejected"
        app_rev = candidate_sha if delivery_approved else None
        v_scope = approval_mod.APPROVAL_GATE_SCOPE_NOTE if (delivery_approved or merged) else ci_gate.VERIFICATION_SCOPE_NOTE
        child_payload = {
            "gid": child_gid, "name": child["name"], "status": final_status,
            "ci_verified": ci_ok, "verified": merged, "delivery_approved": delivery_approved,
            "approval_outcome": app_out, "approved_revision": app_rev,
            "merged": merged, "landed_sha": landed_sha,
            "verification_scope": v_scope,
            "base_branch": feature_branch, "base_sha": base_sha, "head_branch": head_branch,
            "candidate_sha": candidate_sha, "tested_sha": tested_sha, "revision_kind": rev_kind,
            "diff": diff_info, "scope_check": scope_detail,
            "verification_checks": ci_verification.get("checks", []) if isinstance(ci_verification, dict) else [],
            "ci_verification": ci_verification, "approval": approval_rec, "integration": integration_rec, "pr": pr_info,
            "policy_consumption": policy_consumption,
            "safety": {
                "sandbox_flag": "--sandbox", "permission_mode": "auto", "bypass_permissions_used": False,
                "isolated_home": str(isolated_home), "stripped_env_keys": stripped_keys, "probes": probes,
            },
        }
        evidence = {
            **base_evidence, "host_version": host_version, "platform": plat,
            "builder_argv": list(argv), "builder_exit": exit_code, "builder_timed_out": timed_out,
            "builder_parse_error": parse_error, "builder_stdout_path": str(stdout_path),
            "builder_stdout_sha256": runner.digest_text(stdout_text), "builder_stderr_path": str(stderr_path),
            "builder_stderr_sha256": runner.digest_text(stderr_text), "candidate_diff_path": str(cand_diff_path),
            "worktree_status_path": str(wt_status_path), "github_evidence_path": str(gh_evidence_path),
            "github_evidence_sha256": runner.digest_text(gh_trace_text), "github_requests": gh_trace,
            "policy_consumption": policy_consumption,
        }
        if retained_file is not None:
            evidence["retained_consumed_policy_path"] = str(retained_file)
        if (child_dir / "ci-verification.json").is_file():
            evidence["ci_verification_path"] = str(child_dir / "ci-verification.json")
        if approval_rec is not None:
            evidence["approval_gate_path"] = str(child_dir / "approval-gate.json")
        if (child_dir / "integration-request.json").is_file():
            evidence["integration_request_path"] = str(child_dir / "integration-request.json")
        if (child_dir / "integration-record.json").is_file():
            evidence["integration_record_path"] = str(child_dir / "integration-record.json")
        if landed_sha:
            evidence["landed_sha"] = landed_sha
            evidence["completion_confirmed"] = True
        evidence["task_gid"] = task_gid
        evidence["parent_task_url"] = f"https://app.asana.com/0/0/{task_gid}"
        evidence["child_task_url"] = f"https://app.asana.com/0/{task_gid}/{child_gid}"
        pr_url = str((pr_info.get("url") or pr_info.get("html_url") or "") if pr_info else "").strip()
        if pr_url:
            evidence["pr_url"] = pr_url
        evidence["reviewed_revision"] = app_rev
        evidence["tested_revision"] = tested_sha
        evidence["original_base_sha"] = base_sha

        return _finish(
            final_status, blockers, child_payload, measurements, evidence,
            pr_opened=(pr_info is not None), ci_verified=ci_ok, delivery_approved=delivery_approved,
            approval_outcome=app_out, approved_revision=app_rev, candidate_sha=candidate_sha,
            base_sha=base_sha, tested_sha=tested_sha, revision_kind=rev_kind, approval=approval_rec,
            merged=merged, landed_sha=landed_sha, integration=integration_rec,
            policy_consumption=policy_consumption,
        )
    except AttemptTimeoutError as exc:
        measurements["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        child_timeout_payload = {"gid": child_gid, "name": child["name"], "status": "timed-out", "verified": False, "pr": pr_info, "policy_consumption": policy_consumption}
        return _finish("timed-out", [str(exc)], child_timeout_payload, measurements, base_evidence, pr_opened=(pr_info is not None), policy_consumption=policy_consumption)
    finally:
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)


def run_from_cli(paths: RuntimePaths, args: object) -> DeliverResult:
    in_rate = getattr(args, "input_rate_usd_per_1m", None)
    out_rate = getattr(args, "output_rate_usd_per_1m", None)
    if (in_rate is None) != (out_rate is None):
        raise UsageError("deliver requires both --input-rate-usd-per-1m and --output-rate-usd-per-1m when estimating cost")
    rates = worker_module.RateCard(float(in_rate), float(out_rate)) if in_rate is not None and out_rate is not None else None
    p_sel = getattr(args, "policy_selection", None)
    p_rep = getattr(args, "policy_report", None)
    p_prf = getattr(args, "policy_proof", None)
    p_prp = getattr(args, "policy_proposal", None)
    p_repo = getattr(args, "policy_repo", None)
    if p_sel:
        sel_data = json.loads(Path(p_sel).read_text(encoding="utf-8"))
        p_rep = p_rep or sel_data.get("report") or sel_data.get("report_path")
        p_prf = p_prf or sel_data.get("proof") or sel_data.get("proof_path")
        p_prp = p_prp or sel_data.get("proposal") or sel_data.get("proposal_path")
        p_repo = p_repo or sel_data.get("repo") or sel_data.get("repo_path")
    spec = DeliverSpec(
        task_ref=str(getattr(args, "task") or ""),
        time_limit_seconds=parse_duration(str(getattr(args, "time_limit") or "15m")),
        agy_bin=str(getattr(args, "agy_bin") or "agy"),
        rates=rates,
        policy_report=p_rep,
        policy_proof=p_prf,
        policy_proposal=p_prp,
        policy_repo=p_repo,
    )
    return deliver_feature(paths, spec)
