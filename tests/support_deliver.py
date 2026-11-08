"""Reusable disposable delivery workspace setup and evidence fixtures."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import copy, json, os, shutil, sys, time, unittest.mock
from pathlib import Path
from typing import Any

from automated_qa.test_automated_qa_eval import _case
from factory import automated_qa, config as config_module, deliver as deliver_module, gitio, independent_review, runner, security_review
from factory.paths import RuntimePaths, atomic_json, read_json, safe_dir
from support import git
from test_deliver import (
    GOOD_BUILDER_SCRIPT, PARENT_TASK, READY_CHILD,
    _DisposableGitHubServer, _make_disposable_product_workspace, _make_fake_agy,
)
from test_intake import _DisposableAsanaServer
from tests.independent_review.test_independent_review import _make_staged_reviewer_script
from tests.security_review.test_reviewer import REVIEWER_SCRIPT as SEC_REVIEWER_SCRIPT


@dataclass
class DeliveryContext:
    root: Path
    repo: Path
    home: Path
    bare: Path
    paths: RuntimePaths
    conf: config_module.Config
    spec: deliver_module.DeliverSpec
    asana: _DisposableAsanaServer
    gh: _DisposableGitHubServer
    cand_sha: str
    base_sha: str
    head_branch: str
    att_dir: Path
    child_dir: Path
    backup_child_dir: Path
    intake_rec: dict[str, Any]
    child_contract: dict[str, Any]
    valid_snapshots: dict[str, Any]
    builder_agy: Path
    sec_agy: Path
    ir_agy: Path

    def restore_valid_evidence(self) -> None:
        """Restore all 4 prerequisites to the pristine valid state."""
        if self.child_dir.exists():
            shutil.rmtree(self.child_dir)
        shutil.copytree(self.backup_child_dir, self.child_dir)
        (self.child_dir / "approval-gate.json").unlink(missing_ok=True)
        (self.child_dir / "integration-request.json").unlink(missing_ok=True)
        (self.child_dir / "integration-record.json").unlink(missing_ok=True)
        atomic_json(self.att_dir / "record.json", copy.deepcopy(self.valid_snapshots["att_record"]), self.home)
        atomic_json(self.home / "deliveries" / "900" / "record.json", copy.deepcopy(self.valid_snapshots["att_record"]), self.home)
        b_branch = str(self.intake_rec["parent"]["target_feature_branch"])
        git(self.bare, "branch", "-f", b_branch, self.base_sha)
        git(self.bare, "branch", "-f", self.head_branch, self.cand_sha)
        git(self.repo, "fetch", "origin")
        if 1 in self.gh.pulls:
            self.gh.pulls[1]["state"] = "open"
            self.gh.pulls[1]["merged"] = False
            self.gh.pulls[1]["merge_commit_sha"] = None
        self.gh.merge_status = 200
        self.gh.disconnect_after_merge = False
        self.gh.branch_protections = None
        self.gh.protection_status = 200


@contextmanager
def setup_disposable_delivery_context(root: Path):
    """Build a disposable product workspace with all 4 prerequisites fully valid."""
    repo, home, bare = _make_disposable_product_workspace(root)
    paths = RuntimePaths(repo=repo, home=home)
    conf = config_module.load(paths)
    builder_agy = _make_fake_agy(root, "agy-builder", GOOD_BUILDER_SCRIPT)
    sec_agy = _make_fake_agy(root, "agy-sec", SEC_REVIEWER_SCRIPT)
    ir_agy = _make_fake_agy(root, "agy-ir", _make_staged_reviewer_script())
    spec = deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=60, agy_bin=str(builder_agy))

    with ExitStack() as stack:
        asana = stack.enter_context(_DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]))
        gh = stack.enter_context(_DisposableGitHubServer(bare_repo=bare))
        stack.enter_context(unittest.mock.patch.dict(os.environ, {
            "TURBO_ASANA_API_URL": asana.base_url,
            "ASANA_ACCESS_TOKEN": "disposable-asana-token",
            "TURBO_GITHUB_API_URL": gh.base_url,
            "TURBO_GITHUB_TOKEN": "disposable-gh-token",
        }))

        r_ci = deliver_module.deliver_feature(paths, spec)
        assert r_ci.status == "qa-missing" and r_ci.ci_verified and not r_ci.delivery_approved, r_ci
        cand_sha, base_sha = str(r_ci.candidate_sha), str(r_ci.base_sha)
        head_branch = str(r_ci.child["head_branch"])
        att_dir = Path(r_ci.evidence["attempt_dir"])
        child_dir = att_dir / "children" / "101"
        intake_rec = json.loads(Path(r_ci.evidence["intake_record_path"]).read_text(encoding="utf-8"))
        child_contract = intake_rec["children"][0]

        qa_rec = automated_qa.evaluate_child_qa(
            repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url,
            token="disposable-gh-token", repo_slug="example/chat-bridge",
            parent=intake_rec["parent"], child=child_contract, child_record=r_ci.child,
            conf=conf, qa_cases=(_case("QA-AC-1"),), round_number=1,
            deadline=time.monotonic() + 30.0, limit_s=30,
        )
        assert qa_rec["qa_verified"], qa_rec

        sec_rec = security_review.review_candidate_security(
            repo=repo, home=home, child_dir=child_dir, child=child_contract,
            conf=conf, base_sha=base_sha, candidate_sha=cand_sha, round_num=1,
            agy_bin=str(sec_agy), builder_session_id="c-101",
            deadline=time.monotonic() + 30.0, limit_s=30,
        )
        assert sec_rec["ready"], sec_rec

        ir_rec = independent_review.review_candidate_independently(
            repo=repo, home=home, child_dir=child_dir, child=child_contract,
            conf=conf, base_sha=base_sha, candidate_sha=cand_sha, round_num=1,
            agy_bin=str(ir_agy), builder_session_id="c-101",
            builder_summary="Implemented expired token check and test.",
            qa_record=qa_rec, security_record=sec_rec,
            deadline=time.monotonic() + 30.0, limit_s=30,
        )
        assert ir_rec["review_verified"], ir_rec

        backup_child_dir = root / "backup-child-101"
        shutil.copytree(child_dir, backup_child_dir)

        valid_snapshots = {
            "ci": read_json(child_dir / "ci-verification.json", home),
            "qa_round": read_json(child_dir / "automated-qa" / "round-1" / "record.json", home),
            "qa_summary": read_json(child_dir / "automated-qa" / "record.json", home),
            "sec": read_json(child_dir / "security-review.json", home),
            "ir": read_json(child_dir / "independent-review.json", home),
            "att_record": copy.deepcopy(read_json(att_dir / "record.json", home)),
        }

        ctx = DeliveryContext(
            root=root, repo=repo, home=home, bare=bare, paths=paths, conf=conf,
            spec=spec, asana=asana, gh=gh, cand_sha=cand_sha, base_sha=base_sha,
            head_branch=head_branch, att_dir=att_dir, child_dir=child_dir,
            backup_child_dir=backup_child_dir, intake_rec=intake_rec,
            child_contract=child_contract, valid_snapshots=valid_snapshots,
            builder_agy=builder_agy, sec_agy=sec_agy, ir_agy=ir_agy,
        )
        yield ctx


PROVENANCE_NOTE = (
    "disposable fixture run; does not establish live Antigravity or hosted-provider support, "
    "merge approval, or parent acceptance."
)


def run_delivery_lifecycle_demo(evidence_dir: Path) -> dict[str, Any]:
    """Execute four-stage disposable delivery approval demonstration and retain evidence."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stages_dir = evidence_dir / "stages"
    stages_dir.mkdir(parents=True, exist_ok=True)
    workspace_root = evidence_dir / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)

    factory_rev_res = gitio.git(Path(__file__).resolve().parents[1], "rev-parse", "HEAD")
    factory_rev = factory_rev_res.output.strip() if factory_rev_res.ok else "unknown"

    commands_log: list[dict[str, Any]] = []

    def record_cmd(stage: int, cmd_name: str, argv: list[str], exit_code: int, ok: bool, output: str = "") -> None:
        commands_log.append({
            "stage": stage, "command": cmd_name, "argv": argv,
            "exit_code": exit_code, "ok": ok, "output_preview": output[:200],
        })

    vcmd = "python3 -c \"import pathlib, sys; sys.exit(0 if '# lifecycle-token-guard' in pathlib.Path('src/chat_bridge/auth.py').read_text() else 1)\""
    fid = independent_review.compute_review_finding_id("bug", "src/chat_bridge/auth.py", "lifecycle-token-guard")
    finding_contract = {
        "finding_id": fid, "category": "bug", "blocking": True,
        "target": "src/chat_bridge/auth.py", "rule": "lifecycle-token-guard",
        "title": "Missing token expiry guard", "evidence": "seeded lifecycle bug",
        "actionable_correction": "Add # lifecycle-token-guard to auth.py",
        "verification_command": vcmd,
    }

    def _snapshot_stage(stage_num: int, stage_name: str, cand_sha: str, base_sha: str,
                        delivery_res: Any, gate_rec: dict[str, Any] | None, extra: dict[str, Any]) -> dict[str, Any]:
        sdir = stages_dir / f"stage-{stage_num}-{stage_name}"
        sdir.mkdir(parents=True, exist_ok=True)
        atomic_json(sdir / "delivery-result.json", delivery_res.to_dict() if hasattr(delivery_res, "to_dict") else delivery_res, evidence_dir)
        if gate_rec:
            atomic_json(sdir / "approval-gate.json", gate_rec, evidence_dir)
        summary = {
            "stage": stage_num, "name": stage_name, "candidate_sha": cand_sha,
            "base_sha": base_sha, "delivery_approved": getattr(delivery_res, "delivery_approved", False),
            "status": getattr(delivery_res, "status", "unknown"),
            "merged": getattr(delivery_res, "merged", False),
            "landed_sha": getattr(delivery_res, "landed_sha", None),
            "approved_revision": getattr(delivery_res, "approved_revision", None),
            "blockers": list(getattr(delivery_res, "blockers", [])),
            **extra,
        }
        atomic_json(sdir / "stage-summary.json", summary, evidence_dir)
        return summary

    repo, home, bare = _make_disposable_product_workspace(workspace_root)
    paths = RuntimePaths(repo=repo, home=home)
    conf = config_module.load(paths)
    builder_agy = _make_fake_agy(workspace_root, "agy-builder", GOOD_BUILDER_SCRIPT)
    sec_agy = _make_fake_agy(workspace_root, "agy-sec", SEC_REVIEWER_SCRIPT)
    spec = deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=60, agy_bin=str(builder_agy))

    with (
        _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}]) as asana,
        _DisposableGitHubServer(bare_repo=bare) as gh,
        unittest.mock.patch.dict(os.environ, {
            "TURBO_ASANA_API_URL": asana.base_url,
            "ASANA_ACCESS_TOKEN": "disposable-asana-token",
            "TURBO_GITHUB_API_URL": gh.base_url,
            "TURBO_GITHUB_TOKEN": "disposable-gh-token",
        }),
    ):

        # Attempt 1: Deliver initial candidate (stops at missing QA)
        r_init = deliver_module.deliver_feature(paths, spec)
        cand_1, base_sha = str(r_init.candidate_sha), str(r_init.base_sha)
        head_branch = str(r_init.child["head_branch"])
        att_dir = Path(r_init.evidence["attempt_dir"])
        child_dir = att_dir / "children" / "101"
        intake_rec = json.loads(Path(r_init.evidence["intake_record_path"]).read_text(encoding="utf-8"))
        child_contract = intake_rec["children"][0]
        record_cmd(0, "deliver_feature_init", ["deliver", "--task", "900"], 0, True, f"cand_1={cand_1}")

        # QA and Security pass for candidate 1
        qa_rec_1 = automated_qa.evaluate_child_qa(
            repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url,
            token="disposable-gh-token", repo_slug="example/chat-bridge",
            parent=intake_rec["parent"], child=child_contract, child_record=r_init.child,
            conf=conf, qa_cases=(_case("QA-AC-1"),), round_number=1,
            deadline=time.monotonic() + 30.0, limit_s=30,
        )
        sec_rec_1 = security_review.review_candidate_security(
            repo=repo, home=home, child_dir=child_dir, child=child_contract,
            conf=conf, base_sha=base_sha, candidate_sha=cand_1, round_num=1,
            agy_bin=str(sec_agy), builder_session_id="c-101",
            deadline=time.monotonic() + 30.0, limit_s=30,
        )

        # STAGE 1: Blocker identified by reviewer; delivery rejects
        script_r1 = _make_staged_reviewer_script(
            session_id="rev-s1", outcome="changes-requested",
            findings=[finding_contract],
        )
        ir_agy_1 = _make_fake_agy(workspace_root, "agy-ir-s1", script_r1)
        r1_rev = independent_review.review_candidate_independently(
            repo=repo, home=home, child_dir=child_dir, child=child_contract,
            conf=conf, base_sha=base_sha, candidate_sha=cand_1, round_num=1,
            agy_bin=str(ir_agy_1), builder_session_id="c-101",
            builder_summary="Candidate 1 built.", qa_record=qa_rec_1,
            security_record=sec_rec_1, deadline=time.monotonic() + 30.0, limit_s=30,
        )
        record_cmd(1, "independent_review_round_1", ["review_candidate_independently", "round=1"], 0, False, "changes-requested")

        r_stage1 = deliver_module.deliver_feature(paths, spec)
        record_cmd(1, "deliver_feature_stage1", ["deliver_feature"], 0, r_stage1.delivery_approved, f"status={r_stage1.status}")
        gate_1 = json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8")) if (child_dir / "approval-gate.json").is_file() else None
        assert not r_stage1.delivery_approved and r_stage1.status == "changes-requested" and r_stage1.approved_revision is None, r_stage1
        stage1_summary = _snapshot_stage(1, "blocker", cand_1, base_sha, r_stage1, gate_1, {
            "finding_id": fid, "finding_status": "open", "reproducer_command": vcmd,
        })

        # STAGE 2: Ineffective correction; reviewer claims fix but reproducer fails; delivery rejects
        git(repo, "checkout", "-q", head_branch)
        (repo / "src" / "chat_bridge" / "auth.py").write_text((repo / "src" / "chat_bridge" / "auth.py").read_text(encoding="utf-8") + "# ineffective attempt\n", encoding="utf-8")
        git(repo, "add", "src/chat_bridge/auth.py")
        git(repo, "commit", "-q", "-m", "fix: ineffective token correction")
        cand_2 = git(repo, "rev-parse", "HEAD")
        git(repo, "push", "-q", "origin", f"{cand_2}:refs/heads/{head_branch}")
        git(repo, "checkout", "-q", "main")
        gh.pulls[1]["head"]["sha"] = cand_2
        record_cmd(2, "git_commit_ineffective", ["git", "commit", "-m", "ineffective"], 0, True, f"cand_2={cand_2}")

        # Refresh CI for cand_2
        ci_b = json.loads((child_dir / "ci-verification.json").read_text(encoding="utf-8"))
        b_checks = []
        for idx, c in enumerate(ci_b.get("checks", [])):
            txt = f"candidate_sha={cand_2}\nbase_sha={base_sha}\ntested_sha={cand_2}\nrevision_kind=fast-forward-head\ncheck ok\n"
            lp = child_dir / f"ci-cand2-{idx}.log"
            lp.write_text(txt, encoding="utf-8")
            b_checks.append({**c, "candidate_sha": cand_2, "tested_sha": cand_2, "revision_kind": "fast-forward-head", "output_path": str(lp), "output_sha256": runner.digest_text(txt)})
        ci_cand2 = {**ci_b, "candidate_sha": cand_2, "tested_sha": cand_2, "revision_kind": "fast-forward-head", "checks": b_checks, "pr": {**ci_b["pr"], "head_sha": cand_2}}
        atomic_json(child_dir / "ci-verification.json", ci_cand2, home)

        contract_cand2 = {**child_contract, "candidate_sha": cand_2}
        child_rec_cand2 = {**r_stage1.child, "status": "verified", "verified": True, "candidate_sha": cand_2, "tested_sha": cand_2, "revision_kind": "fast-forward-head", "ci_verification": ci_cand2, "pr": {**r_stage1.child["pr"], "head_sha": cand_2}}

        qa_rec_2 = automated_qa.evaluate_child_qa(
            repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url,
            token="disposable-gh-token", repo_slug="example/chat-bridge",
            parent=intake_rec["parent"], child=contract_cand2, child_record=child_rec_cand2,
            conf=conf, qa_cases=(_case("QA-AC-1"),), round_number=2,
            deadline=time.monotonic() + 30.0, limit_s=30,
        )
        sec_rec_2 = security_review.review_candidate_security(
            repo=repo, home=home, child_dir=child_dir, child=contract_cand2,
            conf=conf, base_sha=base_sha, candidate_sha=cand_2, round_num=2,
            agy_bin=str(sec_agy), builder_session_id="c-101",
            deadline=time.monotonic() + 30.0, limit_s=30,
        )

        # Reviewer claims fix, but reproducer execution against cand_2 worktree fails
        script_r2 = _make_staged_reviewer_script(
            session_id="rev-s2", outcome="review-passed",
            reconciliations=[{"finding_id": fid, "resolution": "fixed", "evidence": "claimed fix in prose"}],
        )
        ir_agy_2 = _make_fake_agy(workspace_root, "agy-ir-s2", script_r2)
        r2_rev = independent_review.review_candidate_independently(
            repo=repo, home=home, child_dir=child_dir, child=contract_cand2,
            conf=conf, base_sha=base_sha, candidate_sha=cand_2, round_num=2,
            agy_bin=str(ir_agy_2), builder_session_id="c-101",
            builder_summary="Attempted fix on cand 2.", qa_record=qa_rec_2,
            security_record=sec_rec_2, deadline=time.monotonic() + 30.0, limit_s=30,
        )
        record_cmd(2, "independent_review_round_2", ["review_candidate_independently", "round=2"], 0, False, "reproducer failed")
        assert not r2_rev["review_verified"] and fid in r2_rev["open_finding_ids"], r2_rev

        (child_dir / "approval-gate.json").unlink(missing_ok=True)
        r_stage2 = deliver_module.deliver_feature(paths, spec)
        record_cmd(2, "deliver_feature_stage2", ["deliver_feature"], 0, r_stage2.delivery_approved, f"status={r_stage2.status}")
        gate_2 = json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8")) if (child_dir / "approval-gate.json").is_file() else None
        assert not r_stage2.delivery_approved and r_stage2.approved_revision is None and r_stage2.candidate_sha == cand_2, r_stage2
        stage2_summary = _snapshot_stage(2, "ineffective", cand_2, base_sha, r_stage2, gate_2, {
            "finding_id": fid, "finding_status": "open", "resolution_blocker": "check-failed",
            "reproducer_command": vcmd, "reproducer_executed": True, "reproducer_ok": False,
        })

        # STAGE 3: Verified correction; candidate implements fix; reproducer passes; delivery APPROVES
        git(repo, "checkout", "-q", head_branch)
        (repo / "src" / "chat_bridge" / "auth.py").write_text((repo / "src" / "chat_bridge" / "auth.py").read_text(encoding="utf-8") + "# lifecycle-token-guard\n", encoding="utf-8")
        git(repo, "add", "src/chat_bridge/auth.py")
        git(repo, "commit", "-q", "-m", "fix: genuine token guard fix")
        cand_3 = git(repo, "rev-parse", "HEAD")
        git(repo, "push", "-q", "origin", f"{cand_3}:refs/heads/{head_branch}")
        git(repo, "checkout", "-q", "main")
        gh.pulls[1]["head"]["sha"] = cand_3
        record_cmd(3, "git_commit_genuine_fix", ["git", "commit", "-m", "genuine fix"], 0, True, f"cand_3={cand_3}")

        # Refresh CI for cand_3
        c_checks = []
        for idx, c in enumerate(ci_b.get("checks", [])):
            txt = f"candidate_sha={cand_3}\nbase_sha={base_sha}\ntested_sha={cand_3}\nrevision_kind=fast-forward-head\ncheck ok\n"
            lp = child_dir / f"ci-cand3-{idx}.log"
            lp.write_text(txt, encoding="utf-8")
            c_checks.append({**c, "candidate_sha": cand_3, "tested_sha": cand_3, "revision_kind": "fast-forward-head", "output_path": str(lp), "output_sha256": runner.digest_text(txt)})
        ci_cand3 = {**ci_b, "candidate_sha": cand_3, "tested_sha": cand_3, "revision_kind": "fast-forward-head", "checks": c_checks, "pr": {**ci_b["pr"], "head_sha": cand_3}}
        atomic_json(child_dir / "ci-verification.json", ci_cand3, home)

        contract_cand3 = {**child_contract, "candidate_sha": cand_3}
        child_rec_cand3 = {**r_stage2.child, "status": "verified", "verified": True, "candidate_sha": cand_3, "tested_sha": cand_3, "revision_kind": "fast-forward-head", "ci_verification": ci_cand3, "pr": {**r_stage2.child["pr"], "head_sha": cand_3}}

        qa_rec_3 = automated_qa.evaluate_child_qa(
            repo=repo, home=home, child_dir=child_dir, base_url=gh.base_url,
            token="disposable-gh-token", repo_slug="example/chat-bridge",
            parent=intake_rec["parent"], child=contract_cand3, child_record=child_rec_cand3,
            conf=conf, qa_cases=(_case("QA-AC-1"),), round_number=3,
            deadline=time.monotonic() + 30.0, limit_s=30,
        )
        sec_rec_3 = security_review.review_candidate_security(
            repo=repo, home=home, child_dir=child_dir, child=contract_cand3,
            conf=conf, base_sha=base_sha, candidate_sha=cand_3, round_num=3,
            agy_bin=str(sec_agy), builder_session_id="c-101",
            deadline=time.monotonic() + 30.0, limit_s=30,
        )

        script_r3 = _make_staged_reviewer_script(
            session_id="rev-s3", outcome="review-passed",
            reconciliations=[{"finding_id": fid, "resolution": "fixed", "evidence": "token guard genuinely verified"}],
        )
        ir_agy_3 = _make_fake_agy(workspace_root, "agy-ir-s3", script_r3)
        r3_rev = independent_review.review_candidate_independently(
            repo=repo, home=home, child_dir=child_dir, child=contract_cand3,
            conf=conf, base_sha=base_sha, candidate_sha=cand_3, round_num=3,
            agy_bin=str(ir_agy_3), builder_session_id="c-101",
            builder_summary="Genuine fix implemented.", qa_record=qa_rec_3,
            security_record=sec_rec_3, deadline=time.monotonic() + 30.0, limit_s=30,
        )
        record_cmd(3, "independent_review_round_3", ["review_candidate_independently", "round=3"], 0, True, "review-passed")
        assert r3_rev["review_verified"] and r3_rev["open_finding_ids"] == [], r3_rev

        (child_dir / "approval-gate.json").unlink(missing_ok=True)
        r_stage3 = deliver_module.deliver_feature(paths, spec)
        record_cmd(3, "deliver_feature_stage3", ["deliver_feature"], 0, r_stage3.delivery_approved, f"status={r_stage3.status}")
        gate_3 = json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8"))
        assert r_stage3.delivery_approved and r_stage3.status == "completed" and r_stage3.merged and r_stage3.approved_revision == cand_3 and r_stage3.candidate_sha == cand_3, r_stage3
        stage3_summary = _snapshot_stage(3, "verified", cand_3, base_sha, r_stage3, gate_3, {
            "finding_id": fid, "finding_status": "resolved", "reproducer_command": vcmd,
            "reproducer_executed": True, "reproducer_ok": True, "reconciliation_history_rounds": len(r3_rev["findings"][0]["history"]),
        })

        # STAGE 4: Subsequent revision; candidate advances; stale approval reuse rejected
        git(repo, "checkout", "-q", head_branch)
        (repo / "src" / "chat_bridge" / "auth.py").write_text((repo / "src" / "chat_bridge" / "auth.py").read_text(encoding="utf-8") + "# subsequent revision\n", encoding="utf-8")
        git(repo, "add", "src/chat_bridge/auth.py")
        git(repo, "commit", "-q", "-m", "chore: subsequent post-approval modification")
        cand_4 = git(repo, "rev-parse", "HEAD")
        git(repo, "push", "-q", "origin", f"{cand_4}:refs/heads/{head_branch}")
        git(repo, "checkout", "-q", "main")
        gh.pulls[1]["head"]["sha"] = cand_4
        record_cmd(4, "git_commit_subsequent", ["git", "commit", "-m", "subsequent"], 0, True, f"cand_4={cand_4}")

        r_stage4 = deliver_module.deliver_feature(paths, spec)
        record_cmd(4, "deliver_feature_stage4", ["deliver_feature"], 0, r_stage4.delivery_approved, f"status={r_stage4.status}")
        gate_4 = json.loads((child_dir / "approval-gate.json").read_text(encoding="utf-8"))
        assert not r_stage4.delivery_approved and r_stage4.approved_revision is None and r_stage4.candidate_sha == cand_4, r_stage4
        assert r_stage4.status in ("stale-candidate-revision", "stale-ci-evidence"), r_stage4
        stage4_summary = _snapshot_stage(4, "subsequent-stale", cand_4, base_sha, r_stage4, gate_4, {
            "prior_approved_revision": cand_3,
        })

    summary: dict[str, Any] = {
        "demo": "four-stage-disposable-delivery-approval",
        "provenance": PROVENANCE_NOTE,
        "factory_revision": factory_rev,
        "finding_id": fid,
        "reconciliation_history_preserved": True,
        "stages": {
            "stage_1_blocker": stage1_summary,
            "stage_2_ineffective": stage2_summary,
            "stage_3_verified": stage3_summary,
            "stage_4_subsequent_stale": stage4_summary,
        },
        "commands": commands_log,
        "success": True,
    }
    atomic_json(evidence_dir / "lifecycle-summary.json", summary, evidence_dir)
    return summary


def run_integration_demo(evidence_dir: Path) -> dict[str, Any]:
    """Execute five-stage disposable child integration demonstration and retain evidence."""
    from factory.integration import integrate_approved_child
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stages_dir = safe_dir(evidence_dir / "stages", create=True)
    if (evidence_dir / "workspace").exists():
        shutil.rmtree(evidence_dir / "workspace", ignore_errors=True)
    ws_root = safe_dir(evidence_dir / "workspace", create=True)
    factory_rev_res = gitio.git(Path(__file__).resolve().parents[1], "rev-parse", "HEAD")
    factory_rev = factory_rev_res.output.strip() if factory_rev_res.ok else "unknown"

    with setup_disposable_delivery_context(ws_root) as ctx:
        b_branch, h_branch = str(ctx.intake_rec["parent"]["target_feature_branch"]), ctx.head_branch
        gate = deliver_module.enforce_delivery_approval(
            candidate_sha=ctx.cand_sha, base_sha=ctx.base_sha, repo=ctx.repo, home=ctx.home,
            child_dir=ctx.child_dir, child=ctx.child_contract, conf=ctx.conf,
        )
        assert gate.get("delivery_approved") is True

        def _run_stage(num: int, name: str, **kw: Any) -> Any:
            sdir = safe_dir(stages_dir / f"stage-{num}-{name}", create=True)
            for fn in ("integration-request.json", "integration-record.json"):
                (ctx.child_dir / fn).unlink(missing_ok=True)
            res = integrate_approved_child(
                repo=kw.get("repo", ctx.repo), home=ctx.home, child_dir=ctx.child_dir,
                child=ctx.child_contract, conf=ctx.conf, pr_number=1,
                candidate_sha=kw.get("cand", ctx.cand_sha), base_sha=kw.get("base", ctx.base_sha),
                head_branch=h_branch, base_branch=b_branch, approval_record=gate,
                repo_slug="example/chat-bridge", base_url=ctx.gh.base_url, token="disposable-gh-token",
                on_before_merge=kw.get("hook"),
            )
            for fn in ("integration-request.json", "integration-record.json"):
                if (ctx.child_dir / fn).is_file(): shutil.copy(ctx.child_dir / fn, sdir / fn)
            return res

        # 1. Success
        git(ctx.bare, "branch", "-f", b_branch, ctx.base_sha); git(ctx.bare, "branch", "-f", h_branch, ctx.cand_sha); git(ctx.repo, "fetch", "origin")
        r1 = _run_stage(1, "success")
        assert r1.status == "confirmed" and r1.landed_sha is not None

        # 2. Competing base
        git(ctx.bare, "branch", "-f", b_branch, ctx.base_sha); git(ctx.bare, "branch", "-f", h_branch, ctx.cand_sha); git(ctx.repo, "fetch", "origin")
        ctx.gh.pulls[1]["state"], ctx.gh.pulls[1]["merged"] = "open", False
        def _adv(): git(ctx.bare, "update-ref", f"refs/heads/{b_branch}", git(ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test", "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Comp"), ctx.base_sha)
        r2 = _run_stage(2, "competing-base", hook=_adv)
        assert r2.status == "rejected-competing-base"

        # 3. Stale approval
        r3 = _run_stage(3, "stale-approval", base="0" * 40)
        assert r3.status == "stale-candidate-revision"

        # 4. Unsupported protection
        git(ctx.bare, "branch", "-f", b_branch, ctx.base_sha)
        ctx.gh.branch_protections = {}
        r4 = _run_stage(4, "unsupported-protection")
        assert r4.status == "unsupported-protection"
        ctx.gh.branch_protections = None

        # 5. Uncertain outcome
        ctx.gh.merge_status = 502
        r5 = _run_stage(5, "uncertain-timeout")
        assert r5.status == "uncertain"
        ctx.gh.merge_status = 200

    summary = {
        "demo": "five-stage-child-integration-lifecycle", "provenance": PROVENANCE_NOTE, "factory_revision": factory_rev,
        "stages": {
            "stage_1_success": {"status": r1.status, "landed_sha": r1.landed_sha},
            "stage_2_competing_base": {"status": r2.status, "blockers": r2.blockers},
            "stage_3_stale_approval": {"status": r3.status, "blockers": r3.blockers},
            "stage_4_unsupported_protection": {"status": r4.status, "blockers": r4.blockers},
            "stage_5_uncertain_timeout": {"status": r5.status, "blockers": r5.blockers},
        },
        "success": True,
    }
    atomic_json(evidence_dir / "integration-demo-summary.json", summary, evidence_dir)
    return summary


def run_delivery_integration_demo(evidence_dir: Path) -> dict[str, Any]:
    """Execute four-stage disposable delivery integration demonstration and retain evidence (#78)."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stages_dir = safe_dir(evidence_dir / "stages", create=True)
    if (evidence_dir / "workspace").exists():
        shutil.rmtree(evidence_dir / "workspace", ignore_errors=True)
    ws_root = safe_dir(evidence_dir / "workspace", create=True)
    factory_rev_res = gitio.git(Path(__file__).resolve().parents[1], "rev-parse", "HEAD")
    factory_rev = factory_rev_res.output.strip() if factory_rev_res.ok else "unknown"

    with setup_disposable_delivery_context(ws_root) as ctx:
        main_sha_before = git(ctx.bare, "rev-parse", "refs/heads/main")
        commands_log: list[dict[str, Any]] = []

        def _record_cmd(stage: int, cmd_name: str, argv: list[str], exit_code: int, ok: bool, output: str = "") -> None:
            commands_log.append({
                "stage": stage, "command": cmd_name, "argv": argv,
                "exit_code": exit_code, "ok": ok, "output_preview": output[:200],
            })

        def _snapshot_demo_stage(stage_num: int, stage_name: str, res: Any, extra: dict[str, Any]) -> dict[str, Any]:
            sdir = stages_dir / f"stage-{stage_num}-{stage_name}"
            sdir.mkdir(parents=True, exist_ok=True)
            atomic_json(sdir / "delivery-result.json", res.to_dict() if hasattr(res, "to_dict") else res, evidence_dir)
            gate_p = ctx.child_dir / "approval-gate.json"
            if gate_p.is_file():
                shutil.copy2(gate_p, sdir / "approval-gate.json")
            req_p = ctx.child_dir / "integration-request.json"
            if req_p.is_file():
                shutil.copy2(req_p, sdir / "integration-request.json")
            rec_p = ctx.child_dir / "integration-record.json"
            if rec_p.is_file():
                shutil.copy2(rec_p, sdir / "integration-record.json")
            summary = {
                "stage": stage_num, "name": stage_name, "status": getattr(res, "status", "unknown"),
                "delivery_approved": getattr(res, "delivery_approved", False),
                "approval_outcome": getattr(res, "approval_outcome", "rejected"),
                "approved_revision": getattr(res, "approved_revision", None),
                "merged": getattr(res, "merged", False),
                "landed_sha": getattr(res, "landed_sha", None),
                "blockers": list(getattr(res, "blockers", [])),
                **extra,
            }
            atomic_json(sdir / "stage-summary.json", summary, evidence_dir)
            return summary

        # STAGE 1: Confirmed delivery success
        ctx.restore_valid_evidence()
        r1 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
        _record_cmd(1, "deliver_feature_success", ["deliver_feature"], 0, r1.status == "completed", f"status={r1.status}")
        assert r1.status == "completed" and r1.merged and r1.landed_sha, r1
        assert git(ctx.bare, "rev-parse", "refs/heads/main") == main_sha_before
        s1 = _snapshot_demo_stage(1, "success", r1, {
            "completion_confirmed": r1.evidence.get("completion_confirmed", False),
            "original_base_sha": ctx.base_sha,
            "candidate_sha": ctx.cand_sha,
        })

        # STAGE 2: Stale-base rejection
        ctx.restore_valid_evidence()
        new_base = git(
            ctx.bare, "-c", "user.name=CI", "-c", "user.email=ci@test",
            "commit-tree", f"{ctx.base_sha}^{{tree}}", "-p", ctx.base_sha, "-m", "Advanced base",
        )
        git(ctx.bare, "update-ref", f"refs/heads/{ctx.intake_rec['parent']['target_feature_branch']}", new_base, ctx.base_sha)
        git(ctx.repo, "fetch", "origin")
        r2 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
        _record_cmd(2, "deliver_feature_stale_base", ["deliver_feature"], 0, not r2.merged, f"status={r2.status}")
        assert r2.status != "completed" and not r2.merged and r2.landed_sha is None, r2
        assert not ctx.gh.pulls[1]["merged"]
        s2 = _snapshot_demo_stage(2, "stale-base", r2, {
            "advanced_base_sha": new_base,
            "original_base_sha": ctx.base_sha,
        })

        # STAGE 3: Permission denial
        ctx.restore_valid_evidence()
        ctx.gh.merge_status = 403
        r3 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
        _record_cmd(3, "deliver_feature_denied", ["deliver_feature"], 0, r3.status == "denied-permissions", f"status={r3.status}")
        assert r3.status == "denied-permissions" and r3.delivery_approved and not r3.merged and r3.landed_sha is None, r3
        assert not ctx.gh.pulls[1]["merged"]
        ctx.gh.merge_status = 200
        s3 = _snapshot_demo_stage(3, "denied", r3, {
            "delivery_approved": r3.delivery_approved,
            "denial_reason": "denied-permissions",
        })

        # STAGE 4: Uncertain outcome with retained evidence
        ctx.restore_valid_evidence()
        ctx.gh.merge_status = 502
        r4 = deliver_module.deliver_feature(ctx.paths, ctx.spec)
        _record_cmd(4, "deliver_feature_uncertain", ["deliver_feature"], 0, r4.status == "uncertain", f"status={r4.status}")
        assert r4.status == "uncertain" and r4.delivery_approved and not r4.merged and r4.landed_sha is None, r4
        ctx.gh.merge_status = 200
        s4 = _snapshot_demo_stage(4, "uncertain", r4, {
            "delivery_approved": r4.delivery_approved,
            "uncertain_reason": "uncertain",
        })

    summary: dict[str, Any] = {
        "demo": "four-stage-disposable-delivery-integration",
        "provenance": PROVENANCE_NOTE,
        "factory_revision": factory_rev,
        "stages": {
            "stage_1_success": s1,
            "stage_2_stale_base": s2,
            "stage_3_denied": s3,
            "stage_4_uncertain": s4,
        },
        "commands": commands_log,
        "success": True,
    }
    atomic_json(evidence_dir / "delivery-integration-summary.json", summary, evidence_dir)
    return summary

