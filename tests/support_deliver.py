"""Reusable disposable delivery workspace setup and evidence fixtures."""
from __future__ import annotations

from dataclasses import dataclass
import json, os, shutil, sys, time
from pathlib import Path
from typing import Any

from automated_qa.test_automated_qa_eval import _case
from factory import automated_qa, config as config_module, deliver as deliver_module, independent_review, security_review
from factory.paths import RuntimePaths, atomic_json, read_json
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
        atomic_json(self.att_dir / "record.json", self.valid_snapshots["att_record"], self.home)
        atomic_json(self.home / "deliveries" / "900" / "record.json", self.valid_snapshots["att_record"], self.home)


def setup_disposable_delivery_context(root: Path) -> DeliveryContext:
    """Build a disposable product workspace with all 4 prerequisites fully valid."""
    repo, home, bare = _make_disposable_product_workspace(root)
    paths = RuntimePaths(repo=repo, home=home)
    conf = config_module.load(paths)
    builder_agy = _make_fake_agy(root, "agy-builder", GOOD_BUILDER_SCRIPT)
    sec_agy = _make_fake_agy(root, "agy-sec", SEC_REVIEWER_SCRIPT)
    ir_agy = _make_fake_agy(root, "agy-ir", _make_staged_reviewer_script())
    spec = deliver_module.DeliverSpec(task_ref="900", time_limit_seconds=60, agy_bin=str(builder_agy))

    asana = _DisposableAsanaServer(PARENT_TASK, [{"data": [READY_CHILD], "next_page": None}])
    gh = _DisposableGitHubServer(bare_repo=bare)
    asana.__enter__()
    gh.__enter__()
    os.environ["TURBO_ASANA_API_URL"] = asana.base_url
    os.environ["ASANA_ACCESS_TOKEN"] = "disposable-asana-token"
    os.environ["TURBO_GITHUB_API_URL"] = gh.base_url
    os.environ["TURBO_GITHUB_TOKEN"] = "disposable-gh-token"

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
        "att_record": read_json(att_dir / "record.json", home),
    }

    return DeliveryContext(
        root=root, repo=repo, home=home, bare=bare, paths=paths, conf=conf,
        spec=spec, asana=asana, gh=gh, cand_sha=cand_sha, base_sha=base_sha,
        head_branch=head_branch, att_dir=att_dir, child_dir=child_dir,
        backup_child_dir=backup_child_dir, intake_rec=intake_rec,
        child_contract=child_contract, valid_snapshots=valid_snapshots,
        builder_agy=builder_agy, sec_agy=sec_agy, ir_agy=ir_agy,
    )
