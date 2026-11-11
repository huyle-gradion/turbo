"""Authoritative factory-policy promotion gate and exact-version selection (Issue #69, Part B of #32)."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any
import urllib.request

from factory import gitio
from factory.ci_gate import SHA40_RE
from factory.errors import UsageError
from factory.improvement import (
    AUTHORITY_NOTE as IMPROVEMENT_AUTHORITY_NOTE,
    proposal_digest,
    validate_report_for_review,
)

REVIEW_PACKET_SCHEMA_VERSION = 1
REVIEW_PACKET_AUTHORITY_NOTE = "review-packet-only; not approved, submitted, merged, or promoted"

SHARED_POLICY_PREFIXES = ("factory/", "skills/", "bin/", "guards/")
DURABLE_LESSONS_PREFIX = "factory/lessons/"
EXCLUDED_PATH_PREFIXES = ("pilot/", "examples/", "tests/", "evidence/", "attempts/", "homes/", "context/")


@dataclass(frozen=True)
class ResolutionResult:
    """Documented resolver interface contract for #70."""
    status: str
    verified: bool
    selected_version: str | None = None
    content_sha256: str | None = None
    target_path: str | None = None
    kind: str | None = None
    content_bytes: bytes | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)


def validate_storage_path(target_path: str, kind: str) -> tuple[bool, str]:
    """Validates distinct storage contracts for shared factory policy and durable lessons."""
    norm = target_path.replace("\\", "/").lstrip("/")
    for exc in EXCLUDED_PATH_PREFIXES:
        if norm.startswith(exc):
            return False, f"target_path {target_path!r} resides in excluded area {exc!r}; product context, verification instructions, and private observations cannot become shared policy or lessons"
    if kind == "lesson":
        if not norm.startswith(DURABLE_LESSONS_PREFIX) and not norm.startswith("lessons/"):
            return False, f"durable lesson target_path must start with {DURABLE_LESSONS_PREFIX!r}"
    return True, ""


def _format_markdown_packet(packet: dict[str, Any]) -> str:
    prop = packet["proposed_change"]
    obs = packet["observed_failure"]
    exp = packet["expected_improvement"]
    comp = packet["comparison"]
    lines = [
        f"# Factory Improvement Review Packet: {packet['proposal_id']}",
        "",
        f"**Authority Notice**: {packet['authority_note']}",
        "",
        "## Summary",
        f"- **Proposal ID**: `{packet['proposal_id']}`",
        f"- **Proposal Digest**: `{packet['proposal_digest']}`",
        f"- **Candidate Content Digest**: `{packet['candidate_content_digest']}`",
        f"- **Consumed Factory Revision**: `{packet['factory_revision']}`",
        f"- **Baseline Identity**: `{packet['baseline']['identity']}`",
        f"- **Candidate Identity**: `{packet['candidate']['identity']}`",
        "",
        "## Bounded Proposed Change",
        f"- **Kind**: `{prop.get('kind')}`",
        f"- **Target Path**: `{prop.get('target_path')}`",
        f"- **Content SHA256**: `{prop.get('content_sha256')}`",
        "",
        "## Observed Failure & Evidence",
        f"{obs.get('description')}",
        "",
        "### Artifacts",
    ]
    for art in obs.get("artifacts", []):
        lines.append(f"- `{art.get('path')}` (sha256: `{art.get('sha256')}`)")
    lines.extend([
        "",
        "## Expected Improvement",
        f"- **Rule**: `{exp.get('rule')}`",
        f"- **Description**: {exp.get('description')}",
        "",
        "## Evaluation & Regression Comparison",
        f"- **Rule Satisfied**: `{comp.get('rule_satisfied')}`",
        f"- **Baseline Demonstrated Failure**: `{comp.get('baseline_demonstrated_failure')}`",
        f"- **Candidate Demonstrated Success**: `{comp.get('candidate_demonstrated_success')}`",
        f"- **Candidate Regressions Passed**: `{comp.get('candidate_regressions_passed')}`",
        "",
        "### Candidate Improvement Results",
    ])
    for r in packet["candidate_results"].get("improvement_cases", []):
        lines.append(f"- Case `{r.get('case_id')}`: exit={r.get('exit_code')} passed={r.get('rubric_passed')}")
    lines.extend(["", "### Candidate Regression Results"])
    for r in packet["candidate_results"].get("regression_cases", []):
        lines.append(f"- Case `{r.get('case_id')}`: exit={r.get('exit_code')} passed={r.get('rubric_passed')}")
    lines.extend([
        "",
        "## Measurements & Provenance",
        f"- **Baseline**: {json.dumps(packet['measurements'].get('baseline', {}))}",
        f"- **Candidate**: {json.dumps(packet['measurements'].get('candidate', {}))}",
        "",
        "## Submission Instructions",
        packet["submission_instructions"],
    ])
    return "\n".join(lines) + "\n"


def build_review_packet(report: dict[str, Any], *, proposal_json: str | None = None) -> dict[str, Any]:
    issues = validate_report_for_review(report, proposal_json=proposal_json)
    if issues:
        raise UsageError(f"invalid report for review packet: {'; '.join(issues)}")
    if report.get("eligibility") != "improvement-eligible":
        raise UsageError(f"cannot build review packet for ineligible report: {report.get('eligibility')}")
    comp = report.get("comparison", {})
    if not (comp.get("rule_satisfied") and comp.get("baseline_demonstrated_failure") and comp.get("candidate_demonstrated_success") and comp.get("candidate_regressions_passed")):
        raise UsageError("cannot build review packet: comparison rule conditions are not fully satisfied")

    proposal = report["proposal"]
    instructions = (
        "Human maintainer submission workflow:\n"
        "1. Confirm or file a Definition-of-Ready issue on huyle-gradion/turbo.\n"
        "2. Create branch from main as `<type>/issue-N-slug`.\n"
        f"3. Apply candidate bytes at `{proposal['proposed_change']['target_path']}` (sha256: {report['candidate_content_digest']}).\n"
        "4. Run full checks: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v && bash scripts/smoke.sh && bash scripts/smoke-turbo.sh.\n"
        "5. Commit with Conventional Commits and DCO sign-off (`git commit -s`).\n"
        "6. Push branch and open a pull request (PR) with `Closes #N`.\n"
        "7. Request independent review via the maintainer's gh-review workflow.\n"
        "8. A human maintainer merges to main. No auto-merge or agent-promotion."
    )

    packet: dict[str, Any] = {
        "schema_version": REVIEW_PACKET_SCHEMA_VERSION,
        "authority_note": REVIEW_PACKET_AUTHORITY_NOTE,
        "proposal_id": proposal.get("proposal_id"),
        "proposal_digest": report.get("proposal_digest"),
        "candidate_content_digest": report.get("candidate_content_digest"),
        "factory_revision": report.get("factory_revision", "unknown"),
        "baseline": proposal.get("baseline", {}),
        "candidate": proposal.get("candidate", {}),
        "proposed_change": proposal.get("proposed_change", {}),
        "observed_failure": proposal.get("observed_failure", {}),
        "expected_improvement": proposal.get("expected_improvement", {}),
        "comparison": report.get("comparison", {}),
        "baseline_results": report.get("baseline_results", {}),
        "candidate_results": report.get("candidate_results", {}),
        "measurements": report.get("measurements", {}),
        "submission_instructions": instructions,
    }
    packet["markdown_body"] = _format_markdown_packet(packet)
    return packet


def resolve_approved_version(
    *,
    repo: Path,
    report: dict[str, Any],
    approval_proof: dict[str, Any] | None,
    proposal: dict[str, Any] | None = None,
    proposal_json: str | None = None,
    base_url: str | None = None,
    token: str | None = None,
    timeout_seconds: int = 15,
) -> ResolutionResult:
    """Fail-closed resolver for authoritative human-maintainer approved policy versions.

    Interface contract for #70 consumption:
    - Inputs: repo path, validated evaluation report, approval_proof (PR record / provider), optional proposal.
    - Authoritative source: verified PR targeting 'main', merged by maintainer into main.
    - Output: ResolutionResult with exact content bytes read from git object storage, never workspace.
    - Refusal: returns verified=False with explicit status code and blockers on any drift or mismatch.
    - Side effects: NONE. Does not install files or activate delivery policies.
    """
    def _fail(status: str, msg: str | list[str]) -> ResolutionResult:
        errs = msg if isinstance(msg, list) else [msg]
        return ResolutionResult(status=status, verified=False, blockers=errs)

    if not isinstance(approval_proof, dict) or not approval_proof:
        return _fail("untrusted-approval-source", "missing authoritative approval proof")

    # Reject caller-local approval claims and delivery-approval gate records
    if approval_proof.get("provider") != "github" or approval_proof.get("delivery_approved") is True or "approved" in approval_proof:
        return _fail("untrusted-approval-source", "candidate-local approval flags and delivery approval cannot establish policy promotion authority")

    # 1. Validate report and bound proposal
    issues = validate_report_for_review(report, proposal_json=proposal_json)
    if issues:
        return _fail("binding-mismatch", f"report validation failed: {'; '.join(issues)}")

    if report.get("eligibility") != "improvement-eligible":
        return _fail("ineligible-proposal", f"cannot select ineligible proposal (eligibility: {report.get('eligibility')!r})")

    comp = report.get("comparison", {})
    if not (comp.get("rule_satisfied") and comp.get("baseline_demonstrated_failure") and comp.get("candidate_demonstrated_success") and comp.get("candidate_regressions_passed")):
        return _fail("ineligible-proposal", "evaluation comparison rule conditions not satisfied")

    eff_proposal = proposal if proposal is not None else report.get("proposal")
    if not isinstance(eff_proposal, dict):
        return _fail("binding-mismatch", "missing proposal definition")

    curr_prop_digest = proposal_digest(eff_proposal)
    if curr_prop_digest != report.get("proposal_digest"):
        return _fail("binding-mismatch", f"proposal digest {curr_prop_digest} drifted from report digest {report.get('proposal_digest')}")

    prop_change = eff_proposal.get("proposed_change", {})
    prop_c_sha = prop_change.get("content_sha256")
    if prop_c_sha != report.get("candidate_content_digest"):
        return _fail("binding-mismatch", "proposed_change content_sha256 does not match candidate_content_digest")

    target_path = str(prop_change.get("target_path") or "")
    kind = str(prop_change.get("kind") or "check")
    ok_path, path_err = validate_storage_path(target_path, kind)
    if not ok_path:
        return _fail("forbidden-storage-path", path_err)

    # 2. Authoritative source verification (GitHub PR merge boundary)
    pr_num = approval_proof.get("pr_number")
    repo_slug = approval_proof.get("repo_slug")
    if not isinstance(pr_num, int) or pr_num <= 0:
        return _fail("untrusted-approval-source", f"invalid pr_number: {pr_num!r}")
    if not isinstance(repo_slug, str) or not repo_slug.strip():
        return _fail("untrusted-approval-source", f"invalid repo_slug: {repo_slug!r}")

    pr_data = approval_proof.get("pr_data")
    if pr_data is None and base_url:
        url = f"{base_url.rstrip('/')}/repos/{repo_slug}/pulls/{pr_num}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token or ''}", "Accept": "application/vnd.github+json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                pr_data = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            return _fail("untrusted-approval-source", f"failed to query PR from provider: {exc}")

    if not isinstance(pr_data, dict):
        return _fail("untrusted-approval-source", "missing authoritative PR merge data from provider")

    base_ref = (pr_data.get("base") or {}).get("ref")
    if base_ref != "main":
        return _fail("unintended-target", f"approval PR must target 'main', got {base_ref!r}")

    if pr_data.get("state") != "closed" or pr_data.get("merged") is not True:
        return _fail("unmerged-revision", f"PR #{pr_num} is not in merged state (state={pr_data.get('state')!r}, merged={pr_data.get('merged')!r})")

    merge_sha = pr_data.get("merge_commit_sha")
    if not isinstance(merge_sha, str) or not SHA40_RE.fullmatch(merge_sha):
        return _fail("unmerged-revision", f"invalid merge_commit_sha on PR #{pr_num}: {merge_sha!r}")

    # 3. Git commit object & ancestry verification in repository
    cat_res = gitio.git(repo, "cat-file", "-t", merge_sha)
    if not cat_res.ok or cat_res.output != "commit":
        return _fail("unmerged-revision", f"merge commit {merge_sha} not found in repository")

    if not gitio.is_ancestor(repo, merge_sha, "main") and not gitio.is_ancestor(repo, merge_sha, "HEAD"):
        return _fail("unmerged-revision", f"merge commit {merge_sha} is not an ancestor of main or current HEAD")

    # 4. Extract exact approved content directly from git commit (never local workspace files)
    show_code, content_bytes = gitio._git_bytes(repo, "show", f"{merge_sha}:{target_path}")
    if show_code != 0:
        return _fail("missing-approved-content", f"target file {target_path} not found in merge commit {merge_sha}")

    actual_sha = hashlib.sha256(content_bytes).hexdigest()
    if actual_sha != report.get("candidate_content_digest"):
        return _fail(
            "mismatched-approved-content",
            f"content at {target_path} in commit {merge_sha} has sha256 {actual_sha}, does not match approved candidate digest {report.get('candidate_content_digest')}",
        )

    provenance = {
        "provider": "github",
        "repo_slug": repo_slug,
        "pr_number": pr_num,
        "merge_commit_sha": merge_sha,
        "target_path": target_path,
        "content_sha256": actual_sha,
        "proposal_digest": report.get("proposal_digest"),
        "candidate_content_digest": report.get("candidate_content_digest"),
        "factory_revision": report.get("factory_revision"),
    }
    return ResolutionResult(
        status="resolved",
        verified=True,
        selected_version=merge_sha,
        content_sha256=actual_sha,
        target_path=target_path,
        kind=kind,
        content_bytes=content_bytes,
        provenance=provenance,
        blockers=[],
    )
