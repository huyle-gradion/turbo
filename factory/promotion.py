"""Authoritative factory-policy promotion gate and exact-version selection (Issue #69, Part B of #32)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from factory.errors import UsageError
from factory.improvement import (
    AUTHORITY_NOTE as IMPROVEMENT_AUTHORITY_NOTE,
    proposal_digest,
    validate_report_for_review,
)

REVIEW_PACKET_SCHEMA_VERSION = 1
REVIEW_PACKET_AUTHORITY_NOTE = "review-packet-only; not approved, submitted, merged, or promoted"


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
