"""Status payload for one run."""

from __future__ import annotations

from dataclasses import asdict

from factory.model import Run


def status_payload(run: Run) -> dict[str, object]:
    limits = None
    if run.limits is not None:
        limits = run.limits.to_dict()
    budget_payload: dict[str, object] = {"state": "unpriced", "usd": None, "week": None}
    if run.budget is not None:
        budget_payload = {
            "state": run.budget.state,
            "usd": run.budget.usd,
            "week": run.budget.week,
            "source": run.budget.source,
            "verification": run.budget.verification,
        }
    return {
        "issue": run.issue,
        "phase": run.phase,
        "feature": run.feature,
        "kind": run.kind,
        "declared_model": run.declared_model,
        "model_attestation": run.model_attestation,
        "execution_profile": run.execution_profile,
        "profile_attestation": (
            None if run.profile_attestation is None else run.profile_attestation.to_dict()
        ),
        "verified_by": run.verified_by,
        "branch": run.branch,
        "base_sha": run.base_sha,
        "red_sha": run.red_sha,
        "green_sha": run.green_sha,
        "expected_green_sha": run.expected_green_sha,
        "admitted_at": run.admitted_at,
        "stop_reason": run.stop_reason,
        "stop_detail": run.stop_detail,
        "prior_phase": run.prior_phase,
        "gate_digest": run.gate_digest,
        "gate_chain": list(run.gate_chain),
        "gate_attempts": [asdict(item) for item in run.gate_attempts],
        "gate_observations": [asdict(item) for item in run.gate_observations],
        "red": asdict(run.red) if run.red is not None else None,
        "stage": asdict(run.stage) if run.stage is not None else None,
        "replay": asdict(run.replay) if run.replay is not None else None,
        "green": asdict(run.green) if run.green is not None else None,
        "limits": limits,
        "counters": {
            "operations_used": run.counters.operations_used,
            "repairs_used": run.counters.repairs_used,
            "repair_cap": run.counters.repair_cap,
        },
        "budget": budget_payload,
        "evidence_dir": run.evidence_dir,
        "manifest_path": run.manifest_path,
        "resume_history": [asdict(entry) for entry in run.resume_history],
    }
