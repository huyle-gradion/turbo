# Delivery Approval and Disposable Lifecycle (`#62`)

`factory.deliver` and `factory.independent_review.approval` enforce exact-candidate delivery approval across four required verification prerequisites:
1. CI verification (`factory.ci_gate`)
2. Automated QA (`factory.automated_qa`)
3. Security review (`factory.security_review`)
4. Independent review (`factory.independent_review`)

Final delivery approval requires exact candidate and base revision binding across all four prerequisites, verified historical finding reconciliation, and independent reproducer execution.

## Rejection Matrix

Delivery integration tests (`tests/test_deliver_rejection_matrix.py`) independently reject missing, failing, and stale evidence across all 12 prerequisite combinations (4 prerequisites × 3 rejection modes):
- **CI**: missing (`ci-missing`), failing (`ci-failed`), stale (`stale-ci-evidence`).
- **Automated QA**: missing (`qa-missing`), failing (`qa-failed`), stale (`stale-qa-evidence`).
- **Security review**: missing (`security-review-missing`), failing (`security-blockers-unresolved`), stale (`stale-security-review`).
- **Independent review**: missing (`independent-review-missing`), failing (`changes-requested`), stale (`stale-independent-review`).

Additional delivery boundary tests enforce:
- Rejection of omitted historical blockers (`unresolved-historical-blockers`).
- Rejection of ineffective fixes contradicted by reproducer execution.
- Rejection of unsupported resolution claims (e.g. `thread-closed`, `dismissed`, `comment-resolved`).
- Rejection of reviewer worktree mutation (`reviewer-modified-worktree`).
- Rejection of invalid reviewer session identity (`reused-builder-identity`) and broken protocol ordering (`invalid-review-protocol`).

## Four-Stage Disposable Demonstration

The four-stage disposable approval lifecycle script is runnable via:

```sh
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-issue-62.XXXXXX)" \
  bash scripts/demo-delivery-approval.sh
```

> **Note**: Always use `/tmp` for the evidence directory; directories under `~/.gemini` are restricted by Landlock sandboxing.

The script demonstrates, in order:
1. **Blocker**: Scripted reviewer records a blocking finding with an executable reproducer; delivery rejects.
2. **Ineffective correction**: Candidate advances, reviewer claims resolution, but the original reproducer executes and fails; delivery rejects.
3. **Verified correction**: Candidate implements genuine fix, checks and reproducer pass; delivery approves that exact candidate.
4. **Subsequent revision**: Candidate advances further; attempt to reuse prior approval fails closed.

## Truth Boundaries and Provenance

Fixture-based success in disposable demonstration environments establishes helper contract compliance, but **does not establish live Antigravity or hosted-provider support, merge approval (#24), or parent acceptance**.
