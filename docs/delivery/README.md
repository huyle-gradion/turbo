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

> **Note**: Use `/tmp` or another writable standard temporary directory for the retained evidence directory.

The script demonstrates, in order:
1. **Blocker**: Scripted reviewer records a blocking finding with an executable reproducer; delivery rejects.
2. **Ineffective correction**: Candidate advances, reviewer claims resolution, but the original reproducer executes and fails; delivery rejects.
3. **Verified correction**: Candidate implements genuine fix, checks and reproducer pass; delivery approves that exact candidate.
4. **Subsequent revision**: Candidate advances further; attempt to reuse prior approval fails closed.

## Five-Stage Child Integration Demonstration (`#65`)

The bounded child integration primitive (`factory.integration.integrate_approved_child`) integrates an approved child into its feature branch only under verified branch protections (`strict` status checks, direct push restrictions, admin enforcement) and exact candidate/base bindings. See [`docs/delivery/integration-ownership.md`](integration-ownership.md) for the complete architecture and ownership specification.

The five-stage disposable integration lifecycle script is runnable via:

```sh
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-issue-65.XXXXXX)" \
  bash scripts/demo-child-integration.sh
```

The script demonstrates, in order:
1. **Confirmed integration**: Fully approved child PR integrates cleanly into the protected feature branch; landed commit is recorded.
2. **Boundary competition**: Competing update advances the remote base at the write boundary; provider strict check rejects the stale write (`rejected-competing-base`).
3. **Stale approval**: Prior approval presented against moved base revision is rejected before mutation (`stale-candidate-revision`).
4. **Unsupported protection**: Feature branch lacking strict status checks or admin enforcement fails closed (`unsupported-protection`).
5. **Uncertain outcome**: Provider server error or timeout during merge is classified as `uncertain` without blind retries.

## Four-Stage Final Delivery Integration and Completion Demonstration (`#78`)

Final delivery wires exact-candidate approval to confirmed child integration and authoritative completion evidence:

```sh
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-issue-78.XXXXXX)" \
  bash scripts/demo-delivery-integration.sh
```

The script demonstrates, in order:
1. **Confirmed success**: Final delivery invokes protected integration and records completion once approved, landing the change onto the target feature branch without touching main.
2. **Stale-base rejection**: Advancing the remote target feature branch invalidates authorization and prevents new merge mutation.
3. **Permission denial**: Merge mutation rejected by provider with HTTP 403 preserves approval status while rejecting completion (`denied-permissions`).
4. **Uncertain outcome**: Merge mutation transport error yields `uncertain` status without issuing duplicate mutation, preserving evidence for recovery.

## Repeatable Protected Qualification Harness (`#67`)

Protected repository qualification exercises delivery and integration against allowlisted disposable repository `huyle-gradion/turbo-qual-67`. See [`docs/delivery/qualification-setup.md`](qualification-setup.md) for complete setup, token capability requirements, and the parent `#24` evidence index:

```sh
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-qual-67.XXXXXX)" \
  bash scripts/qualify-protected-demo.sh --mode offline
```

## Truth Boundaries and Provenance

Fixture-based success in disposable demonstration environments establishes helper contract compliance, but **does not establish live Antigravity or hosted-provider support, merge approval (#24), or parent acceptance**.
