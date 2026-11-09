# Protected Repository Qualification Setup and Evidence Index (`#67`)

This document defines the reproducible setup, identity capabilities, and evidence index for qualifying Turbo's protected integration and delivery implementation against disposable test repository `huyle-gradion/turbo-qual-67`.

## 1. Verified Real Repository Setup

- **Disposable Repository**: `huyle-gradion/turbo-qual-67` (public, disposable test repository).
- **Branch Protection** (enforced on `main` and `feature/demo`):
  - `strict: true` ("Require branches to be up to date before merging").
  - `enforce_admins: true` (forbids administrator bypass).
  - Required approvals: `1` with `dismiss_stale_reviews: true`.
  - Force pushes: `false` (`allow_force_pushes: false`).
  - Deletions: `false` (`allow_deletions: false`).
  - Direct push rejection: proved live (`GH006` direct push rejected).

## 2. Test Identities & Token Capabilities

- **Identities**:
  - `huyhuyhuy8s`: Integration actor (collaborator write access, accepted).
  - `cone-orgs`: Competing actor (collaborator write access, accepted).
  - `huyle-turbo`: Restricted reader identity (token-level read-only; write denied 403).
- **Token Permissions**:
  - Scoped fine-grained Personal Access Tokens (PATs) per test account for `huyle-gradion/turbo-qual-67`.
  - Permissions required: `Contents: Read and write`, `Pull requests: Read and write`, `Actions: Read-only`, `Commit statuses: Read-only`, `Checks: Read-only`, `Administration: Read-only`.
- **Known Token Gap (Human Setup Dependency)**:
  - Integrator and competitor tokens currently return `HTTP 403 Forbidden` on `GET /repos/{owner}/{repo}/branches/{branch}/protection`.
  - Branch protection verification at step 7 of `factory.integration` requires `Administration: Read-only`.
  - Live hosted integration must **NOT** be attempted until this fine-grained permission takes effect. The harness halts with `unavailable-protection-capability` (exit status 2).

## 3. Coordinated Competing-Actor Protocol

- **Target Restrictions**: Integration strictly targets feature branches (`feature/*`); `main` is never targeted and its revisions are recorded before and after.
- **Base Advancement**: Competing actor advances the remote feature base via an allowed merge operation.
- **Provider Protection**: GitHub atomically rejects stale integration with `HTTP 405 Method Not Allowed` ("Base branch was modified").
- **Renewed Verification**: Advancing the base invalidates prior approval, requiring candidate re-verification and independent review.

## 4. Execution Commands

### Offline Simulation
```sh
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-qual-67.XXXXXX)" \
  bash scripts/qualify-protected-demo.sh --mode offline
```

### Hosted Qualification (Pending Token Permissions)
```sh
TURBO_LIVE_QUALIFICATION=1 \
TURBO_QUAL_INTEGRATOR_TOKEN="<token>" \
TURBO_QUAL_COMPETITOR_TOKEN="<token>" \
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-qual-67.XXXXXX)" \
  bash scripts/qualify-protected-demo.sh --mode hosted
```

## 5. Parent Acceptance Criteria Evidence Index (`#24`)

| Parent AC | Summary | Scenarios | Status | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **AC1** | Protected repo accepts child merge only when CI, QA, security, and independent review apply | `confirmed_landing`, `prereq_missing_and_denied` | **PENDING** | Offline simulated passed; hosted proof pending |
| **AC2** | Ownership topology and authoritative checks prevent unverified-base integration | `confirmed_landing`, `wrong_target_rejected` | **PENDING** | Offline simulated passed; hosted proof pending |
| **AC3** | Controlled competing-base update forces renewed verification and review | `competing_base_rejection`, `renewed_verification_after_base_change` | **PENDING** | Offline simulated passed; hosted proof pending |
| **AC4** | Protections and permissions honored without bypass; missing permissions stop explicitly | `prereq_missing_and_denied`, `competing_base_rejection` | **PENDING** | Offline simulated passed; hosted proof pending |
| **AC5** | Merge confirmed on feature branch before completion, linking revisions | `confirmed_landing` | **PENDING** | Offline simulated passed; hosted proof pending |
| **AC6** | Tests cover concurrent attempts, changed head/base, uncertain outcome; main untouched | `concurrency_and_uncertain_reconciliation`, `wrong_target_rejected` | **PENDING** | Offline simulated passed; hosted proof pending |

> **Note**: Offline simulation proves code correctness and safety guards under simulated environments. Hosted qualification proof remains **PENDING** until live PAT administration permissions are active.
