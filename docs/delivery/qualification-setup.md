# Protected Repository Qualification Setup and Evidence Index (`#67`)

This document defines the reproducible setup, identity capabilities, and evidence index for qualifying Turbo's protected integration and delivery implementation against disposable test repository `turbo-factory/turbo-qual-67`.

> **Note on repository slug**: The disposable test repository is `turbo-factory/turbo-qual-67` (public, organization `turbo-factory`). The former slug `huyle-gradion/turbo-qual-67` redirects on GitHub and must be explicitly rejected by the authorization allowlist.

## 1. Verified Real Repository Setup

- **Disposable Repository**: `turbo-factory/turbo-qual-67` (public, organization repository).
- **Branch Protection** (enforced and verified live on `main` and `feature/demo`):
  - `strict: true` ("Require branches to be up to date before merging").
  - `enforce_admins: true` (forbids administrator bypass).
  - Required approvals: `1` with `dismiss_stale_reviews: true`.
  - Force pushes: `false` (`allow_force_pushes: false`).
  - Deletions: `false` (`allow_deletions: false`).
  - Direct push rejection: proved live (`GH006` direct push rejected).
  - Required-check contexts: EMPTY (`contexts: []`). This is the current verified repository state, not an error to fix in this slice.
- **Known Repository Setup Gaps (Preparation Baseline)**:
  - `feature/demo` currently holds **ONLY `README.md`** — no CI workflow, product fixture, or factory policy yet. Seed assets and nonempty required-check setup come in a later slice when installed by the maintainer.
  - Required status check contexts are empty (`contexts: []`); nonempty check contexts will be configured once the seed CI workflow is installed.

## 2. Test Identities & Token Capabilities

- **Identities** (all three are the user's own test accounts):
  - `huyhuyhuy8s`: Integration actor (admin on the organization repository `turbo-factory/turbo-qual-67`).
  - `cone-orgs`: Competing actor (collaborator with write access).
  - `huyle-turbo`: Restricted reader identity (token-level read-only; write denied 403).
- **Token Type & Scopes**:
  - Classic Personal Access Tokens (PATs) (user's choice; the earlier fine-grained token story is obsolete).
  - Integrator (`huyhuyhuy8s`): Classic PAT with `repo` scope. Because the integrator is an admin on the repository, it has full capability to read branch protection.
  - Competitor (`cone-orgs`): Classic PAT with `repo` scope (with extra harmless `workflow` scope).
  - Reader (`huyle-turbo`): Classic PAT with no scopes (public read-only access).
- **Credential Management**:
  - Credentials come **only** from the proxy-supplied launch environment: `TURBO_QUAL_INTEGRATOR_TOKEN` and `TURBO_QUAL_COMPETITOR_TOKEN`.
  - Never request, paste, print, persist, or repair token values.
  - Do not pass tokens on the command line or write them to files.

## 3. Coordinated Competing-Actor Protocol

- **Target Restrictions**: Integration strictly targets feature branches (`feature/*`); `main` is never targeted and its revisions are recorded before and after.
- **Base Advancement**: Competing actor advances the remote feature base via an allowed merge operation.
- **Provider Protection**: When the remote base has moved, GitHub rejects stale integration attempts. HTTP 405 Method Not Allowed means broadly "merge cannot be performed" (GitHub does not promise the literal message "Base branch was modified").
- **Prerequisite and Independent Review Enforcement**: Advancing the base invalidates prior approval, requiring candidate re-verification. Note that a GitHub PR approval alone does **NOT** satisfy the factory's independent-review prerequisite; `enforce_delivery_approval` also requires genuine CI, QA, security, and independent-review records.

## 4. Execution Commands

### Offline Simulation
```sh
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-qual-67.XXXXXX)" \
  bash scripts/qualify-protected-demo.sh --mode offline
```

### Hosted Qualification (Preparation Baseline / Execution Not Implemented)
```sh
# Credentials must be pre-set in the launch environment (TURBO_QUAL_INTEGRATOR_TOKEN, TURBO_QUAL_COMPETITOR_TOKEN).
# Do NOT pass token values on the command line or persist them to files.
TURBO_LIVE_QUALIFICATION=1 \
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-qual-67.XXXXXX)" \
  bash scripts/qualify-protected-demo.sh --mode hosted
```

> **Current status**: Hosted qualification scenario execution is **NOT** implemented yet in this slice. Invocations of `run_hosted_qualification` halt with `status: "blocked"` and blocker `hosted-scenarios-pending-human-setup`. No hosted success is claimed; this slice establishes the honest preparation baseline.

## 5. Parent Acceptance Criteria Evidence Index (`#24`)

| Parent AC | Summary | Scenarios | Status | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **AC1** | Protected repo accepts child merge only when CI, QA, security, and independent review apply | `confirmed_landing`, `prereq_missing_and_denied` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC2** | Ownership topology and authoritative checks prevent unverified-base integration | `confirmed_landing`, `wrong_target_rejected` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC3** | Controlled competing-base update forces renewed verification and review | `competing_base_rejection`, `renewed_verification_after_base_change` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC4** | Protections and permissions honored without bypass; missing permissions stop explicitly | `prereq_missing_and_denied`, `competing_base_rejection` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC5** | Merge confirmed on feature branch before completion, linking revisions | `confirmed_landing` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC6** | Tests cover concurrent attempts, changed head/base, uncertain outcome; main untouched | `concurrency_and_uncertain_reconciliation`, `wrong_target_rejected` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |

> **Note**: Offline simulation proves code correctness and safety guards under simulated environments. Hosted qualification proof remains **PENDING** because hosted scenario execution is not implemented yet (`run_hosted_qualification` returns `blocked` with `hosted-scenarios-pending-human-setup`), and seed assets/required check contexts are pending setup in later slices.
