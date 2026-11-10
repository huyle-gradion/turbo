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

### Hosted Qualification (Hosted Safety and Evidence Foundation / Scenarios Not Implemented)
```sh
# Credentials must be pre-set in the launch environment (TURBO_QUAL_INTEGRATOR_TOKEN, TURBO_QUAL_COMPETITOR_TOKEN).
# Do NOT pass token values on the command line or persist them to files.
TURBO_LIVE_QUALIFICATION=1 \
DEMO_KEEP_EVIDENCE_DIR="$(mktemp -d /tmp/turbo-qual-67.XXXXXX)" \
  bash scripts/qualify-protected-demo.sh --mode hosted
```

### Evidence directory and exit status

- The script keeps the evidence directory by default. Without `DEMO_KEEP_EVIDENCE_DIR` or `EVIDENCE`, it creates one with `mktemp -d "${TMPDIR:-/tmp}/turbo-qual-67.XXXXXX"` and prints its path to stderr. Set `DEMO_DELETE_EVIDENCE=1` to delete that generated directory on exit; a directory you name is never deleted.
- Each run first removes any earlier `qualification-summary.json` and `parent-evidence-index.json` from the evidence directory, so both files describe only the current run. If the run raises, the summary records `outcome: "failed"` with `exit_status: 1` and the error is re-raised.
- Exit status: offline mode exits `0` only when the summary outcome is `offline-simulated-verified`, otherwise `2`. Hosted mode exits `0` only when `qualified` is true, otherwise `2`.
- Every parent evidence index entry records `mode` (`offline-simulated` or `hosted`), `command` (the invocation, `python3 -m factory.qualification` plus the arguments `main()` received) and `exit_status` (that run's exit status). Both are `null` when the run functions are called directly without `main()`.
- An index entry is `failed` when any of its scenarios failed, and `unavailable` when a scenario is missing, a scenario recorded no artifact or a missing/empty one, or a preflight or preparation blocker exists. Fully observed simulated entries read `passed-offline-simulated` offline and `passed-simulated` when hosted mode ran against a test origin. `qualified` stays false in every one of these cases.
- Offline scenario results record `outcome: "verified"` when the integration produced the expected status (`expected_status`) and `"failed"` otherwise; the integration's own outcome is kept in `integration_outcome`.
- Hosted scenarios 2 and 3 read `main` from the provider before and after the attempt; `main_preserved` is `null` when either read fails. Provider messages are recorded verbatim or as `null`.

> **Current status (Slice 3)**: Seed assets, deterministic QA cases, factory contracts, workflow template, and genuine candidate preparation machinery are implemented under `examples/qualification/seed/` and `factory/qualification.py`. The disposable test repository (`turbo-factory/turbo-qual-67`) has NOT had the seed installed on `feature/demo` and its required check contexts remain empty (`contexts: []`). Hosted qualification preflight honestly reports `status: "blocked"` with `missing-seed` and `empty-required-check-contexts`. No hosted success is claimed until external reviewed installation and check configuration are performed.

## 5. Protected Seed Installation and Required-Context Setup Instructions

Because `feature/demo` enforces strict branch protection (no direct pushes, 1 approving review, stale dismissals, admin enforcement), seed assets must be installed via a reviewed pull request, and required status checks must be configured via repository protection settings:

### Step 1: Create Seed Setup Branch
Clone `turbo-factory/turbo-qual-67`, fetch the target branch, and create a setup branch:
```sh
git clone https://github.com/turbo-factory/turbo-qual-67.git /tmp/turbo-qual-setup
cd /tmp/turbo-qual-setup
git checkout feature/demo
git checkout -b setup/install-disposable-seed
```

### Step 2: Copy Seed Assets from Turbo Repository
Copy the complete seed directory from Turbo's `examples/qualification/seed/` into the repository root:
```sh
cp -r /path/to/turbo/examples/qualification/seed/.github .
mkdir -p .factory
cp /path/to/turbo/examples/qualification/seed/factory/* .factory/
cp -r /path/to/turbo/examples/qualification/seed/src .
cp -r /path/to/turbo/examples/qualification/seed/tests .
cp -r /path/to/turbo/examples/qualification/seed/qa .
```

Verified seed files installed:
- `.github/workflows/ci.yml`: CI workflow running tests and uploading `turbo-ci-evidence-build`.
- `.factory/policy.json`: Factory verification policy defining protected paths and required checks.
- `.factory/child-contract.json`: Child contract specifying scope and acceptance criteria.
- `src/calc.py`: Minimal product fixture source.
- `tests/test_calc.py`: Unit tests for product fixture.
- `qa/qa-cases.json`: Deterministic QA evaluation rubric and cases.

### Step 3: Commit and Push Seed Setup Branch
Commit changes with sign-off using writer collaborator credentials (`cone-orgs`):
```sh
git add .github .factory src tests qa
git commit -s -m "setup: install disposable qualification seed assets (#67)"
git push -u origin setup/install-disposable-seed
```

### Step 4: Open and Approve Seed Pull Request
Open PR targeting `feature/demo`:
```sh
gh pr create \
  --repo turbo-factory/turbo-qual-67 \
  --base feature/demo \
  --head setup/install-disposable-seed \
  --title "setup: install disposable qualification seed assets" \
  --body "Installs seed CI workflow, factory policy, product fixture, and QA cases. Refs #67"
```

Submit approving review using independent administrator identity (`huyhuyhuy8s`):
```sh
gh pr review <PR_NUMBER> \
  --repo turbo-factory/turbo-qual-67 \
  --approve \
  --body "Seed assets verified against Turbo qualification contract."
```

### Step 5: Merge PR into `feature/demo`
Merge the approved PR into `feature/demo`:
```sh
gh pr merge <PR_NUMBER> \
  --repo turbo-factory/turbo-qual-67 \
  --squash
```

### Step 6: Configure Nonempty Required Status Check Contexts
Once the CI workflow has run on the PR or merge commit, the `build` check context is registered. Update branch protection on `feature/demo` to require `build`:
```sh
gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/turbo-factory/turbo-qual-67/branches/feature/demo/protection/required_status_checks" \
  -f strict=true \
  -f "contexts[]=build"
```

Verify nonempty contexts:
```sh
gh api "/repos/turbo-factory/turbo-qual-67/branches/feature/demo/protection/required_status_checks"
# Expected response: {"strict": true, "contexts": ["build"], ...}
```

## 6. Parent Acceptance Criteria Evidence Index (`#24`)

| Parent AC | Summary | Scenarios | Status | Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **AC1** | Protected repo accepts child merge only when CI, QA, security, and independent review apply | `confirmed_landing`, `prereq_missing_and_denied` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC2** | Ownership topology and authoritative checks prevent unverified-base integration | `confirmed_landing`, `wrong_target_rejected` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC3** | Controlled competing-base update forces renewed verification and review | `competing_base_rejection`, `renewed_verification_after_base_change` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC4** | Protections and permissions honored without bypass; missing permissions stop explicitly | `prereq_missing_and_denied`, `competing_base_rejection` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC5** | Merge confirmed on feature branch before completion, linking revisions | `confirmed_landing` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |
| **AC6** | Tests cover concurrent attempts, changed head/base, uncertain outcome; main untouched | `concurrency_and_uncertain_reconciliation`, `wrong_target_rejected` | **PENDING** | Offline simulated passed; hosted proof pending (hosted execution not implemented) |

> **Note**: Offline simulation proves code correctness and safety guards under simulated environments. Hosted qualification proof remains **PENDING** because hosted scenario execution is not implemented yet (`run_hosted_qualification` returns `blocked` with `hosted-scenarios-pending-human-setup`), and seed assets/required check contexts are pending setup in later slices.
