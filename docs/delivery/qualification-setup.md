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
- **Expected identities**: `TURBO_QUAL_EXPECTED_INTEGRATOR`, `TURBO_QUAL_EXPECTED_COMPETITOR` and `TURBO_QUAL_EXPECTED_READER` name the expected logins; the runner holds no logins, PR numbers or SHAs. Without all three, the observed logins are used, preflight records `identity_expectations: "unconfigured"`, and an `identity-expectations-unconfigured` blocker keeps the run from qualifying.
- **Reader and competitor roles (#98)**: the competitor must be an admin on the disposable repository, because it lands its base advance through `integrate_approved_child`, which reads branch protection. `TURBO_QUAL_READER_TOKEN` is the read-only reader; scenario 2's permission-denial probe uses only that token and must see HTTP 403. Without it the probe is `unavailable`, a `reader-unavailable` blocker is recorded, and the run cannot qualify.

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

The offline simulation is built on test fakes, so it lives in `tests/qualification_offline.py`, not in `factory/`. The script's offline mode (the default) runs it as `python3 -m qualification_offline`; hosted mode runs `python3 -m factory.qualification`, which is hosted-only. Run the offline harness directly with `PYTHONPATH=tests:. python3 -m qualification_offline`.

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
- Every parent evidence index entry records `mode` (`offline-simulated` or `hosted`), `command` (the invocation, `python3 -m qualification_offline` or `python3 -m factory.qualification` plus the arguments `main()` received) and `exit_status` (that run's exit status). Both are `null` when the run functions are called directly without `main()`.
- An index entry is `failed` when any of its scenarios failed, and `unavailable` when a scenario is missing, a scenario recorded no artifact or a missing/empty one, or a preflight or preparation blocker exists. Fully observed simulated entries read `passed-offline-simulated` offline and `passed-simulated` when hosted mode ran against a test origin. `qualified` stays false in every one of these cases.
- Offline scenario results record `outcome: "verified"` when the integration produced the expected status (`expected_status`) and `"failed"` otherwise; the integration's own outcome is kept in `integration_outcome`.
- Hosted scenarios 2 and 3 read `main` from the provider before and after the attempt; `main_preserved` is `null` when either read fails. Provider messages are recorded verbatim or as `null`.
- Each hosted run (#98) creates its own candidate branches `feat/qual-<run_id>-sc1|sc2|sc3|sc3-advance` from the current `feature/demo` and its own PRs, and drives every merge attempt through `integrate_approved_child`: scenario 1 lands its candidate; scenario 2's candidate passes the factory gate without a provider approval, so protection denies it; in scenario 3 the competitor lands its advance through the factory inside `on_before_merge`, so the candidate is rejected; scenario 4 judges scenario 3's evidence stale against the new base, renews the head with `update-branch` (no force push, checked in the provider's ref activity), re-verifies, re-approves and lands it. Every PR the run opened that is left unmerged is closed; the summary records `run_id` and `cleanup`.

> **Current status (Slice 3)**: Seed assets, deterministic QA cases, factory contracts, workflow template, and genuine candidate preparation machinery are implemented under `examples/qualification/seed/` and `factory/qualification.py`. The disposable test repository (`turbo-factory/turbo-qual-67`) has NOT had the seed installed on `feature/demo` and its required check contexts remain empty (`contexts: []`). Hosted qualification preflight honestly reports `status: "blocked"` with `missing-seed` and `empty-required-check-contexts`. No hosted success is claimed until external reviewed installation and check configuration are performed.

## 5. Protected Seed Installation and Required-Context Setup Instructions

The seed in `examples/qualification/seed/` is installed by script, not by hand. Its CI workflow runs one job per check the factory CI gate requires (`build_required_ci_checks`: today `guard/gate-3` and `criterion/CRIT-CALC-1`); each job tests the PR merge commit and uploads its own `turbo-ci-evidence-*` artifact. The install targets only `feature/demo` of the allowlisted `turbo-factory/turbo-qual-67`; `main` and its protection are never touched.

### Step 1: Dry run (default, no requests)
```sh
python3 -m factory.qualification --mode install-seed --repo-slug turbo-factory/turbo-qual-67 --branch feature/demo --dry-run
```
It prints the plan: every seed file (`factory/X` is installed as `.factory/X`) and the required status contexts for `feature/demo`.

### Step 2: Apply
```sh
TURBO_LIVE_QUALIFICATION=1 python3 -m factory.qualification --mode install-seed \
  --repo-slug turbo-factory/turbo-qual-67 --branch feature/demo --apply
```
Tokens come from the launch environment only. `TURBO_QUAL_COMPETITOR_TOKEN` (when set; it has the `workflow` scope that writing `ci.yml` needs) authors branch `feat/qual-seed-install` and a pull request into `feature/demo`; `TURBO_QUAL_INTEGRATOR_TOKEN` (admin) sets the required status contexts of `feature/demo` to the gate's check names (`strict: true`). The printed result lists each step with its HTTP status.

### Step 3: Review and merge the seed pull request
An identity other than the author approves the seed pull request. The seed pull request itself changes protected paths (`.github`, `.factory`), so its `guard/gate-3` check fails by design and protection blocks the merge. Merging it is a deliberate maintainer override of `feature/demo` protection (for example, temporarily lifting `enforce_admins` for an admin merge, then restoring it); record that override. Candidate pull requests after the seed must not change protected paths.

Verify the contexts afterwards:
```sh
gh api "/repos/turbo-factory/turbo-qual-67/branches/feature/demo/protection/required_status_checks"
# Expected: "strict": true, "contexts": ["guard/gate-3", "criterion/CRIT-CALC-1"]
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
