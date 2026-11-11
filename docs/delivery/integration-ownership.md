# Protected Child-Integration Ownership and Revision Safety (#65)

This document specifies the execution topology, authoritative ownership model, and revision safety guarantees for integrating approved child pull requests into a feature branch under issue #65 (sub-slice of parent #24).

## 1. Execution Topology & Ownership Model

- **Authoritative Repository Ownership**:
  The authoritative source of truth for branch state, mergeability, and commit history is the remote repository host (GitHub in production; `_DisposableGitHubServer` in tests).
- **Branch Mutation Restrictions**:
  Direct pushes (`git push`) to the target feature branch (`feature/*`) are prohibited by repository branch protection.
  The feature branch can only be mutated via GitHub's Pull Request Merge API (`PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge`).
- **Target Constraints**:
  Integration targets feature branches only (`feature/<name>`). Targets `main`, `master`, and non-feature refs are rejected before mutation without exception.

## 2. Preventing Unverified-Base Integration (Closing the Race)

- **Provider Merge Operation**:
  GitHub's REST API endpoint `PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge` accepts `sha` (head commit SHA), which strictly binds the PR head commit. It does not provide a base SHA parameter.
- **Provider-Side Concurrency Control**:
  To prevent integration against an unverified or stale base, the target feature branch must enforce `required_status_checks` with `strict: true` ("Require branches to be up to date before merging").
  When `strict: true` is active, GitHub's server-side merge operation atomically checks that the PR head branch is strictly up-to-date with the current head of the base branch. If any concurrent process, direct push, or prior PR has advanced the base branch, GitHub atomically aborts the merge and returns `HTTP 405 Method Not Allowed` with message `"Base branch was modified. Review and try the merge again."`.
- **Pre-Mutation Client Verification**:
  Before calling the merge endpoint, Turbo performs:
  1. Authoritative verification of PR state: state is `open`, `merged` is `false`, head repository and base repository match the target repository slug.
  2. Authoritative verification of revisions: PR head SHA matches `candidate_sha`, PR head ref matches `head_branch`, PR base ref matches `base_branch`, PR base SHA matches `base_sha`.
  3. Authoritative verification of remote git state: `git fetch origin` confirms remote base ref matches `base_sha` and remote head ref matches `candidate_sha`.
  4. Exact-candidate approval verification: `verify_candidate_approval(...)` revalidates all 4 prerequisites (CI, automated QA, security review, independent review) bound to `(candidate_sha, base_sha)`.
  5. Repository protection verification: `GET /repos/{owner}/{repo}/branches/{base_branch}/protection` verifies that `strict: true` is enabled, `enforce_admins` is true, and force pushes/deletions are disabled.
  6. Redacted pre-mutation request record persistence to disk. If persistence fails, mutation is aborted immediately.

## 3. Independent Processes, Competing Writers & Trust Boundaries

- **Independent Processes & Separate Hosts**:
  No local filesystem lock (e.g. flock or mutex) is relied upon for cross-process or cross-host coordination. Multiple independent Turbo instances coordinate exclusively through provider-enforced branch protection and atomic API merge transactions.
- **Competing Writers**:
  If two independent processes attempt to merge PRs into the same feature branch concurrently:
  - The first merge to commit advances the base branch head to a new commit.
  - The second merge attempt is rejected by the provider with HTTP 405 ("Base branch was modified").
  - The rejected process transitions to `rejected-competing-base`, preserves failure evidence, and does not record completion.
- **Bypass Permissions & Admin Boundaries**:
  Integration tokens must not bypass protections. Branch protection must enforce `enforce_admins: true` (or ruleset bypass actor lists must not include the integration actor). If protections can be bypassed, the integration primitive halts with `unsupported-protection`.
- **Configuration Invariance**:
  Branch protection rules require repository admin rights. If protection rules are weakened or modified during the critical interval, the gate halts or fails closed.

## 4. Failure, Timeout & Uncertain Outcome Boundaries

- **Rejection**:
  Deterministic client-side checks or provider rejections (HTTP 400, 404, 405, 409, 422) produce explicit rejection statuses (`rejected-competing-base`, `rejected-head-mismatch`, `stale-candidate-revision`, `unsupported-protection`, etc.).
- **Classified HTTP 405**:
  After a 405 the base is re-read: a moved base gives `rejected-competing-base`; an unchanged base with a missing-approval or required-check message gives `denied-protection` (provider message verbatim); anything else, or a failed re-read, gives `rejected-provider-error`.
- **Denied Permissions**:
  HTTP 401 or 403 results in `denied-permissions`.
- **Uncertain Outcomes, Reconciliation & Recovery**:
  If the HTTP connection times out, disconnects, or returns HTTP 5xx during the merge call, the outcome is classified as `uncertain`. The primitive records the uncertain state and does NOT blindly retry mutation.
  Authoritative landing confirmation and safe retry reconciliation belong to **#66** (delivered by **#77**). Before retrying any previously initiated integration, Turbo reconciles authoritative remote state against retained request evidence and the original authorization tuple `(candidate_sha, base_sha)`. A positively confirmed prior landing is recovered without duplicating mutation. Unresolved remote state neither authorizes a blind retry nor claims confirmation. Changed candidate or base prevents mutation until verification and independent approval are renewed.
  Hosted-provider qualification remains **#67**. Offline fixtures and disposable test harnesses do not establish hosted qualification.
- **Authoritative Landing Confirmation Contract**:
  A successful HTTP merge response alone is insufficient proof of landing. Authoritative follow-up verifies repository slug, PR state (`closed` and `merged: true`), intended feature target branch (`feature/*`), and landed git commit relationship. For the supported `"merge"` method, confirmation proves that the landed commit parents are exactly `[base_sha, candidate_sha]`, its tree matches the tested revision tree (`tested_sha^{tree}`), and it is reachable on the remote base branch. Unsupported or unverifiable relationships fail closed.
- **Evidence Integrity & Redaction**:
  All persisted request and result records are sanitized using `collect_redaction_secrets()` to ensure no tokens or secrets are leaked into evidence. Failed result persistence blocks a usable confirmation result, while retained request evidence enables subsequent recovery.
