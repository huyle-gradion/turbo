# Turbo agreed design

Status: Interview decisions submitted for documentation review before implementation planning. This describes the target factory, not capabilities of the current evidence helper. Repository contribution and merge policies remain unchanged by this document.

## Purpose and delivery dates

Turbo is a reusable software factory, initially serving Chat Bridge, maintained in a dedicated public MIT-licensed repository. It is not embedded in or limited to Chat Bridge. Two independent teams each have three SWEs, one PM, and one non-technical QA teammate.

The factory must be available before November 13, 2026. Product delivery is at the end of November; November 30 is the working interpretation because November 31 does not exist.

## Runtime and packaging

- Support macOS and Linux.
- Start with Antigravity and its CLI, adapting super-board's skill ecosystem into a user-facing orchestrator skill that dispatches builder, automated QA, security, and independent reviewer roles with bounded feedback routing. Deterministic supporting tools own revision checks, safe process execution, evidence, and integrations while keeping host-specific glue separate so future migration does not require rewriting product policies.
- Use Asana and GitHub as the shared workflow records without HumanLayer or another external approval gateway, and do not build other provider or tracker integrations for the initial release.
- Antigravity CLI capabilities are documented, and a remote Linux host can keep runs alive across laptop disconnects, but local and remote integration are not yet proven. A real authenticated smoke run is required before claiming support.
- Each launch has a configurable time allowance and bounded repair attempts. Preserve work and evidence when stopping. Initial defaults require pilot calibration.
- Record tokens, elapsed time, quality outcomes, and monetary cost when available. Distinguish reported usage, estimated cost, and unavailable data. No weekly monetary cap was agreed in this interview.

## Asana work model

- The PM, supported by QA and SWEs, defines a parent task representing a feature, its acceptance criteria, and its assigned SWE reviewer.
- SWEs decompose that task into prepared atomic Asana sub-tasks before launch, and an SWE or PM creates a feature repair sub-task when needed. Each sub-task may have multiple acceptance criteria and produces one child PR.
- A ready sub-task has acceptance criteria, repository, necessary context, and an assigned SWE reviewer for readiness and escalation. Launching Turbo on the parent feature task authorizes autonomous coordination across its prepared sub-tasks until the feature PR awaits QA and assigned SWE approval. Turbo consumes prepared sub-tasks only, never creates missing sub-tasks, and stops with a gap report if sub-tasks are incomplete, blocked, or leave parent criteria uncovered.
- Every sub-task criterion is verifiable without human judgment. Human usability and business acceptance belong to the parent task.
- See ASANA-SUBTASK-STANDARD.md for the authoring template and verification contract.

## Branching, execution, and review

- Each feature has a `feature/<feature-name>` integration branch and opens an integrated feature PR into `main` without manual code edits.
- A sub-task branches from that feature branch and opens a PR back into it. Suggested child name: `task/<asana-subtask-id>-<short-description>`.
- Independent sub-tasks may build in parallel in isolated working copies. Explicit dependencies wait for prerequisite merges.
- Workers communicate handoffs containing contracts, merged revisions, and evidence. They do not coordinate through shared mutable working notes or another worker's uncommitted files.
- Serialize merges into each feature branch. Run guards and user-story tests mapped to the Asana task in CI on every PR, verify against the current base, and invalidate review evidence when the candidate changes.
- The orchestrator routes each sub-task through builder, automated QA, security, and independent reviewer roles. Fresh AI review checks criteria and the diff independently, reruns meaningful verification, and retains finding identities across repairs, adapting super-board's multi-role workflow without copying its host-specific assumptions or human-approval policy for child merges.
- Agents review, approve, and merge child PRs into the feature branch without human approval, using bounded repair runs to update an open child PR before merge when gates or an explicit child-PR repair request require fixes. Confirm the merge landed before marking a sub-task complete.

## Feature acceptance and repairs

- Completed sub-tasks do not establish feature completion. Every parent criterion must pass on an identified integrated build, and the feature PR links the Asana task and verification evidence while holding SWE approval and QA reviews and comments.
- Freeze the feature candidate during acceptance. AI, QA, and the parent task's assigned SWE reviewer must all approve the same revision. Any repair requires renewed approvals.
- A human merges the accepted feature into main. No failed or unverified criterion may be overridden by calling the task complete.
- QA and other reviewers may discuss or request changes. Only the assigned SWE reviewer finalizes a `/turbo repair` feedback batch.
- The reviewer posts that comment, then explicitly launches Turbo with its URL. Turbo verifies the author and handles only the referenced batch, not incidental discussion.
- Unlike a repair run that updates an open child PR before merge, a feature repair requires an SWE or PM to create a new Asana feature repair sub-task first. The authorized repair produces a new child PR into the feature branch, not direct edits to the accepted candidate.

## Safety and evidence

- Unattended runs use disposable test services only. No production credentials, real outgoing messages, or live database changes.
- Worktrees isolate working copies, not process permissions or external effects. Required protections must be tested rather than inferred from instructions.
- Missing verification blocks readiness. Agent success statuses and exit codes alone do not prove the product was checked or a PR was created.
- Capture raw verification results, revision-linked review evidence, and available action traces. Trace gaps remain unknown; traces do not expose complete internal reasoning.
- Product tests verify delivered software. Factory evaluations use representative tasks and explicit rubrics to assess artifacts and safety-relevant actions, without prescribing one exact valid tool sequence.

## Improvement and governance

- Include a small Harness2-inspired improvement workflow before November 13, not the full framework or optimization experiments on every delivery run.
- Record failures, propose a skill/tool/check change, compare baseline and candidate behavior, rerun regression evaluations, and submit the improvement for human review.
- Raw observations are not instructions. Durable lessons require approval before future runs use them. Delivery runs use an identified factory revision.
- The user is the primary maintainer and approves shared checks and factory improvements. Contributions arrive through issues and PRs.
- Shared policies and checks belong in reviewed, versioned configuration; product-specific context and verification remain separate from the reusable factory.

## Minimum readiness demonstration

From a clean checkout, launch Turbo on a real parent Asana feature task with prepared sub-tasks, coordinate child delivery through builder, automated QA, security, and independent review gates into the feature branch, and assemble a CI-verified feature PR awaiting QA and assigned SWE approval. Process an assigned SWE's authorized `/turbo repair` batch into a re-verified commit, record usage, elapsed time, and explicit unknown costs, and demonstrate an honest failure stop when sub-task preparation is missing or blocked or criteria remain unverified.

This minimum demonstration does not replace the full quality bar. Reusable specifications, guardrails, tests, agent evaluations, review gates, recorded actions, and reviewed failure feedback remain required parts of the factory model.
