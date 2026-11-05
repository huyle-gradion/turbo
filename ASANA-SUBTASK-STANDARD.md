# Asana sub-task standard

Target workflow for the redesigned factory. Current Turbo does not yet implement the automation described here. These product-delivery rules do not replace this repository's CONTRIBUTING.md.

A sub-task is one bounded contribution to a parent feature, delivered through one PR into that feature's branch. It may have multiple acceptance criteria. Its criteria must be verifiable without human judgment; human usability and business acceptance remain on the parent task.

The PM defines the parent task with QA and SWE input, including its assigned SWE reviewer. SWEs decompose the parent task into prepared implementation sub-tasks before launch, and an SWE or PM creates a feature repair sub-task when needed. Launching Turbo on the parent task autonomously coordinates delivery across its prepared sub-tasks until the integrated feature PR into main passes automated checks and reviews and waits for QA and parent assigned SWE reviewer approval. Turbo consumes prepared sub-tasks only, never creates missing sub-tasks, and stops with a gap report if sub-tasks are incomplete, blocked, or leave parent criteria uncovered.

## Copy into an Asana sub-task description

```markdown
## Outcome
Describe the observable change and why the parent feature needs it.

## Delivery target
- Parent task: <Asana URL>
- Repository: <URL>
- Target feature branch: feature/<feature-name>
- Assigned SWE reviewer: <Asana identity and GitHub username for sub-task readiness and escalation>
- Kind: implementation | repair

## Scope
- In scope: <bounded behavior or change>
- Out of scope: <explicit exclusions>
- Constraints: <interfaces, security rules, compatibility, forbidden changes>

## Acceptance criteria
- AC-1: Given <state>, when <action>, then <observable result>.
  Parent coverage: <parent criterion ID, or explanation of supporting work>.
  Verification: <automated check or repeatable agent-evaluation case and rubric>.
- AC-2: <another independently checkable criterion, if needed>.
  Parent coverage: <reference>.
  Verification: <method>.

## Dependencies and handoff
- Blocked by: <Asana sub-task URLs, or none>
- Required outputs: <interface, contract, artifact, or merged behavior needed>
- Produces: <what downstream sub-tasks can rely on>

## Context
- Specification/contracts: <links and relevant sections>
- Relevant existing behavior: <paths or documentation, if known>
- Test prerequisites: <fixtures, services, setup instructions; no secrets>
- Open questions: <none, or blocking questions to resolve before launch>

## Repair authorization
For feature repair sub-tasks only:
- Finalized /turbo repair comment: <URL>
- Authorized by: <parent task assigned SWE reviewer>
- Feedback batch: <explicit review/comment links and requested outcomes>
```

## Ready checklist

- [ ] One parent task, one repository, one target feature branch, one intended PR.
- [ ] Acceptance criteria describe observable outcomes, including relevant failure behavior.
- [ ] Each criterion has a verification method and parent-coverage reference.
- [ ] Prepared sub-tasks cover the parent task's engineering scope; missing or blocked sub-tasks stop parent-task orchestration with a gap report instead of automatic task creation.
- [ ] Required context and test prerequisites are available; no blocking ambiguity remains.
- [ ] Dependencies and expected outputs are explicit. Prerequisites must be merged before execution starts.
- [ ] Assigned SWE reviewer is identified across Asana and GitHub for sub-task readiness, escalation, and any child-PR repair authorization, while the parent task names the assigned SWE reviewer for feature acceptance and feature-level repair authorization.
- [ ] Feature-level repair work has a prepared Asana feature repair sub-task created by an SWE or PM and finalized `/turbo repair` authorization from the parent task's assigned SWE reviewer, whereas open child PRs use bounded repair runs before merge.

## Verification rules

Product tests check the delivered behavior. Factory evaluations check agent behavior across representative cases with explicit scoring criteria. A passing product test is not a passing factory evaluation.

Each run must retain criterion-to-evidence links, product-check results, fresh AI-review results, and recorded actions needed to assess policy compliance. Missing trace coverage is unknown, not proof of compliance. Evaluate outcomes and safety-relevant actions, not one prescribed sequence of otherwise valid tool calls.

Use deterministic checks where possible. Guards and user-story tests mapped to the Asana task run in CI on every child PR and on the integrated feature PR, and deterministic supporting tools own revision checks, safe process execution, evidence capture, and Asana and GitHub integration updates. Agent evaluations must name their cases and rubric; a bare "looks good" is not evidence. Do not require authors to duplicate the entire factory evaluation suite in every sub-task. Shared guards, checks, and evaluation policies belong to the versioned product/factory configuration.

Agents may add relevant tests, but may not weaken acceptance criteria, required gates, or protected policies to make a run pass. If the specification conflicts with a check, stop and report the conflict.

## Automated review contract

Adapted from [super-board's skill ecosystem and reviewer workflow](https://github.com/EricTechPro/super-board/blob/main/skills/super-review/SKILL.md), without its host-specific hooks or merge permissions, into a user-facing Antigravity orchestrator skill that dispatches builder, automated QA, security, and independent reviewer roles with bounded feedback routing:

- The orchestrator routes each prepared sub-task through builder, automated QA, security, and independent reviewer skills, using bounded repair runs to update an open child PR before merge when a gate fails.
- The reviewer reads acceptance criteria and the diff before the builder's summary, forms independent failure hypotheses, then checks the builder's claims against evidence.
- Review both requirement compliance and project standards. Inspect criterion coverage, relevant edge cases, and whether tests would detect broken behavior.
- Independently rerun relevant checks. Missing verification blocks approval; an agent success message is not verification.
- Classify findings as missing behavior, bugs, verification gaps, scope drift, or non-blocking maintainability suggestions. Every blocker needs concrete evidence and an actionable correction.
- Preserve finding IDs between rounds. Re-review proves each previous blocker fixed or no longer applicable before approving; a resolved thread alone is not proof.
- Reviewer and builder remain separate roles. A reviewer who changes the candidate cannot independently approve its own edits.
- Approval names the exact candidate revision. Mark the sub-task done only after confirming its merge reached the intended feature branch.

Turbo retains its own authorization policy. AI review approves and merges child PRs into feature branches without human approval, while merging the integrated feature PR into main requires AI, QA, and parent assigned SWE reviewer approval plus a human merge. Automatic child merge still enforces freshness, CI verification, and repository protections.

## Dependencies and parallel work

Workers use isolated working copies and communicate explicit handoffs containing dependency identity, merged revision, delivered contract, and evidence references. They must not coordinate by editing a shared scratchpad or relying on another worker's uncommitted files.

Independent sub-tasks may build in parallel. Merges into the same feature branch are serialized. A merge candidate must incorporate the current feature branch, pass the required checks, and have AI approval for that candidate. Changed candidates require renewed verification and review.

## Done checklist

- [ ] Every sub-task criterion passes, with evidence tied to the reviewed revision.
- [ ] Required product checks, CI guards and user-story tests, automated QA, security checks, and factory policy checks pass.
- [ ] A fresh reviewer-agent session approves the candidate.
- [ ] The child PR targets the parent feature branch and is merged by the factory without human approval.
- [ ] The record links the Asana sub-task, PR, reviewed revision, merge result, evidence, usage, elapsed time, and any unavailable cost data.

An open PR is not a completed sub-task. A failed or unverified criterion blocks completion. Completed sub-tasks do not establish parent task acceptance.

## Feature acceptance boundary

The parent task is assessed on an integrated feature PR into main with no manual code edits and with evidence appropriate to each criterion. Asana and GitHub hold the shared workflow records without HumanLayer or another external approval gateway, and the feature PR links the Asana task and verification evidence while holding SWE approval and QA reviews and comments. AI, QA, and the parent task's assigned SWE reviewer must approve the same candidate revision. Freeze that candidate during acceptance. Unlike a repair run that updates an open child PR before merge, a feature repair requires an SWE or PM to create a new Asana feature repair sub-task after `/turbo repair` authorization, which produces a new child PR into the feature branch and invalidates prior candidate approvals. A human merges the accepted feature into main.

## Suggested naming

- Asana title: `<verb> <observable outcome>`.
- Feature branch: `feature/<feature-name>`.
- Child branch: `task/<asana-subtask-id>-<short-description>`.
- Child PR title: `<observable outcome> [Asana <subtask-id>]`.

Branch naming is a recommendation, not an existing enforced Turbo interface.
