# Issue tracker: GitHub

Issues and published specifications for Turbo development live in
huyle-gradion/turbo on GitHub. Use the gh CLI.

This configuration governs development of Turbo itself.
Asana remains the task source for products delivered by Turbo.

## Conventions

- Read the full issue body, labels, and comments before working.
- Search open and closed issues before creating an issue.
- Create one issue per approved ticket, with observable acceptance
  criteria and explicit blockers.
- Follow the repository's existing contribution and issue-readiness rules.
- Publish only when the user authorizes publication.
- Do not close or modify a parent issue while publishing child tickets.

## Blocking relationships

Use native GitHub issue dependencies when available.
Otherwise record explicit "Blocked by" issue references in the body.
Create blockers before dependent tickets so references use real issue IDs.

A ready-for-agent label describes specification readiness.
Execution must still wait until all blockers are complete.

## Pull requests as a triage surface

PRs as a request surface: no.

## Skill operations

- "Publish to the issue tracker" means create a GitHub issue.
- "Fetch the relevant ticket" means read its body, labels, and comments.
- Apply triage labels using docs/agents/triage-labels.md.
