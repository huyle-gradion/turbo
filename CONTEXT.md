# Turbo software factory

This glossary describes Turbo's target software factory, not the current evidence helper's implemented capabilities. Chat Bridge is its first intended product, not its only supported product.

## Language

**Orchestrator**:
The user-facing factory coordinator that drives a parent task across its prepared sub-tasks through builder, automated QA, security, and independent reviewer roles until the integrated feature pull request awaits human acceptance.
_Avoid_: Cloud scheduler, task decomposer

**Work ticket**:
A bounded requirement that produces one pull request, represented by a prepared Asana sub-task.
_Avoid_: Epic, product specification

**Task**:
A parent feature defined by the PM with QA and SWE input, carrying feature acceptance criteria, an assigned SWE reviewer, and prepared sub-tasks. Completion requires all parent criteria to pass on the integrated feature pull request, approval from AI review, QA, and the parent task's assigned SWE reviewer, and human merge into main.
_Avoid_: Sub-task, epic

**Sub-task**:
A prepared atomic work ticket under a parent task, created by an SWE for implementation or by an SWE or PM for a feature repair, with acceptance criteria verifiable without human judgment and one child pull request. Completion requires its criteria and CI checks to pass and AI review, approval, and merge into its parent feature branch without human approval.
_Avoid_: Parent task, autonomously generated ticket

**Ready sub-task**:
A prepared sub-task with verifiable acceptance criteria, a target repository, required context, explicit dependencies, and an assigned SWE reviewer for readiness and escalation.

**Feature branch**:
The integration branch for one task's merged sub-task pull requests, kept separate from main until feature acceptance and human merge.

**Task acceptance record**:
The shared Asana and feature pull request evidence tying every parent criterion and same-revision AI, QA, and assigned SWE approvals to one frozen integrated build.

**Delivery team**:
One team of three software engineers, one PM, and one non-technical QA teammate. The two current teams build Chat Bridge independently.

**Engineering QC**:
The technical quality checks covering builder verification, automated QA, security checks, CI user-story tests, and independent AI review before merge.
_Avoid_: Acceptance QA

**Acceptance QA**:
The non-technical QA teammate's assessment of whether the integrated feature candidate satisfies the parent task's acceptance criteria.
_Avoid_: Engineering QC, code review

**Delivery run**:
An unattended factory execution launched on a parent task that coordinates its prepared sub-tasks into merged child pull requests and an integrated feature pull request awaiting human acceptance.

**Repair run**:
A bounded execution that updates an existing open pull request to resolve review findings or an authorized repair request and re-verifies the updated revision before merge.

**Assigned SWE reviewer**:
The software engineer designated on a task or sub-task to own readiness, review escalation, and `/turbo repair` authorization, and on a parent task to approve the frozen feature candidate.

**Repair request**:
An explicit `/turbo repair` instruction authorized by the assigned SWE reviewer for a defined batch of pull request feedback.

**Feature repair sub-task**:
An Asana sub-task created by an SWE or PM to address an authorized `/turbo repair` batch on a feature candidate through a new child pull request into the feature branch.

**Dependency handoff**:
An explicit record of a prerequisite sub-task's delivered contract, merged revision, and supporting evidence passed to dependent sub-tasks.

**Merge approval**:
Authorization to integrate a reviewed pull request into its target branch. AI authorizes child pull request merges into a feature branch, whereas a feature pull request requires AI, QA, and parent assigned SWE approval before a human merges it into main.

**Run measurements**:
Usage, elapsed time, and quality observations linked to a work ticket and exact revision to evaluate and improve the factory. Reported usage, estimated cost, and unavailable data remain distinct.

**Durable lesson**:
A reviewed finding approved by a human to guide future factory runs. Automatically recorded observations are not durable lessons until a human approves them.

**Factory maintainer**:
The person responsible for approving shared checks and factory improvements. The project's owner is the primary maintainer, and contributors propose changes through issues and pull requests.
