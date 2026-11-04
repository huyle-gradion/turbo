# Turbo software factory

This glossary describes Turbo's target software factory, not the current evidence helper's implemented capabilities. Chat Bridge is its first intended product, not its only supported product.

## Language

**Work ticket**:
A bounded requirement intended to produce one pull request, represented initially by an Asana sub-task.
_Avoid_: Epic, product specification

**Task**:
A feature defined by the PM with QA and SWE input, with its own acceptance criteria and decomposed by the SWE team into sub-tasks. Completion requires all criteria to pass, approval from AI review, QA, and the assigned SWE reviewer, and human merge into main; completed sub-tasks alone do not establish completion.

**Sub-task**:
An SWE-created atomic work ticket belonging to a task, with one or more acceptance criteria verifiable without human judgment and one associated pull request. Completion requires all its criteria to pass and AI review, approval, and merge into its parent feature branch, without human approval.

**Ready sub-task**:
A sub-task with acceptance criteria, a target repository, necessary context, and an assigned SWE reviewer. An SWE's explicit launch authorizes execution.

**Feature branch**:
The integration branch for one task's sub-tasks, kept separate from main until feature acceptance and human merge.

**Task acceptance record**:
Evidence for a task's acceptance criteria tied to one integrated build, with the evidence method suited to each criterion. AI, QA, and assigned SWE approvals apply to that same frozen candidate; repairs require renewed approvals, and no criterion may remain failed or unverified at completion.

**Delivery team**:
One team of three software engineers, one PM, and one non-technical QA teammate. The two current teams build Chat Bridge independently.

**Engineering QC**:
The technical quality checks owned by the software engineers, including tests and review before merge.
_Avoid_: Acceptance QA

**Acceptance QA**:
The non-technical QA teammate's assessment of whether the delivered product meets its acceptance criteria.
_Avoid_: Engineering QC, code review

**Delivery run**:
An unattended attempt to turn one ready work ticket into a pull request, including implementation and engineering QC.

**Repair run**:
An attempt to address explicitly requested changes on an existing pull request and verify the updated result. Ordinary discussion is not a repair request.

**Assigned SWE reviewer**:
The software engineer designated to consolidate PR feedback and authorize a repair run. QA and other reviewers may contribute feedback, but only this reviewer can finalize the repair request.

**Repair request**:
An explicit `/turbo repair` instruction authorized by the assigned SWE reviewer for a defined batch of PR feedback.

**Feature repair sub-task**:
An Asana sub-task created by an SWE or PM to address a feature-level repair request. Its child PR targets the feature branch and requires the assigned SWE reviewer's finalized repair authorization.

**Dependency handoff**:
An explicit communication of a prerequisite's delivered contract, merged revision, and supporting evidence to dependent work. Workers do not rely on shared mutable working notes or uncommitted files for coordination.

**Merge approval**:
Authorization to integrate a reviewed change into its target branch. AI authorizes sub-task merges into a feature branch; a feature requires AI, QA, and assigned SWE approval before a human merges it into main.

**Run measurements**:
Usage and quality observations linked to a work ticket and exact revision, used to evaluate and improve the factory. Reported usage, estimated cost, and unavailable data remain distinct.

**Durable lesson**:
A reviewed finding approved to guide future factory runs. An automatically recorded observation is not a durable lesson until a human approves it.

**Factory maintainer**:
The person responsible for approving shared checks and factory improvements. The project's owner is the primary maintainer; contributors propose changes through issues and pull requests.
