# Domain docs

## Layout

This is a single-context repository:
- CONTEXT.md at the repository root defines domain vocabulary.
- docs/adr/ holds architecture decisions when present.

## Before exploring

Read CONTEXT.md and any ADRs relevant to the work.
If domain documents or ADR directories are absent, proceed without
requiring their creation.

## Vocabulary and decisions

Use the glossary's terms in tickets, specifications, tests, and reviews.
Do not substitute synonyms the glossary explicitly avoids.
Flag genuine vocabulary gaps for later domain modeling.

Surface conflicts with existing ADRs explicitly.
Do not silently override recorded decisions.

## Target versus implemented behavior

The current glossary describes a target factory, not proof of
implemented capabilities. Verify runtime claims against code and tests.

Later explicit user decisions supersede older interview wording.
Identify the superseded wording rather than treating it as current.
