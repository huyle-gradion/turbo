# Agent instructions

Turbo is a public, MIT-licensed evidence helper for bounded AI-assisted workflows. Keep the recorded evidence contract honest and keep the change small. [`CONTRIBUTING.md`](CONTRIBUTING.md) is the full human guide.

## Start with the repository state

Inspect the branch and any open pull request before choosing a mode:

```sh
git status --short --branch
git branch --show-current
gh pr list --head "$(git branch --show-current)" --state open
```

Search open and closed issues and open pull requests before any work:

```sh
gh issue list --state all --search "<topic>"
gh pr list --state open --search "<topic>"
```

If a matching issue exists, reuse it. If none exists, create a Definition-of-Ready issue first. Do not start implementation from a bare request with no issue.

Use the maintainer's workflow skills instead of re-implementing them:

- https://github.com/huyle-gradion/skills
- https://github.com/huyle-gradion/skills/blob/main/gh-issue/SKILL.md
- https://github.com/huyle-gradion/skills/blob/main/gh-pr/SKILL.md
- https://github.com/huyle-gradion/skills/blob/main/gh-review/SKILL.md

Do not vendor their contents into this repository.

## Workflow

1. Confirm an issue is ready. Reuse a matching one or write a new one with problem, scope, observable acceptance criteria, out-of-scope work, and impact.
2. Branch from `main` as `<type>/issue-N-slug`. For the initial import stack, branch from the predecessor branch and record that base in the pull request.
3. Make the smallest change that satisfies the issue. Keep the factory runtime behavior stable unless the issue explicitly changes it.
4. Add or update a test at the user-observable seam. The current suite uses `unittest` and synthetic Git repositories.
5. Run the checks from the repository root.
6. Commit with the Conventional Commits form and a sign-off, for example `git commit -s -m "fix: reject a missing red marker (#12)"`.
7. Push and open a pull request. Link the issue with `Closes #N` or `Refs #N`. In the initial import stack, use `Refs #1` on every pull request except the final one, which uses `Closes #1`.
8. Request an independent review with the `gh-review` workflow. The author is not the independent reviewer.
9. A human maintainer merges. Do not auto-merge or auto-release.

## Verification commands

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash scripts/smoke.sh
bash scripts/smoke-turbo.sh
```

The tests and smoke scripts must not call a model, use the network, need provider credentials, or touch a real product repository.

Normal changes require the full suite and both smoke scripts on the final candidate before handoff (during red/green TDD iterations, run only the targeted test for the behavior under change, then affected module and integration tests; reuse final-candidate full-suite results if the candidate has not changed). In CI, `push` to `main` and PRs touching shared/cross-cutting code, unmapped paths, or test deletions run the full suite and both smoke scripts, while narrow PRs run essential safety guards, mapped criterion checks, affected regression tests (`factory.ci_selection.select_ci_test_plan`), and both smoke scripts, cancelling only superseded runs for the same PR and workflow and never caching verification results across revisions. For the initial import stack only, intermediate slices record the available syntax checks and byte comparisons for imported source. The final import pull request must run the complete test suite and both smoke scripts after the full tree is assembled. The CI workflow arrives in the last pull request. Do not claim full-suite, smoke, or CI success on an intermediate slice.

## Repository layout

- `factory/` is the standard-library Python package. Keep its behavior and persisted formats stable unless the issue says otherwise.
- `bin/factory` is the source launcher. It resolves the package from its own location, so do not replace it with an installed entry point.
- `tests/` holds the helper unit suite.
- `scripts/smoke.sh` and `scripts/smoke-turbo.sh` drive the real CLI in disposable repositories.
- `skills/` holds the two agent skills. They must resolve the clone from an explicit `FACTORY_ROOT` and work from paths containing spaces.
- `examples/` holds synthetic illustrations, not live configuration.
- `pilot/` holds the evidence packet used by the run-issue workflows. It is process documentation, not helper code.

## Contribution policy

Counted diff is added plus deleted lines from `git diff --numstat` against the base branch. Soft limit 500, hard limit 1000. A change above 1000 is split before review. There is no exemption.

The initial import for issue #1 is delivered as ordered dependent pull requests. Each uses its predecessor branch as the base and stays at or below the hard limit counted conservatively. After a predecessor merges, rebase the later pull requests onto `main`. Use `Refs #1` on every pull request except the final one, which uses `Closes #1`. Root `main` remains incomplete until the full stack is merged. Do not describe `main` as ready until a human has merged the full stack.

## Versioning and releases

`VERSION` holds the development version, currently `0.2.0`. No release tag has been published. The predecessor line is `0.1.0`, private historical code that was never tagged or published. `0.2.0` is the current development version and is not released until a reviewed merge and tag. Published tags use `vX.Y.Z`, and the tag, `VERSION`, and `CHANGELOG.md` must agree. The public contract covers CLI commands and options, observable output and exit behavior, persisted config and evidence formats, and skill compatibility.

Before `1.0.0`, a breaking change bumps the minor version and a fix bumps the patch version. The initial tagged release will be `0.2.0`.

A release is prepared in a reviewed pull request. A human merges it. Do not auto-merge or auto-publish.

## Truth boundaries

- The helper is not a coding agent or a sandbox.
- `local-verified` is not QC approval or product acceptance.
- The `native-turbo` profile is the original Antigravity workflow. The runtime statement names Antigravity even when the `--attest-native-turbo` label differs. Other hosts are not supported or verified; use `manual` unless an operator evaluates an adaptation in a later issue.
- Host declarations are not sandbox proof.
- Spend declarations are not verified billing.
- The pilot has not run on a live product issue. The five cases in `pilot/agent-evals.md` are manual agent-evaluation instructions, not helper unit tests.
- Do not add private logs, runtime state, credentials, personal paths, or historical archives to the repository.

## Agent skills

### Issue tracker

Track Turbo development in GitHub Issues for huyle-gradion/turbo.
See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five canonical triage labels.
See `docs/agents/triage-labels.md`.

### Domain docs

Use the single-context layout with root CONTEXT.md and docs/adr/.
See `docs/agents/domain.md`.
