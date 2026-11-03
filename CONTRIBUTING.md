# Contributing

Turbo is a small, local evidence helper. Contributions are welcome when they keep the recorded evidence honest and the code small.

## Before you write code

Inspect the current branch and any open pull request before choosing a mode:

```sh
git status --short --branch
gh pr list --head "$(git branch --show-current)" --state open
```

Search open and closed issues and open pull requests before starting work:

```sh
gh issue list --state all --search "<topic>"
gh pr list --state open --search "<topic>"
```

If a matching issue exists, reuse it. If none exists, create one that satisfies the Definition of Ready below. Do not start from a bare prompt with no issue.

The maintainer's public workflow skills are the reference for this process:

- https://github.com/huyle-gradion/skills
- https://github.com/huyle-gradion/skills/blob/main/gh-issue/SKILL.md
- https://github.com/huyle-gradion/skills/blob/main/gh-pr/SKILL.md
- https://github.com/huyle-gradion/skills/blob/main/gh-review/SKILL.md

Use those skills if they are installed. This repository links to them instead of copying their contents.

## Definition of Ready

An issue is ready when it states:

- The problem and the user-visible behavior that should change.
- Scope, with the files or areas you expect to touch.
- Observable acceptance criteria, including an error or refusal path where it applies.
- Out-of-scope work, so the change does not grow silently.
- Any platform, compatibility, or data-format impact.
- Confirmation that no matching open or closed issue or open pull request already covers it.

A maintainer marks the issue ready. A blocked or incomplete issue is not ready.

## Branch and commits

Name the branch `<type>/issue-N-slug`, for example `fix/issue-12-red-marker` or `docs/issue-15-paths`. Types follow Conventional Commits: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `build`, `perf`, `style`, `revert`.

Commits use the Conventional Commits form and a sign-off:

```sh
git commit -s -m "fix: reject a missing red marker (#12)"
```

The sign-off certifies the Developer Certificate of Origin. Keep each commit reviewable on its own.

## Pull requests

Open a pull request against `main`. For the initial import stack, use the predecessor branch as the base as described below. The description links the issue with `Closes #N` for a complete fix or `Refs #N` for a partial step. It states the behavior changed, the verification run, and any SemVer impact.

A pull request is ready to merge only when:

- The issue link is present and the issue is ready.
- Unit tests and both smoke scripts pass.
- Documentation matches the behavior.
- No credentials, private state, personal logs, or machine-specific paths are included.
- An independent reviewer has reviewed the change using the maintainer's `gh-review` workflow. The author does not count as the independent reviewer.
- The maintainer, a human, merges it. Do not auto-merge.

## Verification

Normal changes require the full suite and both smoke scripts. Run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash scripts/smoke.sh
bash scripts/smoke-turbo.sh
```

The unit suite and both smoke scripts use disposable synthetic repositories. They must not need a model account, provider credentials, a live host session, or network access.

### Initial import verification staging

The initial import stack has one narrow, one-time exception to verification. It does not change the size limit. Intermediate source slices cannot run the complete 199-test suite or both smoke scripts because the tree is not assembled yet. Each intermediate slice records the checks available in that slice, such as syntax checks and byte comparisons for files imported verbatim from the predecessor line.

Do not claim full-suite, smoke, or CI success on an intermediate slice. The entire chain is mandatory: the final import pull request must run the complete 199-test suite and both smoke scripts after the full tree is assembled. The GitHub Actions workflow is introduced in the last pull request, not earlier. Future normal changes require all tests.

## Contribution size

Counted diff is the added plus deleted line count from `git diff --numstat` against the base branch. The soft limit is 500 lines. Above 500, split the change or explain in the pull request why one review must see it together. The hard limit is 1000. A change above 1000 is split before review. There is no exemption.

## Initial import stack

The initial import starts from a `main` that contains only the GitHub-created `LICENSE` and `README.md`. The import for issue #1 is delivered as ordered dependent pull requests, each at or below the 1000-line hard limit counted conservatively.

Each pull request uses its predecessor branch as its base and records that base in the description. Use `Refs #1` on every pull request except the final one, which uses `Closes #1`. After a predecessor merges, rebase the later pull requests onto `main` and update their bases. Root `main` remains incomplete until the full stack is merged. Do not describe `main` as ready until a human has merged the full stack.

## Versioning

Releases follow [Semantic Versioning 2.0.0](https://semver.org/). The public contract covers:

- CLI commands and options.
- Observable output and exit behavior.
- Persisted config and evidence formats.
- Skill compatibility.

`VERSION` holds the development version, currently `0.2.0`. No release tag has been published. The predecessor line is `0.1.0`, private historical code that was never tagged or published. `0.2.0` is the current development version and is not released until a reviewed merge and tag. Published tags use `vX.Y.Z`, and the tag, `VERSION`, and `CHANGELOG.md` must agree.

Before `1.0.0`, a breaking change bumps the minor version and a fix bumps the patch version. The initial tagged release will be `0.2.0`.

Prepare a release in a reviewed pull request that updates `VERSION` and `CHANGELOG.md`. After the human merge, the maintainer creates the matching tag. Do not auto-merge a release pull request and do not auto-publish a release.

## Security

Do not put secrets or private data in a public issue, pull request, discussion, or test fixture. Follow [`SECURITY.md`](SECURITY.md) for a vulnerability report.

## License

By contributing, you agree that your contribution is licensed under the MIT License in [`LICENSE`](LICENSE).
