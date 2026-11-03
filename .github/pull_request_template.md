## Summary

What changes for a user or operator, and why.

## Linked issue

Closes #N

Use `Refs #N` when the pull request is one step of a larger issue. For the initial import stack, use `Refs #1` on every pull request except the final one, which uses `Closes #1`.

## Stacked import

For the initial import stack only, record the predecessor base branch here:

```text
Based on: <predecessor branch>
```

## Changes

- Behavior changed
- Tests or documentation changed

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash scripts/smoke.sh
bash scripts/smoke-turbo.sh
```

Paste the actual results. State any check you did not run and why.

## Version impact

State whether this is a patch, minor, or breaking change under the policy in `CONTRIBUTING.md`, or write `none`.

## Checklist

- [ ] The linked issue is ready.
- [ ] The branch is named `<type>/issue-N-slug`.
- [ ] Commits use Conventional Commits and include a sign-off.
- [ ] The counted diff is at or below the 1000-line hard limit counted conservatively.
- [ ] Normal change: the full unit suite and both smoke scripts pass.
- [ ] Staged import slice: the available syntax checks and source byte-equivalence checks are recorded. Full-suite, smoke, and CI success are not claimed for this slice.
- [ ] Final import PR: the complete 199-test suite and both smoke scripts pass after the full tree is assembled, and the CI workflow is introduced here.
- [ ] Documentation matches the behavior.
- [ ] No credentials, private state, personal logs, or machine-specific paths are included.
- [ ] An independent reviewer other than the author has reviewed the change.
- [ ] A human maintainer will merge it. No auto-merge or auto-release.
- [ ] For the initial import stack, the predecessor base is recorded and later pull requests will rebase onto `main`.
