# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added

- Initial public import of the Turbo evidence helper, written in standard-library Python 3.11 and runnable from the source launcher.
- Manual and `native-turbo` execution profiles, ordered gate and replay verification, budget declarations, and `local-verified` evidence records.
- The `run-issue` and `run-issue-turbo` agent skills with an explicit `FACTORY_ROOT` launcher contract.
- Synthetic configuration and issue examples.
- Real-issue pilot packet used by the run-issue workflows, plus five manual agent-evaluation cases, all starting at `NOT RUN`.
- Unit tests, two disposable smoke demonstrations, and Ubuntu Python 3.11 CI.
- MIT license, contribution workflow, security policy, issue and pull-request templates, and this changelog.

### Changed

- `deliver` now runs two sessions per child (#117). A test-author session, whose prompt carries `ROLE: test-author`, commits failing tests only and declares its red run on a `TURBO-RED: <json>` line. The factory runs that command itself at the test-author commit, sandboxed without network. An implementer session then runs in its own isolated home and must leave every test-author file byte-identical, and the red command must pass at the candidate. This applies to the initial delivery only, not to repair rounds.
- New refusal statuses, none of which opens a pull request: `test-author-failed`, `red-refused`, `test-files-modified` and `green-failed`.
- New evidence file `test-separation.json`, at `evidence.test_separation_path` and copied to `child.test_separation`. It records both session identities (host conversation IDs, so separate invocations, not separate models or people), the test-author commit, the red and green runs, and the byte-identity result. Usage and cost in `measurements` are summed across both sessions. The record schema stays at 1.
- `missing-tests` is no longer reachable on the `deliver` path, because the test-author commit always supplies the tests.

### Fixed

- Protected-path configuration rejects padded, blank, absolute, and parent-traversing entries at both the CLI and stored-config boundaries. Command configuration rejects blank executables while preserving literal data arguments.
- Replay reuse now requires observed provenance. A staged run re-executes an untrusted replay, while a completed run refuses it without launching a child or changing state.
- The manifest now keeps both budget positions honest. `budget_admission` is the position at `prepare` even when declared spend rises during gates, replay, green, or verify, and `budget_current` records the position at sealing.
- `manifest` now refuses to seal or revalidate when the repository moved after green. The working tree must be clean, the branch and HEAD must match the recorded green commit, and the red test blob at HEAD must be unchanged.
- Host git calls no longer run programs that a builder plants in its working copy (#125). Every factory git call goes through `factory.gitio`, which disables `core.fsmonitor`, hooks, clean/smudge/process filters defined in repository config, external diff and textconv drivers, submodule child diffs, alternate-refs commands, replace refs and lazy fetches from a promisor remote, including settings reached through `include`. `status` does not look inside submodules; instead every gitlink path that holds a `.git` (a populated submodule or a committed nested repository) counts as uncommitted changes, so delivery stops as `uncommitted-changes` naming the path, and the clean-tree checks on the operator repository refuse populated submodules (#134). git-lfs program settings (`lfs.extension.*`, `lfs.customtransfer.*.path`, `lfs.standalonetransferagent`) in repository config are emptied; this is not verified against a real git-lfs. Benign repository config, such as remote URLs, is still read, and global and system config, including operator filters such as LFS, still apply.

### Removed

- `python3 -m factory.independent_review --demo` and its `--evidence-dir` option. The disposable independent-review demo now runs through `scripts/demo-independent-review.sh`, so no code under `factory/` imports the test suite (#102).

### Notes

- The predecessor line is `0.1.0`, private historical code that was never tagged or published. It has no release date in this changelog.
- `0.2.0` is the current development version. It is not released until the reviewed pull requests merge and the maintainer publishes a matching tag.
- The initial import for issue #1 is delivered as ordered dependent pull requests, each within the contribution limits.
- The helper has no live pilot result. It is not a coding agent, sandbox, billing system, or QC approval.
