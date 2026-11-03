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

### Notes

- The predecessor line is `0.1.0`, private historical code that was never tagged or published. It has no release date in this changelog.
- `0.2.0` is the current development version. It is not released until the reviewed pull requests merge and the maintainer publishes a matching tag.
- The initial import for issue #1 is delivered as ordered dependent pull requests, each within the contribution limits.
- The helper has no live pilot result. It is not a coding agent, sandbox, billing system, or QC approval.
