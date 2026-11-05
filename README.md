# Turbo

Turbo is a local evidence helper for bounded AI-assisted software work. It records one issue's red test, replay, gates, budget position, and manifest so a human reviewer can inspect what happened. It does not write code, call a model, use the network, run `gh`, create commits, or merge.

MIT licensed. Development version: `0.2.0`. No release tag has been published.

## What it is

Turbo sits beside an interactive coding agent and a product repository. The operator configures three gates and a budget declaration. The agent writes a failing test, then the implementation. Turbo runs the configured commands, records their raw output in an operator-owned state directory, and refuses to reach `local-verified` when the recorded evidence does not line up.

A completed run ends at `local-verified`. That means Turbo observed the configured red failure, re-ran the exact red command successfully on the staged commit, and saw the three configured gate exits. It is not independent QC, not product acceptance, and not proof of a sandbox.

## What it is not

- Not a coding agent, issue poller, CI service, or PR bot.
- Not a sandbox. The state directory and gate digest protect against accidental drift, not a determined local process.
- Not a billing system. Spend is an operator declaration, not an invoice.
- Not an autonomous merge path. Human review and merge stay outside the helper.

## Requirements

- Python 3.11 or newer. The package uses only the standard library.
- `git` on `PATH`.
- A product repository that is already a git work tree with at least one commit.
- For the `native-turbo` profile, an interactive Antigravity session where the operator has already enabled native Turbo and auto-execution.

There are no pip dependencies and no install step. Run the launcher from the clone:

```sh
FACTORY_ROOT="/absolute/path/to/your turbo clone"
"$FACTORY_ROOT/bin/factory" --help
# or, from the clone
cd "$FACTORY_ROOT"
python3 -m factory --help
```

`bin/factory` resolves the package relative to its own location and runs Python with the current directory off `sys.path`, so a product repository's own `factory/` cannot shadow it. It works from any directory without setting `PYTHONPATH` and without a global install.

Keep the quotes. Clone paths, product paths, and state paths may contain spaces.

## Verify the clone

Run these from the clone root:

```sh
cd "$FACTORY_ROOT"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash scripts/smoke.sh
bash scripts/smoke-turbo.sh
```

The suite creates throwaway git repositories under the system temporary directory. It does not touch a product repository, call a model, or use the network. The two smoke scripts exercise the real CLI in disposable repositories and print `SMOKE_OK` and `SMOKE_TURBO_OK`.

CI runs the same commands on Ubuntu with Python 3.11. Other operating systems are untested. On non-POSIX platforms a timed-out child may leave a grandchild process running.

## Execution profiles

| Profile | How it is set | Verification path |
|---|---|---|
| `manual` (default) | no action, or `configure --profile manual` | one `gate`, `replay`, `green`, and `manifest` command at a time |
| `native-turbo` | `configure --profile native-turbo --attest-native-turbo antigravity-app` | one `verify` command runs the approved ordered bundle |

The `native-turbo` profile is specifically the original Antigravity workflow. The `--attest-native-turbo` value is an operator label recorded with a fixed Antigravity statement. A different label does not generalize the profile to another host. Other hosts are not supported or verified. Use the `manual` profile unless an operator evaluates an adaptation in a later issue.

A profile is an operator declaration. The helper never detects a host mode from an environment variable, a screenshot, or a probe. `native-turbo` does not grant permission, prove a sandbox, or change the host application. It records that the operator selected Antigravity's native mode and probed its behavior.

## State layout

Everything Turbo writes lives under `--home`, never under `--repo`:

```text
<home>/
  config.json                 # profile, attestation, gates, budget policy, declared weeks, binding
  runs/<issue>.json           # one run, including profile snapshot and verification mode
  evidence/<issue>/           # red, replay, gate output, manifest.json
```

Directories are created with mode `0700`; state and evidence files use `0600`. State writes are atomic. Gate, red, and replay output files are created exclusively, so a repeated command never silently overwrites an earlier artifact. `--home` must resolve outside `--repo`, including through symlinks. A state directory or state file that is a symlink is refused.

## Manual profile quickstart

**The examples below are illustrative, not real configuration or evidence.** `python3 -c 'import sys; sys.exit(0)'` is a no-op. It is not a host probe, a safety check, or proof that the host denies a write. The `--usd 12.50` spend record is a synthetic declaration, not a bill or a real budget position. The same no-op appears in `examples/config.example.json`, which is illustration only. Replace both before a real run.

Create a disposable repository and a state home outside it. Substitute your own absolute paths. The example paths contain spaces to keep the quoting honest.

```sh
repo="/absolute/path/to/your product repo"
home="/absolute/path/to/your factory home"
mkdir -p "$repo"
git -C "$repo" init -q -b main
git -C "$repo" config user.email operator@example.test
git -C "$repo" config user.name Operator
printf '# demo\n' > "$repo/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -q -m base
```

Bind the repository, declare the budget timezone, and configure the three gates:

```sh
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" init
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure --timezone UTC

"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure --gate 1 --declare-host-deny -- \
  python3 -c 'import sys; sys.exit(0)'

"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure --gate 2 -- \
  python3 -m unittest discover -s tests -p 'test_*.py' -q

"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure --gate 3 \
  --protected AGENTS.md --protected docs/spec.md --protected guards
```

Factory gate 1 is the operator's host-policy declaration. It is not the product's lint/type Gate 1. The configured command is recorded with the operator's declaration, never validated as a sandbox. Gate 2 is whatever project check you choose. Gate 3 rejects a committed change under a protected path.

Record one week's spending declaration. No record means `UNPRICED`, never zero.

```sh
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" spend record \
  --usd 12.50 --source 'operator export 2026-11-03T09:00Z'
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" spend show
```

Admit an issue. The example below uses the default weekly policy: below 160 USD both kinds run, from 160 up to 200 only `bug` runs, and at or above 200 every kind stops until the week resets.

```sh
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" prepare \
  --issue 7 --feature S-1 --kind feature --model your-model \
  --attest-model-account --time-limit 60m --operation-limit 40 \
  --supervision-turns 40 --supervision-writes 50
```

Admission is a local run record. Turbo prints the branch it expects but does not create it. Create and commit the failing test with separate git commands:

```sh
git -C "$repo" switch -c run-issue-7
# write tests/test_probe.py and probe_impl.py, commit them
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" red --issue 7 \
  --test tests/test_probe.py --selector ProbeTest.test_answer \
  --command "python3 -m unittest discover -s tests -p test_probe.py -v" \
  --expect AssertionError
```

Commit the implementation. Then pin the expected green commit, run each gate separately, replay the exact red command once, and close the run:

```sh
git -C "$repo" rev-parse HEAD
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" stage --issue 7 --commit <head-sha>
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" gate --issue 7 --gate 1
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" gate --issue 7 --gate 2
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" gate --issue 7 --gate 3
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" replay --issue 7
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" green --issue 7
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" manifest --issue 7
```

Inspect or resume:

```sh
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" doctor
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" status --issue 7
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" prompt --issue 7
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" resume --issue 7 --pr none
```

`resume` defaults `--pr` to `unknown` and refuses. It never calls `gh`.

## Native Antigravity Turbo profile

Use this profile only after the operator has enabled native Turbo and auto-execution in Antigravity. Record both the profile and the operator's label:

```sh
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure \
  --profile native-turbo --attest-native-turbo antigravity-app

"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure --gate 1 \
  --declare-host-probed -- python3 -c 'import sys; sys.exit(0)'
```

A native profile needs the operator-probed declaration. It refuses a host-denies-writes claim. The `sys.exit(0)` command above is still the illustrative no-op from the manual example. It is not a host probe and not safety evidence. After the implementation commit and stage, run one bundle:

```sh
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" verify --issue 7
```

`verify` refuses a manual run before any child, state, or counter change. In `native-turbo` it prints the planned gate and replay argvs, then runs gates 1, 2, 3, the exact red replay, green, and manifest in that order. It stops at the first failure. It does not continue, retry, run a hidden shell string, write code, commit, push, or merge.

A fresh verification after red needs four child operations. Red already cost one, so admit at least five total. Repeated `verify` calls are idempotent. A passing gate prefix is reused only when its raw artifact, expected HEAD, test blob, gate digest, and provenance all still match. A new stage resets the gate chain and replay.

## Command surface

| Command | Purpose |
|---|---|
| `init` | Bind one repository to one state home. Writes a config skeleton with no gates. |
| `configure` | Set one thing: the execution profile, one gate, or the budget timezone. |
| `doctor` | Validate config, profile, permissions, binding, gates, and gate digests. |
| `status` | Print one run. `--json` is available. |
| `spend record` / `spend show` | Record or show operator-declared weekly spend. |
| `prepare` | Fail-closed admission. Creates the run in `ready` only when every precondition holds. |
| `red` | Run one command, require a non-zero exit and an explicit failure marker, record the test blob. |
| `stage` | Pin the expected green commit after the implementation commit. |
| `replay` | Re-run the exact recorded red argv on the staged commit; records exit 0 as replay parity. |
| `gate` | Execute exactly one configured gate, with bounded timeout and raw output capture. |
| `verify` | Native Antigravity Turbo only. One ordered bundle of gates, replay, green, and manifest. |
| `green` | Verify the recorded chain and replay; never executes a gate or the replay. |
| `manifest` | Write evidence once; repeated calls revalidate and never overwrite it. |
| `prompt` | Print the next operator instructions with the run's own issue and branch. |
| `stop` | Stop with one reason. Counters are preserved. |
| `resume` | Offline consistency check. No reset, no deletion, no `gh`. |
| `worker` | Execute one bounded, isolated `agy` worker task in a disposable worktree with safety probes and structured telemetry. |

Exit codes are `0` success, `1` policy refusal or failed gate, and `2` invalid usage, missing configuration, unsafe path, or corrupt state.

## Skills

Two skills are included:

- [`skills/run-issue/SKILL.md`](skills/run-issue/SKILL.md) is the manual profile path. It keeps one approved command at a time.
- [`skills/run-issue-turbo/SKILL.md`](skills/run-issue-turbo/SKILL.md) is the native Antigravity Turbo path. It lets one interactive Antigravity session work through one bounded issue and run one `verify` bundle.

Neither skill is installed globally. Set the clone root explicitly when you hand a skill to an agent:

```sh
FACTORY_ROOT="/absolute/path/to/your turbo clone"
FACTORY="$FACTORY_ROOT/bin/factory"
```

If the host does not discover a skill, ask the agent to read the absolute `SKILL.md` path. That is the supported fallback. No host launch flag is guessed.

## Pilot packet

The packet is optional when you drive the helper CLI directly. The bundled [`run-issue`](skills/run-issue/SKILL.md) and [`run-issue-turbo`](skills/run-issue-turbo/SKILL.md) workflows require it before a real product issue.

[`pilot/README.md`](pilot/README.md) and [`pilot/issue-packet.md`](pilot/issue-packet.md) describe the operator-owned packet. The helper does not create, enforce, or validate it. The workflow has not been run on a live product issue, and the five cases in [`pilot/agent-evals.md`](pilot/agent-evals.md) are manual agent-evaluation instructions, not helper tests. Every result starts as `NOT RUN`.

## Limitations

- The helper is not a coding agent. It records commands another agent or the operator ran.
- A host declaration is not a sandbox. The helper cannot prove that a host denies a protected write, that auto-execution is on, or that a screenshot matches runtime behavior. A disposable-path probe proves only that path and action at that time.
- The state home is operator-owned files, not a security boundary. An agent with the same OS user can forge it. The gate digest detects accidental configuration drift, not tampering.
- `local-verified` is not independent QC and not product acceptance. Human review and merge stay separate.
- The helper has no PR ingestion. It never enters a `pr-open` or `accepted` phase.
- Spend is an operator declaration with a source and time. Unknown weeks stay `UNPRICED`. The helper does not read provider pricing, estimates, or invoices.
- Product Gate 1 before the red commit is outside the factory chain. Factory gate 1 is the operator's host-policy declaration, and the recorded chain starts only after the implementation commit.
- Agent turns and file writes are supervision notes only. The helper does not observe or count them.
- A stopped run is not always resumable. Exhausted time or operation limits cannot be extended in place, and a gate-digest or profile change on a stopped run has no re-stage path. `resume` marks those runs `superseded`; counters are preserved, and there is no reset API.
- The helper makes no model calls and no network calls. It does not measure time or cost savings.
- The helper tests exercise Python code and synthetic Git repositories. They include the 197 predecessor tests, portable packaging checks, and review regressions. They are not agent evaluations and do not establish coding-agent quality.
- The `native-turbo` profile is the original Antigravity workflow. The runtime attestation statement names Antigravity even when the `--attest-native-turbo` label differs. Other hosts are not supported or verified. Use `manual` unless an operator evaluates an adaptation in a later issue.
- The live host path and the pilot workflow remain unverified. Antigravity CLI (`agy`) behavior, sandbox restrictions, provider billing, and protected-write denial are unknown.

## Versioning

`VERSION` holds the development version, currently `0.2.0`. No release tag has been published. Releases follow [Semantic Versioning 2.0.0](https://semver.org/). The predecessor line is `0.1.0`, private historical code that was never tagged or published. `0.2.0` is the current development version and is not released until a reviewed merge and tag. The public contract covers the CLI commands and options, observable output and exit behavior, persisted config and evidence formats, and skill compatibility.

While the project is below `1.0.0`, a breaking change bumps the minor version and a fix bumps the patch version. Published tags use `vX.Y.Z` and must agree with `VERSION` and `CHANGELOG.md`.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Search open and closed issues first. Work starts from an issue, uses a linked branch, and lands through an independently reviewed pull request. A human merges.

The workflow builds on the maintainer's public skills:

- https://github.com/huyle-gradion/skills
- https://github.com/huyle-gradion/skills/blob/main/gh-issue/SKILL.md
- https://github.com/huyle-gradion/skills/blob/main/gh-pr/SKILL.md
- https://github.com/huyle-gradion/skills/blob/main/gh-review/SKILL.md

## License

MIT. See [`LICENSE`](LICENSE).

The workflow design is inspired in part by [Sandcastle](https://github.com/mattpocock/sandcastle). Turbo shares no code with it and does not claim an equivalent sandbox.
