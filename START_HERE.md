# Start here

Turbo records evidence for one bounded issue at a time. It does not write code, call a model, use the network, or merge anything. The full behavior lives in [`README.md`](README.md). Development version: `0.2.0`. The predecessor `0.1.0` was private historical code and was never tagged or published.

## 1. Run the checks

```sh
FACTORY_ROOT="/absolute/path/to/your turbo clone"
cd "$FACTORY_ROOT"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash scripts/smoke.sh
bash scripts/smoke-turbo.sh
```

The smoke scripts create disposable synthetic repositories. They need Python 3.11 or newer and `git`. They do not need a model account, provider credentials, a live host session, or an existing runtime.

## 2. Read the manual profile

The default profile keeps one approved command at a time. The quickstart in [`README.md`](README.md#manual-profile-quickstart) shows `init`, gate configuration, spend declaration, admission, red, stage, gates, replay, green, and manifest.

Factory gate 1 is the operator's host-policy declaration. It is not the product's lint/type Gate 1. Product Gate 1 runs after edits and before the red commit, outside the factory chain.

## 3. Choose the native profile only if Antigravity is really configured

The `native-turbo` profile is the original Antigravity workflow and replaces four separate verification commands with one `verify` bundle. It needs both an explicit profile and an operator label. Other hosts are not supported or verified; use `manual` unless an operator evaluates an adaptation in a later issue.

Define the same repository and state-home paths you used in the manual profile:

```sh
repo="/absolute/path/to/your product repo"
home="/absolute/path/to/your factory home"
FACTORY_ROOT="/absolute/path/to/your turbo clone"
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure \
  --profile native-turbo --attest-native-turbo antigravity-app
"$FACTORY_ROOT/bin/factory" --repo "$repo" --home "$home" configure --gate 1 \
  --declare-host-probed -- python3 -c 'import sys; sys.exit(0)'
```

The attestation records what the operator selected and probed. It does not prove a sandbox. The `sys.exit(0)` command above is an illustrative no-op, not a host probe and not safety evidence.

## 4. Use a skill

- [`skills/run-issue/SKILL.md`](skills/run-issue/SKILL.md) for the manual one-command path.
- [`skills/run-issue-turbo/SKILL.md`](skills/run-issue-turbo/SKILL.md) for the native path.

Set the clone root first so the skill can find its launcher and documents:

```sh
FACTORY_ROOT="/absolute/path/to/your turbo clone"
FACTORY="$FACTORY_ROOT/bin/factory"
```

No skill is installed globally. If the host does not discover one, ask the agent to read the absolute `SKILL.md` path.

## 5. Know where it stops

A completed run ends at `local-verified`. That means the helper observed the recorded red failure, replayed the exact red command successfully on the staged commit, and saw the configured gate exits. It is not independent QC, not product acceptance, and not a sandbox proof. Human review and merge stay separate.

The packet is optional when you use the helper CLI directly, but both bundled `run-issue` workflows require it before a real product issue. It lives in [`pilot/README.md`](pilot/README.md). It has not been run on a live product issue. The five cases in [`pilot/agent-evals.md`](pilot/agent-evals.md) are manual agent-evaluation instructions, not helper tests, and every result starts as `NOT RUN`.
