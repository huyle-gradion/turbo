---
name: automated-qa
description: Separate automated QA role that exercises child acceptance criteria with explicit rubrics, routes actionable findings to the builder, and re-verifies corrections without claiming parent human acceptance.
---

# Automated QA (`automated-qa`)

Run the separate automated QA role against a child pull request candidate verified by `#20`'s GitHub Actions CI gate (`factory.ci_gate`), record criterion coverage and repeatable rubric outcomes, route behavioral failures back to the builder in an isolated worktree, and re-verify new candidate revisions through both `#20` CI gate and automated QA regression checks.

## Repository resolution & execution

```sh
FACTORY_ROOT="/absolute/path/to/your turbo clone"
test -x "$FACTORY_ROOT/bin/factory" && test -f "$FACTORY_ROOT/README.md"
PYTHONPATH="$FACTORY_ROOT" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m factory.automated_qa --repo "$PRODUCT_REPO" --home "$FACTORY_HOME" \
  --task "<asana-parent-gid-or-url>" --qa-cases-file "$QA_CASES_JSON" \
  --max-correction-attempts 2 --time-limit 15m --json
bash "$FACTORY_ROOT/scripts/demo-automated-qa.sh"
```

## Authority and truth boundaries

- **Separate role & real `#20` gate integration**: Evaluates `candidate_sha` in an isolated read-only check worktree (`qa-role-violation` on any mutation), calling `factory.ci_gate.revalidate_child_verification` before every QA round and `factory.ci_gate.evaluate_child_pr_ci_gate` after every builder correction commit.
- **Stable finding identities & bounded corrections**: Each finding uses deterministic ID `QA-<child_gid>-<criterion_id>-<case_or_check_id>` and stays `open` on `missing-verification`, `verification-gap`, `stale-evidence`, or `regression-failed`. Corrections are bounded by `--max-correction-attempts` (`0..5`, default `2`); parent task human acceptance remains `pending-human-acceptance` (`--approve-parent-acceptance` exits `2`).
