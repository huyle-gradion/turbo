# Automated QA (`factory.automated_qa`) — Issue #21

`factory.automated_qa` implements Slice `#21` (`[Factory 05] Run automated QA and correct behavioral failures`): a separate automated QA role that exercises every child acceptance criterion using deterministic verification commands and named repeatable evaluation cases with explicit rubrics, routes structured behavioral findings back to the builder without hand edits, and re-verifies repaired revisions through `#20`'s child PR CI gate (`factory.ci_gate`) and regression checks.

## Acceptance Criteria Coverage

1. **Separate automated QA role & explicit rubrics (`evaluate_child_qa`, `QAEvaluationCase`, `QARubric`)**: Runs in an isolated git checkout of `candidate_sha` with an empty verify-home and `allow_network=False`, enforcing role separation (`qa-role-violation` on checkout mutation), rejecting vague/human-judgment rubrics and weakened commands, and recording round evidence in `<child_dir>/automated-qa/round-<N>/record.json`.
2. **Seeded behavioral defect & actionable finding (`reconcile_findings`)**: Links failing checks/cases to `finding_id` (`QA-<child_gid>-<criterion_id>-<case_id>`), `criterion_id`, `case_id`, `rubric_id`, `failing_evidence`, and `requested_correction`.
3. **Orchestrated builder routing & re-verification (`run_automated_qa_delivery`)**: Routes open findings via `_build_qa_repair_prompt` to the builder in an isolated worktree, pushes new revisions to the child PR branch, confirms the PR head SHA, and re-runs `factory.ci_gate.evaluate_child_pr_ci_gate` (`#20`) and `evaluate_child_qa`.
4. **Stable finding identities, missing verification, and stale evidence guards**: Preserves `finding_id`, `created_round`, `created_candidate_sha`, first `resolved_round` / `resolved_candidate_sha`, and `history` across rounds; keeps findings `open` on `missing-verification` or `stale-evidence`.
5. **Scope discipline & bounded attempts**: Checks repair commits against `deliver_checks.evaluate_scope`, Gate 3 protected paths, branch/remote mutation guards, and `ci_gate.evaluate_spec_check_policy` before pushing; bounds attempts by `max_correction_attempts` (`0..5`, default `2`), stopping with `qa-exhausted` while preserving committed work and evidence.
6. **End-to-end demonstration & parent human acceptance boundary**: `scripts/demo-automated-qa.sh` demonstrates the full seeded failure -> finding -> routed builder correction -> `#20` CI gate + QA re-verification loop offline; `build_parent_acceptance_boundary` keeps `parent_accepted: false` (`pending-human-acceptance`) and rejects `--approve-parent-acceptance`.

## Coordinator Integration Notes (Shared Files Kept Read-Only During Parallel Development)

1. `factory/args.py`: Add subparser `qa = sub.add_parser("automated-qa")` with `--task`, `--time-limit`, `--agy-bin`, `--qa-cases-file`, `--max-correction-attempts`, `--input-rate-usd-per-1m`, `--output-rate-usd-per-1m`, `--approve-parent-acceptance`, and `--json`.
2. `factory/cli.py`: Import `from factory import automated_qa as automated_qa_module` and dispatch `case "automated-qa":` to `automated_qa_module.run_from_cli(paths, args)`.
3. `factory/ci_selection.py`: Map `factory/automated_qa/` and `skills/automated-qa/` to `tests/automated_qa/test_automated_qa.py` and `tests/automated_qa/test_automated_qa_eval.py` in `MODULE_TEST_MAP`.
