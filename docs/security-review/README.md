# Security Review and Bounded Repair (`#22`)

`factory.security_review` implements Factory 06 (`#22`): a separate `security-reviewer` role, revision-bound security gating composed with `#20`'s child-candidate CI gate (`factory.ci_gate.evaluate_child_pr_ci_gate`), and a bounded builder repair loop.

## Architecture and Evidence Contract

- **Separate Role (`review_candidate_security`)**:
  - Requires actual `security-reviewer` execution (`reviewer_executed=True`, non-empty `reviewer_session_id`, stored `reviewer_stdout_path`); missing reviewer execution fails closed (`outcome="security-review-missing"`).
  - Prompts the reviewer via `build_security_reviewer_prompt` with applicable baseline/repo security policies (`SEC-POL-01`..`05`, `SECURITY.md`, `AGENTS.md`), sub-task constraints, prior blocking findings, and the required JSON response schema.
  - Fails closed (`outcome="invalid-review"`, `role_separation_verified=False`) if the reviewer mutates the worktree or reuses the builder's `conversation_id`.
- **Finding Identity and Independent Reproducer Verification**:
  - `compute_finding_id(policy_id, file_path, rule)` produces a deterministic `SEC-...` identifier stable across rounds.
  - Every open or prior blocking finding runs a finding-specific reproducer (`verification_command`) in the isolated sandbox (`finding_verifications`). A prior blocker transitions to `status="resolved"` **only** when its finding-specific reproducer exits `0` on the repaired `candidate_sha` with digest-verified log evidence (`reproducer_verification`) and regression checks pass.
- **Revision-Bound Child Gate (`evaluate_child_pr_with_security_gate`) & Bounded Repair (`deliver_with_security_review`)**:
  - Composes with `factory.ci_gate.evaluate_child_pr_ci_gate` (`#20`) and fails closed on `security-review-missing`, `security-review-invalid`, `stale-security-review`, `security-blockers-unresolved`, and `security-verification-missing`.
  - Routes open blocking findings to the builder in an isolated repair checkout under `--sandbox --mode auto`, enforcing scope/protected-path/ancestor invariants and stopping with `security-repair-exhausted` when `repairs_used == max_repair_rounds`.

## Shared-File Coordinator Integration & Typechecking Note

During parallel development with `#21`, shared files remain untouched. Post-parallel coordinator wiring: (1) `factory/deliver.py` calls `security_review.deliver_with_security_review`; (2) `factory/args.py` / `factory/cli.py` add `--max-security-repair-rounds` and `--reviewer-agy-bin`; (3) `factory/ci_selection.py` maps `factory/security_review/__init__.py` -> `tests/security_review/test_security_review.py`. No static typechecker (`mypy`/`pyright`) is configured in the repository.
