---
name: security-review
description: Run separate security review, revision-bound child PR security gating, and bounded finding repair for Turbo delivery (#22)
---

# Security Review and Findings Repair (`security-review`)

Run a separate `security-reviewer` pass on a prepared child candidate, enforce revision-bound security gating on the child PR (`#20`), and route blocking security findings back to the builder for bounded repair (`#22`).

## Resolve the helper from an explicit clone root

```sh
FACTORY_ROOT="/absolute/path/to/your turbo clone"
FACTORY="$FACTORY_ROOT/bin/factory"
test -f "$FACTORY_ROOT/README.md"
test -x "$FACTORY"
```

Keep `"$FACTORY_ROOT"` and `"$FACTORY"` quoted so paths containing spaces work without modification.

## Run child delivery with security review or verify a single file

```sh
PYTHONPATH="$FACTORY_ROOT" python3 -m factory.security_review \
  --repo "/absolute/path/to/disposable-product-repo" \
  --home "/absolute/path/to/disposable-factory-home" \
  --task "<parent-asana-gid-or-url>" --max-repair-rounds 2 --json

PYTHONPATH="$FACTORY_ROOT" python3 -m factory.security_review \
  --repo "/absolute/path/to/disposable-product-repo" --verify-file "src/chat_bridge/auth.py" --json

bash "$FACTORY_ROOT/scripts/demo-security-review.sh"
```

## Contract and guardrails

1. **Mandatory separate reviewer role**: `security-reviewer` must execute in an isolated checkout/session with applicable policies, constraints, and JSON schema (`security-review-missing` if omitted; `invalid-review` if it mutates the worktree or shares the builder session).
2. **Finding-specific independent reproducer**: Prior blockers resolve only when their finding-specific reproducer command exits `0` on the repaired revision with digest-verified log evidence (`reproducer_verification`) and regression checks pass.
3. **Bounded repair without weakening protections**: Repairs cap at `--max-repair-rounds` (`security-repair-exhausted`) and preserve `--sandbox`, `--mode auto`, protected paths, criteria, and security policies.
