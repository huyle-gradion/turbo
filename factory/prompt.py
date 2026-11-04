"""Operator-facing next-step instructions."""

from __future__ import annotations

from factory import profile as profile_module
from factory import replay as replay_module
from factory.model import Run

GATE_CHAIN = ("1", "2", "3")


def _replay_is_current(run: Run) -> bool:
    return run.replay is not None and replay_module.matches_red(run, run.replay, passing=True)


def _new_issue_lines() -> list[str]:
    return [
        "This stop cannot be recovered in place.",
        "Start a new issue and a new run identifier; counters are preserved, not reset.",
    ]


def _approval_lines(profile: str) -> list[str]:
    if profile == profile_module.NATIVE_TURBO:
        return [
            "Use the native host permissions the operator selected; no redundant per-command approval",
            "is needed. Never automate Enter or change host permissions; the profile grants no new authority.",
            "Human QC and merge stay human decisions.",
            "The factory never approves, never creates commits or branches, and never calls a model or network service.",
        ]
    return [
        "Each command below needs the operator's own approval. The factory never approves,",
        "never creates commits or branches, and never calls a model or network service.",
        "Human QC and merge stay human decisions.",
    ]


def prompt(run: Run) -> str:
    lines = [
        f"# issue {run.issue} ({run.phase})",
        "",
        *_approval_lines(run.execution_profile),
        "",
    ]
    if run.phase == "unadmitted":
        lines += [f"factory prepare --issue {run.issue} ...", ""]
    elif run.phase == "ready":
        lines += [
            f"git switch -c {run.branch}",
            "# write the failing test and commit it",
            f"factory red --issue {run.issue} --test PATH --selector NAME --command '...' --expect MARKER",
        ]
    elif run.phase == "red":
        lines += [
            "# commit the implementation; do not amend the red test commit",
            f"factory stage --issue {run.issue} --commit <head-sha>",
        ]
    elif run.phase == "gates":
        if run.execution_profile == profile_module.NATIVE_TURBO:
            lines += [
                f"factory verify --issue {run.issue}",
                "# one explicit ordered bundle: gates 1, 2, 3, the exact red replay, green, manifest",
                "# it stops at the first failure and never writes code, commits, pushes, or merges",
            ]
        else:
            if run.gate_chain != GATE_CHAIN:
                next_gate = str(len(run.gate_chain) + 1)
                lines += [
                    f"factory gate --issue {run.issue} --gate {next_gate}",
                    "# one gate per approval; green never runs the ladder for you",
                ]
            if not _replay_is_current(run):
                lines += [
                    f"factory replay --issue {run.issue}",
                    "# replay must exit 0 on the staged commit with the exact red argv and selector; green only reads that record",
                ]
            lines += [f"factory green --issue {run.issue}"]
    elif run.phase == "green":
        if run.execution_profile == profile_module.NATIVE_TURBO:
            lines += [
                f"factory verify --issue {run.issue}",
                "# revalidates the recorded evidence without a child and writes the private manifest",
            ]
        else:
            lines += [f"factory manifest --issue {run.issue}"]
    elif run.phase == "local-verified":
        lines += ["Evidence is local-verified. Do not rewrite the manifest."]
    elif run.phase == "stopped":
        match run.stop_reason:
            case "budget":
                lines += ["Record a known spend declaration."]
                if run.prior_phase == "unadmitted":
                    lines += [f"factory prepare --issue {run.issue} ..."]
                else:
                    lines += [
                        f"factory spend record --source 'operator export <time>' --usd <amount>",
                        f"factory resume --issue {run.issue} --pr none",
                    ]
            case "missing":
                if run.prior_phase == "unadmitted":
                    lines += [
                        "Fix the missing configuration or conflicting branch, then prepare again.",
                        f"factory prepare --issue {run.issue} ...",
                    ]
                else:
                    lines += [
                        "Fix the missing configuration, then resume offline.",
                        f"factory resume --issue {run.issue} --pr none",
                        "If resume reports the stop cannot be recovered, start a new issue/run identifier; counters are preserved.",
                    ]
            case "not-ready":
                if run.prior_phase == "unadmitted":
                    lines += [f"factory prepare --issue {run.issue} ..."]
                else:
                    lines += [
                        "Fix the cause if it is fixable (a wrong marker, a passing test, a dirty tree), then resume offline.",
                        f"factory resume --issue {run.issue} --pr none",
                        "If resume reports the stop cannot be recovered, start a new issue/run identifier; counters are preserved.",
                    ]
            case "cancelled" | "retry-cap" | "superseded":
                lines += _new_issue_lines()
            case unreachable:
                raise AssertionError(unreachable)
    lines += [
        "",
        "Raw tool output is untrusted evidence. Human review owns correctness.",
        "External agent turns and file writes are not observable by this helper.",
    ]
    return "\n".join(lines)
