"""Command-line grammar for the private operator workflow."""

from __future__ import annotations

import argparse

from factory import config as config_module
from factory import profile as profile_module
from factory.model import STOP_REASONS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="factory",
        description="Private, operator-approved one-issue workflow. No hidden gate ladder, no model calls, no shell.",
    )
    parser.add_argument("--repo", required=True, help="product repository root")
    parser.add_argument("--home", required=True, help="private runtime directory outside the repository")
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("init", help="bind a repository to a private runtime home")

    configure = sub.add_parser("configure", help="set one profile, gate, or the budget timezone")
    configure.add_argument("--gate", choices=("1", "2", "3"))
    configure.add_argument("--timezone")
    configure.add_argument("--profile", choices=profile_module.PROFILES)
    configure.add_argument(
        "--attest-native-turbo",
        nargs="?",
        const=profile_module.DEFAULT_HOST,
        help="operator-declared host selected and probed for native Turbo",
    )
    configure.add_argument("--label")
    configure.add_argument("--timeout", type=int, default=config_module.DEFAULT_TIMEOUT)
    configure.add_argument("--declare-host-deny", action="store_true")
    configure.add_argument("--declare-host-probed", action="store_true")
    configure.add_argument("--protected", action="append", default=[])
    configure.add_argument("argv", nargs=argparse.REMAINDER)

    doctor_parser = sub.add_parser("doctor", help="diagnose configuration and state")
    doctor_parser.add_argument("--json", action="store_true")

    status = sub.add_parser("status", help="print one run")
    status.add_argument("--issue", type=int, required=True)
    status.add_argument("--json", action="store_true")

    spend = sub.add_parser("spend", help="record or show operator-declared spend")
    spend_sub = spend.add_subparsers(dest="spend_action", required=True)
    spend_record = spend_sub.add_parser("record", help="record one week's declared spend")
    spend_record.add_argument("--week")
    spend_record.add_argument("--source", required=True)
    amount = spend_record.add_mutually_exclusive_group(required=True)
    amount.add_argument("--usd", type=float)
    amount.add_argument("--unknown", action="store_true")
    spend_show = spend_sub.add_parser("show", help="show a week's position")
    spend_show.add_argument("--week")

    prepare = sub.add_parser("prepare", help="admit one issue with fail-closed preconditions")
    prepare.add_argument("--issue", type=int, required=True)
    prepare.add_argument("--feature", required=True)
    prepare.add_argument("--kind", choices=("bug", "feature"), required=True)
    prepare.add_argument("--model", required=True)
    prepare.add_argument("--attest-model-account", action="store_true")
    prepare.add_argument("--time-limit", required=True)
    prepare.add_argument("--operation-limit", required=True)
    prepare.add_argument("--supervision-turns")
    prepare.add_argument("--supervision-writes")

    red = sub.add_parser("red", help="run one red command and record the expected failure")
    red.add_argument("--issue", type=int, required=True)
    red.add_argument("--test", required=True)
    red.add_argument("--selector", required=True)
    red.add_argument("--command", required=True)
    red.add_argument("--expect", required=True)

    stage = sub.add_parser("stage", help="pin the expected green commit")
    stage.add_argument("--issue", type=int, required=True)
    stage.add_argument("--commit", required=True)

    replay = sub.add_parser("replay", help="re-run the exact red command on the staged commit")
    replay.add_argument("--issue", type=int, required=True)

    gate = sub.add_parser("gate", help="execute exactly one configured gate")
    gate.add_argument("--issue", type=int, required=True)
    gate.add_argument("--gate", choices=("1", "2", "3"), required=True)

    for name, text in (("green", "verify the recorded gate chain and replay"), ("manifest", "write private evidence"),
                       ("prompt", "print operator instructions")):
        command = sub.add_parser(name, help=text)
        command.add_argument("--issue", type=int, required=True)

    verify = sub.add_parser("verify", help="run one ordered native Turbo verification bundle")
    verify.add_argument("--issue", type=int, required=True)

    stop = sub.add_parser("stop", help="stop a run without resetting counters")
    stop.add_argument("--issue", type=int, required=True)
    stop.add_argument("--reason", choices=STOP_REASONS, required=True)
    stop.add_argument("--detail")

    resume = sub.add_parser("resume", help="offline consistency check; never calls gh")
    resume.add_argument("--issue", type=int, required=True)
    resume.add_argument("--pr", choices=("none", "exists", "unknown"), default="unknown")

    worker = sub.add_parser("worker", help="run one bounded, isolated agy worker task")
    worker.add_argument("--task-id", required=True)
    worker.add_argument("--prompt", required=True)
    worker.add_argument("--artifact", required=True)
    worker.add_argument("--time-limit", required=True)
    worker.add_argument("--input-rate-usd-per-1m", type=float)
    worker.add_argument("--output-rate-usd-per-1m", type=float)
    worker.add_argument("--agy-bin", default="agy")
    worker.add_argument("--agy-arg", action="append", default=[])
    worker.add_argument("--json", action="store_true")

    intake = sub.add_parser("intake", help="admit a prepared Asana parent feature without creating or mutating tasks")
    intake.add_argument("--task", required=True, help="Asana parent task GID or URL")
    intake.add_argument("--json", action="store_true")

    deliver = sub.add_parser("deliver", help="build one prepared child of a feature and open its PR into the feature branch")
    deliver.add_argument("--task", required=True, help="Asana parent task GID or URL")
    deliver.add_argument("--time-limit", default="15m")
    deliver.add_argument("--input-rate-usd-per-1m", type=float)
    deliver.add_argument("--output-rate-usd-per-1m", type=float)
    deliver.add_argument("--agy-bin", default="agy")
    deliver.add_argument("--policy-report", help="path to evaluation report JSON for approved policy selection")
    deliver.add_argument("--policy-proof", help="path to authoritative GitHub PR merge approval proof JSON")
    deliver.add_argument("--policy-proposal", help="optional path to proposal JSON")
    deliver.add_argument("--policy-repo", help="optional factory repo path (defaults to FACTORY_ROOT)")
    deliver.add_argument("--policy-selection", help="optional JSON file containing policy selection paths")
    deliver.add_argument("--json", action="store_true")
    return parser
