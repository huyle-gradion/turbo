"""Focused unit tests for Asana feature contract parsing and DAG readiness evaluation (Issue #17)."""

from __future__ import annotations

import unittest
from unittest import mock

import support  # noqa: F401
from factory import intake_eval
from factory.errors import UsageError

PARENT_NOTES = (
    "## Delivery target\n"
    "- Repository: https://github.com/example/chat-bridge\n"
    "- Target feature branch: feature/chat-auth\n"
    "- Assigned SWE reviewer: @alice-swe (Asana: Alice Nguyen)\n\n"
    "## Acceptance criteria\n"
    "- P-AC-1: Given a request with a bearer token, when validated, then invalid tokens are rejected with 401.\n"
    "  Evaluation: engineering\n"
    "- P-AC-2: Given a valid session, when accessing a protected route, then user context is attached.\n"
    "  Evaluation: engineering\n"
    "- P-AC-3: Error copy and onboarding flow feel clear and intuitive to non-technical users during Acceptance QA.\n"
    "  Evaluation: human-judgment (Acceptance QA usability review)\n"
)


def _child_notes(
    *,
    parent_url: str = "https://app.asana.com/0/0/900",
    repo: str = "https://github.com/example/chat-bridge",
    branch: str = "feature/chat-auth",
    reviewer: str = "@alice-swe (Asana: Alice Nguyen)",
    kind: str = "implementation",
    criteria: str = (
        "- AC-1: Given an expired token, when verified, then TokenExpiredError is raised.\n"
        "  Parent coverage: P-AC-1\n"
        "  Verification: pytest tests/test_auth.py -k test_expired_token"
    ),
    blocked_by: str = "none",
    required_outputs: str = "none",
    produces: str = "TokenValidator contract in chat_bridge.auth",
    spec_links: str = "docs/auth-spec.md#token-validation",
    test_prereqs: str = "disposable local fixtures",
    open_questions: str = "none",
) -> str:
    return (
        "## Outcome\nDeliver bounded feature slice.\n\n"
        f"## Delivery target\n- Parent task: {parent_url}\n- Repository: {repo}\n"
        f"- Target feature branch: {branch}\n- Assigned SWE reviewer: {reviewer}\n- Kind: {kind}\n\n"
        "## Scope\n- In scope: auth slice\n- Out of scope: billing\n- Constraints: stdlib only\n\n"
        f"## Acceptance criteria\n{criteria}\n\n"
        f"## Dependencies and handoff\n- Blocked by: {blocked_by}\n"
        f"- Required outputs: {required_outputs}\n- Produces: {produces}\n\n"
        f"## Context\n- Specification/contracts: {spec_links}\n"
        "- Relevant existing behavior: src/chat_bridge/\n"
        f"- Test prerequisites: {test_prereqs}\n"
        f"- Open questions: {open_questions}\n"
    )


class IntakeEvaluatorTest(unittest.TestCase):
    def test_ambiguous_parent_criteria_and_missing_parent_fields_report_blockers(self) -> None:
        ambiguous_parent = {
            "gid": "900", "name": "Ambiguous parent",
            "notes": (
                "## Delivery target\n"
                "- Repository: https://github.com/example/chat-bridge\n"
                "- Target feature branch: feature/chat-auth\n"
                "- Assigned SWE reviewer: @alice-swe (Asana: Alice Nguyen)\n\n"
                "## Acceptance criteria\n"
                "- P-AC-1: Unclassified criterion with no Evaluation field.\n"
                "- P-AC-2: Mixed criterion.\n"
                "  Evaluation: engineering and human-judgment\n"
            ),
        }
        p_info, _, p_blockers = intake_eval._evaluate("900", ambiguous_parent, [])
        p_by_id = {item["id"]: item for item in p_info["criteria"]}
        for cid in ("P-AC-1", "P-AC-2"):
            self.assertEqual(p_by_id[cid]["classification"], "ambiguous")
            self.assertIsNone(p_by_id[cid]["human_judgment"])
            self.assertEqual(p_by_id[cid]["status"], "ambiguous")
            self.assertTrue(any(f"{cid} has ambiguous" in item for item in p_blockers))

        _, _, missing_blockers = intake_eval._evaluate(
            "900", {"gid": "900", "name": "Unprepared", "notes": "## Acceptance criteria\n"}, []
        )
        for expected in (
            "missing repository", "missing target feature branch",
            "missing reviewer identity", "missing engineering acceptance criteria",
        ):
            self.assertTrue(any(expected in item for item in missing_blockers), missing_blockers)

    def test_transitive_blocking_self_cycles_and_covered_parent_criteria(self) -> None:
        parent_ok = {"gid": "900", "name": "Feature", "notes": PARENT_NOTES}
        child_a = {"gid": "301", "name": "Root A unprepared", "notes": _child_notes(open_questions="Unresolved?")}
        child_b = {
            "gid": "302", "name": "Dependent B",
            "notes": _child_notes(
                criteria="- AC-1: Route.\n  Parent coverage: P-AC-2\n  Verification: pytest",
                blocked_by="301",
                required_outputs="TokenValidator contract in chat_bridge.auth",
                produces="Route contract",
            ),
        }
        child_c = {
            "gid": "303", "name": "Self cycle C",
            "notes": _child_notes(blocked_by="303", required_outputs="Self", produces="Self"),
        }
        p_eval, children, blockers = intake_eval._evaluate("900", parent_ok, [child_a, child_b, child_c])
        by_gid = {child["gid"]: child for child in children}
        self.assertFalse(by_gid["301"]["prepared"])
        self.assertEqual(by_gid["301"]["execution_status"], "blocked")
        self.assertTrue(by_gid["302"]["prepared"])
        self.assertEqual(by_gid["302"]["execution_status"], "blocked")
        self.assertFalse(by_gid["303"]["prepared"])
        self.assertEqual(by_gid["303"]["execution_status"], "blocked")
        self.assertNotIn("dependency cycle", by_gid["302"]["issues"])
        self.assertTrue(any("303 -> 303" in item for item in blockers))
        p_crit = {item["id"]: item for item in p_eval["criteria"]}
        self.assertEqual((p_crit["P-AC-2"]["status"], p_crit["P-AC-2"]["covered_by"]), ("covered", ["302"]))

    def test_1a_overlapping_cycles_mark_every_cyclic_node_unprepared(self) -> None:
        parent_ok = {"gid": "900", "name": "Feature", "notes": PARENT_NOTES}
        node_a = {
            "gid": "301", "name": "Cycle A",
            "notes": _child_notes(blocked_by="302, 304", required_outputs="Out B, Out D", produces="Out A"),
        }
        node_b = {
            "gid": "302", "name": "Cycle B",
            "notes": _child_notes(blocked_by="301", required_outputs="Out A", produces="Out B"),
        }
        node_d = {
            "gid": "304", "name": "Overlapping Cycle D",
            "notes": _child_notes(blocked_by="302", required_outputs="Out B", produces="Out D"),
        }
        _, cyc_children, cyc_blockers = intake_eval._evaluate("900", parent_ok, [node_a, node_b, node_d])
        cyc_by_gid = {child["gid"]: child for child in cyc_children}
        for gid in ("301", "302", "304"):
            self.assertFalse(cyc_by_gid[gid]["prepared"], f"expected {gid} unprepared")
            self.assertIn("dependency cycle", cyc_by_gid[gid]["issues"])
            self.assertEqual(cyc_by_gid[gid]["execution_status"], "blocked")
        self.assertEqual(len(cyc_blockers), len(set(cyc_blockers)))

    def test_1b_duplicate_dependency_ids_are_deduplicated(self) -> None:
        parent_ok = {"gid": "900", "name": "Feature", "notes": PARENT_NOTES}
        d_root = {"gid": "401", "name": "Diamond root", "notes": _child_notes(produces="RootOut")}
        d_left = {
            "gid": "402", "name": "Diamond left",
            "notes": _child_notes(blocked_by="401, https://app.asana.com/0/0/401", required_outputs="RootOut", produces="LeftOut"),
        }
        d_right = {
            "gid": "403", "name": "Diamond right",
            "notes": _child_notes(blocked_by="401", required_outputs="RootOut", produces="RightOut"),
        }
        d_sink = {
            "gid": "404", "name": "Diamond sink",
            "notes": _child_notes(
                criteria="- AC-1: Sink.\n  Parent coverage: P-AC-2\n  Verification: pytest",
                blocked_by="402, 403, 402",
                required_outputs="LeftOut, RightOut",
                produces="SinkOut",
            ),
        }
        _, dia_children, dia_blockers = intake_eval._evaluate("900", parent_ok, [d_root, d_left, d_right, d_sink])
        dia_by_gid = {child["gid"]: child for child in dia_children}
        self.assertEqual(dia_blockers, [])
        self.assertEqual(dia_by_gid["402"]["blocked_by"], ["401"])
        self.assertEqual(dia_by_gid["404"]["blocked_by"], ["402", "403"])
        self.assertEqual(dia_by_gid["404"]["waiting_on"], ["402", "403"])
        self.assertEqual(dia_by_gid["401"]["execution_status"], "ready")
        for gid in ("402", "403", "404"):
            self.assertTrue(dia_by_gid[gid]["prepared"])
            self.assertEqual(dia_by_gid[gid]["execution_status"], "waiting")

    def test_1c_diamond_dependency_graph_evaluates_in_linear_time(self) -> None:
        parent_ok = {"gid": "900", "name": "Feature", "notes": PARENT_NOTES}
        tasks = [{"gid": "1000", "name": "Root", "notes": _child_notes(produces="Out")}]
        for layer in range(1, 22):
            prev_a = str(1000 + (layer - 1) * 2) if layer > 1 else "1000"
            prev_b = str(1000 + (layer - 1) * 2 + 1) if layer > 1 else "1000"
            blocked = prev_a if prev_a == prev_b else f"{prev_a}, {prev_b}"
            for offset in (0, 1):
                gid = str(1000 + layer * 2 + offset)
                tasks.append({
                    "gid": gid, "name": f"L{layer}_{offset}",
                    "notes": _child_notes(blocked_by=blocked, required_outputs="Out", produces="Out"),
                })
        call_count = 0

        class PreparedTracker(dict):
            def __getitem__(self, key: str):
                nonlocal call_count
                if key == "prepared":
                    call_count += 1
                return super().__getitem__(key)

        orig_eval_child = intake_eval._evaluate_child_task
        with mock.patch.object(
            intake_eval, "_evaluate_child_task", side_effect=lambda *a, **kw: PreparedTracker(orig_eval_child(*a, **kw))
        ):
            intake_eval._evaluate("900", parent_ok, tasks)
        self.assertLess(call_count, 500)

    def test_2a_and_2b_boundary_normalization_and_conflicting_child_targets_without_parent(self) -> None:
        parent_missing_target = {
            "gid": "900", "name": "Parent with none/placeholder target",
            "notes": (
                "## Delivery target\n"
                "- Repository: none\n"
                "- Target feature branch: feature/<feature-name>\n"
                "- Assigned SWE reviewer: <Asana identity and GitHub username>\n\n"
                "## Acceptance criteria\n"
                "- P-AC-1: Valid engineering criterion.\n"
                "  Evaluation: engineering\n"
            ),
        }
        child_repo_a = {"gid": "501", "name": "Repo A", "notes": _child_notes(repo="https://github.com/example/repo-a", branch="feature/a")}
        child_repo_b = {"gid": "502", "name": "Repo B", "notes": _child_notes(repo="https://github.com/example/repo-b", branch="feature/b", blocked_by="")}
        p_info, children, blockers = intake_eval._evaluate("900", parent_missing_target, [child_repo_a, child_repo_b])
        self.assertEqual((p_info["repository"], p_info["target_feature_branch"], p_info["assigned_swe_reviewer"]), ("", "", ""))
        by_gid = {child["gid"]: child for child in children}
        for gid in ("501", "502"):
            self.assertFalse(by_gid[gid]["prepared"])
            self.assertEqual(by_gid[gid]["execution_status"], "blocked")
            self.assertTrue(any("conflicting repository target" in item for item in by_gid[gid]["issues"]))
            self.assertTrue(any("conflicting target feature branch" in item for item in by_gid[gid]["issues"]))
        self.assertIn("missing dependency contract", by_gid["502"]["issues"])
        self.assertTrue(any("conflicting repository target" in item for item in blockers))

    def test_3a_and_3b_fan_in_contracts_ordering_only_prerequisites_and_no_substring_match(self) -> None:
        parent_ok = {"gid": "900", "name": "Feature", "notes": PARENT_NOTES}
        p1 = {"gid": "601", "name": "Prereq 1", "notes": _child_notes(produces="TokenValidator contract")}
        p2 = {"gid": "602", "name": "Prereq 2", "notes": _child_notes(produces="SessionStore contract")}
        p_order = {"gid": "605", "name": "Ordering-only prerequisite", "notes": _child_notes(produces="MigrationLockReleased")}
        fan_in_ok = {
            "gid": "603", "name": "Fan-in dependent with ordering prerequisite",
            "notes": _child_notes(
                criteria="- AC-1: Combined.\n  Parent coverage: P-AC-2\n  Verification: pytest",
                blocked_by="601, 602, 605",
                required_outputs="TokenValidator contract, SessionStore contract",
                produces="AuthMiddleware",
            ),
        }
        substring_bad = {
            "gid": "604", "name": "Substring mismatch dependent",
            "notes": _child_notes(blocked_by="601", required_outputs="TokenValidator", produces="Other"),
        }
        _, fan_children, _ = intake_eval._evaluate("900", parent_ok, [p1, p2, p_order, fan_in_ok, substring_bad])
        fan_by_gid = {child["gid"]: child for child in fan_children}
        self.assertTrue(fan_by_gid["603"]["prepared"], fan_by_gid["603"]["issues"])
        self.assertEqual(fan_by_gid["603"]["execution_status"], "waiting")
        self.assertEqual(fan_by_gid["603"]["waiting_on"], ["601", "602", "605"])
        self.assertFalse(fan_by_gid["604"]["prepared"])
        self.assertTrue(any("dependency contract" in item for item in fan_by_gid["604"]["issues"]))

    def test_4a_4b_5a_6a_6b_criteria_subfields_duplicates_reviewers_and_asana_urls(self) -> None:
        bad_parent = {
            "gid": "900", "name": "Parent with duplicate and malformed criteria",
            "notes": (
                "## Delivery target\n"
                "- Repository: https://github.com/example/chat-bridge\n"
                "- Target feature branch: feature/chat-auth\n"
                "- Assigned SWE reviewer: alice@example.com\n\n"
                "## Acceptance criteria\n"
                "- P-AC-1: Valid description.\n"
                "  Evaluation: engineering\n"
                "- P-AC-2: First P-AC-2.\n"
                "  Evaluation: engineering\n"
                "- P-AC-2: Duplicate ID with <placeholder> description.\n"
                "  Evaluation: engineering\n"
                "- Bare bullet without criterion ID that must not be silently dropped\n"
            ),
        }
        nested_child = {
            "gid": "701", "name": "Child with nested subfields",
            "notes": _child_notes(
                parent_url="https://app.asana.com/1/12345/project/67890/task/900",
                criteria=(
                    "- AC-1: Valid nested subfields.\n"
                    "  - Parent coverage:\n"
                    "    - P-AC-1\n"
                    "  - Verification: pytest tests/test_auth.py"
                ),
                spec_links="\n  - docs/auth-spec.md",
            ),
        }
        dup_child = {
            "gid": "702", "name": "Child with duplicate criteria and placeholder reviewer",
            "notes": _child_notes(
                reviewer="@alice-swe (Asana: TBD)",
                criteria=(
                    "- AC-1: <placeholder>\n"
                    "  Parent coverage: P-AC-999\n"
                    "  Verification: pytest\n"
                    "- AC-1: Duplicate child criterion.\n"
                    "  Parent coverage: P-AC-999\n"
                    "  Verification: pytest\n"
                    "  Unknown subfield: something\n"
                ),
                blocked_by="999, 999",
            ),
        }
        _, children, blockers = intake_eval._evaluate("900", bad_parent, [nested_child, dup_child])
        by_gid = {child["gid"]: child for child in children}
        self.assertTrue(by_gid["701"]["prepared"], by_gid["701"]["issues"])
        self.assertFalse(by_gid["702"]["prepared"])
        self.assertEqual(len(by_gid["702"]["issues"]), len(set(by_gid["702"]["issues"])))
        self.assertEqual(len(blockers), len(set(blockers)))
        self.assertTrue(any("duplicate" in item for item in by_gid["702"]["issues"]))
        self.assertTrue(any("description" in item for item in by_gid["702"]["issues"]))
        self.assertTrue(any("subfield" in item for item in by_gid["702"]["issues"]))
        self.assertTrue(any("reviewer identity" in item for item in by_gid["702"]["issues"]))
        self.assertTrue(any("reviewer identity" in item for item in blockers))
        self.assertTrue(any("duplicate" in item for item in blockers))
        self.assertTrue(any("malformed" in item for item in blockers))

        self.assertEqual(intake_eval._parse_task_gid("https://app.asana.com/1/12345/project/67890/task/900"), "900")
        self.assertEqual(intake_eval._parse_task_gid("https://app.asana.com/0/12345/900/f"), "900")
        with self.assertRaises(UsageError):
            intake_eval._parse_task_gid("https://app.asana.com/0/12345/900/bogus")


if __name__ == "__main__":
    unittest.main()
