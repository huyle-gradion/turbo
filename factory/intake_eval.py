"""Pure Asana feature contract parser and DAG readiness evaluator.

Contract-token matching rules:
- ``Produces`` and ``Required outputs`` are split on ``;``, ``,``, or newlines into normalized tokens via
  ``_contract_tokens``: outer whitespace is stripped, internal whitespace is collapsed to single spaces,
  tokens are case-folded, and empty, ``MISSING_WORDS``, or ``<...>`` placeholder values are rejected.
- ``Required outputs: none`` yields an empty required-token set (``set()``), representing an ordering-only
  dependency.
- Every child subtask (including every prerequisite in ``Blocked by``) must declare at least one normalized
  ``Produces`` token; a prerequisite with no valid ``Produces`` tokens emits
  ``missing dependency contract from prerequisite <gid>``.
- When a child declares non-empty ``Required outputs``, every required token must appear in the union of
  ``Produces`` token sets across its declared ``Blocked by`` prerequisites
  (``req_tokens.issubset(available_tokens)``), matched by exact normalized token equality (never substring
  matching). Individual prerequisites in ``Blocked by`` are not required to contribute to ``Required outputs``
  when other prerequisites satisfy all required tokens, preserving ordering-only prerequisites alongside
  data-producing prerequisites in fan-in dependency graphs.
"""

from __future__ import annotations

from collections import deque
import re
from typing import Any

from factory.errors import UsageError

TASK_GID_RE = re.compile(r"^[0-9]{1,32}$")
ASANA_V0_URL_RE = re.compile(
    r"^https://app\.asana\.com/0/(?:(?:search|inbox)/[0-9]{1,32}|[0-9]{1,32})/([0-9]{1,32})(?:/f)?/?(?:[?#].*)?$"
)
ASANA_V1_URL_RE = re.compile(
    r"^https://app\.asana\.com/1/[0-9]{1,32}(?:/[A-Za-z0-9_-]+/[0-9]{1,32})*/(?:task|subtask)/([0-9]{1,32})(?:/f)?/?(?:[?#].*)?$"
)
SECTION_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
TOP_BULLET_RE = re.compile(r"^-\s*([A-Za-z][A-Za-z0-9 _/-]*):\s*(.*?)\s*$")
NESTED_BULLET_RE = re.compile(r"^\s+(?:-\s*)?(.*?)\s*$")
CRITERION_HEAD_RE = re.compile(r"^-\s*([A-Za-z0-9_-]+):\s*(.*?)\s*$")
SUBFIELD_RE = re.compile(r"^\s+(?:-\s*)?([A-Za-z][A-Za-z0-9 _/-]*):\s*(.*?)\s*$")
NESTED_ITEM_RE = re.compile(r"^\s+-\s*(.+?)\s*$")
ENGINEERING_EVAL_RE = re.compile(r"\b(engineering|automated|machine[- ]verifiable|deterministic|ci)\b", re.IGNORECASE)
HUMAN_JUDGMENT_RE = re.compile(
    r"\b(human[- ]judgment|acceptance\s+qa|usability|non-technical\s+qa|manual\s+qa|human\s+review|visual\s+inspection)\b",
    re.IGNORECASE,
)
VAGUE_VERIFICATION_RE = re.compile(r"^(looks\s+good|lgtm|manual|tbd|todo|none|n/a)$", re.IGNORECASE)
PLACEHOLDER_TOKEN_RE = re.compile(r"<[^>\r\n]+>")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")
GITHUB_HANDLE_RE = re.compile(
    r"(?:^|(?<![A-Za-z0-9_-]))@([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)(?![A-Za-z0-9_.-])"
)
MISSING_WORDS = frozenset({"tbd", "todo", "n/a", "na", "unknown", "?", "null", "placeholder"})
PARENT_CRITERION_SUBFIELDS = frozenset({"evaluation"})
CHILD_CRITERION_SUBFIELDS = frozenset({"parent coverage", "verification"})


def _add_unique(items: list[str], message: str) -> None:
    if message not in items:
        items.append(message)


def _is_missing(value: str, *, allow_none_literal: bool = False) -> bool:
    stripped = value.strip()
    if not stripped or PLACEHOLDER_TOKEN_RE.search(stripped):
        return True
    lower = stripped.lower()
    if lower in MISSING_WORDS:
        return True
    return not allow_none_literal and lower == "none"


def _normalize_field(value: str, *, allow_none_literal: bool = False) -> str:
    if _is_missing(value, allow_none_literal=allow_none_literal):
        return ""
    stripped = value.strip()
    return "none" if allow_none_literal and stripped.lower() == "none" else stripped


def _has_reviewer_identity(value: str) -> bool:
    if _is_missing(value):
        return False
    without_emails = EMAIL_RE.sub(" ", value)
    github_match = GITHUB_HANDLE_RE.search(without_emails)
    if github_match is None:
        return False
    handle = github_match.group(1).lower()
    if handle in MISSING_WORDS or handle in ("none", "user", "username", "github", "handle"):
        return False
    remainder = without_emails[: github_match.start()] + " " + without_emails[github_match.end() :]
    cleaned = re.sub(r"(?i)\b(?:asana|github|username|handle|identity|and)\b", " ", remainder).strip(" ()[],;:-/")
    if _is_missing(cleaned):
        return False
    words = [tok.lower() for tok in re.findall(r"[A-Za-z0-9]+", cleaned)]
    return any(word not in MISSING_WORDS and word != "none" for word in words)


def _extract_gid(raw: str) -> str | None:
    stripped = raw.strip()
    if TASK_GID_RE.fullmatch(stripped):
        return stripped
    for pattern in (ASANA_V0_URL_RE, ASANA_V1_URL_RE):
        match = pattern.fullmatch(stripped)
        if match is not None:
            return match.group(1)
    return None


def _parse_task_gid(task_ref: str) -> str:
    gid = _extract_gid(task_ref)
    if gid is not None:
        return gid
    raise UsageError(f"invalid --task {task_ref!r}; provide an Asana numeric task GID or https://app.asana.com/... task URL")


def _parse_gid_list(raw: str) -> tuple[list[str], list[str]]:
    normalized = _normalize_field(raw, allow_none_literal=True)
    if not normalized:
        return [], [raw.strip() or "missing"]
    if normalized == "none":
        return [], []
    gids: list[str] = []
    invalid: list[str] = []
    for token in re.split(r"[\s,]+", normalized):
        if not token:
            continue
        gid = _extract_gid(token)
        if gid is not None:
            _add_unique(gids, gid)
        else:
            _add_unique(invalid, token)
    return gids, invalid


def _split_sections(notes: str) -> dict[str, str]:
    parts = SECTION_RE.split(notes)
    return {parts[index].strip().lower(): parts[index + 1].strip() for index in range(1, len(parts), 2)}


def _parse_bullets(section_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current_key: str | None = None
    for line in section_text.splitlines():
        if not line.strip():
            continue
        top = TOP_BULLET_RE.match(line)
        if top is not None:
            current_key = top.group(1).strip().lower()
            fields[current_key] = top.group(2).strip()
            continue
        nested = NESTED_BULLET_RE.match(line)
        if current_key is not None and nested is not None:
            sub_val = nested.group(1).strip()
            if sub_val:
                fields[current_key] = f"{fields[current_key]}, {sub_val}" if fields[current_key] else sub_val
        else:
            current_key = None
    return fields


def _parse_criteria_block(section_text: str, *, allowed_subfields: frozenset[str]) -> tuple[list[dict[str, str]], list[str]]:
    items: list[dict[str, str]] = []
    errors: list[str] = []
    current: dict[str, str] | None = None
    active_sub: tuple[str, int] | None = None
    for line in section_text.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        head = CRITERION_HEAD_RE.match(line)
        if head is not None:
            if current is not None:
                items.append(current)
            current = {"id": head.group(1).strip(), "description": head.group(2).strip()}
            active_sub = None
            continue
        if current is not None and active_sub is not None and indent > active_sub[1]:
            nested_item = NESTED_ITEM_RE.match(line)
            if nested_item is not None:
                sub_key = active_sub[0]
                val = nested_item.group(1).strip()
                current[sub_key] = f"{current[sub_key]}, {val}" if current.get(sub_key) else val
                continue
        sub = SUBFIELD_RE.match(line)
        if sub is not None and current is not None:
            sub_key = sub.group(1).strip().lower()
            sub_val = sub.group(2).strip()
            if sub_key not in allowed_subfields:
                _add_unique(errors, f"unsupported or malformed subfield {sub_key!r} on criterion {current['id']}")
                active_sub = None
            elif sub_key in current:
                _add_unique(errors, f"duplicate subfield {sub_key!r} on criterion {current['id']}")
                active_sub = None
            else:
                current[sub_key] = sub_val
                active_sub = (sub_key, indent)
            continue
        _add_unique(errors, f"malformed acceptance criterion line: {line.strip()}")
    if current is not None:
        items.append(current)
    return items, errors


def _check_delivery_target(target: dict[str, str]) -> tuple[str, str, str, list[str]]:
    repo = _normalize_field(target.get("repository", ""))
    branch = _normalize_field(target.get("target feature branch", ""))
    raw_reviewer = target.get("assigned swe reviewer", "").strip()
    has_reviewer = _has_reviewer_identity(raw_reviewer)
    reviewer = raw_reviewer if has_reviewer else ""
    issues: list[str] = []
    if not repo:
        issues.append("missing repository")
    if not branch:
        issues.append("missing target feature branch")
    if not has_reviewer:
        issues.append("missing reviewer identity (requires Asana and GitHub @handle)")
    return repo, branch, reviewer, issues


def _contract_tokens(raw: str, *, allow_none_literal: bool = False) -> set[str]:
    normalized = _normalize_field(raw, allow_none_literal=allow_none_literal)
    if not normalized or normalized == "none":
        return set()
    tokens: set[str] = set()
    for piece in re.split(r"[;,\n]+", normalized):
        cleaned = _normalize_field(piece, allow_none_literal=False)
        if cleaned:
            tokens.add(" ".join(cleaned.split()).casefold())
    return tokens


def _classify_parent_criterion(criterion: dict[str, str]) -> tuple[str, bool | None, str]:
    raw_evaluation = criterion.get("evaluation", "").strip()
    if _is_missing(raw_evaluation):
        return "ambiguous", None, "ambiguous"
    is_engineering = bool(ENGINEERING_EVAL_RE.search(raw_evaluation))
    is_human = bool(HUMAN_JUDGMENT_RE.search(raw_evaluation))
    if is_engineering and not is_human:
        return "engineering", False, "uncovered"
    if is_human and not is_engineering:
        return "human-judgment", True, "pending-human-acceptance"
    return "ambiguous", None, "ambiguous"


def _parse_parent_task(task_gid: str, parent_raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[str]]:
    sections = _split_sections(str(parent_raw.get("notes") or ""))
    target = _parse_bullets(sections.get("delivery target", ""))
    repo, branch, reviewer, target_issues = _check_delivery_target(target)
    blockers: list[str] = []
    for issue in target_issues:
        _add_unique(blockers, f"parent task {task_gid} is {issue}")

    raw_criteria, parse_errors = _parse_criteria_block(
        sections.get("acceptance criteria", ""), allowed_subfields=PARENT_CRITERION_SUBFIELDS
    )
    for err in parse_errors:
        _add_unique(blockers, f"parent task {task_gid} has {err}")

    criteria: list[dict[str, Any]] = []
    criteria_by_id: dict[str, dict[str, Any]] = {}
    for item in raw_criteria:
        criterion_id = item["id"]
        description = _normalize_field(item.get("description", ""))
        if not description:
            _add_unique(blockers, f"parent criterion {criterion_id} has missing or placeholder description")
        classification, human_judgment, status = _classify_parent_criterion(item)
        if classification == "ambiguous":
            _add_unique(blockers, f"parent criterion {criterion_id} has ambiguous or missing evaluation classification")
        if criterion_id in criteria_by_id:
            _add_unique(blockers, f"parent task {task_gid} has duplicate criterion ID {criterion_id}")
            criteria_by_id[criterion_id]["classification"] = "ambiguous"
            criteria_by_id[criterion_id]["human_judgment"] = None
            criteria_by_id[criterion_id]["status"] = "ambiguous"
            continue
        entry: dict[str, Any] = {
            "id": criterion_id, "description": description, "classification": classification,
            "human_judgment": human_judgment, "covered_by": [], "status": status,
        }
        criteria.append(entry)
        criteria_by_id[criterion_id] = entry

    if not any(item["classification"] == "engineering" for item in criteria):
        _add_unique(blockers, f"parent task {task_gid} is missing engineering acceptance criteria")

    parent_info = {
        "gid": task_gid, "name": str(parent_raw.get("name") or ""), "repository": repo,
        "target_feature_branch": branch, "assigned_swe_reviewer": reviewer, "criteria": criteria,
    }
    return parent_info, criteria_by_id, blockers


def _evaluate_child_task(raw: dict[str, Any], parent_criteria_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    gid = str(raw.get("gid")).strip()
    sections = _split_sections(str(raw.get("notes") or ""))
    repo, branch, reviewer, issues = _check_delivery_target(_parse_bullets(sections.get("delivery target", "")))
    dependencies = _parse_bullets(sections.get("dependencies and handoff", ""))
    context = _parse_bullets(sections.get("context", ""))
    criteria_raw, criteria_errors = _parse_criteria_block(
        sections.get("acceptance criteria", ""), allowed_subfields=CHILD_CRITERION_SUBFIELDS
    )
    for err in criteria_errors:
        _add_unique(issues, err)

    if not _normalize_field(context.get("specification/contracts", "")) or not _normalize_field(context.get("test prerequisites", "")):
        _add_unique(issues, "missing context (specification/contracts or test prerequisites)")
    if _normalize_field(context.get("open questions", ""), allow_none_literal=True) != "none":
        raw_open = context.get("open questions", "").strip()
        _add_unique(issues, f"blocking ambiguity in open questions: {raw_open or 'missing'}")

    blocked_by, invalid_deps = _parse_gid_list(dependencies.get("blocked by", ""))
    required_outputs = _normalize_field(dependencies.get("required outputs", ""), allow_none_literal=True)
    produces = _normalize_field(dependencies.get("produces", ""))
    if (
        "blocked by" not in dependencies
        or invalid_deps
        or not _contract_tokens(produces)
        or (blocked_by and not required_outputs)
    ):
        _add_unique(issues, "missing dependency contract")

    coverage: list[str] = []
    parsed_criteria: list[dict[str, Any]] = []
    seen_criteria: set[str] = set()
    if not criteria_raw:
        _add_unique(issues, "missing criterion verification")
        _add_unique(issues, "missing parent coverage")
    for item in criteria_raw:
        criterion_id = item["id"]
        if criterion_id in seen_criteria:
            _add_unique(issues, f"duplicate criterion ID {criterion_id}")
        seen_criteria.add(criterion_id)
        description = _normalize_field(item.get("description", ""))
        if not description:
            _add_unique(issues, f"missing or placeholder description on criterion {criterion_id}")
        raw_verification = item.get("verification", "").strip()
        verification = _normalize_field(raw_verification)
        coverage_raw = _normalize_field(item.get("parent coverage", ""))
        if (
            not verification
            or VAGUE_VERIFICATION_RE.fullmatch(verification)
            or HUMAN_JUDGMENT_RE.search(raw_verification)
            or HUMAN_JUDGMENT_RE.search(item.get("description", ""))
        ):
            _add_unique(issues, f"missing or ambiguous criterion verification on {criterion_id}")
        covered_ids = [tok.strip() for tok in re.split(r"[,;]+", coverage_raw) if tok.strip()] if coverage_raw else []
        if not covered_ids:
            _add_unique(issues, f"missing parent coverage on {criterion_id}")
        for ref in covered_ids:
            parent_criterion = parent_criteria_by_id.get(ref)
            if parent_criterion is None or parent_criterion["classification"] != "engineering":
                _add_unique(issues, f"ambiguous or unknown parent coverage {ref} on {criterion_id}")
            else:
                _add_unique(coverage, ref)
        parsed_criteria.append({
            "id": criterion_id, "description": description,
            "parent_coverage": covered_ids, "verification": verification,
        })

    return {
        "gid": gid, "name": str(raw.get("name") or ""), "repository": repo,
        "target_feature_branch": branch, "assigned_swe_reviewer": reviewer,
        "criteria": parsed_criteria, "parent_coverage": coverage, "blocked_by": blocked_by,
        "required_outputs": required_outputs, "produces": produces,
        "waiting_on": list(blocked_by), "issues": issues,
        "prepared": False, "execution_status": "blocked",
    }


def _shortest_cycle_in_scc(start: str, scc_set: set[str], child_by_gid: dict[str, dict[str, Any]]) -> list[str]:
    queue: deque[tuple[str, list[str]]] = deque()
    for dep in child_by_gid[start]["blocked_by"]:
        if dep == start:
            return [start, start]
        if dep in scc_set:
            queue.append((dep, [start, dep]))
    visited: set[str] = set()
    while queue:
        node, path = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        for nxt in child_by_gid[node]["blocked_by"]:
            if nxt == start:
                return path + [start]
            if nxt in scc_set and nxt not in visited:
                queue.append((nxt, path + [nxt]))
    return [start, start]


def _detect_dependency_cycles(children: list[dict[str, Any]], child_by_gid: dict[str, dict[str, Any]]) -> tuple[set[str], list[str]]:
    index_counter = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    in_cycle: set[str] = set()
    cycle_blockers: list[str] = []

    def _strongconnect(gid: str) -> None:
        nonlocal index_counter
        indices[gid] = index_counter
        lowlink[gid] = index_counter
        index_counter += 1
        stack.append(gid)
        on_stack.add(gid)
        for dep_gid in child_by_gid[gid]["blocked_by"]:
            if dep_gid not in child_by_gid:
                continue
            if dep_gid not in indices:
                _strongconnect(dep_gid)
                lowlink[gid] = min(lowlink[gid], lowlink[dep_gid])
            elif dep_gid in on_stack:
                lowlink[gid] = min(lowlink[gid], indices[dep_gid])
        if lowlink[gid] == indices[gid]:
            scc: list[str] = []
            while True:
                node = stack.pop()
                on_stack.remove(node)
                scc.append(node)
                if node == gid:
                    break
            scc_set = set(scc)
            if len(scc) > 1 or gid in child_by_gid[gid]["blocked_by"]:
                in_cycle.update(scc_set)
                covered: set[str] = set()
                for member in reversed(scc):
                    if member not in covered:
                        cycle_path = _shortest_cycle_in_scc(member, scc_set, child_by_gid)
                        covered.update(cycle_path)
                        _add_unique(cycle_blockers, f"dependency cycle: {' -> '.join(cycle_path)}")

    for child in children:
        if child["gid"] not in indices:
            _strongconnect(child["gid"])
    return in_cycle, cycle_blockers


def _evaluate(task_gid: str, parent_raw: dict[str, Any], children_raw: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    parent_info, parent_criteria_by_id, blockers = _parse_parent_task(task_gid, parent_raw)
    child_records: list[dict[str, Any]] = []
    child_by_gid: dict[str, dict[str, Any]] = {}
    for raw in children_raw:
        child_record = _evaluate_child_task(raw, parent_criteria_by_id)
        child_records.append(child_record)
        child_by_gid[child_record["gid"]] = child_record

    if not child_records:
        _add_unique(blockers, f"parent task {task_gid} has no prepared sub-tasks")
        return parent_info, child_records, blockers

    for field, parent_value, label in (
        ("repository", parent_info["repository"], "repository target"),
        ("target_feature_branch", parent_info["target_feature_branch"], "target feature branch"),
    ):
        values = {val for val in [parent_value, *(c[field] for c in child_records)] if val}
        if len(values) > 1:
            _add_unique(blockers, f"conflicting {label}: {', '.join(sorted(values))}")
            for child in child_records:
                if child[field] and (not parent_value or child[field] != parent_value):
                    _add_unique(child["issues"], f"conflicting {label} {child[field]}")

    produces_by_gid = {c["gid"]: _contract_tokens(c["produces"]) for c in child_records}
    for child in child_records:
        req_tokens = _contract_tokens(child["required_outputs"], allow_none_literal=True)
        available_tokens: set[str] = set()
        for dep_gid in child["blocked_by"]:
            if dep_gid not in child_by_gid:
                msg = f"missing dependency {dep_gid}"
                _add_unique(child["issues"], msg)
                _add_unique(blockers, f"child {child['gid']} has {msg}")
                continue
            prereq_tokens = produces_by_gid[dep_gid]
            available_tokens.update(prereq_tokens)
            if not prereq_tokens:
                msg = f"missing dependency contract from prerequisite {dep_gid}"
                _add_unique(child["issues"], msg)
                _add_unique(blockers, f"child {child['gid']} has {msg}")
        if req_tokens and not req_tokens.issubset(available_tokens):
            msg = "missing dependency contract for required outputs"
            _add_unique(child["issues"], msg)
            _add_unique(blockers, f"child {child['gid']} has {msg}")

    in_cycle, cycle_blockers = _detect_dependency_cycles(child_records, child_by_gid)
    for cycle_blocker in cycle_blockers:
        _add_unique(blockers, cycle_blocker)
    for gid in in_cycle:
        _add_unique(child_by_gid[gid]["issues"], "dependency cycle")
    for child in child_records:
        child["prepared"] = len(child["issues"]) == 0

    blocked_cache: dict[str, bool] = {}
    visiting: set[str] = set()

    def _is_blocked(gid: str) -> bool:
        if gid in blocked_cache:
            return blocked_cache[gid]
        if gid in visiting:
            return True
        current = child_by_gid[gid]
        if not current["prepared"]:
            blocked_cache[gid] = True
            return True
        visiting.add(gid)
        is_blk = any(dep not in child_by_gid or _is_blocked(dep) for dep in current["blocked_by"])
        visiting.remove(gid)
        blocked_cache[gid] = is_blk
        return is_blk

    for child in child_records:
        if child["prepared"]:
            for ref in child["parent_coverage"]:
                parent_criterion = parent_criteria_by_id.get(ref)
                if parent_criterion is not None and child["gid"] not in parent_criterion["covered_by"]:
                    parent_criterion["covered_by"].append(child["gid"])
                    if parent_criterion["classification"] == "engineering":
                        parent_criterion["status"] = "covered"
        if _is_blocked(child["gid"]):
            child["execution_status"] = "blocked"
            for issue in child["issues"]:
                _add_unique(blockers, f"child {child['gid']}: {issue}")
        else:
            child["execution_status"] = "waiting" if child["blocked_by"] else "ready"

    for parent_criterion in parent_info["criteria"]:
        if parent_criterion["classification"] == "engineering" and parent_criterion["status"] != "covered":
            _add_unique(blockers, f"uncovered parent criterion {parent_criterion['id']}")
    return parent_info, child_records, blockers
