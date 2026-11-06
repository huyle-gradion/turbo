"""Prepared Asana parent feature HTTP intake, evidence persistence, and CLI entrypoint."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from factory import config as config_module, gitio, runner
from factory.config import now
from factory.errors import UsageError
from factory.intake_eval import (
    _add_unique,
    _classify_parent_criterion,
    _contract_tokens,
    _detect_dependency_cycles,
    _evaluate,
    _evaluate_child_task,
    _extract_gid,
    _has_reviewer_identity,
    _is_missing,
    _normalize_field,
    _parse_bullets,
    _parse_criteria_block,
    _parse_gid_list,
    _parse_parent_task,
    _parse_task_gid,
    _shortest_cycle_in_scc,
    _split_sections,
)
from factory.paths import RuntimePaths, atomic_json, safe_dir, write_evidence

FACTORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ASANA_API_URL = "https://app.asana.com/api/1.0"
BEARER_SECRET_RE = re.compile(r"(?i)\bBearer\s+[^\s\"',;]+")

__all__ = [
    "DEFAULT_ASANA_API_URL",
    "FACTORY_ROOT",
    "IntakeResult",
    "_NoRedirectHandler",
    "_RetrievalError",
    "_add_unique",
    "_classify_parent_criterion",
    "_contract_tokens",
    "_detect_dependency_cycles",
    "_evaluate",
    "_evaluate_child_task",
    "_extract_gid",
    "_fetch_parent_and_children",
    "_get_json",
    "_has_reviewer_identity",
    "_is_missing",
    "_normalize_field",
    "_parse_bullets",
    "_parse_criteria_block",
    "_parse_gid_list",
    "_parse_parent_task",
    "_parse_task_gid",
    "_redact_value",
    "_resolve_api_base",
    "_same_api_origin",
    "_shortest_cycle_in_scc",
    "_split_sections",
    "run_from_cli",
]


class _RetrievalError(Exception):
    """Raised when Asana API retrieval or pagination validation fails."""


class _NoRedirectHandler(HTTPRedirectHandler):
    """Refuses all HTTP redirects so credentials never follow a redirect target."""

    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Request | None:
        raise HTTPError(req.full_url, code, f"refused HTTP {code} redirect to {newurl}", headers, fp)


@dataclass(frozen=True, slots=True)
class IntakeResult:
    schema: int
    task_gid: str
    status: str
    delivery_ready: bool
    factory_revision: str
    subtask_pages: int
    parent: dict[str, Any]
    children: list[dict[str, Any]]
    blockers: list[str]
    measurements: dict[str, Any]
    evidence: dict[str, Any]
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _resolve_api_base() -> str:
    raw = os.environ.get("TURBO_ASANA_API_URL", DEFAULT_ASANA_API_URL).strip().rstrip("/")
    parsed = urlparse(raw)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise UsageError(
            f"disallowed Asana API URL {raw!r}; credentials, query, and fragment are forbidden"
        )
    path_ok = parsed.path.rstrip("/") == "/api/1.0"
    is_canonical = parsed.scheme == "https" and parsed.hostname == "app.asana.com" and path_ok
    is_loopback = (
        parsed.scheme == "http"
        and parsed.hostname in ("127.0.0.1", "localhost", "::1")
        and path_ok
    )
    if is_canonical or is_loopback:
        return raw
    raise UsageError(
        f"disallowed Asana API URL {raw!r}; only https://app.asana.com/api/1.0 or loopback test server is permitted"
    )


def _same_api_origin(url: str, base_url: str) -> bool:
    base_parsed = urlparse(base_url)
    target_parsed = urlparse(url)
    if target_parsed.username or target_parsed.password or target_parsed.fragment:
        return False
    if (target_parsed.scheme, target_parsed.netloc) != (base_parsed.scheme, base_parsed.netloc):
        return False
    target_segments = target_parsed.path.split("/")
    if ".." in target_segments or "." in target_segments:
        return False
    base_path = base_parsed.path.rstrip("/")
    target_path = target_parsed.path.rstrip("/")
    return target_path == base_path or target_path.startswith(base_path + "/")


def _get_json(url: str, token: str, base_url: str, trace: list[dict[str, Any]]) -> dict[str, Any]:
    target_parsed = urlparse(url)
    if not _same_api_origin(url, base_url):
        trace.append({"method": "GET", "url": url, "status": "blocked-origin"})
        raise _RetrievalError(
            f"refused to send credentials to untrusted pagination or API destination: {url}"
        )
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}"}
    request = Request(url, headers=headers, method="GET")
    opener = build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=15) as response:
            status_code = getattr(response, "status", 200)
            body = response.read().decode("utf-8", "replace")
    except HTTPError as exc:
        trace.append({"method": "GET", "url": url, "status": exc.code})
        raise _RetrievalError(f"Asana API HTTP {exc.code} on {target_parsed.path}: {exc.reason}") from exc
    except (URLError, OSError) as exc:
        trace.append({"method": "GET", "url": url, "status": "network-error"})
        raise _RetrievalError(f"Asana API request failed on {target_parsed.path}: {exc}") from exc
    trace.append({"method": "GET", "url": url, "status": status_code})
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise _RetrievalError(f"malformed JSON from Asana API on {target_parsed.path}") from exc
    if not isinstance(parsed, dict):
        raise _RetrievalError(f"Asana API response on {target_parsed.path} must be a JSON object")
    return parsed


def _fetch_parent_and_children(
    task_gid: str, base_url: str, token: str, trace: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    parent_url = f"{base_url}/tasks/{task_gid}?opt_fields=gid,name,notes,completed"
    parent = _get_json(parent_url, token, base_url, trace).get("data")
    if not isinstance(parent, dict) or str(parent.get("gid") or "").strip() != task_gid:
        raise _RetrievalError("Asana parent task response is missing or mismatched data.gid")
    children: list[dict[str, Any]] = []
    seen_child_gids: set[str] = set()
    pages = 0
    seen_offsets: set[str] = set()
    next_offset: str | None = None
    while True:
        query: dict[str, str] = {"opt_fields": "gid,name,notes,completed", "limit": "50"}
        if next_offset is not None:
            query["offset"] = next_offset
        subtasks_url = f"{base_url}/tasks/{task_gid}/subtasks?{urlencode(query)}"
        page = _get_json(subtasks_url, token, base_url, trace)
        pages += 1
        data = page.get("data")
        if not isinstance(data, list) or "next_page" not in page:
            raise _RetrievalError(
                "truncated or malformed Asana subtasks response (requires data list and next_page)"
            )
        for item in data:
            item_gid = str(item.get("gid") or "").strip() if isinstance(item, dict) else ""
            if not item_gid or item_gid in seen_child_gids:
                raise _RetrievalError("Asana subtask entry has missing or duplicate gid")
            seen_child_gids.add(item_gid)
            children.append(item)
        next_page = page["next_page"]
        if next_page is None:
            break
        if not isinstance(next_page, dict):
            raise _RetrievalError("malformed next_page in Asana subtasks response")
        uri = next_page.get("uri")
        if uri is not None and (not isinstance(uri, str) or not _same_api_origin(uri, base_url)):
            raise _RetrievalError(f"refused untrusted pagination destination in next_page.uri: {uri!r}")
        offset = next_page.get("offset")
        if not isinstance(offset, str) or not offset.strip() or offset in seen_offsets:
            raise _RetrievalError(f"invalid or cyclic pagination offset {offset!r}")
        seen_offsets.add(offset)
        next_offset = offset
    return parent, children, pages


def _redact_value(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        redacted = BEARER_SECRET_RE.sub("Bearer [REDACTED]", value)
        for secret in secrets:
            if secret:
                redacted = redacted.replace(secret, "[REDACTED]")
        return redacted
    if isinstance(value, list):
        return [_redact_value(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, secrets) for item in value)
    if isinstance(value, dict):
        return {key: _redact_value(val, secrets) for key, val in value.items()}
    return value


def run_from_cli(paths: RuntimePaths, args: object) -> IntakeResult:
    started = time.monotonic()
    conf = config_module.load(paths)
    config_module.require_binding(conf, paths)
    task_gid = _parse_task_gid(str(getattr(args, "task") or ""))
    base_url = _resolve_api_base()
    raw_secrets = tuple(
        s
        for s in (
            (os.environ.get("ASANA_ACCESS_TOKEN") or "").strip(),
            (os.environ.get("ASANA_PAT") or "").strip(),
            (os.environ.get("ASANA_TOKEN") or "").strip(),
        )
        if s
    )
    env_secrets = tuple(dict.fromkeys([*raw_secrets, *(quote(s, safe="") for s in raw_secrets)]))
    token = raw_secrets[0] if raw_secrets else ""
    intake_dir = safe_dir(paths.home / "intake" / task_gid, create=True, root=paths.home)
    revision_result = gitio.git(FACTORY_ROOT, "rev-parse", "HEAD")
    factory_revision = (
        revision_result.output
        if revision_result.ok and re.fullmatch(r"[0-9a-f]{40}", revision_result.output)
        else "unavailable"
    )
    trace: list[dict[str, Any]] = []
    parent_raw: dict[str, Any] = {}
    children_raw: list[dict[str, Any]] = []
    pages = 0
    try:
        if not token:
            raise _RetrievalError("missing Asana authentication token (ASANA_ACCESS_TOKEN or ASANA_PAT)")
        parent_raw, children_raw, pages = _fetch_parent_and_children(task_gid, base_url, token, trace)
    except _RetrievalError as exc:
        parent_info: dict[str, Any] = {"gid": task_gid, "name": "", "criteria": []}
        children: list[dict[str, Any]] = []
        blockers: list[str] = [str(exc)]
        status = "retrieval-failed"
    else:
        parent_info, children, blockers = _evaluate(task_gid, parent_raw, children_raw)
        status = "empty" if not children else ("ready" if not blockers else "blocked")

    elapsed_ms = int((time.monotonic() - started) * 1000)
    trace_payload = _redact_value(
        {
            "requests": trace,
            "parent": parent_raw,
            "children": children_raw,
            "status": status,
            "blockers": blockers,
        },
        env_secrets,
    )
    trace_text = json.dumps(trace_payload, indent=2, sort_keys=True) + "\n"
    evidence_path = write_evidence(intake_dir, "retrieval", trace_text, paths.home)
    measurements = {
        "elapsed_ms": elapsed_ms,
        "usage": {
            "state": "unavailable",
            "provenance": "unavailable; deterministic HTTP intake makes no model calls",
        },
        "cost": {
            "state": "unavailable",
            "usd": None,
            "provenance": "unavailable; deterministic HTTP intake has no model spend",
        },
    }
    evidence = {
        "retrieval_path": str(evidence_path),
        "retrieval_sha256": runner.digest_text(trace_text),
        "requests": trace_payload["requests"],
    }
    result = IntakeResult(
        schema=1,
        task_gid=task_gid,
        status=status,
        delivery_ready=(status == "ready"),
        factory_revision=factory_revision,
        subtask_pages=pages,
        parent=_redact_value(parent_info, env_secrets),
        children=_redact_value(children, env_secrets),
        blockers=trace_payload["blockers"],
        measurements=measurements,
        evidence=evidence,
        recorded_at=now(),
    )
    atomic_json(intake_dir / "record.json", result.to_dict(), paths.home)
    return result
