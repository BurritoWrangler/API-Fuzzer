"""Declarative stateful workflow execution for business-logic testing.

Phase 6 introduces a small YAML/JSON workflow format for ordered API requests
that test business flows (create → approve → pay → finalize), out-of-order
execution, one-time-token replay, idempotency-key reuse, and prerequisite
omission. Workflows are opt-in and execute against a provided session.
"""

from __future__ import annotations

import copy
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
import yaml


@dataclass(frozen=True)
class WorkflowStep:
    id: str
    method: str
    path: str
    auth_profile: str = "default"
    body: Optional[Any] = None
    query: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    extract: Dict[str, str] = field(default_factory=dict)  # var_name -> json_path
    assertions: List[str] = field(default_factory=list)
    skip_if: Optional[str] = None
    cleanup: bool = False
    media_type: str = "application/json"
    expected_status: Optional[int] = None
    label: str = ""


@dataclass
class WorkflowResult:
    step_id: str
    status_code: int = 0
    success: bool = False
    assertions_passed: int = 0
    assertions_failed: int = 0
    error: Optional[str] = None
    extracted: Dict[str, Any] = field(default_factory=dict)
    response_body: Optional[str] = None


@dataclass
class WorkflowReport:
    workflow_name: str
    results: List[WorkflowResult] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    completed: bool = False
    error: Optional[str] = None


# Maximum steps and recursion depth to prevent unbounded workflows.
MAX_STEPS = 200
MAX_EXTRACTION_DEPTH = 10


def load_workflow(source: str) -> Dict[str, Any]:
    """Load a workflow definition from YAML or JSON text."""
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError:
        try:
            data = json.loads(source)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Could not parse workflow as YAML or JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Workflow root must be an object.")
    return data


def parse_steps(workflow: Dict[str, Any]) -> List[WorkflowStep]:
    """Parse a workflow definition into a list of WorkflowStep objects."""
    raw_steps = workflow.get("steps") or []
    if not isinstance(raw_steps, list):
        raise ValueError("Workflow 'steps' must be a list.")
    if len(raw_steps) > MAX_STEPS:
        raise ValueError(f"Workflow has too many steps ({len(raw_steps)} > {MAX_STEPS}).")
    steps: List[WorkflowStep] = []
    seen_ids: set = set()
    for index, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            raise ValueError(f"Step {index} must be an object.")
        step_id = str(raw.get("id") or f"step_{index}")
        if step_id in seen_ids:
            raise ValueError(f"Duplicate step id: {step_id}")
        seen_ids.add(step_id)
        method = str(raw.get("method") or "GET").upper()
        path = str(raw.get("path") or "")
        if not path:
            raise ValueError(f"Step {step_id} missing 'path'.")
        steps.append(
            WorkflowStep(
                id=step_id,
                method=method,
                path=path,
                auth_profile=str(raw.get("auth_profile") or "default"),
                body=copy.deepcopy(raw.get("body")),
                query=dict(raw.get("query") or {}),
                headers=dict(raw.get("headers") or {}),
                extract=dict(raw.get("extract") or {}),
                assertions=list(raw.get("assertions") or []),
                skip_if=raw.get("skip_if"),
                cleanup=bool(raw.get("cleanup", False)),
                media_type=str(raw.get("media_type") or "application/json"),
                expected_status=raw.get("expected_status"),
                label=str(raw.get("label") or ""),
            )
        )
    return steps


def _resolve_value(value: Any, variables: Dict[str, Any]) -> Any:
    """Replace ``${var}`` placeholders in strings with extracted variables."""
    if isinstance(value, str):
        def replace(match):
            name = match.group(1)
            resolved = variables.get(name)
            return str(resolved) if resolved is not None else match.group(0)
        return re.sub(r"\$\{(\w+)\}", replace, value)
    if isinstance(value, dict):
        return {k: _resolve_value(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_value(item, variables) for item in value]
    return value


def _extract_json_path(data: Any, path: str, depth: int = 0) -> Optional[Any]:
    """Extract a value from parsed JSON using dot/bracket notation."""
    if depth > MAX_EXTRACTION_DEPTH:
        return None
    current = data
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", path):
        part = part.strip("[]")
        if part.isdigit():
            index = int(part)
            if isinstance(current, list) and 0 <= index < len(current):
                current = current[index]
            else:
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _evaluate_assertion(
    assertion: str,
    *,
    status_code: int,
    body: Optional[str],
    variables: Dict[str, Any],
) -> bool:
    """Evaluate a simple assertion expression.

    Supported forms:
      ``status == 200``
      ``status != 403``
      ``body contains "token"``
      ``var:token is not None``
    """
    assertion = assertion.strip()
    if "==" in assertion:
        left, right = assertion.split("==", 1)
        return _resolve_assertion_operand(left.strip(), status_code, body, variables) == \
               _resolve_assertion_operand(right.strip(), status_code, body, variables)
    if "!=" in assertion:
        left, right = assertion.split("!=", 1)
        return _resolve_assertion_operand(left.strip(), status_code, body, variables) != \
               _resolve_assertion_operand(right.strip(), status_code, body, variables)
    if " contains " in assertion:
        left, right = assertion.split(" contains ", 1)
        left_val = str(_resolve_assertion_operand(left.strip(), status_code, body, variables))
        right_val = str(_resolve_assertion_operand(right.strip(), status_code, body, variables))
        return right_val in left_val
    if " is not None" in assertion:
        left = assertion.replace(" is not None", "").strip()
        return _resolve_assertion_operand(left, status_code, body, variables) is not None
    if " is None" in assertion:
        left = assertion.replace(" is None", "").strip()
        return _resolve_assertion_operand(left, status_code, body, variables) is None
    return False


def _resolve_assertion_operand(
    operand: str,
    status_code: int,
    body: Optional[str],
    variables: Dict[str, Any],
) -> Any:
    if operand == "status":
        return status_code
    if operand == "body":
        return body or ""
    if operand.startswith("var:"):
        return variables.get(operand[4:])
    try:
        return int(operand)
    except ValueError:
        pass
    return operand.strip('"').strip("'")


def _evaluate_skip_if(
    condition: Optional[str],
    variables: Dict[str, Any],
) -> bool:
    if condition is None:
        return False
    condition = condition.strip()
    if condition.startswith("var:"):
        name = condition[4:].strip()
        return name in variables and variables[name] is not None
    return False


def execute_workflow(
    steps: Sequence[WorkflowStep],
    *,
    base_url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_headers: Optional[Dict[str, Dict[str, str]]] = None,
    workflow_name: str = "workflow",
) -> WorkflowReport:
    """Execute workflow steps sequentially, extracting variables and checking assertions."""
    report = WorkflowReport(workflow_name=workflow_name)
    auth_headers = auth_headers or {}
    try:
        for step in steps:
            if _evaluate_skip_if(step.skip_if, report.variables):
                result = WorkflowResult(step_id=step.id, success=True)
                result.assertions_passed = 1
                report.results.append(result)
                continue

            path = _resolve_value(step.path, report.variables)
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            headers = dict(step.headers)
            profile_headers = auth_headers.get(step.auth_profile, {})
            headers.update(profile_headers)
            body = _resolve_value(step.body, report.variables) if step.body is not None else None
            query = _resolve_value(step.query, report.variables)

            result = WorkflowResult(step_id=step.id)
            try:
                kwargs: Dict[str, Any] = {
                    "headers": headers,
                    "timeout": timeout,
                    "allow_redirects": False,
                }
                if query:
                    kwargs["params"] = query
                if body is not None:
                    if step.media_type == "application/json":
                        kwargs["json"] = body
                    else:
                        kwargs["data"] = body
                resp = session.request(step.method, url, **kwargs)
                result.status_code = resp.status_code
                result.response_body = resp.text or ""
            except requests.exceptions.RequestException as exc:
                result.error = f"{type(exc).__name__}: {exc}"
                report.results.append(result)
                if not step.cleanup:
                    report.error = f"Step {step.id} failed: {result.error}"
                    return report
                continue

            # Extract variables from the response body.
            try:
                parsed = json.loads(result.response_body) if result.response_body else None
            except (json.JSONDecodeError, TypeError):
                parsed = None
            for var_name, json_path in step.extract.items():
                if parsed is not None:
                    result.extracted[var_name] = _extract_json_path(parsed, json_path)
                    report.variables[var_name] = result.extracted[var_name]

            # Evaluate assertions.
            for assertion in step.assertions:
                if _evaluate_assertion(
                    assertion,
                    status_code=result.status_code,
                    body=result.response_body,
                    variables=report.variables,
                ):
                    result.assertions_passed += 1
                else:
                    result.assertions_failed += 1
                    report.findings.append(
                        f"Step {step.id}: assertion failed: {assertion} "
                        f"(status {result.status_code})"
                    )

            # Expected status check.
            if step.expected_status is not None and result.status_code != step.expected_status:
                report.findings.append(
                    f"Step {step.id}: expected status {step.expected_status} "
                    f"but got {result.status_code}"
                )
                result.assertions_failed += 1

            result.success = result.assertions_failed == 0 and result.error is None
            report.results.append(result)

        report.completed = True
    except Exception as exc:  # pragma: no cover - safety net
        report.error = f"Workflow execution error: {type(exc).__name__}: {exc}"
    return report


@dataclass(frozen=True)
class RaceResult:
    label: str
    status_codes: List[int]
    success_count: int
    conflict_count: int
    finding: str = ""


def execute_race(
    *,
    method: str,
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    concurrency: int = 5,
    iterations: int = 10,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Any] = None,
    label: str = "race",
    expected_conflict: bool = False,
) -> RaceResult:
    """Execute bounded concurrent requests to test race conditions.

    Sends ``concurrency`` parallel requests, ``iterations`` times. Reports
    status code distribution and flags unexpected success rates that may
    indicate a TOCTOU or quota-race vulnerability.
    """
    concurrency = max(1, min(concurrency, 20))
    iterations = max(1, min(iterations, 50))
    all_statuses: List[int] = []
    success_count = 0
    conflict_count = 0

    for _ in range(iterations):
        barrier = threading.Barrier(concurrency)
        results: List[Optional[int]] = [None] * concurrency
        threads: List[threading.Thread] = []

        def worker(idx: int):
            barrier.wait()
            try:
                kwargs: Dict[str, Any] = {
                    "headers": headers or {},
                    "timeout": timeout,
                    "allow_redirects": False,
                }
                if body is not None:
                    kwargs["json"] = body
                resp = session.request(method, url, **kwargs)
                results[idx] = resp.status_code
            except requests.exceptions.RequestException:
                results[idx] = 0

        for i in range(concurrency):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=timeout + 5)

        for status in results:
            if status is None:
                continue
            all_statuses.append(status)
            if 200 <= status < 300:
                success_count += 1
            if status in (409, 429):
                conflict_count += 1

    statuses = sorted(set(s for s in all_statuses if s != 0))
    finding = ""
    total = len(all_statuses)
    if total > 0:
        success_rate = success_count / total
        if expected_conflict and success_rate > 0.8:
            finding = (
                f"Race condition: {success_count}/{total} concurrent requests succeeded "
                f"where conflicts were expected — possible TOCTOU or quota-race bypass."
            )
        elif not expected_conflict and conflict_count > 0:
            finding = (
                f"Race condition: {conflict_count}/{total} concurrent requests returned "
                f"409/429 — possible race-induced conflict."
            )
    return RaceResult(
        label=label,
        status_codes=statuses,
        success_count=success_count,
        conflict_count=conflict_count,
        finding=finding,
    )
