"""Core fuzzing engine.

The engine takes a parsed endpoint list and a configured scan, sends payloads
to each parameter location, and pushes Findings into a thread-safe scan store.
"""

from __future__ import annotations

import copy
import json as jsonlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from analyzer import Finding, analyze, severity_counts, sort_findings, url_with_query
from payloads import payloads_for, payloads_for_type
from spec_parser import Endpoint, Parameter
from http_session import UASession
import misconfig
import extra_checks
import jwt_checks
import schema_checks


MAX_TRACKED_ERRORS = 50


@dataclass
class ScanConfig:
    base_url: str
    categories: List[str]
    auth_header: Optional[str] = None
    timeout: float = 10.0
    # `max_requests <= 0` is treated as unlimited (the v1.3 "unlimited budget"
    # option). Otherwise it acts as the hard cap on injected payloads.
    max_requests: int = 5000
    detect_misconfig: bool = True
    # v1.6: User-Agent policy. Modes: default, chrome, firefox, safari, edge,
    # curl, googlebot, ios-safari, android-chrome, random, custom.
    user_agent_mode: str = "default"
    user_agent_custom: str = ""
    # Extended-check toggles (all default ON; user can disable in the UI).
    extra_mass_assignment: bool = True
    extra_hpp: bool = True
    extra_method_override: bool = True
    extra_content_type_confusion: bool = True
    extra_open_redirect: bool = True
    extra_canary_reflection: bool = True
    jwt_attacks: bool = True
    schema_violations: bool = True
    rate_limit_probe: bool = True
    api_version_inventory: bool = True


@dataclass
class ScanState:
    scan_id: str
    status: str = "pending"  # pending | running | completed | failed
    started_at: float = 0.0
    finished_at: float = 0.0
    total_requests: int = 0
    completed_requests: int = 0
    current_endpoint: str = ""
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    base_url: str = ""
    categories: List[str] = field(default_factory=list)
    endpoint_count: int = 0
    failed_requests: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    detect_misconfig: bool = True
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "scan_id": self.scan_id,
                "status": self.status,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "total_requests": self.total_requests,
                "completed_requests": self.completed_requests,
                "current_endpoint": self.current_endpoint,
                "error": self.error,
                "base_url": self.base_url,
                "categories": list(self.categories),
                "endpoint_count": self.endpoint_count,
                "severity_counts": severity_counts(self.findings),
                "findings_count": len(self.findings),
                "failed_requests": self.failed_requests,
                "warnings": list(self.warnings),
                "errors": list(self.errors),
                "detect_misconfig": self.detect_misconfig,
            }


def _placeholder_value(param: Parameter) -> Any:
    if param.example is not None:
        return param.example
    if param.schema_type in ("integer", "number"):
        return 1
    if param.schema_type == "boolean":
        return True
    return "test"


def _build_path(template: str, path_params: Dict[str, Any]) -> str:
    out = template
    for name, value in path_params.items():
        out = out.replace("{" + name + "}", requests.utils.quote(str(value), safe=""))
    return out


def _baseline_request(
    session: requests.Session,
    endpoint: Endpoint,
    cfg: ScanConfig,
) -> Dict[str, Any]:
    """Run a benign request and capture latency + response metadata.

    Returns a dict with keys:
        latency_ms       Optional[int]
        status_code      int
        response_headers Dict[str, str]
        set_cookies      List[str]
        url              str (absolute)
        error            Optional[str]
    """
    out: Dict[str, Any] = {
        "latency_ms": None,
        "status_code": 0,
        "response_headers": {},
        "set_cookies": [],
        "url": "",
        "error": None,
    }
    try:
        url, headers, params, body = _benign_request(endpoint, cfg)
        out["url"] = url
        t0 = time.perf_counter()
        resp = session.request(
            method=endpoint.method,
            url=url,
            headers=headers,
            params=params,
            json=body if endpoint.has_body and endpoint.consumes_json else None,
            data=body if endpoint.has_body and not endpoint.consumes_json else None,
            timeout=cfg.timeout,
            allow_redirects=False,
        )
        out["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        out["status_code"] = resp.status_code
        out["response_headers"] = dict(resp.headers)
        out["set_cookies"] = misconfig.extract_set_cookies(resp)
    except requests.exceptions.RequestException as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _benign_request(endpoint: Endpoint, cfg: ScanConfig):
    path_params = {p.name: _placeholder_value(p) for p in endpoint.parameters if p.location == "path"}
    url = cfg.base_url.rstrip("/") + _build_path(endpoint.path, path_params)
    headers: Dict[str, str] = {}
    if cfg.auth_header:
        if cfg.auth_header.lower().startswith("authorization:"):
            _, _, val = cfg.auth_header.partition(":")
            headers["Authorization"] = val.strip()
        else:
            headers["Authorization"] = cfg.auth_header
    for p in endpoint.parameters:
        if p.location == "header":
            headers[p.name] = str(_placeholder_value(p))
    params = {p.name: _placeholder_value(p) for p in endpoint.parameters if p.location == "query"}
    body = copy.deepcopy(endpoint.body_example) if endpoint.has_body else None
    return url, headers, params, body


def _inject(value: Any, payload: str) -> str:
    return payload  # full replacement strategy


def _walk_body_targets(body: Any, prefix: str = ""):
    """Yield (path_key, leaf_holder) tuples to mutate body leaves in-place."""
    if isinstance(body, dict):
        for k, v in list(body.items()):
            new_prefix = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from _walk_body_targets(v, new_prefix)
            else:
                yield (new_prefix, body, k)
    elif isinstance(body, list):
        for i, v in enumerate(body):
            new_prefix = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _walk_body_targets(v, new_prefix)
            else:
                yield (new_prefix, body, i)


def _send(
    session: requests.Session,
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, Any],
    body: Any,
    consumes_json: bool,
    has_body: bool,
    timeout: float,
):
    t0 = time.perf_counter()
    try:
        resp = session.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=body if has_body and consumes_json else None,
            data=body if has_body and not consumes_json else None,
            timeout=timeout,
            allow_redirects=False,
        )
        elapsed = int((time.perf_counter() - t0) * 1000)
        text = resp.text or ""
        return resp.status_code, dict(resp.headers), text, elapsed, None
    except requests.exceptions.Timeout:
        elapsed = int((time.perf_counter() - t0) * 1000)
        return 0, {}, "", elapsed, "timeout"
    except requests.exceptions.RequestException as exc:
        elapsed = int((time.perf_counter() - t0) * 1000)
        return 0, {}, "", elapsed, str(exc)


def _record(scan: ScanState, *finds: Finding):
    if not finds:
        return
    with scan._lock:
        scan.findings.extend(finds)


def _bump(scan: ScanState, current_endpoint: Optional[str] = None):
    with scan._lock:
        scan.completed_requests += 1
        if current_endpoint is not None:
            scan.current_endpoint = current_endpoint


def _record_failure(scan: ScanState, err: str) -> None:
    with scan._lock:
        scan.failed_requests += 1
        if err and err not in scan.errors:
            scan.errors.append(err)
            if len(scan.errors) > MAX_TRACKED_ERRORS:
                scan.errors = scan.errors[-MAX_TRACKED_ERRORS:]


def _add_warning(scan: ScanState, msg: str) -> None:
    with scan._lock:
        if msg and msg not in scan.warnings:
            scan.warnings.append(msg)


def estimate_total_requests(endpoints: List[Endpoint], categories: List[str]) -> int:
    selected = payloads_for(categories)
    total = 0
    for ep in endpoints:
        targets = _injection_targets(ep)
        if not targets:
            continue
        for target in targets:
            for cat, items in selected.items():
                if cat == "type_juggling":
                    # v1.9: pick payload list per parameter schema type.
                    items = payloads_for_type(target.get("schema_type", "string"))
                total += len(items)
    return total


def _injection_targets(endpoint: Endpoint) -> List[Dict[str, Any]]:
    """Enumerate (parameter_label, location) targets we will inject into.

    Each target dict carries `schema_type` so the v1.9 type-juggling category
    can pick payloads that match the parameter's declared type.
    """
    targets: List[Dict[str, Any]] = []
    for p in endpoint.parameters:
        if p.location in ("query", "path", "header"):
            targets.append({
                "name": p.name,
                "location": p.location,
                "kind": "param",
                "schema_type": (p.schema_type or "string").lower(),
            })
    if endpoint.has_body and isinstance(endpoint.body_example, dict):
        for key_path, holder, key in _walk_body_targets(endpoint.body_example):
            # Infer JSON body type from the example value's Python type.
            example_val = holder[key] if isinstance(holder, dict) else holder[key]
            if isinstance(example_val, bool):
                t = "boolean"
            elif isinstance(example_val, int):
                t = "integer"
            elif isinstance(example_val, float):
                t = "number"
            else:
                t = "string"
            targets.append({
                "name": key_path,
                "location": "body",
                "kind": "body",
                "schema_type": t,
            })
    elif endpoint.has_body and endpoint.body_example is None:
        targets.append({
            "name": "<body>",
            "location": "body",
            "kind": "raw_body",
            "schema_type": "string",
        })
    return targets


def run_scan(scan: ScanState, endpoints: List[Endpoint], cfg: ScanConfig) -> None:
    """Run the scan synchronously. Designed to be invoked from a thread."""
    session = UASession(cfg.user_agent_mode, cfg.user_agent_custom)
    selected = payloads_for(cfg.categories)
    total_requests = estimate_total_requests(endpoints, cfg.categories)

    with scan._lock:
        scan.status = "running"
        scan.started_at = time.time()
        scan.total_requests = total_requests
        scan.endpoint_count = len(endpoints)
        scan.base_url = cfg.base_url
        scan.categories = list(cfg.categories)
        scan.detect_misconfig = cfg.detect_misconfig

    # --- Preflight + global misconfiguration probes ----------------------
    if cfg.detect_misconfig:
        try:
            pf_findings, pf_warnings = misconfig.preflight(
                cfg.base_url, session, cfg.timeout, cfg.auth_header
            )
            _record(scan, *pf_findings)
            for w in pf_warnings:
                _add_warning(scan, w)
            path_findings = misconfig.probe_common_paths(
                cfg.base_url, session, cfg.timeout, cfg.auth_header
            )
            _record(scan, *path_findings)
        except Exception as exc:  # pragma: no cover - defensive
            _add_warning(scan, f"Misconfig preflight failed: {type(exc).__name__}: {exc}")

    # --- Rate-limit probe (once per scan) ---------------------------------
    if cfg.rate_limit_probe:
        try:
            probe_path = endpoints[0].path if endpoints else "/"
            rl_findings = misconfig.probe_rate_limit(
                cfg.base_url, probe_path, session, cfg.timeout, cfg.auth_header
            )
            _record(scan, *rl_findings)
        except Exception as exc:  # pragma: no cover - defensive
            _add_warning(scan, f"Rate-limit probe failed: {type(exc).__name__}: {exc}")

    # --- API version inventory (once per scan) ----------------------------
    if cfg.api_version_inventory:
        try:
            av_findings = misconfig.probe_api_versions(
                cfg.base_url,
                [ep.path for ep in endpoints],
                session,
                cfg.timeout,
                cfg.auth_header,
            )
            _record(scan, *av_findings)
        except Exception as exc:  # pragma: no cover - defensive
            _add_warning(scan, f"API version probe failed: {type(exc).__name__}: {exc}")

    # --- JWT attacks (once per scan, against the first reachable endpoint) -
    jwt_done = False

    sent = 0
    auth_required_count = 0  # endpoints that returned 401/403 on baseline
    reached_count = 0
    try:
        for ep in endpoints:
            ep_label = f"{ep.method} {ep.path}"
            targets = _injection_targets(ep)
            if not targets:
                continue

            baseline = _baseline_request(session, ep, cfg)
            if baseline["error"]:
                _record_failure(scan, f"baseline {ep_label}: {baseline['error']}")
            else:
                reached_count += 1
                if baseline["status_code"] in (401, 403):
                    auth_required_count += 1
                if cfg.detect_misconfig and baseline["response_headers"]:
                    is_https = cfg.base_url.lower().startswith("https://")
                    mc_findings = misconfig.inspect_response(
                        response_headers=baseline["response_headers"],
                        set_cookies=baseline["set_cookies"],
                        status_code=baseline["status_code"],
                        request_url=baseline["url"],
                        endpoint=ep.path,
                        method=ep.method,
                        response_text="",
                        is_https=is_https,
                        response_time_ms=baseline["latency_ms"] or 0,
                    )
                    _record(scan, *mc_findings)
                    # Cache-Control on authenticated 2xx responses.
                    if cfg.auth_header:
                        _record(scan, *misconfig.check_auth_cache_control(
                            baseline["response_headers"],
                            status_code=baseline["status_code"],
                            request_url=baseline["url"],
                            endpoint=ep.path,
                            method=ep.method,
                            used_auth=True,
                        ))
                # JWT attacks: run once against the first reachable endpoint.
                if cfg.jwt_attacks and not jwt_done and 200 <= baseline["status_code"] < 300:
                    try:
                        jwt_findings = jwt_checks.run_jwt_attacks(
                            auth_header=cfg.auth_header,
                            target_url=baseline["url"],
                            target_method=ep.method,
                            target_endpoint_path=ep.path,
                            baseline_status=baseline["status_code"],
                            session=session,
                            timeout=cfg.timeout,
                        )
                        _record(scan, *jwt_findings)
                    except Exception as exc:  # pragma: no cover - defensive
                        _add_warning(scan, f"JWT attacks failed: {type(exc).__name__}: {exc}")
                    jwt_done = True
            if cfg.detect_misconfig:
                method_findings = misconfig.enumerate_methods(
                    cfg.base_url, ep.path, session, cfg.timeout, cfg.auth_header
                )
                _record(scan, *method_findings)

            baseline_ms = baseline["latency_ms"]

            # --- Extended request-mutation checks (once per endpoint) -----
            benign_query = {p.name: _placeholder_value(p) for p in ep.parameters if p.location == "query"}
            try:
                if cfg.extra_mass_assignment and ep.has_body and isinstance(ep.body_example, dict):
                    _record(scan, *extra_checks.mass_assignment_probe(
                        base_url=cfg.base_url, endpoint_path=ep.path, method=ep.method,
                        body_example=ep.body_example, baseline_status=baseline["status_code"],
                        session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                    ))
                if cfg.extra_hpp and benign_query:
                    _record(scan, *extra_checks.http_parameter_pollution_probe(
                        base_url=cfg.base_url, endpoint_path=ep.path, method=ep.method,
                        benign_query=benign_query,
                        session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                    ))
                if cfg.extra_method_override:
                    _record(scan, *extra_checks.method_override_probe(
                        base_url=cfg.base_url, endpoint_path=ep.path, method=ep.method,
                        session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                    ))
                if cfg.extra_content_type_confusion:
                    _record(scan, *extra_checks.content_type_confusion_probe(
                        base_url=cfg.base_url, endpoint_path=ep.path, method=ep.method,
                        body_example=ep.body_example, consumes_json=ep.consumes_json,
                        session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                    ))
                if cfg.extra_open_redirect:
                    for p in ep.parameters:
                        _record(scan, *extra_checks.open_redirect_focused_probe(
                            base_url=cfg.base_url, endpoint_path=ep.path, method=ep.method,
                            parameter_name=p.name, parameter_location=p.location,
                            benign_query=benign_query,
                            session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                        ))
                if cfg.extra_canary_reflection:
                    for p in ep.parameters:
                        _record(scan, *extra_checks.canary_reflection_probe(
                            base_url=cfg.base_url, endpoint_path=ep.path, method=ep.method,
                            parameter_name=p.name, parameter_location=p.location,
                            benign_query=benign_query, benign_body=ep.body_example,
                            consumes_json=ep.consumes_json,
                            session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                        ))
                if cfg.schema_violations:
                    _record(scan, *schema_checks.run_schema_checks(
                        endpoint=ep, base_url=cfg.base_url,
                        session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                    ))
            except Exception as exc:  # pragma: no cover - defensive
                _add_warning(scan, f"Extended checks failed for {ep_label}: {type(exc).__name__}: {exc}")

            for target in targets:
                for category, items in selected.items():
                    # v1.9: type_juggling resolves its payload list per parameter type.
                    if category == "type_juggling":
                        items = payloads_for_type(target.get("schema_type", "string"))
                    for payload, technique in items:
                        if cfg.max_requests > 0 and sent >= cfg.max_requests:
                            _add_warning(
                                scan,
                                f"Request budget ({cfg.max_requests}) reached; remaining payloads skipped.",
                            )
                            with scan._lock:
                                scan.status = "completed"
                                scan.finished_at = time.time()
                                scan.findings = sort_findings(scan.findings)
                                scan.findings = misconfig.dedupe(scan.findings)
                            return
                        sent += 1

                        url, headers, params, body = _benign_request(ep, cfg)
                        request_body_str: Optional[str] = None

                        if target["location"] == "query":
                            params[target["name"]] = _inject(params.get(target["name"]), payload)
                        elif target["location"] == "path":
                            path_params = {
                                p.name: _placeholder_value(p)
                                for p in ep.parameters
                                if p.location == "path"
                            }
                            path_params[target["name"]] = payload
                            url = cfg.base_url.rstrip("/") + _build_path(ep.path, path_params)
                        elif target["location"] == "header":
                            headers[target["name"]] = payload
                        elif target["location"] == "body":
                            body_copy = copy.deepcopy(body) if isinstance(body, (dict, list)) else body
                            if target["kind"] == "body" and isinstance(body_copy, dict):
                                _set_body_leaf(body_copy, target["name"], payload)
                                body = body_copy
                            elif target["kind"] == "raw_body":
                                body = payload
                            request_body_str = (
                                jsonlib.dumps(body)
                                if isinstance(body, (dict, list))
                                else (body if isinstance(body, str) else None)
                            )

                        status, _resp_headers, text, elapsed, err = _send(
                            session,
                            ep.method,
                            url,
                            headers,
                            params,
                            body,
                            ep.consumes_json,
                            ep.has_body,
                            cfg.timeout,
                        )

                        if err and err != "timeout":
                            _record_failure(scan, f"{ep_label}: {err}")
                        else:
                            # v1.7: bake any query-string params into the URL
                            # we record so the Finding's raw_request blob
                            # shows the payload-bearing query parameter.
                            recorded_url = url_with_query(url, params)
                            findings = analyze(
                                category=category,
                                payload=payload,
                                technique=technique,
                                endpoint_path=ep.path,
                                method=ep.method,
                                parameter=target["name"],
                                location=target["location"],
                                request_url=recorded_url,
                                request_headers=headers,
                                request_body=request_body_str,
                                status_code=status,
                                response_text=text,
                                response_time_ms=elapsed,
                                baseline_time_ms=baseline_ms,
                                response_headers=_resp_headers,
                            )
                            _record(scan, *findings)

                        _bump(scan, ep_label)

        # Post-pass diagnostics.
        if reached_count == 0 and endpoints:
            _add_warning(
                scan,
                "No endpoint baseline succeeded \u2014 verify base URL, network reachability, and TLS settings.",
            )
        elif auth_required_count and auth_required_count == reached_count:
            _add_warning(
                scan,
                "Every reachable endpoint returned 401/403 on baseline \u2014 your auth header may be missing or invalid.",
            )

        with scan._lock:
            scan.status = "completed"
            scan.finished_at = time.time()
            scan.findings = misconfig.dedupe(sort_findings(scan.findings))
    except Exception as exc:  # pragma: no cover - safety net
        with scan._lock:
            scan.status = "failed"
            scan.finished_at = time.time()
            scan.error = f"{type(exc).__name__}: {exc}"


def _set_body_leaf(body: Dict[str, Any], dotted_key: str, value: Any) -> None:
    """Set a nested leaf inside `body` using a dotted path produced by _walk_body_targets."""
    cur: Any = body
    parts: List[Any] = []
    token = ""
    i = 0
    while i < len(dotted_key):
        ch = dotted_key[i]
        if ch == ".":
            if token:
                parts.append(token)
                token = ""
        elif ch == "[":
            if token:
                parts.append(token)
                token = ""
            j = dotted_key.index("]", i)
            parts.append(int(dotted_key[i + 1 : j]))
            i = j
        else:
            token += ch
        i += 1
    if token:
        parts.append(token)

    for p in parts[:-1]:
        cur = cur[p]
    cur[parts[-1]] = value
