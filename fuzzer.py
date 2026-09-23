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

from analyzer import Finding, analyze, severity_counts, sort_findings
from payloads import payloads_for, payloads_for_type
from spec_parser import Endpoint, Parameter
from http_session import UASession
from models import (
    AuthProfile,
    DEFAULT_SCAN_MODE,
    PreparedRequest,
    RequestLedger,
    RequestTemplate,
    SafetyLevel,
    normalize_scan_mode,
    safety_allowed,
)
from request_builder import build_request, substitute_path
import obfuscator
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
    # v1.10: payload obfuscation policy for WAF evasion.
    # off | basic | aggressive | random. See obfuscator.py for details.
    payload_obfuscation: str = "off"
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
    # Phase 0: scan execution mode (passive | safe_active | intrusive).
    # Defaults to safe_active; intrusive behavior remains unsupported until a
    # later check provides explicit opt-in and cleanup semantics.
    scan_mode: str = DEFAULT_SCAN_MODE


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
    # Phase 0: scan mode, cancellation, request ledger, and richer progress.
    scan_mode: str = DEFAULT_SCAN_MODE
    cancelled: bool = False
    planned_requests: int = 0
    skipped_requests: int = 0
    budget_exhausted: int = 0
    ledger: RequestLedger = field(default_factory=RequestLedger, repr=False)
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def request_cancel(self) -> None:
        """Request the scan to stop at the next loop boundary."""
        self.cancel_event.set()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            ledger_summary = self.ledger.summary()
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
                # Phase 0 additions (legacy keys above are preserved).
                "scan_mode": self.scan_mode,
                "cancelled": self.cancelled,
                "planned_requests": self.planned_requests,
                "skipped_requests": self.skipped_requests,
                "budget_exhausted": self.budget_exhausted,
                "ledger_count": ledger_summary["ledger_count"],
                "sent_requests": ledger_summary["sent"],
                "succeeded_requests": ledger_summary["succeeded"],
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
    # Delegate to request_builder so path substitution has a single source of
    # truth; kept as a backward-compatible helper for tests and internal calls.
    return substitute_path(template, path_params)


def _baseline_request(
    session: requests.Session,
    endpoint: Endpoint,
    cfg: ScanConfig,
    scan: Optional[ScanState] = None,
) -> Dict[str, Any]:
    """Run a benign request and capture latency + response metadata.

    Returns a dict with keys:
        latency_ms       Optional[int]
        status_code      int
        response_headers Dict[str, str]
        set_cookies      List[str]
        url              str (absolute)
        error            Optional[str]

    Phase 0: routes construction through request_builder and records a ledger
    entry so the baseline is accounted for in the scan's request accounting.
    """
    out: Dict[str, Any] = {
        "latency_ms": None,
        "status_code": 0,
        "response_headers": {},
        "set_cookies": [],
        "url": "",
        "error": None,
    }
    prepared: Optional[PreparedRequest] = None
    try:
        template = _endpoint_template(endpoint, cfg)
        prepared = build_request(template)
        out["url"] = prepared.url
        kwargs: Dict[str, Any] = {
            "headers": prepared.headers,
            "params": prepared.query_params or None,
            "timeout": cfg.timeout,
            "allow_redirects": False,
        }
        if endpoint.has_body and prepared.body is not None:
            kwargs["data"] = prepared.body
        t0 = time.perf_counter()
        resp = session.request(method=endpoint.method, url=prepared.url, **kwargs)
        elapsed = int((time.perf_counter() - t0) * 1000)
        out["latency_ms"] = elapsed
        out["status_code"] = resp.status_code
        out["response_headers"] = dict(resp.headers)
        out["set_cookies"] = misconfig.extract_set_cookies(resp)
        _ledger(
            scan,
            prepared=prepared,
            status_code=resp.status_code,
            latency_ms=elapsed,
            check_id="baseline",
            safety_level=SafetyLevel.PASSIVE.value,
            outcome=RequestLedger.OUTCOME_SUCCEEDED,
        )
    except requests.exceptions.Timeout:
        out["error"] = "timeout"
        _ledger(
            scan,
            prepared=prepared,
            status_code=0,
            error="timeout",
            check_id="baseline",
            safety_level=SafetyLevel.PASSIVE.value,
            outcome=RequestLedger.OUTCOME_FAILED,
        )
    except requests.exceptions.RequestException as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        _ledger(
            scan,
            prepared=prepared,
            status_code=0,
            error=str(exc),
            check_id="baseline",
            safety_level=SafetyLevel.PASSIVE.value,
            outcome=RequestLedger.OUTCOME_FAILED,
        )
    except Exception as exc:  # pragma: no cover - defensive
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def _endpoint_template(endpoint: Endpoint, cfg: ScanConfig) -> RequestTemplate:
    """Build a RequestTemplate mirroring the legacy benign request for an endpoint."""
    path_params = {p.name: _placeholder_value(p) for p in endpoint.parameters if p.location == "path"}
    query_params = {p.name: _placeholder_value(p) for p in endpoint.parameters if p.location == "query"}
    header_params = {p.name: _placeholder_value(p) for p in endpoint.parameters if p.location == "header"}
    cookie_params = {p.name: _placeholder_value(p) for p in endpoint.parameters if p.location == "cookie"}
    media_type = "application/json" if endpoint.consumes_json else "application/x-www-form-urlencoded"
    body = copy.deepcopy(endpoint.body_example) if endpoint.has_body else None
    return RequestTemplate(
        method=endpoint.method,
        path=endpoint.path,
        base_url=cfg.base_url,
        path_params=path_params,
        query_params=query_params,
        header_params=header_params,
        cookie_params=cookie_params,
        body=body,
        media_type=media_type if endpoint.has_body else "",
        has_body=endpoint.has_body,
        auth_profile=AuthProfile.from_header("default", cfg.auth_header),
    )


def _benign_request(endpoint: Endpoint, cfg: ScanConfig):
    """Return (url, headers, query_params, body) for a benign request.

    Backward-compatible tuple form; construction is routed through
    request_builder so the prepared representation is canonical.
    """
    template = _endpoint_template(endpoint, cfg)
    prepared = build_request(template)
    return prepared.url, dict(prepared.headers), dict(prepared.query_params), template.body


def _anonymous_baseline(
    session: requests.Session,
    endpoint: Endpoint,
    cfg: ScanConfig,
    scan: Optional[ScanState] = None,
) -> Dict[str, Any]:
    """Run a benign request with no Authorization header.

    Used to suppress auth_bypass false positives: if the anonymous request
    also succeeds (2xx), the endpoint is public and weak credentials are not
    a bypass. The result shape matches _baseline_request.
    """
    out: Dict[str, Any] = {
        "latency_ms": None,
        "status_code": 0,
        "response_headers": {},
        "set_cookies": [],
        "url": "",
        "error": None,
    }
    prepared: Optional[PreparedRequest] = None
    try:
        template = _endpoint_template(endpoint, cfg)
        template.auth_profile = None  # strip Authorization
        prepared = build_request(template)
        out["url"] = prepared.url
        kwargs: Dict[str, Any] = {
            "headers": prepared.headers,
            "params": prepared.query_params or None,
            "timeout": cfg.timeout,
            "allow_redirects": False,
        }
        if endpoint.has_body and prepared.body is not None:
            kwargs["data"] = prepared.body
        t0 = time.perf_counter()
        resp = session.request(method=endpoint.method, url=prepared.url, **kwargs)
        elapsed = int((time.perf_counter() - t0) * 1000)
        out["latency_ms"] = elapsed
        out["status_code"] = resp.status_code
        out["response_headers"] = dict(resp.headers)
        out["set_cookies"] = misconfig.extract_set_cookies(resp)
        _ledger(
            scan,
            prepared=prepared,
            status_code=resp.status_code,
            latency_ms=elapsed,
            check_id="baseline_anonymous",
            safety_level=SafetyLevel.PASSIVE.value,
            outcome=RequestLedger.OUTCOME_SUCCEEDED,
        )
    except requests.exceptions.RequestException as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        _ledger(
            scan,
            prepared=prepared,
            status_code=0,
            error=str(exc),
            check_id="baseline_anonymous",
            safety_level=SafetyLevel.PASSIVE.value,
            outcome=RequestLedger.OUTCOME_FAILED,
        )
    except Exception as exc:  # pragma: no cover - defensive
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


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


def _send_prepared(
    session: requests.Session,
    prepared: PreparedRequest,
    has_body: bool,
    timeout: float,
):
    """Send a PreparedRequest; returns (status, headers, text, elapsed_ms, error).

    The serialized body and Content-Type are carried on ``prepared``; query
    params are passed via ``params=`` so the existing FakeSession test harness
    (which inspects ``kwargs['params']``) keeps working. The exact encoded URL
    is recorded separately on ``prepared.encoded_url``.
    """
    t0 = time.perf_counter()
    try:
        kwargs: Dict[str, Any] = {
            "headers": prepared.headers,
            "params": prepared.query_params or None,
            "timeout": timeout,
            "allow_redirects": False,
        }
        if has_body and prepared.body is not None:
            kwargs["data"] = prepared.body
        resp = session.request(prepared.method, prepared.url, **kwargs)
        elapsed = int((time.perf_counter() - t0) * 1000)
        text = resp.text or ""
        return resp.status_code, dict(resp.headers), text, elapsed, None
    except requests.exceptions.Timeout:
        elapsed = int((time.perf_counter() - t0) * 1000)
        return 0, {}, "", elapsed, "timeout"
    except requests.exceptions.RequestException as exc:
        elapsed = int((time.perf_counter() - t0) * 1000)
        return 0, {}, "", elapsed, str(exc)


def _ledger(
    scan: Optional[ScanState],
    *,
    prepared: Optional[PreparedRequest],
    status_code: int = 0,
    latency_ms: Optional[int] = None,
    error: Optional[str] = None,
    check_id: str = "",
    safety_level: str = SafetyLevel.SAFE_ACTIVE.value,
    outcome: str = RequestLedger.OUTCOME_SUCCEEDED,
) -> None:
    """Append a request ledger entry for an outbound request (no-op if no scan)."""
    if scan is None:
        return
    method = prepared.method if prepared is not None else ""
    url = prepared.encoded_url if prepared is not None else ""
    return scan.ledger.record(
        method=method,
        url=url,
        check_id=check_id,
        safety_level=safety_level,
        status_code=status_code,
        latency_ms=latency_ms,
        error=error,
        outcome=outcome,
    )


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
    scan_mode = normalize_scan_mode(cfg.scan_mode)

    with scan._lock:
        scan.status = "running"
        scan.started_at = time.time()
        scan.total_requests = total_requests
        scan.planned_requests = total_requests
        scan.endpoint_count = len(endpoints)
        scan.base_url = cfg.base_url
        scan.categories = list(cfg.categories)
        scan.detect_misconfig = cfg.detect_misconfig
        scan.scan_mode = scan_mode

    # --- Preflight + global misconfiguration probes ----------------------
    if cfg.detect_misconfig and safety_allowed(SafetyLevel.PASSIVE.value, scan_mode):
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
    if cfg.rate_limit_probe and safety_allowed(SafetyLevel.SAFE_ACTIVE.value, scan_mode):
        try:
            probe_path = endpoints[0].path if endpoints else "/"
            rl_findings = misconfig.probe_rate_limit(
                cfg.base_url, probe_path, session, cfg.timeout, cfg.auth_header
            )
            _record(scan, *rl_findings)
        except Exception as exc:  # pragma: no cover - defensive
            _add_warning(scan, f"Rate-limit probe failed: {type(exc).__name__}: {exc}")

    # --- API version inventory (once per scan) ----------------------------
    if cfg.api_version_inventory and safety_allowed(SafetyLevel.PASSIVE.value, scan_mode):
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
            if scan.cancel_event.is_set():
                _add_warning(scan, "Scan cancelled by user.")
                with scan._lock:
                    scan.cancelled = True
                    scan.status = "completed"
                    scan.finished_at = time.time()
                    scan.findings = misconfig.dedupe(sort_findings(scan.findings))
                return

            ep_label = f"{ep.method} {ep.path}"
            targets = _injection_targets(ep)

            # Phase 0: always run a baseline and passive/observational checks
            # for every endpoint -- do not skip just because there is no
            # injectable parameter. Only the payload loop is skipped below.
            baseline = _baseline_request(session, ep, cfg, scan)
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
                if (
                    cfg.jwt_attacks
                    and not jwt_done
                    and 200 <= baseline["status_code"] < 300
                    and safety_allowed(SafetyLevel.SAFE_ACTIVE.value, scan_mode)
                ):
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

            # Phase 0: substitute path parameters before every specialized probe.
            path_params = {p.name: _placeholder_value(p) for p in ep.parameters if p.location == "path"}
            resolved_path = _build_path(ep.path, path_params)

            if cfg.detect_misconfig and safety_allowed(SafetyLevel.PASSIVE.value, scan_mode):
                method_findings = misconfig.enumerate_methods(
                    cfg.base_url, resolved_path, session, cfg.timeout, cfg.auth_header
                )
                _record(scan, *method_findings)

            baseline_ms = baseline["latency_ms"]

            # FP fix: anonymous baseline for auth_bypass differential. Only
            # needed when auth is configured and the auth_bypass category is
            # selected; one extra passive request per endpoint.
            anonymous_status: Optional[int] = None
            if cfg.auth_header and "auth_bypass" in cfg.categories:
                anon_base = _anonymous_baseline(session, ep, cfg, scan)
                if not anon_base["error"]:
                    anonymous_status = anon_base["status_code"]

            # --- Extended request-mutation checks (once per endpoint) -----
            benign_query = {p.name: _placeholder_value(p) for p in ep.parameters if p.location == "query"}
            if safety_allowed(SafetyLevel.SAFE_ACTIVE.value, scan_mode):
                try:
                    if cfg.extra_mass_assignment and ep.has_body and isinstance(ep.body_example, dict):
                        _record(scan, *extra_checks.mass_assignment_probe(
                            base_url=cfg.base_url, endpoint_path=resolved_path, method=ep.method,
                            body_example=ep.body_example, baseline_status=baseline["status_code"],
                            session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                        ))
                    if cfg.extra_hpp and benign_query:
                        _record(scan, *extra_checks.http_parameter_pollution_probe(
                            base_url=cfg.base_url, endpoint_path=resolved_path, method=ep.method,
                            benign_query=benign_query,
                            session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                        ))
                    if cfg.extra_method_override:
                        _record(scan, *extra_checks.method_override_probe(
                            base_url=cfg.base_url, endpoint_path=resolved_path, method=ep.method,
                            session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                        ))
                    if cfg.extra_content_type_confusion:
                        _record(scan, *extra_checks.content_type_confusion_probe(
                            base_url=cfg.base_url, endpoint_path=resolved_path, method=ep.method,
                            body_example=ep.body_example, consumes_json=ep.consumes_json,
                            session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                        ))
                    if cfg.extra_open_redirect:
                        for p in ep.parameters:
                            _record(scan, *extra_checks.open_redirect_focused_probe(
                                base_url=cfg.base_url, endpoint_path=resolved_path, method=ep.method,
                                parameter_name=p.name, parameter_location=p.location,
                                benign_query=benign_query,
                                session=session, timeout=cfg.timeout, auth_header=cfg.auth_header,
                            ))
                    if cfg.extra_canary_reflection:
                        for p in ep.parameters:
                            _record(scan, *extra_checks.canary_reflection_probe(
                                base_url=cfg.base_url, endpoint_path=resolved_path, method=ep.method,
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

            # --- Payload injection loop (only for endpoints with targets) --
            if not targets:
                with scan._lock:
                    scan.skipped_requests += 1
                continue

            # Passive mode observes only; skip active payload injection.
            if not safety_allowed(SafetyLevel.SAFE_ACTIVE.value, scan_mode):
                continue

            for target in targets:
                for category, items in selected.items():
                    # v1.9: type_juggling resolves its payload list per parameter type.
                    if category == "type_juggling":
                        items = payloads_for_type(target.get("schema_type", "string"))
                    for raw_payload, technique in items:
                        if scan.cancel_event.is_set():
                            _add_warning(scan, "Scan cancelled by user.")
                            with scan._lock:
                                scan.cancelled = True
                                scan.status = "completed"
                                scan.finished_at = time.time()
                                scan.findings = misconfig.dedupe(sort_findings(scan.findings))
                            return
                        # v1.10: apply WAF-evasion obfuscation before sending.
                        # The transformed value is what hits the wire AND what
                        # we record on the Finding's `payload` field, so the
                        # raw_request preview shows the actual bytes.
                        payload = obfuscator.obfuscate(
                            raw_payload, category, cfg.payload_obfuscation
                        )
                        if cfg.max_requests > 0 and sent >= cfg.max_requests:
                            with scan._lock:
                                scan.budget_exhausted = max(0, total_requests - sent)
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

                        # Phase 0: build the request through request_builder so
                        # the exact encoded URL, headers, and serialized body
                        # are recorded on the finding and in the ledger.
                        template = _endpoint_template(ep, cfg)
                        if target["location"] == "query":
                            template.query_params[target["name"]] = _inject(
                                template.query_params.get(target["name"]), payload
                            )
                        elif target["location"] == "path":
                            template.path_params[target["name"]] = payload
                        elif target["location"] == "header":
                            template.header_params[target["name"]] = payload
                        elif target["location"] == "body":
                            if target["kind"] == "body" and isinstance(template.body, dict):
                                body_copy = copy.deepcopy(template.body)
                                _set_body_leaf(body_copy, target["name"], payload)
                                template.body = body_copy
                            elif target["kind"] == "raw_body":
                                template.body = payload
                        prepared = build_request(template)

                        status, _resp_headers, text, elapsed, err = _send_prepared(
                            session, prepared, ep.has_body, cfg.timeout
                        )

                        if err and err != "timeout":
                            _record_failure(scan, f"{ep_label}: {err}")
                            _ledger(
                                scan, prepared=prepared, status_code=0, latency_ms=elapsed,
                                error=err, check_id=category,
                                safety_level=SafetyLevel.SAFE_ACTIVE.value,
                                outcome=RequestLedger.OUTCOME_FAILED,
                            )
                        elif err == "timeout":
                            _ledger(
                                scan, prepared=prepared, status_code=0, latency_ms=elapsed,
                                error="timeout", check_id=category,
                                safety_level=SafetyLevel.SAFE_ACTIVE.value,
                                outcome=RequestLedger.OUTCOME_FAILED,
                            )
                        else:
                            findings = analyze(
                                category=category,
                                payload=payload,
                                technique=technique,
                                endpoint_path=ep.path,
                                method=ep.method,
                                parameter=target["name"],
                                location=target["location"],
                                request_url=prepared.encoded_url,
                                request_headers=prepared.headers,
                                request_body=prepared.body,
                                status_code=status,
                                response_text=text,
                                response_time_ms=elapsed,
                                baseline_time_ms=baseline_ms,
                                response_headers=_resp_headers,
                                check_id=category,
                                safety_level=SafetyLevel.SAFE_ACTIVE.value,
                                auth_profile="default" if cfg.auth_header else "anonymous",
                                # FP fix: differential suppression inputs.
                                baseline_status=baseline["status_code"],
                                anonymous_status=anonymous_status,
                            )
                            _record(scan, *findings)
                            entry = _ledger(
                                scan, prepared=prepared, status_code=status, latency_ms=elapsed,
                                check_id=category, safety_level=SafetyLevel.SAFE_ACTIVE.value,
                                outcome=RequestLedger.OUTCOME_SUCCEEDED,
                            )
                            # Link each emitted finding to its ledger entry so
                            # every finding references a reproducible request.
                            if entry is not None:
                                for _f in findings:
                                    _f.ledger_index = entry.index

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
