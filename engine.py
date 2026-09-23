"""Central execution engine for the apifuzz scanner.

Provides endpoint iteration, identity baselines, a check registry,
request ledger integration, budgets, cancellation, scan retention,
cleanup hooks, and progress reporting. This module orchestrates the
new Phase 2-6 check modules alongside the legacy ``fuzzer.run_scan`` loop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence

import requests

from analyzer import Finding, sort_findings
from models import (
    AuthProfile,
    CheckResult,
    RequestLedger,
    SafetyLevel,
    safety_allowed,
)
from spec_parser import Endpoint


def _coerce_finding(obj: Any) -> Finding:
    """Convert a module-specific finding dataclass to analyzer.Finding.

    Check modules (auth_engine, token_session_checks, resource_checks,
    parser_checks, upload_checks, sspp_checks, blind_checks) return their own
    dataclasses. The engine aggregates everything as analyzer.Finding so
    sorting, dedup, and reporting stay uniform. Unknown objects are coerced
    with getattr defaults instead of failing the whole scan.
    """
    if isinstance(obj, Finding):
        return obj
    return Finding(
        severity=str(getattr(obj, "severity", "low") or "low"),
        category=str(getattr(obj, "category", "") or "misc"),
        title=str(getattr(obj, "title", "") or ""),
        endpoint=str(getattr(obj, "endpoint", "") or ""),
        method=str(getattr(obj, "method", "") or ""),
        parameter=str(getattr(obj, "parameter", "") or ""),
        location=str(getattr(obj, "location", "") or ""),
        payload=str(getattr(obj, "payload", "") or ""),
        technique=str(getattr(obj, "technique", "") or ""),
        evidence=str(getattr(obj, "evidence", "") or ""),
        status_code=int(getattr(obj, "status_code", 0) or 0),
        response_time_ms=int(getattr(obj, "response_time_ms", 0) or 0),
        request_url=str(getattr(obj, "request_url", "") or ""),
        confidence=str(getattr(obj, "confidence", "") or ""),
        owasp_api=str(getattr(obj, "owasp_api", "") or ""),
        cwe=str(getattr(obj, "cwe", "") or ""),
        safety_level=str(getattr(obj, "safety_level", "") or ""),
    )


def _authz_config_from(scan: Optional[Any], auth_header: Optional[str]):
    """Build an AuthzConfig from the scan's profiles when available.

    Differential authorization (BOLA/BFLA/BOPLA) needs at least two distinct
    identities plus an anonymous baseline. Single-header scans cannot run
    them, so the adapter returns a config with no profiles (the probes
    no-op) rather than producing meaningless differentials.
    """
    import auth_engine

    profiles = getattr(scan, "auth_profiles", None) if scan is not None else None
    if profiles and len(profiles) >= 2:
        named = [p for p in profiles if not p.is_anonymous]
        if len(named) >= 2:
            owner = named[0].name
            attacker = named[1].name
            return auth_engine.AuthzConfig(
                profiles=list(profiles),
                owner_profile=owner,
                attacker_profile=attacker,
                enable_write_probes=False,
            )
    return auth_engine.AuthzConfig(profiles=[])


# --- Adapter registry: check_id -> executable run_fn -----------------------


def _run_bola(endpoints, base_url, session, timeout, auth_header, scan):
    import auth_engine
    cfg = _authz_config_from(scan, auth_header)
    return auth_engine.run_bola_probes(endpoints, base_url, session, cfg, timeout)


def _run_bfla(endpoints, base_url, session, timeout, auth_header, scan):
    import auth_engine
    cfg = _authz_config_from(scan, auth_header)
    return auth_engine.run_bfla_probes(endpoints, base_url, session, cfg, timeout)


def _run_bopla(endpoints, base_url, session, timeout, auth_header, scan):
    import auth_engine
    cfg = _authz_config_from(scan, auth_header)
    return auth_engine.run_bopla_probes(endpoints, base_url, session, cfg, timeout)


def _run_jwt_differential(endpoints, base_url, session, timeout, auth_header, scan):
    import jwt_checks
    from request_builder import build_encoded_url

    for ep in endpoints:
        path_params = {
            p.name: (p.example if p.example is not None else 1)
            for p in ep.parameters
            if p.location == "path"
        }
        url = build_encoded_url(base_url, ep.path, path_params, {})
        return jwt_checks.run_jwt_attacks(
            auth_header=auth_header,
            target_url=url,
            target_method=ep.method,
            target_endpoint_path=ep.path,
            baseline_status=0,
            session=session,
            timeout=timeout,
        )
    return []


def _run_token_session(endpoints, base_url, session, timeout, auth_header, scan):
    import token_session_checks
    return token_session_checks.run_token_session_checks(
        list(endpoints), base_url, session, timeout, auth_header,
    )


def _run_resource(endpoints, base_url, session, timeout, auth_header, scan):
    import resource_checks
    findings = []
    for ep in endpoints:
        findings.extend(
            resource_checks.probe_pagination(ep, base_url, session, timeout, auth_header)
        )
    return findings


def _run_upload(endpoints, base_url, session, timeout, auth_header, scan):
    import upload_checks
    findings = []
    for ep in endpoints:
        findings.extend(
            upload_checks.probe_uploads(ep, base_url, session, timeout, auth_header)
        )
    return findings


def _run_parser(endpoints, base_url, session, timeout, auth_header, scan):
    import parser_checks
    findings = []
    for ep in endpoints:
        findings.extend(parser_checks.probe_duplicate_json_keys(
            ep, base_url, session, timeout, auth_header))
        findings.extend(parser_checks.probe_deep_nesting(
            ep, base_url, session, timeout, auth_header))
        findings.extend(parser_checks.probe_numeric_overflow(
            ep, base_url, session, timeout, auth_header))
        findings.extend(parser_checks.probe_unsafe_type_fields(
            ep, base_url, session, timeout, auth_header))
    return findings


def _run_sspp(endpoints, base_url, session, timeout, auth_header, scan):
    import sspp_checks
    findings = []
    for ep in endpoints:
        findings.extend(sspp_checks.probe_query_truncation(
            ep, base_url, session, timeout, auth_header))
        findings.extend(sspp_checks.probe_param_injection(
            ep, base_url, session, timeout, auth_header))
        findings.extend(sspp_checks.probe_json_pollution(
            ep, base_url, session, timeout, auth_header))
    return findings


def _run_rate_limit_bypass(endpoints, base_url, session, timeout, auth_header, scan):
    import rate_limit_bypass
    return rate_limit_bypass.run_rate_limit_bypass(
        endpoints, base_url, session, timeout, auth_header, scan,
    )


def _run_cache_deception(endpoints, base_url, session, timeout, auth_header, scan):
    import cache_checks
    return cache_checks.run_cache_deception(
        endpoints, base_url, session, timeout, auth_header, scan,
    )


def _run_host_header(endpoints, base_url, session, timeout, auth_header, scan):
    import host_header_checks
    return host_header_checks.run_host_header_trust(
        endpoints, base_url, session, timeout, auth_header, scan,
    )


def _run_webdav(endpoints, base_url, session, timeout, auth_header, scan):
    import extra_checks
    findings = []
    intrusive = True  # only invoked under intrusive scan mode by get_enabled()
    for ep in endpoints[:10]:
        findings.extend(extra_checks.webdav_put_probe(
            base_url=base_url, endpoint_path=ep.path,
            session=session, timeout=timeout, auth_header=auth_header,
            confirmed_intrusive=intrusive,
        ))
    return findings


def _run_content_negotiation(endpoints, base_url, session, timeout, auth_header, scan):
    import extra_checks
    findings = []
    for ep in endpoints[:10]:
        declared = set()
        for resp in ep.responses.values():
            for media in resp.content:
                declared.add(media.split(";", 1)[0].strip().lower())
        findings.extend(extra_checks.content_negotiation_probe(
            base_url=base_url, endpoint_path=ep.path, method=ep.method,
            session=session, timeout=timeout, auth_header=auth_header,
            declared_types=declared or None,
        ))
    return findings


def _run_csrf(endpoints, base_url, session, timeout, auth_header, scan):
    import csrf_checks
    # CSRF requires cookie identities; scan.auth_profiles supplies them.
    profiles = getattr(scan, "auth_profiles", None) if scan is not None else None
    cookie_profile = next(
        (p for p in (profiles or []) if getattr(p, "cookies", None)), None,
    ) if profiles else None
    if cookie_profile is None:
        return []
    return csrf_checks.run_csrf_checks(
        endpoints, base_url, session, timeout,
        cookies=dict(cookie_profile.cookies),
        headers=dict(cookie_profile.headers),
        confirmed_intrusive=True,
        scan=scan,
    )


def _run_oauth(endpoints, base_url, session, timeout, auth_header, scan):
    import oauth_checks
    cfg = getattr(scan, "oauth_config", None) if scan is not None else None
    if cfg is None:
        return []  # requires explicit user-supplied OAuth config
    return oauth_checks.run_oauth_checks(session, cfg, timeout)


def _run_smuggling(endpoints, base_url, session, timeout, auth_header, scan):
    import smuggling_checks
    return smuggling_checks.run_smuggling(
        endpoints, base_url, session, timeout, auth_header, scan,
    )


def _run_jwt_key_confusion(endpoints, base_url, session, timeout, auth_header, scan):
    import jwt_checks
    from request_builder import build_encoded_url
    oast = getattr(scan, "oast_provider", None) if scan is not None else None
    if oast is None or not getattr(oast, "available", False):
        return []
    for ep in endpoints:
        path_params = {
            p.name: (p.example if p.example is not None else 1)
            for p in ep.parameters
            if p.location == "path"
        }
        url = build_encoded_url(base_url, ep.path, path_params, {})
        return jwt_checks.run_jwt_key_confusion(
            auth_header=auth_header,
            target_url=url,
            target_method=ep.method,
            target_endpoint_path=ep.path,
            session=session,
            timeout=timeout,
            oast=oast,
        )
    return []


_RUN_FN_BY_CHECK = {
    "bola": _run_bola,
    "bfla": _run_bfla,
    "bopla": _run_bopla,
    "jwt_differential": _run_jwt_differential,
    "jwt_key_confusion": _run_jwt_key_confusion,
    "token_session": _run_token_session,
    "resource_consumption": _run_resource,
    "upload_safety": _run_upload,
    "parser_confusion": _run_parser,
    "sspp": _run_sspp,
    "rate_limit_bypass": _run_rate_limit_bypass,
    "cache_deception": _run_cache_deception,
    "host_header_trust": _run_host_header,
    "webdav": _run_webdav,
    "content_negotiation": _run_content_negotiation,
    "csrf": _run_csrf,
    "oauth": _run_oauth,
    "smuggling": _run_smuggling,
}


class Check(Protocol):
    """Common interface for all check families.

    Each check module implements this interface so the engine can
    discover, gate, and run checks uniformly.
    """

    @property
    def check_id(self) -> str:
        ...

    @property
    def owasp_api(self) -> str:
        ...

    @property
    def cwe(self) -> str:
        ...

    @property
    def safety_level(self) -> str:
        ...

    @property
    def max_requests(self) -> int:
        ...

    def run(
        self,
        endpoints: Sequence[Endpoint],
        base_url: str,
        session: requests.Session,
        timeout: float,
        auth_header: Optional[str],
        scan: Optional[Any] = None,
    ) -> CheckResult:
        ...


@dataclass
class CheckRegistration:
    """A registered check with its metadata and callable."""
    check_id: str
    owasp_api: str
    cwe: str
    safety_level: str
    max_requests: int
    enabled: bool = True
    run_fn: Optional[Callable] = None
    module_name: str = ""


class CheckRegistry:
    """Registry of available checks, gated by scan mode and user toggles."""

    def __init__(self) -> None:
        self._checks: List[CheckRegistration] = []

    def register(
        self,
        *,
        check_id: str,
        owasp_api: str,
        cwe: str,
        safety_level: str = SafetyLevel.SAFE_ACTIVE.value,
        max_requests: int = 100,
        enabled: bool = True,
        run_fn: Optional[Callable] = None,
        module_name: str = "",
    ) -> None:
        self._checks.append(
            CheckRegistration(
                check_id=check_id,
                owasp_api=owasp_api,
                cwe=cwe,
                safety_level=safety_level,
                max_requests=max_requests,
                enabled=enabled,
                run_fn=run_fn,
                module_name=module_name,
            )
        )

    def get_enabled(self, scan_mode: str) -> List[CheckRegistration]:
        """Return checks allowed under the given scan mode."""
        return [
            c for c in self._checks
            if c.enabled and safety_allowed(c.safety_level, scan_mode)
        ]

    def __len__(self) -> int:
        return len(self._checks)

    def all_checks(self) -> List[CheckRegistration]:
        return list(self._checks)


def default_registry() -> CheckRegistry:
    """Build a registry with all Phase 2-6 checks enabled by default."""
    registry = CheckRegistry()

    # Phase 2: Authorization
    registry.register(
        check_id="bola",
        owasp_api="API1:2023",
        cwe="CWE-639",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=50,
        module_name="auth_engine",
    )
    registry.register(
        check_id="bfla",
        owasp_api="API5:2023",
        cwe="CWE-285",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=50,
        module_name="auth_engine",
    )
    registry.register(
        check_id="bopla",
        owasp_api="API3:2023",
        cwe="CWE-915",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=20,
        module_name="auth_engine",
    )

    # Phase 3: Response contracts and authentication
    registry.register(
        check_id="response_contract",
        owasp_api="API8:2023",
        cwe="CWE-20",
        safety_level=SafetyLevel.PASSIVE.value,
        max_requests=0,
        module_name="response_contract",
    )
    registry.register(
        check_id="jwt_differential",
        owasp_api="API2:2023",
        cwe="CWE-347",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=30,
        module_name="jwt_checks",
    )
    registry.register(
        check_id="token_session",
        owasp_api="API2:2023",
        cwe="CWE-306",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=50,
        module_name="token_session_checks",
    )

    # Phase 4: Bounded active checks
    registry.register(
        check_id="resource_consumption",
        owasp_api="API4:2023",
        cwe="CWE-400",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=30,
        module_name="resource_checks",
    )
    registry.register(
        check_id="upload_safety",
        owasp_api="API8:2023",
        cwe="CWE-434",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=10,
        module_name="upload_checks",
    )
    registry.register(
        check_id="parser_confusion",
        owasp_api="API8:2023",
        cwe="CWE-502",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=15,
        module_name="parser_checks",
    )
    registry.register(
        check_id="sspp",
        owasp_api="API8:2023",
        cwe="CWE-233",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=30,
        module_name="sspp_checks",
    )

    # Phase 5: OAST and protocol plug-ins
    registry.register(
        check_id="blind_ssrf",
        owasp_api="API7:2023",
        cwe="CWE-918",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=20,
        enabled=False,  # requires OAST configuration
        module_name="blind_checks",
    )
    registry.register(
        check_id="graphql",
        owasp_api="API8:2023",
        cwe="CWE-200",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=10,
        enabled=False,  # requires GraphQL endpoint config
        module_name="graphql_adapter",
    )

    # Post-review additions: rate-limit bypass, cache deception,
    # host-header trust, content negotiation, WebDAV, CSRF, OAuth,
    # JWT key confusion, and request smuggling.
    registry.register(
        check_id="rate_limit_bypass",
        owasp_api="API4:2023",
        cwe="CWE-799",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=60,
        module_name="rate_limit_bypass",
    )
    registry.register(
        check_id="cache_deception",
        owasp_api="API6:2023",
        cwe="CWE-524",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=10,
        module_name="cache_checks",
    )
    registry.register(
        check_id="host_header_trust",
        owasp_api="API8:2023",
        cwe="CWE-644",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=10,
        module_name="host_header_checks",
    )
    registry.register(
        check_id="content_negotiation",
        owasp_api="API8:2023",
        cwe="CWE-436",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=6,
        module_name="extra_checks",
    )
    registry.register(
        check_id="jwt_key_confusion",
        owasp_api="API2:2023",
        cwe="CWE-347",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=6,
        enabled=False,  # requires OAST configuration
        module_name="jwt_checks",
    )
    registry.register(
        check_id="webdav",
        owasp_api="API8:2023",
        cwe="CWE-434",
        safety_level=SafetyLevel.INTRUSIVE.value,
        max_requests=20,
        module_name="extra_checks",
    )
    registry.register(
        check_id="csrf",
        owasp_api="API8:2023",
        cwe="CWE-352",
        safety_level=SafetyLevel.INTRUSIVE.value,
        max_requests=10,
        enabled=False,  # requires cookie identity profiles
        module_name="csrf_checks",
    )
    registry.register(
        check_id="oauth",
        owasp_api="API2:2023",
        cwe="CWE-601",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=10,
        enabled=False,  # requires explicit OAuthConfig
        module_name="oauth_checks",
    )
    registry.register(
        check_id="smuggling",
        owasp_api="API8:2023",
        cwe="CWE-436",
        safety_level=SafetyLevel.INTRUSIVE.value,
        max_requests=12,
        module_name="smuggling_checks",
    )

    # Phase 6: Workflows and inventory
    registry.register(
        check_id="inventory",
        owasp_api="API9:2023",
        cwe="CWE-200",
        safety_level=SafetyLevel.PASSIVE.value,
        max_requests=0,
        module_name="inventory",
    )
    registry.register(
        check_id="workflow",
        owasp_api="API6:2023",
        cwe="CWE-840",
        safety_level=SafetyLevel.INTRUSIVE.value,
        max_requests=100,
        enabled=True,  # gated by safety_level=intrusive, not by enabled flag
        module_name="workflow_engine",
    )

    return registry


@dataclass
class EngineScanResult:
    """Result of running the engine over a set of endpoints."""
    findings: List[Finding] = field(default_factory=list)
    check_results: List[CheckResult] = field(default_factory=list)
    total_requests: int = 0
    elapsed_ms: int = 0
    error: Optional[str] = None


def run_engine(
    endpoints: Sequence[Endpoint],
    base_url: str,
    session: requests.Session,
    *,
    registry: CheckRegistry,
    scan_mode: str = "safe_active",
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
    scan: Optional[Any] = None,
    disabled_checks: Optional[set] = None,
) -> EngineScanResult:
    """Run all enabled checks from the registry against the endpoints.

    This is the Phase 2-6 orchestration layer. It does NOT replace
    ``fuzzer.run_scan`` — it runs alongside it for checks that need
    multi-identity or contract-aware execution.
    """
    result = EngineScanResult()
    disabled = disabled_checks or set()
    enabled_checks = [
        c for c in registry.get_enabled(scan_mode)
        if c.check_id not in disabled
    ]
    t0 = time.perf_counter()

    for reg in enabled_checks:
        check_result = CheckResult(
            check_id=reg.check_id,
            safety_level=reg.safety_level,
            owasp_api=reg.owasp_api,
            cwe=reg.cwe,
        )
        run_fn = reg.run_fn or _RUN_FN_BY_CHECK.get(reg.check_id)
        try:
            if run_fn is not None:
                out = run_fn(
                    endpoints=endpoints,
                    base_url=base_url,
                    session=session,
                    timeout=timeout,
                    auth_header=auth_header,
                    scan=scan,
                )
                # run_fn may return (findings, request_count) for an honest
                # request count, or just a findings list (count = len).
                if isinstance(out, tuple) and len(out) == 2:
                    raw_findings, request_count = out
                else:
                    raw_findings, request_count = out, None
                coerced = [_coerce_finding(f) for f in raw_findings]
                check_result.findings = coerced
                check_result.request_count = (
                    request_count if request_count is not None else len(coerced)
                )
                result.findings.extend(coerced)
            check_result.notes = "completed"
        except Exception as exc:  # pragma: no cover - safety net
            check_result.notes = f"Check {reg.check_id} errored: {type(exc).__name__}: {exc}"
        result.check_results.append(check_result)

    result.findings = sort_findings(result.findings)
    result.elapsed_ms = int((time.perf_counter() - t0) * 1000)
    result.total_requests = sum(cr.request_count for cr in result.check_results)
    return result
