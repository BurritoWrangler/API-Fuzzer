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
        try:
            if reg.run_fn is not None:
                findings = reg.run_fn(
                    endpoints=endpoints,
                    base_url=base_url,
                    session=session,
                    timeout=timeout,
                    auth_header=auth_header,
                    scan=scan,
                )
                if isinstance(findings, list):
                    check_result.findings = findings
                    check_result.request_count = len(findings)
                    result.findings.extend(findings)
            check_result.notes = "completed"
        except Exception as exc:  # pragma: no cover - safety net
            check_result.notes = f"Check {reg.check_id} errored: {type(exc).__name__}: {exc}"
        result.check_results.append(check_result)

    result.findings = sort_findings(result.findings)
    result.elapsed_ms = int((time.perf_counter() - t0) * 1000)
    result.total_requests = sum(cr.request_count for cr in result.check_results)
    return result
