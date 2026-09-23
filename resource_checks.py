"""Phase 4: Bounded resource consumption probes.

Detects pagination/sizing parameters and probes zero, negative, boundary, and
capped-large values. Compares response count, body size, and latency to
baselines without attempting exhaustion. Each check declares hard ceilings.
"""

from __future__ import annotations

import json as jsonlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from analyzer import Finding
from models import SafetyLevel
from spec_parser import Endpoint


PAGINATION_PARAM_NAMES = {
    "limit", "page_size", "per_page", "pagesize", "count", "size",
    "offset", "page", "skip", "take", "max", "batch",
}
MAX_PROBE_VALUE = 10000
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MiB safety ceiling


@dataclass
class ResourceFinding:
    category: str
    severity: str
    confidence: str
    title: str
    endpoint: str
    method: str
    parameter: str
    evidence: str
    owasp_api: str
    cwe: str
    request_url: str
    status_code: int = 0
    response_size: int = 0
    latency_ms: int = 0


def _is_pagination_param(name: str) -> bool:
    return name.lower() in PAGINATION_PARAM_NAMES


def _send_probe(
    session: requests.Session,
    method: str,
    url: str,
    params: Dict[str, Any],
    headers: Dict[str, str],
    timeout: float,
) -> Optional[Tuple[int, int, int]]:
    """Send a single probe and return (status, body_size, latency_ms)."""
    try:
        t0 = time.perf_counter()
        resp = session.request(
            method, url, params=params, headers=headers,
            timeout=timeout, allow_redirects=False,
        )
        elapsed = int((time.perf_counter() - t0) * 1000)
        body_size = len(resp.text or "")
        return resp.status_code, min(body_size, MAX_RESPONSE_SIZE), elapsed
    except requests.exceptions.RequestException:
        return None


def probe_pagination(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[ResourceFinding]:
    """Probe pagination/sizing parameters with bounded values."""
    findings: List[ResourceFinding] = []
    pagination_params = [p for p in endpoint.parameters if _is_pagination_param(p.name)]
    if not pagination_params:
        return findings

    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header

    base_params = {p.name: p.example if p.example is not None else "test"
                   for p in endpoint.parameters if p.location == "query"}
    base_url_full = base_url.rstrip("/") + endpoint.path

    # Baseline response.
    baseline = _send_probe(session, endpoint.method, base_url_full, base_params, headers, timeout)
    if baseline is None:
        return findings
    base_status, base_size, base_latency = baseline

    probe_values = [0, -1, 1, 100, 1000, MAX_PROBE_VALUE]
    for param in pagination_params:
        for value in probe_values:
            probe_params = dict(base_params)
            probe_params[param.name] = value
            result = _send_probe(session, endpoint.method, base_url_full, probe_params, headers, timeout)
            if result is None:
                continue
            status, size, latency = result

            # Flag if response is dramatically larger than baseline.
            if base_size > 0 and size > base_size * 10:
                findings.append(ResourceFinding(
                    category="resource_consumption",
                    severity="medium",
                    confidence="tentative",
                    title=f"Unrestricted pagination: {param.name}={value} caused large response",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=param.name,
                    evidence=(
                        f"Baseline response {base_size} bytes; probe with {param.name}={value} "
                        f"returned {size} bytes ({size / base_size:.1f}x baseline)."
                    ),
                    owasp_api="API4:2023",
                    cwe="CWE-770",
                    request_url=base_url_full,
                    status_code=status,
                    response_size=size,
                    latency_ms=latency,
                ))

            # Flag if response is significantly slower.
            if base_latency > 0 and latency > base_latency * 5:
                findings.append(ResourceFinding(
                    category="resource_consumption",
                    severity="low",
                    confidence="tentative",
                    title=f"Unrestricted pagination: {param.name}={value} caused slow response",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=param.name,
                    evidence=(
                        f"Baseline latency {base_latency}ms; probe with {param.name}={value} "
                        f"took {latency}ms ({latency / base_latency:.1f}x baseline)."
                    ),
                    owasp_api="API4:2023",
                    cwe="CWE-400",
                    request_url=base_url_full,
                    status_code=status,
                    response_size=size,
                    latency_ms=latency,
                ))

    return findings
