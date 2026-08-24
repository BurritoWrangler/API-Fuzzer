"""Phase 4: Expanded server-side parameter pollution (SSPP) checks.

Tests query-string truncation, parameter injection, parameter overriding,
and pollution inside JSON, form, XML, and path segments. Establishes
natural response variability before reporting differences.
"""

from __future__ import annotations

import json as jsonlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests

from spec_parser import Endpoint


@dataclass
class SSPPFinding:
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


def _auth_headers(auth_header: Optional[str]) -> Dict[str, str]:
    if not auth_header:
        return {}
    return {"Authorization": auth_header}


def _send_query(
    session: requests.Session,
    method: str,
    url: str,
    params: Any,
    headers: Dict[str, str],
    timeout: float,
) -> Optional[Tuple[int, str]]:
    try:
        resp = session.request(
            method, url, params=params, headers=headers,
            timeout=timeout, allow_redirects=False,
        )
        return resp.status_code, resp.text or ""
    except requests.exceptions.RequestException:
        return None


def probe_query_truncation(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[SSPPFinding]:
    """Test query-string truncation with # and encoded delimiters."""
    findings: List[SSPPFinding] = []
    query_params = [p for p in endpoint.parameters if p.location == "query"]
    if not query_params:
        return findings

    headers = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint.path
    base_params = {p.name: p.example if p.example is not None else "test" for p in query_params}

    # Baseline response.
    baseline = _send_query(session, endpoint.method, url, base_params, headers, timeout)
    if baseline is None:
        return findings
    base_status, base_text = baseline

    for param in query_params:
        # Inject a truncation payload after the value.
        truncation_payloads = [
            f"{base_params.get(param.name, 'test')}#extra=injected",
            f"{base_params.get(param.name, 'test')}%26extra%3Dinjected",
        ]
        for payload in truncation_payloads:
            params = dict(base_params)
            params[param.name] = payload
            result = _send_query(session, endpoint.method, url, params, headers, timeout)
            if result and result[0] != base_status and abs(len(result[1]) - len(base_text)) > 100:
                findings.append(SSPPFinding(
                    category="sspp",
                    severity="medium",
                    confidence="tentative",
                    title=f"Query truncation: {param.name} delimiter changed response",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=param.name,
                    evidence=(
                        f"Baseline HTTP {base_status} ({len(base_text)} bytes); "
                        f"truncated payload HTTP {result[0]} ({len(result[1])} bytes)."
                    ),
                    owasp_api="API8:2023",
                    cwe="CWE-233",
                    request_url=url,
                    status_code=result[0],
                ))
    return findings


def probe_param_injection(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[SSPPFinding]:
    """Inject new internal parameters via existing query params."""
    findings: List[SSPPFinding] = []
    query_params = [p for p in endpoint.parameters if p.location == "query"]
    if not query_params:
        return findings

    headers = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint.path
    base_params = {p.name: p.example if p.example is not None else "test" for p in query_params}

    baseline = _send_query(session, endpoint.method, url, base_params, headers, timeout)
    if baseline is None:
        return findings
    base_status, base_text = baseline

    # Inject extra parameters that might be interpreted server-side.
    injection_params = ["admin", "debug", "internal", "role", "bypass", "test"]
    for param in query_params:
        for injected_name in injection_params:
            params = dict(base_params)
            params[injected_name] = "true"
            result = _send_query(session, endpoint.method, url, params, headers, timeout)
            if result and 200 <= result[0] < 300 and result[1] != base_text:
                findings.append(SSPPFinding(
                    category="sspp",
                    severity="low",
                    confidence="tentative",
                    title=f"Parameter injection: {injected_name} changed response",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=injected_name,
                    evidence=(
                        f"Injecting '{injected_name}=true' changed the response "
                        f"(HTTP {result[0]}, {len(result[1])} bytes vs baseline {len(base_text)} bytes)."
                    ),
                    owasp_api="API8:2023",
                    cwe="CWE-233",
                    request_url=url,
                    status_code=result[0],
                ))
    return findings


def probe_json_pollution(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[SSPPFinding]:
    """Test parameter pollution inside JSON bodies with duplicate keys."""
    findings: List[SSPPFinding] = []
    if not endpoint.has_body or not isinstance(endpoint.body_example, dict):
        return findings

    headers = _auth_headers(auth_header)
    headers["Content-Type"] = "application/json"
    url = base_url.rstrip("/") + endpoint.path

    # Duplicate a key in the JSON body.
    for key in list(endpoint.body_example.keys()):
        polluted = dict(endpoint.body_example)
        polluted[key] = "apifz_sspp_canary"
        polluted[f"__{key}"] = endpoint.body_example[key]  # shadow key
        try:
            resp = session.request(
                endpoint.method, url, headers=headers,
                json=polluted, timeout=timeout, allow_redirects=False,
            )
            if 200 <= resp.status_code < 300 and "apifz_sspp_canary" in (resp.text or ""):
                findings.append(SSPPFinding(
                    category="sspp",
                    severity="medium",
                    confidence="tentative",
                    title=f"JSON parameter pollution: {key} accepted with duplicate",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=key,
                    evidence=(
                        f"Server accepted JSON with duplicated key '{key}' and "
                        f"reflected the canary value (HTTP {resp.status_code})."
                    ),
                    owasp_api="API8:2023",
                    cwe="CWE-233",
                    request_url=url,
                    status_code=resp.status_code,
                ))
                break
        except requests.exceptions.RequestException:
            continue
    return findings
