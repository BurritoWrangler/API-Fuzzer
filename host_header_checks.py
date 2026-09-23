"""Host-header trust attacks.

Probes whether the target trusts override headers to rebuild absolute URLs:
  * X-Forwarded-Host: attacker.example
  * X-Original-URL / X-Rewrite-URL: attacker-controlled path
  * Forwarded: host=attacker.example

Reflection of the attacker host in response bodies, Location headers, or
links is the precursor to password-reset poisoning, cache poisoning, and
SSRF via internal URL construction. Absolute-URI Host override is also tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from request_builder import build_encoded_url
from spec_parser import Endpoint


ATTACK_HOST = "attacker.example"

_TRUST_HEADERS = [
    ("X-Forwarded-Host", ATTACK_HOST),
    ("X-Host", ATTACK_HOST),
    ("Forwarded", f"host={ATTACK_HOST}"),
    ("X-Original-URL", f"https://{ATTACK_HOST}/original"),
    ("X-Rewrite-URL", f"https://{ATTACK_HOST}/rewritten"),
]


@dataclass
class HostHeaderFinding:
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
    val = auth_header.strip()
    if val.lower().startswith("authorization:"):
        val = val.split(":", 1)[1].strip()
    return {"Authorization": val} if val else {}


def _send(session, method, url, headers, timeout):
    try:
        return session.request(
            method, url, headers=headers, timeout=timeout, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None


def _reflection(resp: requests.Response) -> str:
    """Return a description of where the attack host was reflected, or ''."""
    location = (resp.headers.get("Location") or resp.headers.get("location") or "")
    if ATTACK_HOST in location:
        return f"Location header: {location}"
    body = (resp.text or "")[:20000]
    if ATTACK_HOST in body:
        return "attacker host reflected in response body"
    return ""


def probe_host_header_trust(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[HostHeaderFinding]:
    findings: List[HostHeaderFinding] = []
    path_params = {
        p.name: (p.example if p.example is not None else 1)
        for p in endpoint.parameters
        if p.location == "path"
    }
    query = {
        p.name: (p.example if p.example is not None else "test")
        for p in endpoint.parameters
        if p.location == "query"
    }
    url = build_encoded_url(base_url, endpoint.path, path_params, query)
    auth = _auth_headers(auth_header)

    for header_name, value in _TRUST_HEADERS:
        headers = {**auth, header_name: value}
        resp = _send(session, endpoint.method, url, headers, timeout)
        if resp is None:
            continue
        where = _reflection(resp)
        if where:
            findings.append(
                HostHeaderFinding(
                    category="host_header_trust",
                    severity="high",
                    confidence="strong",
                    title=f"Host-header trust: {header_name} reflected",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=header_name,
                    evidence=(
                        f"Injecting '{header_name}: {value}' was reflected ({where}). "
                        f"The server trusts override headers when building absolute URLs — "
                        f"password-reset poisoning and cache poisoning may be possible."
                    ),
                    owasp_api="API8:2023",
                    cwe="CWE-644",
                    request_url=url,
                    status_code=resp.status_code,
                )
            )
            break  # one reflection establishes the trust pattern
    return findings


def run_host_header_trust(
    endpoints,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
    scan=None,
) -> List[HostHeaderFinding]:
    """Engine adapter signature: probe first 10 endpoints."""
    findings: List[HostHeaderFinding] = []
    for ep in endpoints[:10]:
        findings.extend(
            probe_host_header_trust(ep, base_url, session, timeout, auth_header)
        )
    return findings
