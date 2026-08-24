"""Phase 4: Structured parser and input-format probes.

Tests for duplicate JSON keys, invalid encodings, numeric overflow/precision,
deep nesting, XML external entities (mock), and unsafe polymorphic type fields.
All probes are bounded and use safe canary content only.
"""

from __future__ import annotations

import json as jsonlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from spec_parser import Endpoint


MAX_NESTING_DEPTH = 100
MAX_BODY_SIZE = 256 * 1024  # 256 KiB safety ceiling


@dataclass
class ParserFinding:
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


def _send_body(
    session: requests.Session,
    method: str,
    url: str,
    body: str,
    content_type: str,
    headers: Dict[str, str],
    timeout: float,
) -> Optional[Tuple[int, str]]:
    """Send a raw body and return (status, response_text)."""
    hdrs = dict(headers)
    hdrs["Content-Type"] = content_type
    try:
        resp = session.request(
            method, url, headers=hdrs, data=body.encode("utf-8"),
            timeout=timeout, allow_redirects=False,
        )
        return resp.status_code, resp.text or ""
    except requests.exceptions.RequestException:
        return None


def probe_duplicate_json_keys(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[ParserFinding]:
    """Send JSON with duplicate keys to test parser behavior."""
    findings: List[ParserFinding] = []
    if not endpoint.has_body:
        return findings
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    url = base_url.rstrip("/") + endpoint.path

    duplicate_body = '{"id": 1, "id": 2, "name": "test", "name": "overwritten"}'
    result = _send_body(session, endpoint.method, url, duplicate_body, "application/json", headers, timeout)
    if result and 200 <= result[0] < 300:
        findings.append(ParserFinding(
            category="parser_confusion",
            severity="medium",
            confidence="tentative",
            title="Duplicate JSON keys accepted",
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter="<body>",
            evidence=f"Server accepted JSON with duplicate keys (HTTP {result[0]}). Last-value-wins may differ from first-value-wins.",
            owasp_api="API8:2023",
            cwe="CWE-20",
            request_url=url,
            status_code=result[0],
        ))
    return findings


def probe_deep_nesting(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[ParserFinding]:
    """Send deeply nested JSON to test stack-depth limits."""
    findings: List[ParserFinding] = []
    if not endpoint.has_body:
        return findings
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    url = base_url.rstrip("/") + endpoint.path

    nested = '{"a": ' * MAX_NESTING_DEPTH + '"b"' + '}' * MAX_NESTING_DEPTH
    if len(nested) > MAX_BODY_SIZE:
        nested = nested[:MAX_BODY_SIZE]
    result = _send_body(session, endpoint.method, url, nested, "application/json", headers, timeout)
    if result and 200 <= result[0] < 300:
        findings.append(ParserFinding(
            category="parser_confusion",
            severity="low",
            confidence="tentative",
            title=f"Deeply nested JSON ({MAX_NESTING_DEPTH} levels) accepted",
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter="<body>",
            evidence=f"Server accepted {MAX_NESTING_DEPTH}-level nested JSON (HTTP {result[0]}). May cause stack exhaustion.",
            owasp_api="API4:2023",
            cwe="CWE-674",
            request_url=url,
            status_code=result[0],
        ))
    return findings


def probe_numeric_overflow(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[ParserFinding]:
    """Send numeric overflow/precision values to integer/number parameters."""
    findings: List[ParserFinding] = []
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    url = base_url.rstrip("/") + endpoint.path

    overflow_values = [
        "999999999999999999999999999999999999",
        "1.7976931348623157e308",
        "-1.7976931348623157e308",
        "0.1",
        "1e400",
    ]
    numeric_params = [p for p in endpoint.parameters if p.schema_type in ("integer", "number")]
    for param in numeric_params:
        for value in overflow_values:
            if param.location == "query":
                params = {p.name: p.example if p.example is not None else "1"
                           for p in endpoint.parameters if p.location == "query"}
                params[param.name] = value
                try:
                    resp = session.request(
                        endpoint.method, url, params=params, headers=headers,
                        timeout=timeout, allow_redirects=False,
                    )
                    if 200 <= resp.status_code < 300:
                        findings.append(ParserFinding(
                            category="numeric_overflow",
                            severity="low",
                            confidence="tentative",
                            title=f"Numeric overflow accepted: {param.name}={value}",
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            parameter=param.name,
                            evidence=f"Server accepted overflow value for {param.name} (HTTP {resp.status_code}).",
                            owasp_api="API3:2023",
                            cwe="CWE-190",
                            request_url=url,
                            status_code=resp.status_code,
                        ))
                except requests.exceptions.RequestException:
                    continue
    return findings


def probe_unsafe_type_fields(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[ParserFinding]:
    """Probe for unsafe polymorphic type fields in JSON bodies."""
    findings: List[ParserFinding] = []
    if not endpoint.has_body or not isinstance(endpoint.body_example, dict):
        return findings
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    url = base_url.rstrip("/") + endpoint.path

    unsafe_fields = ["$type", "@class", "__type", "@type", "class"]
    body = dict(endpoint.body_example)
    for field_name in unsafe_fields:
        body_copy = dict(body)
        body_copy[field_name] = "java.lang.Runtime"
        result = _send_body(session, endpoint.method, url, jsonlib.dumps(body_copy), "application/json", headers, timeout)
        if result and 200 <= result[0] < 300:
            findings.append(ParserFinding(
                category="unsafe_deserialization",
                severity="high",
                confidence="tentative",
                title=f"Unsafe type field accepted: {field_name}",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter=field_name,
                evidence=(
                    f"Server accepted '{field_name}' field in JSON body (HTTP {result[0]}). "
                    f"Review for unsafe polymorphic deserialization."
                ),
                owasp_api="API8:2023",
                cwe="CWE-502",
                request_url=url,
                status_code=result[0],
            ))
            break
    return findings
