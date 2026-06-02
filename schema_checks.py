"""Schema-driven negative testing.

Given a parsed endpoint, derive negative test cases from its declared parameter
schema and exercise them. Findings flag servers that silently accept invalid
input (a frequent precursor to deeper bugs).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

import requests

from analyzer import Finding, url_with_query
from spec_parser import Endpoint, Parameter


CATEGORY = "schema_violation"


def _mk(
    severity: str,
    title: str,
    *,
    endpoint: str,
    method: str,
    request_url: str,
    evidence: str,
    parameter: str,
    location: str,
    payload: str,
    technique: str,
    status_code: int,
    request_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    response_headers: Optional[Dict[str, str]] = None,
) -> Finding:
    from analyzer import capture_body
    captured, truncated = capture_body(response_body)
    return Finding(
        severity=severity,
        category=CATEGORY,
        title=title,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        location=location,
        payload=payload,
        technique=technique,
        evidence=evidence,
        status_code=status_code,
        response_time_ms=0,
        request_url=request_url,
        request_headers=dict(request_headers or {}),
        request_body=None,
        response_body=captured,
        response_headers=dict(response_headers or {}),
        response_truncated=truncated,
    )


def _auth_headers(auth_header: Optional[str]) -> Dict[str, str]:
    if not auth_header:
        return {}
    val = auth_header.strip()
    if val.lower().startswith("authorization:"):
        val = val.split(":", 1)[1].strip()
    return {"Authorization": val}


def _placeholder(p: Parameter) -> Any:
    if p.example is not None:
        return p.example
    if p.schema_type in ("integer", "number"):
        return 1
    if p.schema_type == "boolean":
        return True
    return "test"


def _send(session, method, url, *, headers, params=None, data=None, json=None, timeout=10.0):
    try:
        return session.request(
            method, url,
            headers=headers, params=params, data=data, json=json,
            timeout=timeout, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None


def run_schema_checks(
    *,
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []
    headers = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint.path

    # Build a benign query/header set + path substitution.
    path_params = {p.name: _placeholder(p) for p in endpoint.parameters if p.location == "path"}
    benign_query = {p.name: _placeholder(p) for p in endpoint.parameters if p.location == "query"}
    benign_headers = {p.name: str(_placeholder(p)) for p in endpoint.parameters if p.location == "header"}
    benign_url = url
    for name, val in path_params.items():
        benign_url = benign_url.replace("{" + name + "}", str(val))

    # 1. Required-field omission (query / header / required path)
    for p in endpoint.parameters:
        if not p.required:
            continue
        if p.location == "query":
            params = {k: v for k, v in benign_query.items() if k != p.name}
            resp = _send(session, endpoint.method, benign_url, headers={**headers, **benign_headers}, params=params, timeout=timeout)
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(_mk(
                    "medium",
                    f"Required query parameter '{p.name}' silently accepted as missing",
                    endpoint=endpoint.path, method=endpoint.method,
                    request_url=url_with_query(benign_url, params),
                    evidence=f"Spec marks '{p.name}' required but request without it returned HTTP {resp.status_code}.",
                    parameter=p.name, location="query", payload="<omitted>",
                    technique="required-field omission",
                    status_code=resp.status_code, request_headers={**headers, **benign_headers},
                    response_body=resp.text or "", response_headers=dict(resp.headers),
                ))
        elif p.location == "header":
            h = {**headers, **{k: v for k, v in benign_headers.items() if k != p.name}}
            resp = _send(session, endpoint.method, benign_url, headers=h, params=benign_query, timeout=timeout)
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(_mk(
                    "medium",
                    f"Required header '{p.name}' silently accepted as missing",
                    endpoint=endpoint.path, method=endpoint.method,
                    request_url=url_with_query(benign_url, benign_query),
                    evidence=f"Spec marks header '{p.name}' required but request without it returned HTTP {resp.status_code}.",
                    parameter=p.name, location="header", payload="<omitted>",
                    technique="required-field omission",
                    status_code=resp.status_code, request_headers=h,
                    response_body=resp.text or "", response_headers=dict(resp.headers),
                ))

    # 2. Type mismatch: send a string where integer/number is expected.
    for p in endpoint.parameters:
        if p.schema_type not in ("integer", "number"):
            continue
        bogus_value = "not_a_number_apifz"
        if p.location == "query":
            params = dict(benign_query)
            params[p.name] = bogus_value
            resp = _send(session, endpoint.method, benign_url, headers={**headers, **benign_headers}, params=params, timeout=timeout)
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(_mk(
                    "low",
                    f"Type mismatch silently accepted for '{p.name}'",
                    endpoint=endpoint.path, method=endpoint.method,
                    request_url=url_with_query(benign_url, params),
                    evidence=f"'{p.name}' is declared {p.schema_type} but server accepted a string (HTTP {resp.status_code}).",
                    parameter=p.name, location="query", payload=bogus_value,
                    technique="type mismatch",
                    status_code=resp.status_code, request_headers={**headers, **benign_headers},
                    response_body=resp.text or "", response_headers=dict(resp.headers),
                ))
        elif p.location == "path":
            patched_url = url
            for name, val in path_params.items():
                patched_url = patched_url.replace("{" + name + "}", bogus_value if name == p.name else str(val))
            resp = _send(session, endpoint.method, patched_url, headers={**headers, **benign_headers}, params=benign_query, timeout=timeout)
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(_mk(
                    "low",
                    f"Type mismatch silently accepted for path '{p.name}'",
                    endpoint=endpoint.path, method=endpoint.method,
                    request_url=url_with_query(patched_url, benign_query),
                    evidence=f"Path '{p.name}' declared {p.schema_type} but server accepted a string (HTTP {resp.status_code}).",
                    parameter=p.name, location="path", payload=bogus_value,
                    technique="type mismatch",
                    status_code=resp.status_code, request_headers={**headers, **benign_headers},
                    response_body=resp.text or "", response_headers=dict(resp.headers),
                ))

    # 3. Enum out-of-range
    for p in endpoint.parameters:
        if not p.enum or p.location != "query":
            continue
        params = dict(benign_query)
        params[p.name] = "apifz_not_in_enum"
        resp = _send(session, endpoint.method, benign_url, headers={**headers, **benign_headers}, params=params, timeout=timeout)
        if resp is not None and 200 <= resp.status_code < 300:
            findings.append(_mk(
                "low",
                f"Enum violation silently accepted for '{p.name}'",
                endpoint=endpoint.path, method=endpoint.method,
                request_url=url_with_query(benign_url, params),
                evidence=f"'{p.name}' declared enum {p.enum} but server accepted an out-of-range value (HTTP {resp.status_code}).",
                parameter=p.name, location="query", payload="apifz_not_in_enum",
                technique="enum out-of-range",
                status_code=resp.status_code, request_headers={**headers, **benign_headers},
                response_body=resp.text or "", response_headers=dict(resp.headers),
            ))

    # 4. maxLength violation
    for p in endpoint.parameters:
        if p.max_length is None or p.schema_type != "string":
            continue
        try:
            oversize = "A" * (int(p.max_length) + 64)
        except Exception:
            continue
        if p.location == "query":
            params = dict(benign_query)
            params[p.name] = oversize
            resp = _send(session, endpoint.method, benign_url, headers={**headers, **benign_headers}, params=params, timeout=timeout)
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(_mk(
                    "low",
                    f"maxLength violation silently accepted for '{p.name}'",
                    endpoint=endpoint.path, method=endpoint.method,
                    request_url=url_with_query(benign_url, params),
                    evidence=f"'{p.name}' has maxLength={p.max_length} but server accepted a {len(oversize)}-char value (HTTP {resp.status_code}).",
                    parameter=p.name, location="query", payload=oversize[:80] + "…",
                    technique="maxLength violation",
                    status_code=resp.status_code, request_headers={**headers, **benign_headers},
                    response_body=resp.text or "", response_headers=dict(resp.headers),
                ))

    # 5. Numeric maximum violation
    for p in endpoint.parameters:
        if p.maximum is None or p.schema_type not in ("integer", "number"):
            continue
        oversize_val = str(int(p.maximum) + 1_000_000) if p.schema_type == "integer" else str(float(p.maximum) + 1_000_000.0)
        if p.location == "query":
            params = dict(benign_query)
            params[p.name] = oversize_val
            resp = _send(session, endpoint.method, benign_url, headers={**headers, **benign_headers}, params=params, timeout=timeout)
            if resp is not None and 200 <= resp.status_code < 300:
                findings.append(_mk(
                    "low",
                    f"maximum violation silently accepted for '{p.name}'",
                    endpoint=endpoint.path, method=endpoint.method,
                    request_url=url_with_query(benign_url, params),
                    evidence=f"'{p.name}' has maximum={p.maximum} but server accepted {oversize_val} (HTTP {resp.status_code}).",
                    parameter=p.name, location="query", payload=oversize_val,
                    technique="maximum violation",
                    status_code=resp.status_code, request_headers={**headers, **benign_headers},
                    response_body=resp.text or "", response_headers=dict(resp.headers),
                ))

    return findings
