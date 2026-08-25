"""Request-mutation security checks.

These are observational tests that don't fit the simple payload-injection
loop. Each function performs one or more crafted requests and returns
`Finding`s.
"""

from __future__ import annotations

import copy
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from analyzer import Finding, url_with_query


# Sentinel admin-style fields commonly accepted via mass assignment.
MASS_ASSIGNMENT_FIELDS = {
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "role": "admin",
    "roles": ["admin"],
    "permissions": ["admin"],
    "verified": True,
    "email_verified": True,
    "is_staff": True,
    "is_superuser": True,
    "owner": "admin",
}

# Query/body parameter names that commonly accept a URL — used to focus
# the open-redirect check.
URL_PARAM_NAMES = {
    "url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "return", "returnto", "return_url", "next", "callback", "continue",
    "dest", "destination", "u", "redir",
}


def _mk(
    severity: str,
    title: str,
    category: str,
    *,
    endpoint: str,
    method: str,
    request_url: str,
    evidence: str,
    payload: str = "",
    technique: str = "request mutation",
    parameter: str = "<n/a>",
    location: str = "request",
    status_code: int = 0,
    response_time_ms: int = 0,
    request_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    response_headers: Optional[Dict[str, str]] = None,
    request_body: Optional[str] = None,
) -> Finding:
    from analyzer import capture_body
    captured, truncated = capture_body(response_body)
    return Finding(
        severity=severity,
        category=category,
        title=title,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        location=location,
        payload=payload,
        technique=technique,
        evidence=evidence,
        status_code=status_code,
        response_time_ms=response_time_ms,
        request_url=request_url,
        request_headers=dict(request_headers or {}),
        request_body=request_body,
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


# ---------------------------------------------------------------------------
# Mass assignment
# ---------------------------------------------------------------------------

def mass_assignment_probe(
    *,
    base_url: str,
    endpoint_path: str,
    method: str,
    body_example: Dict[str, Any],
    baseline_status: int,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    """If a JSON body endpoint accepts an admin-flavoured extra field at 2xx,
    flag it as a probable mass-assignment exposure."""
    findings: List[Finding] = []
    if not isinstance(body_example, dict):
        return findings
    url = base_url.rstrip("/") + endpoint_path
    headers = {**_auth_headers(auth_header), "Content-Type": "application/json"}

    augmented = copy.deepcopy(body_example)
    augmented.update(MASS_ASSIGNMENT_FIELDS)
    augmented["apifz_marker"] = secrets.token_hex(4)
    try:
        resp = session.request(
            method, url, headers=headers, json=augmented, timeout=timeout, allow_redirects=False
        )
    except requests.exceptions.RequestException:
        return findings

    # Compare to baseline_status: if baseline was 4xx and we now get 2xx, that's notable;
    # if baseline was 2xx, only echo of the marker in the response is interesting.
    full_body = resp.text or ""
    resp_hdrs = dict(resp.headers)
    if 200 <= resp.status_code < 300:
        body_sniff = full_body[:1500]
        if augmented["apifz_marker"] in body_sniff or any(
            isinstance(v, str) and v in body_sniff for v in (MASS_ASSIGNMENT_FIELDS["role"], "admin")
        ):
            findings.append(
                _mk(
                    "high",
                    "Possible mass assignment: admin fields echoed in response",
                    "mass_assignment",
                    endpoint=endpoint_path,
                    method=method,
                    request_url=url,
                    evidence=f"Server echoed admin-flavoured field(s) (HTTP {resp.status_code}).",
                    status_code=resp.status_code,
                    request_headers=headers,
                    request_body="<augmented body>",
                    response_body=full_body,
                    response_headers=resp_hdrs,
                )
            )
        elif baseline_status and baseline_status >= 400:
            findings.append(
                _mk(
                    "medium",
                    "Body with admin fields accepted where baseline was rejected",
                    "mass_assignment",
                    endpoint=endpoint_path,
                    method=method,
                    request_url=url,
                    evidence=f"Baseline status {baseline_status} \u2192 augmented {resp.status_code}.",
                    status_code=resp.status_code,
                    request_headers=headers,
                    response_body=full_body,
                    response_headers=resp_hdrs,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# HTTP Parameter Pollution
# ---------------------------------------------------------------------------

def http_parameter_pollution_probe(
    *,
    base_url: str,
    endpoint_path: str,
    method: str,
    benign_query: Dict[str, Any],
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []
    if not benign_query:
        return findings
    url = base_url.rstrip("/") + endpoint_path
    headers = _auth_headers(auth_header)
    for name, val in benign_query.items():
        # Send the same param twice with different values.
        try:
            polluted = [(name, str(val)), (name, "apifz_hpp_canary")]
            resp = session.request(
                method, url, headers=headers, params=polluted, timeout=timeout, allow_redirects=False
            )
        except requests.exceptions.RequestException:
            continue
        text = resp.text or ""
        if "apifz_hpp_canary" in text and 200 <= resp.status_code < 300:
            # Record the URL with the duplicated query baked in.
            recorded_url = url + ("?" if "?" not in url else "&") + \
                f"{name}={val}&{name}=apifz_hpp_canary"
            findings.append(
                _mk(
                    "medium",
                    "HTTP Parameter Pollution: duplicate parameter accepted",
                    "http_parameter_pollution",
                    endpoint=endpoint_path,
                    method=method,
                    request_url=recorded_url,
                    evidence=f"Duplicated query parameter '{name}' was accepted; second value reflected.",
                    payload="apifz_hpp_canary",
                    parameter=name,
                    location="query",
                    status_code=resp.status_code,
                    request_headers=headers,
                    response_body=text,
                    response_headers=dict(resp.headers),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# HTTP method override
# ---------------------------------------------------------------------------

OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]


def method_override_probe(
    *,
    base_url: str,
    endpoint_path: str,
    method: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    """For a benign GET endpoint, try the same URL with method override
    headers requesting DELETE. A 2xx is highly suspicious."""
    findings: List[Finding] = []
    if method.upper() != "GET":
        return findings
    url = base_url.rstrip("/") + endpoint_path
    base = _auth_headers(auth_header)
    for h in OVERRIDE_HEADERS:
        headers = {**base, h: "DELETE"}
        try:
            resp = session.request("GET", url, headers=headers, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        if 200 <= resp.status_code < 300:
            findings.append(
                _mk(
                    "medium",
                    f"Method override accepted via {h}",
                    "method_override",
                    endpoint=endpoint_path,
                    method="GET",
                    request_url=url,
                    evidence=f"GET with {h}: DELETE returned HTTP {resp.status_code}; verify the server didn't actually delete data.",
                    payload=f"{h}: DELETE",
                    parameter=h,
                    location="header",
                    status_code=resp.status_code,
                    request_headers=headers,
                    response_body=resp.text or "",
                    response_headers=dict(resp.headers),
                )
            )
            break  # one override is enough to flag
    return findings


# ---------------------------------------------------------------------------
# Content-Type confusion
# ---------------------------------------------------------------------------

def content_type_confusion_probe(
    *,
    base_url: str,
    endpoint_path: str,
    method: str,
    body_example: Optional[Dict[str, Any]],
    consumes_json: bool,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []
    if not body_example or not isinstance(body_example, dict):
        return findings
    url = base_url.rstrip("/") + endpoint_path
    base = _auth_headers(auth_header)
    if consumes_json:
        # Try the same payload form-encoded.
        try:
            resp = session.request(
                method,
                url,
                headers={**base, "Content-Type": "application/x-www-form-urlencoded"},
                data={k: str(v) for k, v in body_example.items()},
                timeout=timeout,
                allow_redirects=False,
            )
            if 200 <= resp.status_code < 300:
                findings.append(
                    _mk(
                        "low",
                        "JSON endpoint accepted form-encoded body",
                        "content_type_confusion",
                        endpoint=endpoint_path,
                        method=method,
                        request_url=url,
                        evidence=f"Endpoint expects JSON but accepted form-encoded body (HTTP {resp.status_code}).",
                        status_code=resp.status_code,
                        response_body=resp.text or "",
                        response_headers=dict(resp.headers),
                    )
                )
        except requests.exceptions.RequestException:
            pass
    else:
        try:
            resp = session.request(
                method,
                url,
                headers={**base, "Content-Type": "application/json"},
                json=body_example,
                timeout=timeout,
                allow_redirects=False,
            )
            if 200 <= resp.status_code < 300:
                findings.append(
                    _mk(
                        "low",
                        "Form endpoint accepted JSON body",
                        "content_type_confusion",
                        endpoint=endpoint_path,
                        method=method,
                        request_url=url,
                        evidence=f"Endpoint expects form-encoded body but accepted JSON (HTTP {resp.status_code}).",
                        status_code=resp.status_code,
                        response_body=resp.text or "",
                        response_headers=dict(resp.headers),
                    )
                )
        except requests.exceptions.RequestException:
            pass
    return findings


# ---------------------------------------------------------------------------
# Open redirect (focused: only on URL-like parameters)
# ---------------------------------------------------------------------------

def open_redirect_focused_probe(
    *,
    base_url: str,
    endpoint_path: str,
    method: str,
    parameter_name: str,
    parameter_location: str,
    benign_query: Dict[str, Any],
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    """Only fires when the parameter name resembles a URL/redirect parameter."""
    findings: List[Finding] = []
    if parameter_name.lower() not in URL_PARAM_NAMES:
        return findings
    url = base_url.rstrip("/") + endpoint_path
    headers = _auth_headers(auth_header)
    params = dict(benign_query)
    params[parameter_name] = "https://evil.example.com/"
    try:
        resp = session.request(method, url, headers=headers, params=params, timeout=timeout, allow_redirects=False)
    except requests.exceptions.RequestException:
        return findings
    loc = resp.headers.get("Location", "")
    if loc and "evil.example.com" in loc:
        findings.append(
            _mk(
                "high",
                "Open redirect to attacker-controlled host",
                "open_redirect",
                endpoint=endpoint_path,
                method=method,
                request_url=url_with_query(url, params),
                evidence=f"Location header redirects to: {loc}",
                payload="https://evil.example.com/",
                parameter=parameter_name,
                location=parameter_location,
                status_code=resp.status_code,
                request_headers=headers,
                response_body=resp.text or "",
                response_headers=dict(resp.headers),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Canary reflection map
# ---------------------------------------------------------------------------

def canary_reflection_probe(
    *,
    base_url: str,
    endpoint_path: str,
    method: str,
    parameter_name: str,
    parameter_location: str,
    benign_query: Dict[str, Any],
    benign_body: Optional[Dict[str, Any]],
    consumes_json: bool,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    """Send a unique canary token in the named parameter; flag if it shows up
    in response headers or body, which is a precursor for XSS/CRLF/cache poisoning."""
    findings: List[Finding] = []
    canary = "apifz_canary_" + secrets.token_hex(4)
    url = base_url.rstrip("/") + endpoint_path
    headers = _auth_headers(auth_header)

    params = dict(benign_query) if parameter_location == "query" else dict(benign_query)
    body: Any = copy.deepcopy(benign_body) if isinstance(benign_body, dict) else None

    if parameter_location == "query":
        params[parameter_name] = canary
    elif parameter_location == "header":
        headers[parameter_name] = canary
    elif parameter_location == "body" and isinstance(body, dict) and parameter_name in body:
        body[parameter_name] = canary
    elif parameter_location == "path":
        url = url.replace("{" + parameter_name + "}", canary)
    else:
        return findings

    try:
        kwargs = {
            "headers": headers,
            "params": params,
            "timeout": timeout,
            "allow_redirects": False,
        }
        if isinstance(body, dict):
            kwargs["json" if consumes_json else "data"] = body
        resp = session.request(method, url, **kwargs)
    except requests.exceptions.RequestException:
        return findings

    text = resp.text or ""
    resp_hdrs = dict(resp.headers)
    recorded_url = url_with_query(url, params)
    # FP fix: only flag canary reflection in executable (HTML) contexts.
    # JSON responses that echo a search query are normal API behavior, not XSS.
    resp_content_type = resp_hdrs.get("Content-Type", "").lower()
    is_executable_context = "html" in resp_content_type or resp_content_type == "" or resp_content_type.startswith("text/")
    if canary in text and is_executable_context:
        findings.append(
            _mk(
                "low",
                f"Input reflected in response for parameter '{parameter_name}'",
                "canary_reflection",
                endpoint=endpoint_path,
                method=method,
                request_url=recorded_url,
                evidence="Server echoed unique canary value in response body.",
                payload=canary,
                parameter=parameter_name,
                location=parameter_location,
                status_code=resp.status_code,
                request_headers=headers,
                response_body=text,
                response_headers=resp_hdrs,
            )
        )
    else:
        for hname, hval in resp_hdrs.items():
            if canary in hval:
                findings.append(
                    _mk(
                        "medium",
                        f"Input reflected in response header '{hname}'",
                        "canary_reflection",
                        endpoint=endpoint_path,
                        method=method,
                        request_url=recorded_url,
                        evidence=f"Canary echoed into response header {hname}: {hval}",
                        payload=canary,
                        parameter=parameter_name,
                        location=parameter_location,
                        status_code=resp.status_code,
                        request_headers=headers,
                        response_body=text,
                        response_headers=resp_hdrs,
                    )
                )
                break
    return findings
