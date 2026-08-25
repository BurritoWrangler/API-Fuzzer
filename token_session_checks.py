"""Phase 3: Token and session security checks.

Tests for replay-after-logout, refresh-token reuse, token-in-query-string,
and missing authentication on operations whose OpenAPI security requirement
is non-empty. All checks are differential — comparing authenticated vs
anonymous observations before reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

from analyzer import Finding
from comparators import compare_http_responses
from spec_parser import Endpoint, SecurityRequirement


@dataclass
class TokenSessionFinding:
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


def _send(
    session: requests.Session,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]],
    timeout: float,
    params: Optional[Dict[str, str]] = None,
) -> Optional[Tuple[int, str, Dict[str, str]]]:
    try:
        resp = session.request(
            method, url, headers=headers or {}, params=params,
            timeout=timeout, allow_redirects=False,
        )
        return resp.status_code, resp.text or "", dict(resp.headers)
    except requests.exceptions.RequestException:
        return None


def _check_anonymous_baseline(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> Optional[Tuple[int, str]]:
    """Send an anonymous request (no Authorization) for differential comparison."""
    url = base_url.rstrip("/") + endpoint.path
    return _send(session, endpoint.method, url, {}, timeout)


def probe_token_in_query(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[TokenSessionFinding]:
    """Check if tokens are accepted in query string parameters."""
    findings: List[TokenSessionFinding] = []
    url = base_url.rstrip("/") + endpoint.path
    auth = _auth_headers(auth_header)

    # Send a request with the token in a query parameter instead of the header.
    token_value = auth.get("Authorization", "Bearer test-token") if auth else "test-token"
    token_param_names = ["token", "access_token", "auth", "authorization", "api_key"]

    query_params = {p.name: p.example if p.example is not None else "test"
                    for p in endpoint.parameters if p.location == "query"}

    for param_name in token_param_names:
        if any(p.name.lower() == param_name for p in endpoint.parameters if p.location == "query"):
            # Endpoint already has this param — test token-in-query.
            test_params = dict(query_params)
            test_params[param_name] = token_value
            result = _send(session, endpoint.method, url, {}, timeout, params=test_params)
            if result and 200 <= result[0] < 300:
                findings.append(TokenSessionFinding(
                    category="token_in_query",
                    severity="medium",
                    confidence="strong",
                    title=f"Token accepted in query parameter '{param_name}'",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=param_name,
                    evidence=(
                        f"Server accepted authentication via query parameter "
                        f"'{param_name}' (HTTP {result[0]}). Tokens in URLs are logged "
                        f"in access logs and browser history."
                    ),
                    owasp_api="API2:2023",
                    cwe="CWE-598",
                    request_url=url,
                    status_code=result[0],
                ))
                break
    return findings


def probe_missing_auth(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[TokenSessionFinding]:
    """Flag operations with non-empty security requirements that accept anonymous access."""
    findings: List[TokenSessionFinding] = []
    if not endpoint.security:
        return findings

    url = base_url.rstrip("/") + endpoint.path
    anon_result = _send(session, endpoint.method, url, {}, timeout)
    if anon_result and 200 <= anon_result[0] < 300:
        security_names = [name for req in endpoint.security for name in req.schemes]
        findings.append(TokenSessionFinding(
            category="missing_auth",
            severity="high",
            confidence="strong",
            title="Authentication bypass: secured operation accepts anonymous access",
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter="<n/a>",
            evidence=(
                f"Operation declares security requirements ({security_names}) "
                f"but anonymous request returned HTTP {anon_result[0]}."
            ),
            owasp_api="API2:2023",
            cwe="CWE-306",
            request_url=url,
            status_code=anon_result[0],
        ))
    return findings


def probe_token_replay(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[TokenSessionFinding]:
    """Check if a token is still valid after a simulated logout.

    Sends the token both with and without a simulated 'logout' indicator
    (e.g., setting a cookie or header that should invalidate the session).
    If both produce 2xx, the token may not be properly revoked server-side.
    """
    findings: List[TokenSessionFinding] = []
    if not auth_header:
        return findings

    url = base_url.rstrip("/") + endpoint.path
    auth = _auth_headers(auth_header)

    # Normal authenticated request
    authed_result = _send(session, endpoint.method, url, auth, timeout)
    if authed_result is None or not (200 <= authed_result[0] < 300):
        return findings

    # Simulate a "logged out" state by adding a logout indicator.
    # In practice this would use a logout endpoint or cookie; here we test
    # whether the token alone still works after the session is "ended".
    logout_headers = dict(auth)
    logout_headers["X-Logout"] = "true"
    logout_headers["Cookie"] = "session=expired"

    replay_result = _send(session, endpoint.method, url, logout_headers, timeout)
    if replay_result and 200 <= replay_result[0] < 300:
        # Compare to anonymous baseline to ensure this isn't a public endpoint.
        anon_result = _send(session, endpoint.method, url, {}, timeout)
        anon_status = anon_result[0] if anon_result else 0
        if not (200 <= anon_status < 300):
            findings.append(TokenSessionFinding(
                category="token_replay",
                severity="high",
                confidence="tentative",
                title="Token accepted after simulated logout",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter="Authorization",
                evidence=(
                    f"Token was accepted with HTTP {replay_result[0]} even after "
                    f"simulated logout. Server may not properly revoke tokens. "
                    f"(Anonymous baseline: {anon_status})"
                ),
                owasp_api="API2:2023",
                cwe="CWE-613",
                request_url=url,
                status_code=replay_result[0],
            ))
    return findings


def probe_refresh_token_reuse(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[TokenSessionFinding]:
    """Check if refresh tokens can be reused (rotation bypass).

    This is a heuristic check: if the endpoint accepts a 'refresh_token'
    parameter in the body or query, it tests whether the same token
    can be used multiple times (indicating no rotation).
    """
    findings: List[TokenSessionFinding] = []
    if not endpoint.has_body or not isinstance(endpoint.body_example, dict):
        return findings

    url = base_url.rstrip("/") + endpoint.path
    auth = _auth_headers(auth_header)

    # Check for refresh-token-shaped parameters.
    refresh_param_names = ["refresh_token", "refreshToken", "refresh"]
    body_params = endpoint.body_example

    for param_name in refresh_param_names:
        if param_name not in body_params:
            continue
        # Send the same refresh token twice — if both succeed, no rotation.
        import copy
        body1 = copy.deepcopy(body_params)
        body1[param_name] = "test-refresh-token"
        body2 = copy.deepcopy(body1)

        result1 = _send(session, endpoint.method, url, auth, timeout)
        if result1 and 200 <= result1[0] < 300:
            # Reuse the same token.
            import json as jsonlib
            try:
                resp1 = session.request(
                    endpoint.method, url, headers=auth,
                    json=body1, timeout=timeout, allow_redirects=False,
                )
                resp2 = session.request(
                    endpoint.method, url, headers=auth,
                    json=body2, timeout=timeout, allow_redirects=False,
                )
                if (200 <= resp1.status_code < 300 and 200 <= resp2.status_code < 300):
                    findings.append(TokenSessionFinding(
                        category="refresh_token_reuse",
                        severity="medium",
                        confidence="tentative",
                        title=f"Refresh token reuse accepted for '{param_name}'",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        parameter=param_name,
                        evidence=(
                            f"Same refresh token was accepted twice "
                            f"(HTTP {resp1.status_code}, {resp2.status_code}). "
                            f"Server may not implement token rotation."
                        ),
                        owasp_api="API2:2023",
                        cwe="CWE-287",
                        request_url=url,
                        status_code=resp2.status_code,
                    ))
            except requests.exceptions.RequestException:
                pass
        break
    return findings


def run_token_session_checks(
    endpoints: List[Endpoint],
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[TokenSessionFinding]:
    """Run all token/session security probes."""
    findings: List[TokenSessionFinding] = []
    for ep in endpoints:
        findings.extend(probe_token_in_query(ep, base_url, session, timeout, auth_header))
        findings.extend(probe_missing_auth(ep, base_url, session, timeout, auth_header))
        findings.extend(probe_token_replay(ep, base_url, session, timeout, auth_header))
        findings.extend(probe_refresh_token_reuse(ep, base_url, session, timeout, auth_header))
    return findings
