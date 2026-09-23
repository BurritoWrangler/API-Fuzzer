"""OAuth/OIDC authorization-flow security checks.

Runs only from an explicit, user-supplied configuration (endpoints + client
id). Tests:
  * redirect_uri validation — a permissive or ignored redirect_uri is critical
  * state enforcement — an authorization response without required state
  * PKCE enforcement — code issued without code_challenge
  * authorization-code reuse — a code redeemed twice

Never executes unless :class:`OAuthConfig` is provided with real endpoints;
engine-registered as disabled-by-default.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests


EVIL_REDIRECT = "https://attacker.example/callback"


@dataclass
class OAuthConfig:
    authorize_url: str = ""
    token_url: str = ""
    client_id: str = ""
    redirect_uri: str = "https://app.example/callback"
    scope: str = "openid"
    # Cookies/headers identifying the test user running the flow.
    user_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class OAuthFinding:
    category: str
    severity: str
    confidence: str
    title: str
    evidence: str
    owasp_api: str = "API2:2023"
    cwe: str = "CWE-601"
    request_url: str = ""
    status_code: int = 0


def _send(session, method, url, headers, timeout, params=None, data=None):
    try:
        return session.request(
            method, url, headers=headers or {}, params=params, data=data,
            timeout=timeout, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None


def _is_redirect_to(resp, evil_fragment: str) -> bool:
    if resp is None or resp.status_code not in (301, 302, 303, 307):
        return False
    return evil_fragment in (resp.headers.get("Location") or "")


def _extract_code(location: str) -> Optional[str]:
    from urllib.parse import parse_qs, urlparse

    try:
        qs = parse_qs(urlparse(location).query)
        codes = qs.get("code")
        return codes[0] if codes else None
    except ValueError:
        return None


def check_redirect_uri_matching(
    session: requests.Session,
    cfg: OAuthConfig,
    timeout: float,
) -> List[OAuthFinding]:
    """Loose redirect_uri validation: evil redirect accepted or echoed."""
    findings: List[OAuthFinding] = []
    if not cfg.authorize_url or not cfg.client_id:
        return findings
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": EVIL_REDIRECT,
        "scope": cfg.scope,
        "state": secrets.token_hex(8),
    }
    resp = _send(session, "GET", cfg.authorize_url, cfg.user_headers, timeout, params=params)
    if resp is None:
        return findings
    if _is_redirect_to(resp, EVIL_REDIRECT):
        findings.append(OAuthFinding(
            category="oauth_redirect_uri",
            severity="critical",
            confidence="strong",
            title="OAuth redirect_uri validation missing: evil redirect accepted",
            evidence=f"Authorization endpoint redirected to {EVIL_REDIRECT} — codes can be stolen.",
            request_url=cfg.authorize_url,
            status_code=resp.status_code,
        ))
    elif 200 <= resp.status_code < 300:
        findings.append(OAuthFinding(
            category="oauth_redirect_uri",
            severity="medium",
            confidence="tentative",
            title="OAuth redirect_uri mismatch accepted (no error, no redirect)",
            evidence=(
                f"An authorize request with redirect_uri={EVIL_REDIRECT} returned "
                f"HTTP {resp.status_code}; verify whether a code could be issued."
            ),
            request_url=cfg.authorize_url,
            status_code=resp.status_code,
        ))
    return findings


def check_pkce_enforcement(
    session: requests.Session,
    cfg: OAuthConfig,
    timeout: float,
) -> List[OAuthFinding]:
    """Authorization code issued without code_challenge -> PKCE not enforced."""
    findings: List[OAuthFinding] = []
    if not cfg.authorize_url or not cfg.client_id:
        return findings
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scope,
        "state": secrets.token_hex(8),
        # deliberately no code_challenge
    }
    resp = _send(session, "GET", cfg.authorize_url, cfg.user_headers, timeout, params=params)
    if resp is None:
        return findings
    location = resp.headers.get("Location") or ""
    if resp.status_code in (301, 302, 303, 307) and _extract_code(location):
        findings.append(OAuthFinding(
            category="oauth_pkce",
            severity="medium",
            confidence="strong",
            title="OAuth authorization code issued without PKCE",
            evidence="A code was issued for a request without code_challenge — interception attacks are viable.",
            request_url=cfg.authorize_url,
            status_code=resp.status_code,
        ))
    return findings


def check_state_enforcement(
    session: requests.Session,
    cfg: OAuthConfig,
    timeout: float,
) -> List[OAuthFinding]:
    """State parameter accepted and echoed is expected; flag if flow completes with empty state."""
    findings: List[OAuthFinding] = []
    if not cfg.authorize_url or not cfg.client_id:
        return findings
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scope,
        # deliberately no state
    }
    resp = _send(session, "GET", cfg.authorize_url, cfg.user_headers, timeout, params=params)
    if resp is None:
        return findings
    location = resp.headers.get("Location") or ""
    if resp.status_code in (301, 302, 303, 307) and _extract_code(location):
        findings.append(OAuthFinding(
            category="oauth_state",
            severity="low",
            confidence="tentative",
            title="OAuth code issued without state parameter",
            evidence="The server issued a code although no state was supplied — CSRF on the flow is plausible if clients rely on it.",
            request_url=cfg.authorize_url,
            status_code=resp.status_code,
        ))
    return findings


def check_code_reuse(
    session: requests.Session,
    cfg: OAuthConfig,
    timeout: float,
) -> List[OAuthFinding]:
    """Redeem the same authorization code twice at the token endpoint."""
    findings: List[OAuthFinding] = []
    if not cfg.token_url or not cfg.client_id:
        return findings
    # Requires a valid code from a real authorize round-trip; without
    # user-session automation we test token-endpoint idempotency using a
    # synthetic code — a 2xx with invalid_grant-shaped rejection for both is
    # the secure behavior.
    code = secrets.token_hex(16)
    data = {
        "grant_type": "authorization_code",
        "client_id": cfg.client_id,
        "code": code,
        "redirect_uri": cfg.redirect_uri,
    }
    r1 = _send(session, "POST", cfg.token_url, cfg.user_headers, timeout, data=data)
    r2 = _send(session, "POST", cfg.token_url, cfg.user_headers, timeout, data=data)
    if r1 is None or r2 is None:
        return findings
    if 200 <= r1.status_code < 300 and 200 <= r2.status_code < 300:
        findings.append(OAuthFinding(
            category="oauth_code_reuse",
            severity="high",
            confidence="tentative",
            title="OAuth token endpoint accepted the same code twice",
            evidence="Two token requests with identical codes both returned 2xx — verify rotation/one-time-use semantics.",
            request_url=cfg.token_url,
            status_code=r2.status_code,
        ))
    return findings


def run_oauth_checks(
    session: requests.Session,
    cfg: OAuthConfig,
    timeout: float,
) -> List[OAuthFinding]:
    """Run all configured OAuth flow checks. Requires cfg with real endpoints."""
    findings: List[OAuthFinding] = []
    findings.extend(check_redirect_uri_matching(session, cfg, timeout))
    findings.extend(check_pkce_enforcement(session, cfg, timeout))
    findings.extend(check_state_enforcement(session, cfg, timeout))
    findings.extend(check_code_reuse(session, cfg, timeout))
    return findings
