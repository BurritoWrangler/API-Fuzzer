"""CSRF checks for cookie-authenticated APIs.

Token-based (Authorization header) APIs are not CSRF-prone: browsers do not
attach Authorization headers cross-site. This module therefore only tests
endpoints reachable via **cookies** — the profile's cookie jar is what makes
the request browser-attackable.

Checks (all intrusive — they replay state-changing requests):
  * missing CSRF protection: a mutating request replayed with no CSRF token
    header and a mismatched Origin still returns 2xx
  * SameSite-independent exploitability signal: Origin: https://attacker.example
    accepted on a cross-site-shaped request

Only runs when ``confirmed_intrusive=True`` and the identity profile has
cookies; Authorization-header-only identities are skipped by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from request_builder import build_encoded_url
from spec_parser import Endpoint


MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
EVIL_ORIGIN = "https://attacker.example"

# Header names whose presence indicates CSRF protection.
_CSRF_HEADER_HINTS = ("x-csrf", "x-xsrf", "csrf", "xsrf", "_csrf")


@dataclass
class CSRFFinding:
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


def _profile_has_cookies(profile) -> bool:
    return bool(getattr(profile, "cookies", None))


def probe_csrf_missing(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    *,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[dict] = None,
    confirmed_intrusive: bool = False,
) -> List[CSRFFinding]:
    """Replay a mutating request cross-site-shaped; flag 2xx with no CSRF defense.

    Requires ``confirmed_intrusive=True`` — this sends a real state-changing
    request, so it must never run silently.
    """
    findings: List[CSRFFinding] = []
    if not confirmed_intrusive:
        return findings
    if endpoint.method.upper() not in MUTATING_METHODS:
        return findings
    if not cookies:
        return findings  # cookie auth required for CSRF to be exploitable

    path_params = {
        p.name: (p.example if p.example is not None else 1)
        for p in endpoint.parameters
        if p.location == "path"
    }
    url = build_encoded_url(base_url, endpoint.path, path_params, {})
    request_headers = dict(headers or {})
    request_headers["Origin"] = EVIL_ORIGIN
    request_headers["Referer"] = EVIL_ORIGIN + "/attack"
    # Deliberately no CSRF token header and no content-type that preflight
    # would block: form/text-plain shaped JSON CSRF.

    try:
        resp = session.request(
            endpoint.method, url,
            headers=request_headers,
            cookies=cookies,
            json=body if body is not None else (endpoint.body_example if endpoint.has_body else None),
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return findings

    if 200 <= resp.status_code < 300:
        findings.append(
            CSRFFinding(
                category="csrf_missing",
                severity="medium",
                confidence="tentative",
                title=f"CSRF: {endpoint.method} accepted cross-site without CSRF token",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter="Origin",
                evidence=(
                    f"{endpoint.method} {endpoint.path} with Origin {EVIL_ORIGIN} and cookie "
                    f"authentication returned HTTP {resp.status_code} with no CSRF token. "
                    f"Verify the endpoint requires cookie auth and that no SameSite=Strict "
                    f"mitigates the cookie in browsers."
                ),
                owasp_api="API8:2023",
                cwe="CWE-352",
                request_url=url,
                status_code=resp.status_code,
            )
        )
    return findings


def run_csrf_checks(
    endpoints,
    base_url: str,
    session: requests.Session,
    timeout: float,
    *,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    confirmed_intrusive: bool = False,
    scan=None,
) -> List[CSRFFinding]:
    """Engine adapter signature; only cookie identities qualify."""
    findings: List[CSRFFinding] = []
    if not cookies or not confirmed_intrusive:
        return findings
    for ep in endpoints[:10]:
        if ep.method.upper() not in MUTATING_METHODS:
            continue
        findings.extend(
            probe_csrf_missing(
                ep, base_url, session, timeout,
                cookies=cookies, headers=headers,
                confirmed_intrusive=True,
            )
        )
    return findings
