"""Rate-limit bypass testing.

After the base rate probe detects limiting (429 or rate-limit headers), this
module tests whether the limiter can be evaded via:
  * client-IP spoofing headers (X-Forwarded-For, X-Real-IP, ...)
  * path-normalization variants (trailing slash, /./, //, case, %2e)
  * verb variation (GET <-> HEAD)

Only endpoints that actually exhibited a limit are probed, so findings mean
"the limiter was evaded", not "no limiter present".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from misconfig import RATE_LIMIT_HEADERS


# Bounded: at most this many bypass variants are tried per endpoint.
MAX_BYPASS_VARIANTS = 12

_IP_SPOOF_HEADERS: List[Tuple[str, str]] = [
    ("X-Forwarded-For", "203.0.113.9"),
    ("X-Real-IP", "203.0.113.9"),
    ("X-Originating-IP", "203.0.113.9"),
    ("X-Remote-Addr", "203.0.113.9"),
    ("X-Client-IP", "203.0.113.9"),
    ("True-Client-IP", "203.0.113.9"),
]

# Path normalization variants that gateways may treat as a different cache/
# limiter key while routing to the same handler.
_PATH_VARIANTS = [
    lambda p: p + "/",
    lambda p: p + "/.",
    lambda p: p.replace("//", "/") + "/",
    lambda p: p + "%20",
    lambda p: "/." + p,
    lambda p: p.lower() if p != p.lower() else p + "/",
]


@dataclass
class RateLimitBypassFinding:
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
    bypass_vector: str = ""


def _auth_headers(auth_header: Optional[str]) -> Dict[str, str]:
    if not auth_header:
        return {}
    val = auth_header.strip()
    if val.lower().startswith("authorization:"):
        val = val.split(":", 1)[1].strip()
    return {"Authorization": val} if val else {}


def _limit_observed(resp: requests.Response) -> bool:
    lower = {k.lower() for k in resp.headers.keys()}
    return resp.status_code == 429 or any(h in lower for h in RATE_LIMIT_HEADERS)


def _send(session, method, url, headers, timeout) -> Optional[requests.Response]:
    try:
        return session.request(
            method, url, headers=headers, timeout=timeout, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None


def _variants(base_url: str, path: str, auth: Dict[str, str]):
    """Yield (label, method, url, headers) bypass variants."""
    base = base_url.rstrip("/")
    for name, value in _IP_SPOOF_HEADERS[:4]:
        yield (
            f"ip-spoof:{name}",
            "GET",
            base + path,
            {**auth, name: value},
        )
    for i, variant in enumerate(_PATH_VARIANTS[:4]):
        yield (f"path-variant:{i}", "GET", base + variant(path), auth)
    yield ("verb:HEAD", "HEAD", base + path, auth)


def probe_rate_limit_bypass(
    endpoint_path: str,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
    trigger_burst: int = 10,
) -> List[RateLimitBypassFinding]:
    """Trigger the limiter, then try bounded bypass variants.

    Returns findings only when the limiter was observed to engage AND a
    variant subsequently succeeded — a confirmed evasion, not an absence.
    """
    findings: List[RateLimitBypassFinding] = []
    auth = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint_path

    # 1. Trigger the limiter with a small burst.
    limit_hit = False
    for _ in range(max(1, min(trigger_burst, 30))):
        resp = _send(session, "GET", url, auth, timeout)
        if resp is None:
            return findings  # network issue: no claims either way
        if _limit_observed(resp):
            limit_hit = True
            break
    if not limit_hit:
        return findings  # nothing to bypass

    # 2. Try bypass variants (bounded).
    tried = 0
    for label, method, variant_url, headers in _variants(base_url, endpoint_path, auth):
        if tried >= MAX_BYPASS_VARIANTS:
            break
        tried += 1
        resp = _send(session, method, variant_url, headers, timeout)
        if resp is None:
            continue
        if not _limit_observed(resp):
            findings.append(
                RateLimitBypassFinding(
                    category="rate_limit_bypass",
                    severity="medium",
                    confidence="strong",
                    title=f"Rate limit bypassed via {label}",
                    endpoint=endpoint_path,
                    method=method,
                    parameter=label.split(":", 1)[1] if ":" in label else label,
                    evidence=(
                        f"Limiter engaged on {endpoint_path}, but a follow-up request "
                        f"using {label} returned HTTP {resp.status_code} — the limit "
                        f"did not apply to this variant."
                    ),
                    owasp_api="API4:2023",
                    cwe="CWE-799",
                    request_url=variant_url,
                    status_code=resp.status_code,
                    bypass_vector=label,
                )
            )
            break  # one evasion is enough evidence
    return findings


def run_rate_limit_bypass(
    endpoints,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
    scan=None,
) -> List[RateLimitBypassFinding]:
    """Engine adapter signature: probe each endpoint (bounded)."""
    findings: List[RateLimitBypassFinding] = []
    for ep in endpoints[:5]:  # bounded: bypass probing is burst-heavy
        findings.extend(
            probe_rate_limit_bypass(
                ep.path, base_url, session, timeout, auth_header,
            )
        )
    return findings
