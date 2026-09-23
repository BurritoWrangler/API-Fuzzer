"""Web cache deception detection.

For an authenticated GET endpoint returning private data, probe sibling paths
with static extensions (/users/1/foo.css, /users/1/a.js, /users/1%0a.css).
If the server returns the *same authenticated body* for the extension path
AND permits shared caching, a victim's browser could be tricked into storing
their data at a guessable URL — classic cache deception.

Detection is differential: the extension-path body must materially match the
baseline body (via comparators) and Cache-Control must lack private/no-store.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from comparators import compare_http_responses


# Extension suffixes to probe (bounded).
_DECEPTION_SUFFIXES = [".css", ".js", "/a.css", "/favicon.ico"]

# Cache directives that make a shared-cache deception payload harmless.
_SAFE_DIRECTIVES = ("no-store", "private", "no-cache")


@dataclass
class CacheDeceptionFinding:
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


def _cacheable(headers: Dict[str, str]) -> bool:
    cc = ""
    for k, v in headers.items():
        if k.lower() == "cache-control":
            cc = str(v).lower()
            break
    if not cc:
        # No Cache-Control: heuristic caches may still store 2xx GETs.
        return True
    return not any(d in cc for d in _SAFE_DIRECTIVES)


def _send(session, method, url, headers, timeout):
    try:
        return session.request(
            method, url, headers=headers, timeout=timeout, allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return None


def probe_cache_deception(
    endpoint_path: str,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[CacheDeceptionFinding]:
    """Probe extension-sibling paths for cache-deception behavior."""
    findings: List[CacheDeceptionFinding] = []
    if not auth_header:
        return findings  # deception needs an authenticated victim response
    auth = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint_path

    baseline = _send(session, "GET", url, auth, timeout)
    if baseline is None or not (200 <= baseline.status_code < 300):
        return findings

    for suffix in _DECEPTION_SUFFIXES:
        deception_url = url + suffix
        resp = _send(session, "GET", deception_url, auth, timeout)
        if resp is None or not (200 <= resp.status_code < 300):
            continue
        if not _cacheable(dict(resp.headers)):
            continue

        comparison = compare_http_responses(
            baseline_status=baseline.status_code,
            baseline_headers=dict(baseline.headers),
            baseline_body=baseline.text or "",
            candidate_status=resp.status_code,
            candidate_headers=dict(resp.headers),
            candidate_body=resp.text or "",
        )
        # The extension path must return materially the same private body.
        if comparison.equivalent or comparison.similarity >= 0.9:
            findings.append(
                CacheDeceptionFinding(
                    category="cache_deception",
                    severity="high",
                    confidence="strong",
                    title=f"Cache deception: authenticated body served at {suffix} path",
                    endpoint=endpoint_path,
                    method="GET",
                    parameter=suffix,
                    evidence=(
                        f"{deception_url} returned the authenticated response body "
                        f"with cache-permitting headers ({comparison.summary}). "
                        f"A victim's browser can be tricked into caching private data."
                    ),
                    owasp_api="API6:2023",
                    cwe="CWE-524",
                    request_url=deception_url,
                    status_code=resp.status_code,
                )
            )
            break
    return findings


def run_cache_deception(
    endpoints,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
    scan=None,
) -> List[CacheDeceptionFinding]:
    """Engine adapter signature: probe authenticated GET endpoints (bounded)."""
    findings: List[CacheDeceptionFinding] = []
    for ep in endpoints[:10]:
        if ep.method.upper() != "GET":
            continue
        findings.extend(
            probe_cache_deception(ep.path, base_url, session, timeout, auth_header)
        )
    return findings
