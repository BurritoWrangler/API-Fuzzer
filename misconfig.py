"""Misconfiguration detection.

Observational checks that do not require fuzzing payloads:
  * Transport security (HTTP, HSTS missing)
  * Security response headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
  * CORS: wildcard ACAO, reflected Origin
  * Cookie flags: Secure / HttpOnly / SameSite
  * Server / framework disclosure headers
  * Common exposed paths (.git, .env, /actuator, /metrics, …)
  * Dangerous HTTP methods (TRACE)

All functions return `analyzer.Finding` lists so the dashboard handles them
exactly like fuzzing findings.
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import requests

from analyzer import Finding


RATE_LIMIT_HEADERS = (
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
)


CATEGORY = "misconfiguration"


# Recommended security headers and severity if missing.
REQUIRED_HEADERS: List[Tuple[str, str, str]] = [
    ("Strict-Transport-Security", "medium", "Missing HSTS — browsers may downgrade to HTTP."),
    ("Content-Security-Policy", "medium", "Missing CSP — content-injection mitigations not advertised."),
    ("X-Content-Type-Options", "low", "Missing X-Content-Type-Options — MIME-sniffing protection absent."),
    ("X-Frame-Options", "low", "Missing X-Frame-Options — clickjacking protection absent (CSP frame-ancestors also works)."),
    ("Referrer-Policy", "low", "Missing Referrer-Policy — referrer leakage possible."),
]

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
]

# Common exposed paths to probe once per scan.
COMMON_PATHS: List[Tuple[str, str]] = [
    ("/.git/config", "Git config exposed"),
    ("/.env", "Environment file exposed"),
    ("/swagger.json", "Swagger spec exposed"),
    ("/openapi.json", "OpenAPI spec exposed"),
    ("/api-docs", "API documentation exposed"),
    ("/actuator", "Spring Actuator root exposed"),
    ("/actuator/env", "Spring Actuator env exposed"),
    ("/actuator/heapdump", "Spring Actuator heapdump exposed"),
    ("/metrics", "Metrics endpoint exposed"),
    ("/server-status", "Apache server-status exposed"),
    ("/server-info", "Apache server-info exposed"),
    ("/debug/pprof/", "Go pprof exposed"),
    ("/admin", "Admin path reachable"),
    ("/console", "Web console reachable"),
    ("/phpinfo.php", "phpinfo() exposed"),
]


def _mk(
    severity: str,
    title: str,
    *,
    endpoint: str,
    method: str,
    request_url: str,
    evidence: str,
    status_code: int = 0,
    response_body: Optional[str] = None,
    response_headers: Optional[Dict[str, str]] = None,
    request_headers: Optional[Dict[str, str]] = None,
    parameter: str = "<n/a>",
    location: str = "response",
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
        payload="",
        technique="observational",
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


def extract_set_cookies(resp: requests.Response) -> List[str]:
    """Return the list of raw Set-Cookie header values from a Response.

    requests joins multiple Set-Cookie headers with commas in `.headers`, which
    is lossy because cookie values can themselves contain commas. The urllib3
    raw headers preserve them as a list.
    """
    raw = getattr(resp, "raw", None)
    if raw is not None:
        raw_headers = getattr(raw, "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "getlist"):
            try:
                values = raw_headers.getlist("Set-Cookie")
                if values:
                    return list(values)
            except Exception:
                pass
    # Fallback: requests merged header (lossy but better than nothing).
    merged = resp.headers.get("Set-Cookie")
    return [merged] if merged else []


def _auth_headers(auth_header: Optional[str]) -> Dict[str, str]:
    if not auth_header:
        return {}
    val = auth_header.strip()
    if val.lower().startswith("authorization:"):
        val = val.split(":", 1)[1].strip()
    return {"Authorization": val}


# ---------------------------------------------------------------------------
# Transport + server-level checks
# ---------------------------------------------------------------------------

def preflight(
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> Tuple[List[Finding], List[str]]:
    """Hit the base URL once. Returns (findings, warnings).

    `warnings` is a list of human-readable operational diagnostics (e.g. DNS
    failure) that the UI shows separately from findings.
    """
    findings: List[Finding] = []
    warnings: List[str] = []
    parsed = urlparse(base_url)

    if parsed.scheme.lower() == "http":
        findings.append(
            _mk(
                "high",
                "Target uses plaintext HTTP",
                endpoint="/",
                method="GET",
                request_url=base_url,
                evidence="Base URL scheme is http://; credentials and payloads transit in cleartext.",
            )
        )

    headers = _auth_headers(auth_header)
    try:
        t0 = time.perf_counter()
        resp = session.get(base_url, headers=headers, timeout=timeout, allow_redirects=False)
        elapsed = int((time.perf_counter() - t0) * 1000)
        findings.extend(
            inspect_response(
                response_headers=dict(resp.headers),
                set_cookies=extract_set_cookies(resp),
                status_code=resp.status_code,
                request_url=base_url,
                endpoint="/",
                method="GET",
                response_text=resp.text[:500] if resp.text else "",
                is_https=(parsed.scheme.lower() == "https"),
                response_time_ms=elapsed,
            )
        )
    except requests.exceptions.SSLError as exc:
        findings.append(
            _mk(
                "high",
                "TLS error contacting target",
                endpoint="/",
                method="GET",
                request_url=base_url,
                evidence=f"SSL error: {exc}",
            )
        )
        warnings.append(f"TLS error reaching {base_url}: {exc}")
    except requests.exceptions.ConnectionError as exc:
        warnings.append(f"Connection error reaching {base_url}: {exc}")
    except requests.exceptions.Timeout:
        warnings.append(f"Timed out contacting {base_url} during preflight.")
    except requests.exceptions.RequestException as exc:
        warnings.append(f"Preflight request failed: {exc}")

    return findings, warnings


def probe_common_paths(
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []
    headers = _auth_headers(auth_header)
    for path, label in COMMON_PATHS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue

        if 200 <= resp.status_code < 300 and (resp.text or "").strip():
            severity = "high"
            text = resp.text or ""
            # Tighten signal: only mark .git/.env as critical when content looks like the real file.
            if path == "/.git/config" and "[core]" in text:
                severity = "critical"
            if path == "/.env" and re.search(r"\b[A-Z_][A-Z0-9_]*\s*=", text):
                severity = "critical"
            if path.startswith("/actuator") and ("\"_links\"" in text or "\"diskSpace\"" in text):
                severity = "critical"
            if path == "/server-status" and "Apache Server Status" in text:
                severity = "high"
            if path == "/phpinfo.php" and "PHP Version" in text:
                severity = "critical"
            findings.append(
                _mk(
                    severity,
                    f"Exposed path: {path}",
                    endpoint=path,
                    method="GET",
                    request_url=url,
                    evidence=f"{label} (HTTP {resp.status_code}).",
                    status_code=resp.status_code,
                    response_body=text,
                    response_headers=dict(resp.headers),
                )
            )
        # 401/403 on these paths is fine; only 2xx counts as exposure.
    return findings


def enumerate_methods(
    base_url: str,
    endpoint_path: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
) -> List[Finding]:
    """Try TRACE and OPTIONS on the endpoint. Looks for TRACE enabled and CORS reflection."""
    findings: List[Finding] = []
    headers = _auth_headers(auth_header)
    url = base_url.rstrip("/") + endpoint_path

    # TRACE
    try:
        resp = session.request("TRACE", url, headers=headers, timeout=timeout, allow_redirects=False)
        if resp.status_code == 200 and resp.text and "TRACE" in resp.text.upper():
            findings.append(
                _mk(
                    "high",
                    "HTTP TRACE method enabled",
                    endpoint=endpoint_path,
                    method="TRACE",
                    request_url=url,
                    evidence="TRACE returned 200 with the request echoed back; enables XST in legacy stacks.",
                    status_code=resp.status_code,
                    response_body=resp.text or "",
                    response_headers=dict(resp.headers),
                )
            )
    except requests.exceptions.RequestException:
        pass

    # OPTIONS with an Origin header to detect reflected CORS.
    options_headers = {**headers, "Origin": "https://evil.example.com",
                       "Access-Control-Request-Method": "GET"}
    try:
        resp = session.request("OPTIONS", url, headers=options_headers, timeout=timeout, allow_redirects=False)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(
                _mk(
                    "critical",
                    "CORS misconfiguration: wildcard ACAO with credentials",
                    endpoint=endpoint_path,
                    method="OPTIONS",
                    request_url=url,
                    evidence="Access-Control-Allow-Origin: * combined with Allow-Credentials: true is a browser-level vulnerability.",
                    status_code=resp.status_code,
                )
            )
        elif acao == "https://evil.example.com":
            findings.append(
                _mk(
                    "high",
                    "CORS misconfiguration: Origin reflected",
                    endpoint=endpoint_path,
                    method="OPTIONS",
                    request_url=url,
                    evidence=f"Server echoed our Origin in Access-Control-Allow-Origin (Allow-Credentials: {acac!r}).",
                    status_code=resp.status_code,
                )
            )
        elif acao == "null":
            findings.append(
                _mk(
                    "medium",
                    "CORS: Allow-Origin set to 'null'",
                    endpoint=endpoint_path,
                    method="OPTIONS",
                    request_url=url,
                    evidence="ACAO of 'null' is exploitable from sandboxed iframes.",
                    status_code=resp.status_code,
                )
            )
    except requests.exceptions.RequestException:
        pass

    return findings


# ---------------------------------------------------------------------------
# Per-response inspection
# ---------------------------------------------------------------------------

def inspect_response(
    *,
    response_headers: Dict[str, str],
    set_cookies: List[Optional[str]],
    status_code: int,
    request_url: str,
    endpoint: str,
    method: str,
    response_text: str,
    is_https: bool,
    response_time_ms: int,
    # FP fix: auth context for CORS wildcard suppression on public endpoints.
    used_auth: bool = False,
) -> List[Finding]:
    """Return Findings for missing/weak headers, cookies, server disclosure."""
    findings: List[Finding] = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    # FP fix: determine response content type to suppress browser-only
    # security header findings on JSON/API responses.
    content_type = lower_headers.get("content-type", "").split(";", 1)[0].strip().lower()
    is_html_response = content_type in ("text/html", "application/xhtml+xml", "")

    # Security headers
    for header_name, severity, message in REQUIRED_HEADERS:
        if header_name.lower() not in lower_headers:
            # HSTS only matters if the response is over HTTPS.
            if header_name == "Strict-Transport-Security" and not is_https:
                continue
            # FP fix: CSP and X-Frame-Options are browser-level protections
            # for HTML responses. API endpoints returning JSON don't need them.
            if header_name in ("Content-Security-Policy", "X-Frame-Options") and not is_html_response:
                continue
            findings.append(
                _mk(
                    severity,
                    f"Missing security header: {header_name}",
                    endpoint=endpoint,
                    method=method,
                    request_url=request_url,
                    evidence=message,
                    status_code=status_code,
                    request_headers=response_headers,
                )
            )

    # CORS
    acao = lower_headers.get("access-control-allow-origin", "")
    acac = lower_headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(
            _mk(
                "critical",
                "CORS misconfiguration: wildcard ACAO with credentials",
                endpoint=endpoint,
                method=method,
                request_url=request_url,
                evidence="Allow-Origin: * with Allow-Credentials: true is forbidden by the spec and exploitable in browsers.",
                status_code=status_code,
                request_headers=response_headers,
            )
        )
    elif acao == "*":
        # FP fix: don't flag ACAO:* on public/unauthenticated endpoints.
        # If no auth was used and the endpoint is public, * is intentional.
        if used_auth:
            findings.append(
                _mk(
                    "low",
                    "CORS: wildcard Access-Control-Allow-Origin",
                    endpoint=endpoint,
                    method=method,
                    request_url=request_url,
                    evidence="ACAO of '*' may be intentional for public APIs; review whether it should be tighter.",
                    status_code=status_code,
                    request_headers=response_headers,
                )
            )

    # Cookie flags
    for raw_cookie in set_cookies:
        if not raw_cookie:
            continue
        name = raw_cookie.split("=", 1)[0].strip()
        cookie_lc = raw_cookie.lower()
        missing = []
        if "secure" not in cookie_lc and is_https:
            missing.append("Secure")
        if "httponly" not in cookie_lc:
            missing.append("HttpOnly")
        if "samesite=" not in cookie_lc:
            missing.append("SameSite")
        if missing:
            findings.append(
                _mk(
                    "medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                    f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    endpoint=endpoint,
                    method=method,
                    request_url=request_url,
                    evidence=f"Set-Cookie header: {raw_cookie}",
                    status_code=status_code,
                    request_headers=response_headers,
                )
            )

    # Server / framework disclosure
    for h in DISCLOSURE_HEADERS:
        val = response_headers.get(h)
        if val:
            # Heuristic: only flag if it contains a version number or a known framework name.
            if re.search(r"\d|express|kestrel|werkzeug|gunicorn|nginx|apache|iis|jetty|tomcat", val, re.IGNORECASE):
                findings.append(
                    _mk(
                        "low",
                        f"Server/framework disclosure via {h} header",
                        endpoint=endpoint,
                        method=method,
                        request_url=request_url,
                        evidence=f"{h}: {val}",
                        status_code=status_code,
                        request_headers=response_headers,
                    )
                )

    return findings


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Deduplicate misconfig findings by (title, endpoint)."""
    seen: set = set()
    out: List[Finding] = []
    for f in findings:
        if f.category != CATEGORY:
            out.append(f)
            continue
        key = (f.title, f.endpoint)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Rate-limit detection
# ---------------------------------------------------------------------------

def probe_rate_limit(
    base_url: str,
    probe_path: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
    burst: int = 50,
) -> List[Finding]:
    """Fire `burst` quick GETs and look for rate-limit signals.

    If none of the responses ever expose `Retry-After` or any `RateLimit-*`
    header and no 429 is returned, emit a *low* informational finding.

    FP fix: raised burst from 20 to 50 and lowered severity from medium to low
    — most rate limiters have thresholds far above 20.
    """
    findings: List[Finding] = []
    headers = _auth_headers(auth_header)
    url = urljoin(base_url.rstrip("/") + "/", probe_path.lstrip("/"))
    seen_signal = False
    last_status = 0
    for _ in range(burst):
        try:
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            return findings  # network issue, don't claim absence of rate limits
        last_status = resp.status_code
        lower = {k.lower() for k in resp.headers.keys()}
        if resp.status_code == 429 or any(h in lower for h in RATE_LIMIT_HEADERS):
            seen_signal = True
            break
    if not seen_signal:
        findings.append(
            _mk(
                "low",
                "No rate-limiting signal observed",
                endpoint=probe_path,
                method="GET",
                request_url=url,
                evidence=f"{burst} consecutive requests returned without 429 or any Retry-After/RateLimit-* header (last status {last_status}).",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Cache-control on auth'd responses
# ---------------------------------------------------------------------------

def check_auth_cache_control(
    response_headers: Dict[str, str],
    *,
    status_code: int,
    request_url: str,
    endpoint: str,
    method: str,
    used_auth: bool,
) -> List[Finding]:
    """When the request carried Authorization, the response must not be
    cacheable in shared caches. Look for missing/permissive Cache-Control."""
    if not used_auth or not (200 <= status_code < 300):
        return []
    cc = (response_headers.get("Cache-Control") or response_headers.get("cache-control") or "").lower()
    if not cc:
        return [
            _mk(
                "medium",
                "Authenticated response is missing Cache-Control",
                endpoint=endpoint, method=method, request_url=request_url,
                evidence="Authenticated 2xx response carries no Cache-Control; intermediaries may cache sensitive data.",
                status_code=status_code, request_headers=response_headers,
            )
        ]
    if "no-store" not in cc and ("public" in cc or "max-age" in cc):
        # FP fix: accept 'private' as well as 'no-store' — both prevent
        # shared-cache storage of authenticated responses.
        if "private" not in cc:
            return [
                _mk(
                    "medium",
                    "Authenticated response cacheable in shared caches",
                    endpoint=endpoint, method=method, request_url=request_url,
                    evidence=f"Authenticated 2xx response uses Cache-Control: {cc!r} (lacks 'no-store' or 'private').",
                    status_code=status_code, request_headers=response_headers,
                )
            ]
    return []


# ---------------------------------------------------------------------------
# API version inventory
# ---------------------------------------------------------------------------

VERSION_RE = re.compile(r"/v(\d+)(?=/|$)")


def probe_api_versions(
    base_url: str,
    endpoint_paths: List[str],
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str],
    max_probes: int = 12,
) -> List[Finding]:
    """Look for sibling API versions of the declared endpoints.

    For any path that contains `/vN/`, probe `/v{N-1}/...` and `/v{N+1}/...`
    (capped). A 2xx is suspicious — it means an older or unannounced version
    is still reachable.
    """
    findings: List[Finding] = []
    headers = _auth_headers(auth_header)
    probed = 0
    seen: set = set()
    for path in endpoint_paths:
        if probed >= max_probes:
            break
        m = VERSION_RE.search(path)
        if not m:
            continue
        version = int(m.group(1))
        for candidate_version in (version - 1, version + 1):
            if candidate_version < 1:
                continue
            new_path = VERSION_RE.sub(f"/v{candidate_version}", path, count=1)
            if (new_path, base_url) in seen:
                continue
            seen.add((new_path, base_url))
            url = base_url.rstrip("/") + new_path
            try:
                resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            except requests.exceptions.RequestException:
                continue
            probed += 1
            if 200 <= resp.status_code < 300:
                findings.append(
                    _mk(
                        "medium",
                        f"Sibling API version reachable: v{candidate_version}",
                        endpoint=new_path, method="GET", request_url=url,
                        evidence=f"Endpoint declared at v{version}; sibling v{candidate_version} returned HTTP {resp.status_code}.",
                        status_code=resp.status_code,
                        response_body=resp.text or "",
                        response_headers=dict(resp.headers),
                    )
                )
            if probed >= max_probes:
                break
    return findings
