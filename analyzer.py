"""Response analysis: classify responses into severity-ranked findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode

from models import Confidence, SafetyLevel
from redaction import (
    DEFAULT_REDACTION_CONFIG,
    RedactionConfig,
    redact_body_text,
    redact_headers,
    redact_url_query,
)


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Phase 0: per-category OWASP API / CWE / safety metadata and a default
# confidence mapping. Confidence is intentionally separate from severity
# (impact); heuristic detections override the default with a lower confidence.
CATEGORY_META: Dict[str, Dict[str, str]] = {
    "sql_injection": {"owasp_api": "API3:2023", "cwe": "CWE-89", "safety": "safe_active"},
    "nosql_injection": {"owasp_api": "API3:2023", "cwe": "CWE-943", "safety": "safe_active"},
    "command_injection": {"owasp_api": "API3:2023", "cwe": "CWE-78", "safety": "safe_active"},
    "xss": {"owasp_api": "API3:2023", "cwe": "CWE-79", "safety": "safe_active"},
    "path_traversal": {"owasp_api": "API3:2023", "cwe": "CWE-22", "safety": "safe_active"},
    "ssrf": {"owasp_api": "API4:2023", "cwe": "CWE-918", "safety": "safe_active"},
    "header_injection": {"owasp_api": "API3:2023", "cwe": "CWE-93", "safety": "safe_active"},
    "auth_bypass": {"owasp_api": "API1:2023", "cwe": "CWE-287", "safety": "safe_active"},
    "info_disclosure": {"owasp_api": "API3:2023", "cwe": "CWE-209", "safety": "passive"},
    "ssti": {"owasp_api": "API3:2023", "cwe": "CWE-94", "safety": "safe_active"},
    "ldap_injection": {"owasp_api": "API3:2023", "cwe": "CWE-90", "safety": "safe_active"},
    "xpath_injection": {"owasp_api": "API3:2023", "cwe": "CWE-643", "safety": "safe_active"},
    "prototype_pollution": {"owasp_api": "API3:2023", "cwe": "CWE-1321", "safety": "safe_active"},
    "open_redirect": {"owasp_api": "API3:2023", "cwe": "CWE-601", "safety": "safe_active"},
    "ssi_injection": {"owasp_api": "API3:2023", "cwe": "CWE-97", "safety": "safe_active"},
    "type_juggling": {"owasp_api": "API3:2023", "cwe": "CWE-843", "safety": "safe_active"},
}

_SEVERITY_CONFIDENCE: Dict[str, str] = {
    "critical": Confidence.HIGH.value,
    "high": Confidence.HIGH.value,
    "medium": Confidence.MEDIUM.value,
    "low": Confidence.LOW.value,
    "info": Confidence.INFORMATIONAL.value,
}


def _severity_to_confidence(severity: str) -> str:
    return _SEVERITY_CONFIDENCE.get(severity, Confidence.INFORMATIONAL.value)


# Hard cap on the captured response body to keep scan memory bounded. Larger
# than this is rare for typical API responses; anything bigger gets truncated
# with an explicit marker so the user knows.
MAX_BODY_BYTES = 1_048_576  # 1 MiB

# Static User-Agent used by `format_raw_http_request` only when the supplied
# request_headers dict has no User-Agent of its own. As of Phase 0 the scan's
# actual User-Agent is scan-local: `UASession` stamps it into every per-call
# headers dict (and therefore into each Finding's request_headers), so the
# displayed raw HTTP request matches what was transmitted without relying on
# process-global state. This constant is no longer mutated per-scan; the
# setter/getter below remain for backward compatibility.
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def set_default_user_agent(ua: str) -> None:
    """Set the static User-Agent fallback used by `format_raw_http_request`.

    Deprecated for per-scan use: the scan's UA is now carried by per-request
    headers. This setter remains for backward compatibility with external
    callers.
    """
    global _DEFAULT_USER_AGENT
    if ua:
        _DEFAULT_USER_AGENT = ua


def get_default_user_agent() -> str:
    return _DEFAULT_USER_AGENT


def url_with_query(url: str, params: Optional[Dict[str, Any]]) -> str:
    """Return `url` with `params` baked into the query string.

    Used by emitters so the Finding's `request_url` (and therefore the v1.5
    raw HTTP request blob) reflects the URL that was actually transmitted on
    the wire, including any payload-bearing query parameters.

    Handles the case where `url` already contains a `?` by appending with `&`.
    A list value is encoded as repeated `name=v` pairs (matching how
    `requests` serialises list params).
    """
    if not params:
        return url
    # Coerce non-string scalars to str so urlencode works uniformly.
    flat: List[Tuple[str, str]] = []
    for k, v in params.items():
        if isinstance(v, (list, tuple)):
            for item in v:
                flat.append((str(k), str(item)))
        else:
            flat.append((str(k), str(v)))
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode(flat)


def format_raw_http_request(
    method: str,
    request_url: str,
    request_headers: Optional[Dict[str, str]] = None,
    request_body: Optional[str] = None,
) -> str:
    """Render a method/url/headers/body tuple as raw HTTP/1.1 wire format.

    The output is suitable for pasting into Burp Suite's Repeater ("Raw" tab)
    or any other tool that expects an HTTP request as a single text blob.
    Headers that requests() would have set automatically (Host, Content-Length,
    Content-Type when there is a body, Accept, User-Agent) are filled in if
    they are not already present, so the rendered request is replayable.
    """
    method = (method or "GET").upper()
    parsed = urlparse(request_url or "")
    host = parsed.netloc or ""
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query

    # Copy so we don't mutate the caller's dict; preserve declaration order.
    headers: List[Tuple[str, str]] = []
    for k, v in (request_headers or {}).items():
        if k.lower() == "host":
            continue  # we always re-emit Host from the URL
        headers.append((str(k), str(v)))

    body = request_body or ""
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", errors="replace")
    body_bytes = body.encode("utf-8", errors="replace") if isinstance(body, str) else b""

    lower_keys = {k.lower() for k, _ in headers}
    if body:
        if "content-length" not in lower_keys:
            headers.append(("Content-Length", str(len(body_bytes))))
            lower_keys.add("content-length")
        if "content-type" not in lower_keys:
            stripped = body.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                headers.append(("Content-Type", "application/json"))
            elif "=" in stripped and not stripped.startswith("<"):
                headers.append(("Content-Type", "application/x-www-form-urlencoded"))
            elif stripped.startswith("<"):
                headers.append(("Content-Type", "application/xml"))
            else:
                headers.append(("Content-Type", "text/plain"))
            lower_keys.add("content-type")
    if "accept" not in lower_keys:
        headers.append(("Accept", "*/*"))
    if "user-agent" not in lower_keys:
        headers.append(("User-Agent", _DEFAULT_USER_AGENT))
    if "connection" not in lower_keys:
        headers.append(("Connection", "close"))

    lines = [f"{method} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    for k, v in headers:
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    endpoint: str
    method: str
    parameter: str
    location: str  # query / path / header / body
    payload: str
    technique: str
    evidence: str
    status_code: int
    response_time_ms: int
    request_url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    # v1.4: the full server response. response_body holds the entire response
    # text (capped at MAX_BODY_BYTES). response_headers carries the response
    # header set (separate from the request_headers field above).
    response_body: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_truncated: bool = False
    # v1.5: raw HTTP/1.1 request string for pasting into Burp Repeater.
    # Auto-populated from method/request_url/request_headers/request_body in
    # __post_init__ if the emitter doesn't supply one explicitly.
    raw_request: str = ""
    # Phase 0: expanded evidence/safety/confidence metadata. All optional and
    # backward compatible -- legacy emitters and report fields keep working.
    confidence: str = ""
    owasp_api: str = ""
    cwe: str = ""
    auth_profile: str = ""
    baseline_summary: str = ""
    comparison_summary: str = ""
    safety_level: str = ""
    check_id: str = ""
    # Phase 0: index of the request ledger entry this finding was produced from.
    ledger_index: Optional[int] = None
    redacted_fields: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.raw_request:
            self.raw_request = format_raw_http_request(
                self.method, self.request_url, self.request_headers, self.request_body
            )

    def to_dict(self, redaction: Optional[RedactionConfig] = None) -> Dict[str, Any]:
        """Return a JSON-serializable dict, redacted by default.

        Authorization, cookies, API keys, tokens, and configured sensitive
        JSON paths are redacted unless a non-default ``redaction`` config
        disables it. The raw HTTP request blob is rebuilt from the redacted
        fields so no secret leaks through it. Use :meth:`to_raw_dict` for the
        separately labeled exact-raw opt-in.
        """
        data = asdict(self)
        cfg = redaction if redaction is not None else DEFAULT_REDACTION_CONFIG
        if not cfg.enabled:
            return data
        headers, header_fields = redact_headers(data.get("request_headers") or {}, cfg)
        data["request_headers"] = headers
        url, url_fields = redact_url_query(data.get("request_url") or "", cfg)
        data["request_url"] = url
        body, body_fields = redact_body_text(data.get("request_body"), cfg)
        data["request_body"] = body
        resp, resp_fields = redact_body_text(data.get("response_body"), cfg)
        data["response_body"] = resp
        data["raw_request"] = format_raw_http_request(
            data["method"], data["request_url"], data["request_headers"], data["request_body"]
        )
        data["redacted_fields"] = (
            [f"request_headers.{name}" for name in header_fields]
            + url_fields
            + [f"request_body.{name}" for name in body_fields]
            + [f"response_body.{name}" for name in resp_fields]
        )
        return data

    def to_raw_dict(self) -> Dict[str, Any]:
        """Return the exact, unredacted finding dict (separately labeled opt-in)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlite3\.operationalerror",
    r"pg::syntaxerror",
    r"psycopg2\.errors",
    r"ora-\d{5}",
    r"odbc.*sql server",
    r"microsoft.*odbc.*sql server",
    r"sqlstate\[\w+\]",
    r"sql syntax.*near",
    r"unterminated quoted string",
]

STACK_TRACE_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"at [\w\.$]+\([\w\.]+\.java:\d+\)",  # Java
    r"system\.\w+exception",  # .NET
    r"\bnullpointerexception\b",
    r"at\s+[\w$./]+\(.+?\.kt:\d+\)",  # Kotlin
    r"runtimeerror:\s",
    r"undefined index:",
    r"fatal error:",
    r"warning:\s+\w+\(\):",  # PHP warning
]

COMMAND_OUTPUT_PATTERNS = [
    r"uid=\d+\(\w+\)\s+gid=\d+",          # `id` output
    r"root:[x*]:0:0:",                    # /etc/passwd
    r"\[boot loader\]",                  # win.ini
    r"daemon:[x*]:\d+",
]

PATH_TRAVERSAL_PATTERNS = [
    r"root:[x*]:0:0:",
    r"\[fonts\]",
    r"\[extensions\]",
]

SSRF_PATTERNS = [
    r"instance-id",
    r"ami-id",
    r"computeMetadata",
    r"\"hostname\":",
    # Multi-cloud / container metadata markers.
    r"metadata/instance",
    r"\"imageName\"",
    r"accounts\.google",
]

SENSITIVE_DISCLOSURE_PATTERNS = [
    (r"-----begin (rsa |ec |dsa |openssh )?private key-----", "private key"),
    (r"aws_secret_access_key", "AWS secret"),
    (r"\baws_access_key_id\s*=\s*akia[0-9a-z]{10,}", "AWS access key"),
    # FP fix: narrow Bearer regex to avoid matching tokens echoed in
    # error/validation messages that show what was sent. Require the
    # token to appear in a JSON value context, not in an echo/debug line.
    (r'"access_token"\s*:\s*"bearer\s+[a-z0-9\-_\.=]{20,}', "bearer token"),
    (r'"token"\s*:\s*"bearer\s+[a-z0-9\-_\.=]{20,}', "bearer token"),
    (r"x-amz-security-token", "AWS session token"),
]

XSS_REFLECTED_NEEDLE = "<script>alert(1)</script>"
XSS_OTHER_NEEDLES = [
    "onerror=alert(1)",
    "svg/onload=alert(1)",
    "javascript:alert(1)",
]

SSTI_PRODUCT = "60481729"  # 7777 * 7777

NOSQL_ERROR_PATTERNS = [
    r"mongoerror",
    r"cast to objectid failed",
    r"\bbson\b.*error",
    r"unknown top level operator",
    r"\$where is not allowed",
    r"e11000 duplicate key",
]

LDAP_ERROR_PATTERNS = [
    r"javax\.naming\.directory\.invalidsearchfilterexception",
    r"ldap:.*invalid filter",
    r"com\.sun\.jndi\.ldap",
    r"openldap.*error",
    r"unbalanced parenthesis",
]

XPATH_ERROR_PATTERNS = [
    r"xpathexception",
    r"system\.xml\.xpath",
    r"unterminated string literal in xpath",
    r"a closing bracket expected",
]

EXTERNAL_REDIRECT_HOST = "evil.example.com"

# Techniques in the v1.9 STRING_TYPE_JUGGLING list that are interesting even
# for plain string parameters; everything else for string is too noisy to flag.
_STRING_TJ_INTERESTING = {
    "empty string",
    "embedded NUL byte",
    "10KB oversize string",
}


def _type_juggling_severity(payload: str, technique: str) -> Optional[str]:
    """Return the severity for a type-juggling finding, or None to suppress it.

    We only flag values that clearly don't match the declared type. Numbers
    that happen to parse cleanly (e.g. ``-1`` against an integer parameter)
    are skipped to keep the report low-noise.

    FP fix: boolean parameters accepting true/false/1/0/yes/no/on/off are
    suppressed entirely — these are framework conventions, not vulnerabilities.
    Only unusual boolean values (arrays, objects, quoted strings) are flagged.
    """
    p = (payload or "").strip()
    t = (technique or "").lower()
    # FP fix: suppress common boolean truthy/falsy values that frameworks
    # legitimately accept as boolean alternatives. Covers any technique
    # whose label contains "truthy" or "falsy" (e.g. "HTML-checkbox truthy",
    # "English truthy string") not just techniques with "boolean" in the name.
    _BOOLEAN_BENIGN = {"1", "0", "true", "false", "yes", "no", "on", "off", "null", "undefined"}
    if ("truthy" in t or "falsy" in t or "boolean" in t) and p.lower() in _BOOLEAN_BENIGN:
        return None
    # FP fix: suppress benign integer values (1, 0, -1) that are normal
    # for integer parameters — the server accepting them is expected.
    _INTEGER_BENIGN = {"1", "0", "-1"}
    if "integer" in t and p in _INTEGER_BENIGN:
        return None
    # Numeric category: skip values that parse as a plain int/float (the server
    # accepting `-1` for an integer is normal).
    try:
        float(p)
        is_numeric = True
    except (ValueError, TypeError):
        is_numeric = False
    if "truthy integer" in t or "falsy integer" in t or "out-of-range integer" in t \
            or "negative integer" in t or "negative one" in t or t == "zero" \
            or "32-bit integer near overflow" in t:
        # Numerics being accepted in numeric or boolean fields can still be a
        # smell (boolean accepting 2 is suspicious) so flag low.
        if "integer" in t and any(k in t for k in ("truthy", "falsy", "out-of-range", "negative")):
            return "low"
        return None if is_numeric else "low"
    if "string" in t and t not in _STRING_TJ_INTERESTING:
        # Skip most string-type-juggling 2xx results — servers accept arbitrary
        # strings all the time.
        return None
    return "low"


def _first_match(text_lc: str, patterns: List[str]) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, text_lc, flags=re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def capture_body(s: Optional[str], limit: int = MAX_BODY_BYTES) -> Tuple[Optional[str], bool]:
    """Return (captured_text, was_truncated) capped at `limit` characters."""
    if s is None:
        return None, False
    if len(s) <= limit:
        return s, False
    return s[:limit] + "\n… [response truncated at {} bytes]".format(limit), True


# Backwards-compatible alias used by some emitters; just delegates to capture_body.
def _truncate(s: str, limit: int = MAX_BODY_BYTES) -> str:
    captured, _ = capture_body(s, limit=limit)
    return captured or ""


def analyze(
    *,
    category: str,
    payload: str,
    technique: str,
    endpoint_path: str,
    method: str,
    parameter: str,
    location: str,
    request_url: str,
    request_headers: Dict[str, str],
    request_body: Optional[str],
    status_code: int,
    response_text: str,
    response_time_ms: int,
    baseline_time_ms: Optional[int] = None,
    response_headers: Optional[Dict[str, str]] = None,
    confidence: Optional[str] = None,
    check_id: str = "",
    safety_level: str = "",
    auth_profile: str = "",
    # FP fix: anonymous baseline status for differential auth_bypass suppression.
    anonymous_status: Optional[int] = None,
    # FP fix: baseline response status for 5xx differential suppression.
    baseline_status: Optional[int] = None,
) -> List[Finding]:
    """Return zero or more Findings for a single request/response."""
    findings: List[Finding] = []
    body_lc = (response_text or "").lower()

    captured_body, was_truncated = capture_body(response_text)

    meta = CATEGORY_META.get(category, {})

    def _mk(severity: str, title: str, evidence: str, confidence: Optional[str] = None) -> Finding:
        return Finding(
            severity=severity,
            category=category,
            title=title,
            endpoint=endpoint_path,
            method=method,
            parameter=parameter,
            location=location,
            payload=payload,
            technique=technique,
            evidence=evidence,
            status_code=status_code,
            response_time_ms=response_time_ms,
            request_url=request_url,
            request_headers=dict(request_headers),
            request_body=request_body,
            response_body=captured_body,
            response_headers=dict(response_headers or {}),
            response_truncated=was_truncated,
            confidence=confidence or _severity_to_confidence(severity),
            owasp_api=meta.get("owasp_api", ""),
            cwe=meta.get("cwe", ""),
            safety_level=safety_level or meta.get("safety", SafetyLevel.SAFE_ACTIVE.value),
            check_id=check_id,
            auth_profile=auth_profile,
        )

    if category == "sql_injection":
        hit = _first_match(body_lc, SQL_ERROR_PATTERNS)
        if hit:
            findings.append(
                _mk("critical", "SQL error disclosed in response", f"Matched signature: {hit}")
            )
        elif (
            baseline_time_ms is not None
            and "sleep" in payload.lower() + technique.lower()
            and response_time_ms - baseline_time_ms >= 4000
        ):
            findings.append(
                _mk(
                    "high",
                    "Possible time-based blind SQL injection",
                    f"Response delayed {response_time_ms - baseline_time_ms} ms vs baseline",
                    confidence=Confidence.MEDIUM.value,
                )
            )

    elif category == "xss":
        if XSS_REFLECTED_NEEDLE in (response_text or ""):
            findings.append(
                _mk("high", "Reflected XSS payload echoed in response", "Exact script tag reflected")
            )
        else:
            for needle in XSS_OTHER_NEEDLES:
                if needle in (response_text or ""):
                    findings.append(
                        _mk("medium", "XSS payload reflected (filter bypass candidate)", f"Reflected: {needle}")
                    )
                    break

    elif category == "command_injection":
        hit = _first_match(body_lc, COMMAND_OUTPUT_PATTERNS)
        if hit:
            findings.append(
                _mk("critical", "Command injection: shell output observed", f"Matched: {hit}")
            )
        elif (
            baseline_time_ms is not None
            and "sleep" in payload.lower()
            and response_time_ms - baseline_time_ms >= 4000
        ):
            findings.append(
                _mk(
                    "high",
                    "Possible time-based blind command injection",
                    f"Response delayed {response_time_ms - baseline_time_ms} ms vs baseline",
                    confidence=Confidence.MEDIUM.value,
                )
            )

    elif category == "path_traversal":
        hit = _first_match(body_lc, PATH_TRAVERSAL_PATTERNS)
        if hit:
            findings.append(
                _mk("critical", "Path traversal: sensitive file content returned", f"Matched: {hit}")
            )

    elif category == "ssrf":
        hit = _first_match(body_lc, SSRF_PATTERNS)
        if hit:
            findings.append(
                _mk("critical", "SSRF: internal/metadata content returned", f"Matched: {hit}")
            )

    elif category == "header_injection":
        if "x-injected: yes" in body_lc:
            findings.append(
                _mk("high", "CRLF header injection reflected", "X-Injected header reached client")
            )

    elif category == "auth_bypass":
        # FP fix: only flag auth_bypass if the endpoint is not public.
        # If anonymous_status is provided and also 2xx, the endpoint is likely
        # public and accepting any credential is not a bypass.
        if 200 <= status_code < 300:
            if anonymous_status is not None and 200 <= anonymous_status < 300:
                # Anonymous also gets 2xx — endpoint is public, not a bypass.
                pass
            else:
                findings.append(
                    _mk(
                        "high",
                        "Possible auth bypass: success status with weak credential",
                        f"HTTP {status_code} returned for payload '{payload!r}' (anonymous: {anonymous_status})",
                        confidence=Confidence.LOW.value,
                    )
                )

    elif category == "info_disclosure":
        hit = _first_match(body_lc, STACK_TRACE_PATTERNS)
        if hit:
            findings.append(
                _mk("medium", "Stack trace / verbose error disclosure", f"Matched: {hit}")
            )

    elif category == "nosql_injection":
        hit = _first_match(body_lc, NOSQL_ERROR_PATTERNS)
        if hit:
            findings.append(
                _mk("high", "NoSQL error disclosed in response", f"Matched signature: {hit}")
            )
        elif (
            baseline_time_ms is not None
            and "sleep" in payload.lower()
            and response_time_ms - baseline_time_ms >= 4000
        ):
            findings.append(
                _mk(
                    "high",
                    "Possible time-based blind NoSQL injection",
                    f"Response delayed {response_time_ms - baseline_time_ms} ms vs baseline",
                    confidence=Confidence.MEDIUM.value,
                )
            )
        elif 200 <= status_code < 300 and parameter and "$ne" in payload:
            findings.append(
                _mk(
                    "medium",
                    "Operator smuggling returned 200 \u2014 verify auth/filter bypass",
                    f"NoSQL operator payload accepted with HTTP {status_code}",
                    confidence=Confidence.LOW.value,
                )
            )

    elif category == "ssi_injection":
        # SSI evaluation manifests like command injection (exec) or file
        # disclosure (include). Reuse command-output patterns plus an
        # SSI-unparsed marker for partial evaluation.
        hit = _first_match(body_lc, COMMAND_OUTPUT_PATTERNS + PATH_TRAVERSAL_PATTERNS)
        if hit:
            findings.append(
                _mk(
                    "critical",
                    "SSI injection: server-side include evaluated",
                    f"Matched: {hit}",
                )
            )

    elif category == "ssti":
        if SSTI_PRODUCT in (response_text or ""):
            findings.append(
                _mk(
                    "critical",
                    "Server-Side Template Injection (arithmetic evaluated)",
                    f"Response contains literal '{SSTI_PRODUCT}' (= 7777*7777), indicating template-side evaluation.",
                )
            )
        elif "<class " in (response_text or "") and "__class__" in payload:
            findings.append(
                _mk(
                    "high",
                    "SSTI class probe reflected",
                    "Response echoes Python class repr (e.g. <class 'str'>).",
                )
            )

    elif category == "ldap_injection":
        hit = _first_match(body_lc, LDAP_ERROR_PATTERNS)
        if hit:
            findings.append(
                _mk("high", "LDAP error disclosed in response", f"Matched signature: {hit}")
            )

    elif category == "xpath_injection":
        hit = _first_match(body_lc, XPATH_ERROR_PATTERNS)
        if hit:
            findings.append(
                _mk("high", "XPath error disclosed in response", f"Matched signature: {hit}")
            )

    elif category == "prototype_pollution":
        # Echo of canary value in response indicates the server reflected the
        # pollution attempt; only the absence of obvious sanitisation is
        # diagnostic, so emit medium.
        if "apifz_pp_canary" in (response_text or ""):
            findings.append(
                _mk(
                    "medium",
                    "Prototype-pollution canary reflected in response",
                    "Server echoed the polluted key value back; review for real prototype impact.",
                )
            )

    elif category == "open_redirect":
        # Look for Location header pointing at our external host.
        if response_headers:
            loc = response_headers.get("Location") or response_headers.get("location")
            if loc and EXTERNAL_REDIRECT_HOST in loc:
                findings.append(
                    _mk(
                        "high",
                        "Open redirect to attacker-controlled host",
                        f"Location header: {loc}",
                    )
                )

    elif category == "type_juggling":
        # The parameter's declared schema type is embedded in `technique` for
        # the boolean/numeric lists (e.g. "truthy integer"), so we just need
        # to flag 2xx responses to clearly type-mismatched payloads.
        if 200 <= status_code < 300:
            severity = _type_juggling_severity(payload, technique)
            if severity is not None:
                findings.append(
                    _mk(
                        severity,
                        f"Type juggling: server accepted '{technique}' as a typed value",
                        f"Payload {payload!r} returned HTTP {status_code} "
                        f"— weak input-type validation.",
                    )
                )

    # Generic sensitive-data sweep on every response.
    for pat, label in SENSITIVE_DISCLOSURE_PATTERNS:
        if re.search(pat, body_lc):
            findings.append(
                _mk(
                    "critical",
                    f"Sensitive data disclosed: {label}",
                    f"Pattern matched: {label}",
                    confidence=Confidence.CONFIRMED.value,
                )
            )

    # Generic 5xx for any category — useful low-noise signal.
    # FP fix: only flag 5xx if the benign baseline didn't also produce 5xx.
    # If baseline_status is provided and also 5xx, the 5xx is likely
    # background server instability, not payload-induced.
    if 500 <= status_code < 600 and not findings:
        if baseline_status is not None and 500 <= baseline_status < 600:
            # Baseline also produced 5xx — not payload-induced.
            pass
        else:
            findings.append(
                _mk(
                    "low",
                    f"Server error (HTTP {status_code}) triggered by payload",
                    "Payload caused 5xx; investigate for unhandled exception path",
                )
            )

    return findings


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.endpoint, f.parameter))


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
