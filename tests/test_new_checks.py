"""Tests for the post-review API checks (1-12)."""

from __future__ import annotations

import json

import analyzer
import auth_engine
import cache_checks
import csrf_checks
import host_header_checks
import id_enrichment
import jwt_checks
import oauth_checks
import payloads
import protocol_adapters
import rate_limit_bypass
import smuggling_checks
import smuggling_transport
from authorization_checks import IdentifierCandidate
from models import AuthProfile
from oast import MemoryOASTProvider
from spec_parser import Endpoint, Parameter
from tests.fakes import FakeResponse, FakeSession


# --- 1. Rate-limit bypass ---------------------------------------------------


def test_rate_limit_bypass_flagged_when_ip_spoof_evades():
    """429 on burst, then 200 with X-Forwarded-For -> bypass finding."""
    call_count = [0]
    def responder(method, url, kwargs):
        call_count[0] += 1
        headers = kwargs.get("headers") or {}
        if call_count[0] <= 10 and "X-Forwarded-For" not in headers:
            return FakeResponse(429, '{"error": "rate limited"}', headers={"Retry-After": "60"})
        return FakeResponse(200, '{"ok": true}')
    session = FakeSession(responder)
    findings = rate_limit_bypass.probe_rate_limit_bypass(
        "/api", "https://api.example", session, timeout=5, auth_header=None,
        trigger_burst=10,
    )
    assert len(findings) == 1
    assert findings[0].category == "rate_limit_bypass"
    assert findings[0].owasp_api == "API4:2023"


def test_rate_limit_bypass_no_finding_without_limit():
    """No 429 observed -> nothing to bypass -> no findings."""
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    findings = rate_limit_bypass.probe_rate_limit_bypass(
        "/api", "https://api.example", session, timeout=5,
    )
    assert findings == []


# --- 2. Cache deception -----------------------------------------------------


def test_cache_deception_detected():
    """Extension path returns authenticated body with cacheable headers."""
    private_body = json.dumps({"user": "victim", "ssn": "123-45-6789"})
    def responder(method, url, kwargs):
        return FakeResponse(200, private_body, headers={})
    session = FakeSession(responder)
    findings = cache_checks.probe_cache_deception(
        "/profile", "https://api.example", session, timeout=5,
        auth_header="Bearer victim-token",
    )
    assert len(findings) == 1
    assert findings[0].category == "cache_deception"
    assert findings[0].severity == "high"


def test_cache_deception_suppressed_when_no_store():
    """Cache-Control: no-store prevents the deception — no finding."""
    body = json.dumps({"user": "victim"})
    def responder(method, url, kwargs):
        return FakeResponse(200, body, headers={"Cache-Control": "no-store"})
    session = FakeSession(responder)
    findings = cache_checks.probe_cache_deception(
        "/profile", "https://api.example", session, timeout=5,
        auth_header="Bearer victim-token",
    )
    assert findings == []


# --- 3. Host-header trust ----------------------------------------------------


def test_host_header_reflection_detected():
    """X-Forwarded-Host reflected in Location header -> finding."""
    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        xfwd = headers.get("X-Forwarded-Host", "")
        if xfwd:
            return FakeResponse(302, "", headers={"Location": f"https://{xfwd}/login"})
        return FakeResponse(200, '{"ok": true}')
    session = FakeSession(responder)
    ep = Endpoint("/login", "GET")
    findings = host_header_checks.probe_host_header_trust(
        ep, "https://api.example", session, timeout=5,
    )
    assert len(findings) == 1
    assert findings[0].owasp_api == "API8:2023"


# --- 4. JWT jku/x5u ----------------------------------------------------------


def test_jwt_key_confusion_needs_oast():
    """Without OAST, jku/x5u probes return empty."""
    session = FakeSession(lambda m, u, k: FakeResponse(200, "{}"))
    findings = jwt_checks.run_jwt_key_confusion(
        auth_header="Bearer not-a-jwt",
        target_url="https://api.example/",
        target_method="GET",
        target_endpoint_path="/",
        session=session,
        timeout=5,
        oast=None,
    )
    assert findings == []


def test_jwt_key_confusion_jku_flagged_with_oast_callback():
    """Server fetching attacker jku (OAST callback) -> confirmed critical."""
    import base64 as b64
    import hashlib
    import hmac as hmac_mod

    def sign(payload_dict, secret=b""):
        h = jwt_checks._b64url_encode(json.dumps({"alg": "RS256", "typ": "JWT", "jku": "https://attacker.example/jwks.json"}).encode())
        p = jwt_checks._b64url_encode(json.dumps(payload_dict).encode())
        sig = hmac_mod.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
        return f"{h}.{p}.{jwt_checks._b64url_encode(sig)}", h, p

    valid_token, _, _ = sign({"sub": "user"})
    oast = MemoryOASTProvider(domain="oast.invalid")

    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if not auth:
            return FakeResponse(401, '{"error": "unauthorized"}')
        # Server fetches the jku URL: record a callback for the OAST token.
        for token in list(oast._interactions.keys()):
            oast.record_interaction(token, protocol="http")
        return FakeResponse(200, '{"data": "ok"}')

    session = FakeSession(responder)
    findings = jwt_checks.run_jwt_key_confusion(
        auth_header=f"Bearer {valid_token}",
        target_url="https://api.example/admin",
        target_method="GET",
        target_endpoint_path="/admin",
        session=session,
        timeout=5,
        oast=oast,
    )
    jku = [f for f in findings if f.technique == "jku key-source injection"]
    assert len(jku) == 1
    assert jku[0].confidence == "confirmed"
    assert jku[0].severity == "critical"


# --- 5/6. Payload additions ---------------------------------------------------


def test_ssrf_payloads_include_ip_encodings():
    techniques = [t for _, t in payloads.SSRF]
    assert "decimal-encoded localhost" in techniques
    assert "aws ipv6 metadata" in techniques
    assert any("2130706433" in p for p, _ in payloads.SSRF)


def test_path_traversal_payloads_include_bypasses():
    techniques = [t for _, t in payloads.PATH_TRAVERSAL]
    assert "semicolon bypass (Java/Tomcat)" in techniques
    assert "overlong UTF-8 slash bypass" in techniques


def test_ssi_injection_detected_by_analyzer():
    findings = analyzer.analyze(
        category="ssi_injection",
        payload='<!--#exec cmd="id"-->',
        technique="SSI exec command",
        endpoint_path="/page",
        method="GET",
        parameter="q",
        location="query",
        request_url="https://api.example/page",
        request_headers={},
        request_body=None,
        status_code=200,
        response_text="uid=1000(www) gid=1000(www) groups=1000(www)",
        response_time_ms=10,
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].cwe == "CWE-97"


def test_ssi_injection_clean_when_not_evaluated():
    findings = analyzer.analyze(
        category="ssi_injection",
        payload='<!--#exec cmd="id"-->',
        technique="SSI exec command",
        endpoint_path="/page",
        method="GET",
        parameter="q",
        location="query",
        request_url="https://api.example/page",
        request_headers={},
        request_body=None,
        status_code=200,
        response_text='{"comment": "<!--#exec cmd=\\"id\\"-->"}',
        response_time_ms=10,
    )
    assert findings == []


# --- 7. WebDAV (intrusive) ----------------------------------------------------


def test_webdav_probe_requires_intrusive_confirmation():
    session = FakeSession(lambda m, u, k: FakeResponse(201, ""))
    ep = Endpoint("/dav", "GET")
    findings = extra_checks_import().webdav_put_probe(
        base_url="https://api.example", endpoint_path="/dav",
        session=session, timeout=5, auth_header=None,
        confirmed_intrusive=False,
    )
    assert findings == []


def extra_checks_import():
    import extra_checks
    return extra_checks


def test_webdav_put_confirmed_with_readback():
    written = {}
    def responder(method, url, kwargs):
        if method == "PUT":
            written[url] = kwargs.get("data") or b""
            return FakeResponse(201, "")
        if method == "GET" and url in written:
            return FakeResponse(200, written[url])
        return FakeResponse(404, "")
    session = FakeSession(responder)
    findings = extra_checks_import().webdav_put_probe(
        base_url="https://api.example", endpoint_path="/dav",
        session=session, timeout=5, auth_header=None,
        confirmed_intrusive=True,
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"


# --- 8. Content negotiation ----------------------------------------------------


def test_content_negotiation_flags_undeclared_xml():
    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        accept = headers.get("Accept", "")
        if "xml" in accept:
            return FakeResponse(200, "<root><secret>1</secret></root>",
                                headers={"Content-Type": "application/xml"})
        return FakeResponse(200, '{"secret": 1}', headers={"Content-Type": "application/json"})
    session = FakeSession(responder)
    findings = extra_checks_import().content_negotiation_probe(
        base_url="https://api.example", endpoint_path="/items", method="GET",
        session=session, timeout=5, auth_header=None,
        declared_types={"application/json"},
    )
    assert len(findings) == 1
    assert "application/xml" in findings[0].evidence


# --- 9. Smuggling transport + probes --------------------------------------------


class FakeRawSocket:
    """Minimal socket fake for RawHTTPTransport."""
    def __init__(self, response_bytes):
        self.response_bytes = response_bytes
        self.sent = b""
        self.closed = False
    def settimeout(self, t): pass
    def connect(self, addr): pass
    def sendall(self, data): self.sent += data
    def recv(self, n):
        if self.response_bytes:
            out, self.response_bytes = self.response_bytes, b""
            return out
        return b""
    def close(self): self.closed = True


def test_parse_response_handles_basic_response():
    raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nhi"
    parsed = smuggling_transport.parse_response(raw)
    assert parsed.status_code == 404
    assert parsed.is_http


def test_smuggling_probe_flags_status_change():
    """Baseline 404; after poison, follow-up returns 200 (smuggled path served)."""
    calls = [0]
    def factory():
        calls[0] += 1
        if calls[0] == 1:
            return FakeRawSocket(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nhi")
        # Every later socket: the desynced back-end serves the smuggled
        # dead-path request -> 404 vs follow-up expected 404? We simulate
        # poisoning: follow-up returns 200 (our dead path echo).
        return FakeRawSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
    transport = smuggling_transport.RawHTTPTransport(socket_factory=factory)
    findings = smuggling_checks.probe_smuggling(
        "http://front.example", "/", transport=transport,
    )
    assert len(findings) == 1
    assert findings[0].smuggle_class in ("CL.TE", "TE.CL", "TE.TE")
    assert findings[0].confidence == "tentative"


def test_smuggling_clean_when_no_desync():
    def factory():
        return FakeRawSocket(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nhi")
    transport = smuggling_transport.RawHTTPTransport(socket_factory=factory)
    findings = smuggling_checks.probe_smuggling(
        "http://front.example", "/", transport=transport,
    )
    assert findings == []


# --- 10. Protocol adapters ------------------------------------------------------


def test_soap_wsdl_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, "<wsdl:definitions></wsdl:definitions>"))
    findings = protocol_adapters.probe_soap_wsdl("https://api.example/soap", session, timeout=5)
    assert len(findings) == 1
    assert findings[0].confidence == "strong"


def test_soap_action_spoofing_flagged_on_2xx():
    session = FakeSession(lambda m, u, k: FakeResponse(200, "<soap:Envelope></soap:Envelope>"))
    findings = protocol_adapters.probe_soap_action_spoofing("https://api.example/soap", session, timeout=5)
    assert len(findings) == 1
    assert findings[0].owasp_api == "API5:2023"


def test_websocket_origin_probe_bypasses_evil_origin():
    """101 handshake with evil Origin -> finding (monkeypatched handshake)."""
    original = protocol_adapters._ws_handshake
    protocol_adapters._ws_handshake = lambda *a, **k: (101, {"sec-websocket-accept": "x"})
    try:
        findings = protocol_adapters.probe_websocket_origin("ws://api.example/socket")
    finally:
        protocol_adapters._ws_handshake = original
    assert len(findings) == 1
    assert findings[0].category == "ws_origin_bypass"


def test_grpc_clean_skip_without_package(monkeypatch):
    monkeypatch.setattr(protocol_adapters, "grpc_available", lambda: False)
    findings = protocol_adapters.probe_grpc_reflection("api.example:50051")
    assert findings == []


# --- 11. OAuth checks ------------------------------------------------------------


def test_oauth_checks_skip_without_config():
    session = FakeSession()
    assert oauth_checks.run_oauth_checks(session, oauth_checks.OAuthConfig(), timeout=5) == []


def test_oauth_redirect_uri_flagged_on_evil_redirect():
    def responder(method, url, kwargs):
        return FakeResponse(302, "", headers={"Location": "https://attacker.example/callback?code=abc"})
    session = FakeSession(responder)
    cfg = oauth_checks.OAuthConfig(
        authorize_url="https://api.example/authorize",
        client_id="test-client",
    )
    findings = oauth_checks.check_redirect_uri_matching(session, cfg, timeout=5)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_oauth_pkce_flagged_when_code_issued_without_challenge():
    def responder(method, url, kwargs):
        return FakeResponse(302, "", headers={"Location": "https://app.example/callback?code=abc"})
    session = FakeSession(responder)
    cfg = oauth_checks.OAuthConfig(
        authorize_url="https://api.example/authorize",
        client_id="test-client",
    )
    findings = oauth_checks.check_pkce_enforcement(session, cfg, timeout=5)
    assert len(findings) == 1


# --- 12. CSRF ---------------------------------------------------------------------


def test_csrf_requires_intrusive_confirmation():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/items", "POST", has_body=True, body_example={"name": "x"})
    findings = csrf_checks.probe_csrf_missing(
        ep, "https://api.example", session, timeout=5,
        cookies={"session": "abc"}, confirmed_intrusive=False,
    )
    assert findings == []


def test_csrf_flagged_with_cookies_and_evil_origin():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/items", "POST", has_body=True, body_example={"name": "x"})
    findings = csrf_checks.probe_csrf_missing(
        ep, "https://api.example", session, timeout=5,
        cookies={"session": "abc"}, confirmed_intrusive=True,
    )
    assert len(findings) == 1
    assert findings[0].category == "csrf_missing"


def test_csrf_skips_header_auth_apis():
    """No cookies -> no CSRF risk -> no probes."""
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/items", "POST", has_body=True, body_example={"name": "x"})
    findings = csrf_checks.probe_csrf_missing(
        ep, "https://api.example", session, timeout=5,
        cookies=None, confirmed_intrusive=True,
    )
    assert findings == []


# --- Data quality: ID enrichment ----------------------------------------------------


def test_uuid1_timestamp_extracted():
    v1 = "1efcb2e0-53a1-11ef-923f-0242ac110002"  # UUIDv1
    ts = id_enrichment.uuid1_timestamp(v1)
    assert ts is not None
    assert id_enrichment.uuid1_timestamp("not-a-uuid") is None
    assert id_enrichment.uuid1_timestamp("00000000-0000-4000-8000-000000000000") is None  # v4


def test_encoded_ids_expanded_for_bola():
    base64_id = "NDI="  # base64("42")
    candidate = IdentifierCandidate(
        value=base64_id, field_name="user_id", json_path="$.user_id",
        source_profile="owner", source_endpoint="GET /x",
    )
    enriched = id_enrichment.enrich_candidates([candidate])
    values = [c.value for c in enriched]
    assert base64_id in [str(v) for v in values]
    assert 42 in values  # decoded integer added as a new candidate


def test_bola_uses_enriched_candidates():
    """BOLA with a base64-encoded owner ID substitutes the decoded integer."""
    owner_object = json.dumps({"user_id": "NDI=", "name": "victim"})

    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if "owner" in auth:
            return FakeResponse(200, owner_object)
        if "attacker" in auth:
            if "/users/42" in url:
                return FakeResponse(200, owner_object)
            return FakeResponse(404, '{"error": "nf"}')
        return FakeResponse(401, "{}")

    profiles = [
        AuthProfile(name="owner", headers={"Authorization": "Bearer owner"}),
        AuthProfile(name="attacker", headers={"Authorization": "Bearer attacker"}),
        AuthProfile.anonymous(),
    ]
    cfg = auth_engine.AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
        enable_bfla=False, enable_bopla=False,
    )
    session = FakeSession(responder)
    ep = Endpoint("/users/{id}", "GET", parameters=[Parameter("id", "path", example=1)])
    findings = auth_engine.run_bola_probes([ep], "https://api.example", session, cfg, timeout=5)
    assert len(findings) == 1
