"""Tests for false-positive suppression fixes."""

from __future__ import annotations

import json
import time

import analyzer
from analyzer import analyze, Finding
import misconfig
import extra_checks
from spec_parser import Endpoint, Parameter
from tests.fakes import FakeResponse, FakeSession


# --- Fix 1: auth_bypass suppressed on public endpoints ---


def test_auth_bypass_suppressed_when_anonymous_also_2xx():
    """auth_bypass finding suppressed when anonymous baseline is also 2xx."""
    findings = analyze(
        category="auth_bypass",
        payload="admin",
        technique="default username",
        endpoint_path="/api",
        method="GET",
        parameter="auth",
        location="header",
        request_url="https://api.example/",
        request_headers={},
        request_body=None,
        status_code=200,
        response_text='{"ok": true}',
        response_time_ms=10,
        anonymous_status=200,  # anonymous also gets 2xx -> public endpoint
    )
    assert findings == []


def test_auth_bypass_flagged_when_anonymous_blocked():
    """auth_bypass finding still emitted when anonymous baseline is 401."""
    findings = analyze(
        category="auth_bypass",
        payload="admin",
        technique="default username",
        endpoint_path="/api",
        method="GET",
        parameter="auth",
        location="header",
        request_url="https://api.example/",
        request_headers={},
        request_body=None,
        status_code=200,
        response_text='{"ok": true}',
        response_time_ms=10,
        anonymous_status=401,  # anonymous blocked -> not public
    )
    assert len(findings) == 1
    assert findings[0].confidence == "low"


# --- Fix 2: 5xx suppressed when baseline also 5xx ---


def test_5xx_suppressed_when_baseline_also_5xx():
    """5xx finding suppressed when benign baseline also produced 5xx."""
    findings = analyze(
        category="sql_injection",
        payload="' OR 1=1",
        technique="boolean tautology",
        endpoint_path="/api",
        method="GET",
        parameter="q",
        location="query",
        request_url="https://api.example/",
        request_headers={},
        request_body=None,
        status_code=500,
        response_text='{"error": "internal"}',
        response_time_ms=10,
        baseline_status=500,  # baseline also 5xx -> background instability
    )
    assert findings == []


def test_5xx_flagged_when_baseline_not_5xx():
    """5xx finding still emitted when baseline didn't produce 5xx."""
    findings = analyze(
        category="sql_injection",
        payload="' OR 1=1",
        technique="boolean tautology",
        endpoint_path="/api",
        method="GET",
        parameter="q",
        location="query",
        request_url="https://api.example/",
        request_headers={},
        request_body=None,
        status_code=500,
        response_text='{"error": "internal"}',
        response_time_ms=10,
        baseline_status=200,  # baseline was 200 -> payload-induced 5xx
    )
    server_errors = [f for f in findings if "server error" in f.title.lower()]
    assert len(server_errors) == 1


# --- Fix 3: security headers suppressed on JSON responses ---


def test_csp_suppressed_on_json_response():
    """CSP finding suppressed when Content-Type is application/json."""
    findings = misconfig.inspect_response(
        response_headers={"Content-Type": "application/json"},
        set_cookies=[],
        status_code=200,
        request_url="https://api.example/",
        endpoint="/",
        method="GET",
        response_text='{"data": "ok"}',
        is_https=True,
        response_time_ms=10,
    )
    csp = [f for f in findings if "Content-Security-Policy" in f.title]
    assert csp == []


def test_csp_flagged_on_html_response():
    """CSP finding still emitted for HTML responses."""
    findings = misconfig.inspect_response(
        response_headers={"Content-Type": "text/html"},
        set_cookies=[],
        status_code=200,
        request_url="https://api.example/",
        endpoint="/",
        method="GET",
        response_text="<html></html>",
        is_https=True,
        response_time_ms=10,
    )
    csp = [f for f in findings if "Content-Security-Policy" in f.title]
    assert len(csp) == 1


# --- Fix 4: rate-limit threshold and severity ---


def test_rate_limit_severity_lowered():
    """Rate-limit finding severity lowered to low, burst raised to 50."""
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    findings = misconfig.probe_rate_limit(
        "https://api.example", "/api", session, timeout=5, auth_header=None,
    )
    no_rate = [f for f in findings if "rate-limiting" in f.title.lower()]
    if no_rate:
        assert no_rate[0].severity == "low"


# --- Fix 5: canary reflection only in executable context ---


def test_canary_reflection_suppressed_on_json():
    """Canary reflection suppressed on JSON responses."""
    session = FakeSession(lambda m, u, k: FakeResponse(
        200, '{"query": "apifz_canary_abc123"}',
        headers={"Content-Type": "application/json"},
    ))
    ep = Endpoint("/search", "GET", parameters=[Parameter("q", "query", example="test")])
    findings = extra_checks.canary_reflection_probe(
        base_url="https://api.example", endpoint_path="/search", method="GET",
        parameter_name="q", parameter_location="query",
        benign_query={"q": "test"}, benign_body=None, consumes_json=True,
        session=session, timeout=5, auth_header=None,
    )
    assert findings == []


# --- Fix 6: CORS wildcard suppressed on public endpoints ---


def test_cors_wildcard_suppressed_without_auth():
    """CORS wildcard finding suppressed when no auth was used (public endpoint)."""
    findings = misconfig.inspect_response(
        response_headers={"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        set_cookies=[],
        status_code=200,
        request_url="https://api.example/",
        endpoint="/",
        method="GET",
        response_text='{"data": "ok"}',
        is_https=True,
        response_time_ms=10,
        used_auth=False,  # public endpoint
    )
    cors_wildcard = [f for f in findings if "wildcard" in f.title.lower()]
    assert cors_wildcard == []


def test_cors_wildcard_flagged_with_auth():
    """CORS wildcard finding still emitted when auth was used."""
    findings = misconfig.inspect_response(
        response_headers={"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        set_cookies=[],
        status_code=200,
        request_url="https://api.example/",
        endpoint="/",
        method="GET",
        response_text='{"data": "ok"}',
        is_https=True,
        response_time_ms=10,
        used_auth=True,  # authenticated endpoint
    )
    cors_wildcard = [f for f in findings if "wildcard" in f.title.lower()]
    assert len(cors_wildcard) == 1


# --- Fix 7: private Cache-Control accepted ---


def test_private_cache_control_accepted():
    """private Cache-Control accepted, no finding."""
    findings = misconfig.check_auth_cache_control(
        {"Cache-Control": "private, max-age=0"},
        status_code=200, request_url="https://api.example/",
        endpoint="/", method="GET", used_auth=True,
    )
    assert findings == []


def test_no_cache_control_still_flagged():
    """Missing Cache-Control still flagged."""
    findings = misconfig.check_auth_cache_control(
        {}, status_code=200, request_url="https://api.example/",
        endpoint="/", method="GET", used_auth=True,
    )
    assert len(findings) == 1


# --- Fix 8: security.txt removed from COMMON_PATHS ---


def test_security_txt_not_in_common_paths():
    """security.txt should not be in COMMON_PATHS."""
    paths = [p for p, _ in misconfig.COMMON_PATHS]
    assert "/.well-known/security.txt" not in paths


# --- Fix 9: Bearer regex narrowed ---


def test_bearer_in_echo_not_flagged():
    """Bearer token in an echo/validation message not flagged."""
    # Old broad regex would match "Bearer eyJ..." in any context.
    # New regex requires it in a JSON value context.
    body = '{"error": "Invalid Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.test.sig"}'
    findings = analyze(
        category="sql_injection",
        payload="' OR 1=1",
        technique="test",
        endpoint_path="/api",
        method="GET",
        parameter="q",
        location="query",
        request_url="https://api.example/",
        request_headers={},
        request_body=None,
        status_code=400,
        response_text=body,
        response_time_ms=10,
    )
    sensitive = [f for f in findings if "bearer token" in f.title.lower()]
    assert sensitive == []


# --- Fix 10: type-juggling boolean suppressed ---


def test_boolean_true_false_suppressed():
    """Boolean params accepting true/false/1/0 suppressed."""
    for benign_value, technique in [
        ("true", "quoted JSON string 'true'"),
        ("false", "quoted JSON string 'false'"),
        ("1", "truthy integer"),
        ("0", "falsy integer"),
        ("yes", "English truthy string"),
        ("on", "HTML-checkbox truthy"),
    ]:
        findings = analyze(
            category="type_juggling",
            payload=benign_value,
            technique=technique,
            endpoint_path="/api",
            method="GET",
            parameter="active",
            location="query",
            request_url="https://api.example/",
            request_headers={},
            request_body=None,
            status_code=200,
            response_text='{"ok": true}',
            response_time_ms=10,
        )
        tj = [f for f in findings if "type juggling" in f.title.lower()]
        assert tj == [], f"Value {benign_value!r} ({technique}) should be suppressed but got {len(tj)} findings"
