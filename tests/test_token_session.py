"""Tests for Phase 3 token_session_checks."""

from __future__ import annotations

import token_session_checks
from spec_parser import Endpoint, Parameter, SecurityRequirement
from tests.fakes import FakeResponse, FakeSession


def test_missing_auth_flags_secured_endpoint():
    """Endpoint with security requirement that accepts anonymous -> finding."""
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": "ok"}'))
    ep = Endpoint("/admin", "GET", security=[SecurityRequirement(schemes={"bearerAuth": []})])
    findings = token_session_checks.probe_missing_auth(ep, "https://api.example", session, timeout=5)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].owasp_api == "API2:2023"


def test_missing_auth_no_finding_when_anonymous_blocked():
    session = FakeSession(lambda m, u, k: FakeResponse(401, '{"error": "unauthorized"}'))
    ep = Endpoint("/admin", "GET", security=[SecurityRequirement(schemes={"bearerAuth": []})])
    findings = token_session_checks.probe_missing_auth(ep, "https://api.example", session, timeout=5)
    assert findings == []


def test_missing_auth_no_finding_without_security():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": "ok"}'))
    ep = Endpoint("/public", "GET")
    findings = token_session_checks.probe_missing_auth(ep, "https://api.example", session, timeout=5)
    assert findings == []


def test_token_in_query_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": "ok"}'))
    ep = Endpoint("/search", "GET", parameters=[Parameter("token", "query", example="test")])
    findings = token_session_checks.probe_token_in_query(ep, "https://api.example", session, timeout=5)
    assert len(findings) == 1
    assert "token" in findings[0].title.lower() or "query" in findings[0].title.lower()


def test_token_in_query_no_finding_without_token_param():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": "ok"}'))
    ep = Endpoint("/search", "GET", parameters=[Parameter("q", "query", example="test")])
    findings = token_session_checks.probe_token_in_query(ep, "https://api.example", session, timeout=5)
    assert findings == []


def test_token_replay_detected():
    """Token still works after simulated logout on protected endpoint -> finding."""
    responses = [FakeResponse(200, '{"ok": true}'), FakeResponse(200, '{"ok": true}'), FakeResponse(401, '{"error": "unauthorized"}')]
    idx = [0]
    def responder(method, url, kwargs):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    session = FakeSession(responder)
    ep = Endpoint("/data", "GET")
    findings = token_session_checks.probe_token_replay(ep, "https://api.example", session, timeout=5, auth_header="Bearer test-token")
    assert len(findings) == 1
    assert findings[0].category == "token_replay"


def test_token_replay_no_finding_on_public():
    responses = [FakeResponse(200, '{"ok": true}'), FakeResponse(200, '{"ok": true}'), FakeResponse(200, '{"ok": true}')]
    idx = [0]
    def responder(method, url, kwargs):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    session = FakeSession(responder)
    ep = Endpoint("/public", "GET")
    findings = token_session_checks.probe_token_replay(ep, "https://api.example", session, timeout=5, auth_header="Bearer test-token")
    assert findings == []


def test_run_token_session_checks_aggregates():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": "ok"}'))
    ep = Endpoint("/admin", "GET", security=[SecurityRequirement(schemes={"bearerAuth": []})])
    findings = token_session_checks.run_token_session_checks([ep], "https://api.example", session, timeout=5)
    assert len(findings) >= 1
    categories = {f.category for f in findings}
    assert "missing_auth" in categories
