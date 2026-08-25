"""Tests for the Phase 3 JWT differential rework."""

from __future__ import annotations

import json
import time

import jwt_checks
from tests.fakes import FakeResponse, FakeSession


# Build a real HS256 JWT for testing.
def _make_jwt(payload_overrides=None, alg="HS256", secret="test-secret"):
    header = {"alg": alg, "typ": "JWT"}
    payload = {"sub": "user123", "role": "user", "iss": "https://api.example.com", "aud": "api-client"}
    if payload_overrides:
        payload.update(payload_overrides)
    return jwt_checks._sign_hs(header, payload, secret.encode(), alg)


def _protected_responder(forged_status=200, forged_body='{"data": "ok"}', anon_status=401, anon_body='{"error": "unauthorized"}'):
    """Build a responder that returns anon_status for anonymous, forged_status for forged tokens."""
    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if not auth:
            return FakeResponse(anon_status, anon_body)
        return FakeResponse(forged_status, forged_body)
    return responder


def test_alg_none_forgery_flagged_on_protected_endpoint():
    """alg:none token accepted on a protected endpoint -> finding."""
    valid_jwt = _make_jwt()
    session = FakeSession(_protected_responder())
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/users/1",
        target_method="GET",
        target_endpoint_path="/users/{id}",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    alg_none = [f for f in findings if "alg:none" in f.title.lower()]
    assert len(alg_none) >= 1
    assert alg_none[0].severity == "critical"


def test_alg_none_not_flagged_on_public_endpoint():
    """alg:none token on a public endpoint (anon also 2xx) -> no finding."""
    valid_jwt = _make_jwt()
    # Both anonymous and forged get 200 with same body -> public endpoint
    session = FakeSession(_protected_responder(forged_status=200, forged_body='{"data": "public"}', anon_status=200, anon_body='{"data": "public"}'))
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/public",
        target_method="GET",
        target_endpoint_path="/public",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    alg_none = [f for f in findings if "alg:none" in f.title.lower()]
    assert alg_none == []


def test_expired_token_forgery_flagged():
    valid_jwt = _make_jwt({"exp": int(time.time()) + 3600})
    session = FakeSession(_protected_responder())
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/users/1",
        target_method="GET",
        target_endpoint_path="/users/{id}",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    expired = [f for f in findings if "expired" in f.title.lower()]
    assert len(expired) >= 1


def test_claim_mutation_iss_forgery():
    valid_jwt = _make_jwt({"iss": "https://api.example.com"})
    session = FakeSession(_protected_responder())
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/users/1",
        target_method="GET",
        target_endpoint_path="/users/{id}",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    iss_findings = [f for f in findings if "iss" in f.technique.lower()]
    assert len(iss_findings) >= 1


def test_role_escalation_forgery():
    valid_jwt = _make_jwt({"role": "user"})
    session = FakeSession(_protected_responder())
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/admin",
        target_method="GET",
        target_endpoint_path="/admin",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    role_findings = [f for f in findings if "escalation" in f.technique.lower()]
    assert len(role_findings) >= 1
    assert role_findings[0].severity == "high"


def test_non_jwt_auth_header_returns_empty():
    session = FakeSession()
    findings = jwt_checks.run_jwt_attacks(
        auth_header="Bearer not-a-jwt",
        target_url="https://api.example/",
        target_method="GET",
        target_endpoint_path="/",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    assert findings == []


def test_findings_have_owasp_and_cwe_metadata():
    valid_jwt = _make_jwt()
    session = FakeSession(_protected_responder())
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/users/1",
        target_method="GET",
        target_endpoint_path="/users/{id}",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    assert len(findings) >= 1
    for f in findings:
        assert f.owasp_api == "API2:2023"
        assert f.cwe == "CWE-347"
        assert f.confidence in ("strong", "medium", "low", "tentative", "confirmed", "informational")
