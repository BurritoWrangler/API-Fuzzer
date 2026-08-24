"""Phase 2 auth_engine tests with deterministic vulnerable fixtures."""

from __future__ import annotations

import json

import auth_engine
from auth_engine import AuthzConfig, AuthzFinding
from models import AuthProfile
from spec_parser import Endpoint, MediaType, Parameter, Response
from tests.fakes import FakeResponse, FakeSession


def _ep_with_responses(path="/accounts/{id}", schema=None):
    responses = {}
    if schema:
        responses["200"] = Response(
            status_code="200",
            content={"application/json": MediaType(media_type="application/json", schema=schema)},
        )
    return Endpoint(
        path=path, method="GET",
        parameters=[Parameter("id", "path", example=1)],
        responses=responses,
    )


def _owner_json():
    return json.dumps({"id": 42, "user_id": "alice", "name": "Alice", "email": "alice@example.com", "balance": 1000})


def _attacker_json():
    # Same object returned to attacker — BOLA
    return json.dumps({"id": 42, "user_id": "alice", "name": "Alice", "email": "alice@example.com", "balance": 1000})


def _anon_json():
    return json.dumps({"error": "unauthorized"})


def _make_profiles():
    owner = AuthProfile(name="owner", headers={"Authorization": "Bearer owner-token"})
    attacker = AuthProfile(name="attacker", headers={"Authorization": "Bearer attacker-token"})
    anonymous = AuthProfile.anonymous()
    return [owner, attacker, anonymous], owner, attacker, anonymous


def _responder(method, url, kwargs):
    headers = kwargs.get("headers") or {}
    auth = headers.get("Authorization", "")
    if "owner-token" in auth:
        return FakeResponse(200, _owner_json(), {"Content-Type": "application/json"})
    if "attacker-token" in auth:
        return FakeResponse(200, _attacker_json(), {"Content-Type": "application/json"})
    return FakeResponse(401, _anon_json(), {"Content-Type": "application/json"})


def test_bola_detects_cross_profile_object_access():
    profiles, owner, attacker, anonymous = _make_profiles()
    session = FakeSession(_responder)
    endpoint = Endpoint("/users/{id}", "GET", parameters=[Parameter("id", "path", example=42)])
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
        enable_bfla=False, enable_bopla=False,
    )
    findings = auth_engine.run_bola_probes([endpoint], "https://api.example", session, cfg, timeout=5)
    bola = [f for f in findings if f.category == "bola"]
    assert len(bola) >= 1
    assert bola[0].severity == "high"
    assert bola[0].confidence == "strong"
    assert bola[0].owasp_api == "API1:2023"
    assert "cross-profile" in bola[0].title.lower()


def test_bola_no_finding_when_attacker_blocked():
    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if "owner-token" in auth:
            return FakeResponse(200, _owner_json())
        # Attacker gets 403 — blocked
        return FakeResponse(403, '{"error":"forbidden"}')

    profiles, owner, attacker, anonymous = _make_profiles()
    session = FakeSession(responder)
    endpoint = Endpoint("/users/{id}", "GET", parameters=[Parameter("id", "path", example=42)])
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
        enable_bfla=False, enable_bopla=False,
    )
    findings = auth_engine.run_bola_probes([endpoint], "https://api.example", session, cfg, timeout=5)
    assert findings == []


def test_bola_no_finding_for_public_endpoint():
    def responder(method, url, kwargs):
        # Everyone gets 200 — public endpoint, not BOLA
        return FakeResponse(200, '{"id": 42, "name": "public"}')

    profiles, owner, attacker, anonymous = _make_profiles()
    session = FakeSession(responder)
    endpoint = Endpoint("/posts/{id}", "GET", parameters=[Parameter("id", "path", example=42)])
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
        enable_bfla=False, enable_bopla=False,
    )
    findings = auth_engine.run_bola_probes([endpoint], "https://api.example", session, cfg, timeout=5)
    assert findings == []


def test_bfla_detects_privileged_function_access():
    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if "admin" in auth:
            return FakeResponse(200, '{"status": "ok"}')
        if "attacker" in auth:
            return FakeResponse(200, '{"status": "ok"}')  # Normal user gets 2xx — BFLA
        return FakeResponse(401, '{"error": "unauthorized"}')

    owner = AuthProfile(name="admin", headers={"Authorization": "Bearer admin"}, expected_role="admin")
    normal = AuthProfile(name="attacker", headers={"Authorization": "Bearer attacker"}, expected_role="user")
    anonymous = AuthProfile.anonymous()
    profiles = [owner, normal, anonymous]
    session = FakeSession(responder)
    endpoint = Endpoint("/admin/users", "DELETE")
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="admin", attacker_profile="attacker",
        enable_bola=False, enable_bopla=False,
    )
    findings = auth_engine.run_bfla_probes([endpoint], "https://api.example", session, cfg, timeout=5)
    bfla = [f for f in findings if f.category == "bfla"]
    assert len(bfla) == 1
    assert bfla[0].severity == "high"
    assert bfla[0].owasp_api == "API5:2023"


def test_bopla_detects_sensitive_property_in_response():
    def responder(method, url, kwargs):
        return FakeResponse(200, '{"id": 1, "role": "admin", "balance": 9999}')

    profiles, owner, _, _ = _make_profiles()
    session = FakeSession(responder)
    ep = _ep_with_responses(schema={"properties": {
        "id": {"type": "integer"},
        "role": {"type": "string"},
        "balance": {"type": "number"},
    }})
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
        enable_bola=False, enable_bfla=False,
    )
    findings = auth_engine.run_bopla_probes([ep], "https://api.example", session, cfg, timeout=5)
    bopla = [f for f in findings if f.category == "bopla"]
    # Should flag "role" and "balance" as sensitive properties in response
    assert len(bopla) >= 1
    sensitive_params = {f.parameter for f in bopla}
    assert "role" in sensitive_params or "balance" in sensitive_params


def test_bola_skipped_with_insufficient_profiles():
    profiles = [AuthProfile(name="solo", headers={"Authorization": "Bearer x"})]
    session = FakeSession()
    endpoint = Endpoint("/users/{id}", "GET", parameters=[Parameter("id", "path")])
    cfg = AuthzConfig(profiles=profiles, enable_bfla=False, enable_bopla=False)
    findings = auth_engine.run_bola_probes([endpoint], "https://api.example", session, cfg, timeout=5)
    assert findings == []


def test_run_authorization_checks_aggregates_all():
    profiles, owner, attacker, anonymous = _make_profiles()
    session = FakeSession(_responder)
    endpoint = Endpoint("/users/{id}", "GET", parameters=[Parameter("id", "path", example=42)])
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
    )
    findings = auth_engine.run_authorization_checks([endpoint], "https://api.example", session, cfg, timeout=5)
    assert len(findings) >= 1
    categories = {f.category for f in findings}
    assert "bola" in categories
