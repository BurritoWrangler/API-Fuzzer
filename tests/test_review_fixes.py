"""Regression tests for the efficiency and functionality review fixes."""

from __future__ import annotations

import json
import time

import auth_engine
import comparators
import engine
import jwt_checks
from analyzer import Finding
from auth_engine import AuthzConfig
from models import AuthProfile
from spec_parser import (
    Endpoint,
    MediaType,
    Parameter,
    RefResolver,
    RequestBody,
    build_request,
)
from tests.fakes import FakeResponse, FakeSession


# --- BOLA substitution fix -------------------------------------------------


def test_bola_probe_actually_substitutes_identifier():
    """The attacker request must contain the owner's identifier.

    Regression: run_bola_probes computed the mutation but sent a benign
    attacker request, so the probe never tested cross-object access.
    """
    owner_object = json.dumps({"id": 42, "name": "secret-doc"})

    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if "owner-token" in auth:
            return FakeResponse(200, owner_object)
        if "attacker-token" in auth:
            # Only the true owner's ID returns the object.
            if "/42" in url:
                return FakeResponse(200, owner_object)
            return FakeResponse(404, '{"error": "not found"}')
        return FakeResponse(401, '{"error": "unauthorized"}')

    profiles = [
        AuthProfile(name="owner", headers={"Authorization": "Bearer owner-token"}),
        AuthProfile(name="attacker", headers={"Authorization": "Bearer attacker-token"}),
        AuthProfile.anonymous(),
    ]
    cfg = AuthzConfig(
        profiles=profiles,
        owner_profile="owner",
        attacker_profile="attacker",
        enable_bfla=False,
        enable_bopla=False,
    )
    session = FakeSession(responder)
    ep = Endpoint("/documents/{id}", "GET", parameters=[Parameter("id", "path", example=1)])

    findings = auth_engine.run_bola_probes([ep], "https://api.example", session, cfg, timeout=5)

    bola = [f for f in findings if f.category == "bola"]
    assert len(bola) == 1
    # Verify the attacker's request actually hit /documents/42.
    attacker_calls = [
        c for c in session.calls
        if (c.get("headers") or {}).get("Authorization", "") == "Bearer attacker-token"
    ]
    assert any("/42" in c["url"] for c in attacker_calls)


def test_bola_no_finding_when_server_blocks_other_ids():
    """Properly authorized servers produce no BOLA finding."""
    owner_object = json.dumps({"id": 42, "name": "secret-doc"})

    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if "owner-token" in auth:
            return FakeResponse(200, owner_object)
        return FakeResponse(403, '{"error": "forbidden"}')

    profiles = [
        AuthProfile(name="owner", headers={"Authorization": "Bearer owner-token"}),
        AuthProfile(name="attacker", headers={"Authorization": "Bearer attacker-token"}),
        AuthProfile.anonymous(),
    ]
    cfg = AuthzConfig(
        profiles=profiles, owner_profile="owner", attacker_profile="attacker",
        enable_bfla=False, enable_bopla=False,
    )
    session = FakeSession(responder)
    ep = Endpoint("/documents/{id}", "GET", parameters=[Parameter("id", "path", example=1)])
    findings = auth_engine.run_bola_probes([ep], "https://api.example", session, cfg, timeout=5)
    assert findings == []


# --- JWT weak-HMAC break fix ------------------------------------------------


def test_weak_hmac_reports_single_finding_when_all_secrets_accepted():
    """A server accepting every forged secret yields ONE weak-HMAC finding.

    Regression: the reworked loop lost the break, producing up to 16
    duplicate findings for the same weakness.
    """
    valid_jwt = jwt_checks._sign_hs(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "user", "role": "user"},
        b"real-secret",
        "HS256",
    )

    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        if not headers.get("Authorization"):
            return FakeResponse(401, '{"error": "unauthorized"}')
        return FakeResponse(200, '{"data": "ok"}')

    session = FakeSession(responder)
    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {valid_jwt}",
        target_url="https://api.example/admin",
        target_method="GET",
        target_endpoint_path="/admin",
        baseline_status=200,
        session=session,
        timeout=5,
    )
    weak_hmac = [f for f in findings if "weak hmac" in f.technique.lower()]
    assert len(weak_hmac) == 1


def test_jwt_no_duplicate_return_statement():
    """Sanity: module-level probe function has a single exit (dead code removed)."""
    import inspect
    source = inspect.getsource(jwt_checks.run_jwt_attacks)
    assert source.count("return findings") == 1


# --- build_request $ref resolution fix -------------------------------------


def test_build_request_resolves_ref_schemas_with_resolver():
    """build_request generates real body values for $ref schemas when given a resolver."""
    spec = {
        "components": {
            "schemas": {
                "Item": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "qty": {"type": "integer"},
                    },
                    "required": ["name", "qty"],
                }
            }
        }
    }
    resolver = RefResolver(spec)
    ep = Endpoint(
        "/items", "POST",
        has_body=True,
        request_body=RequestBody(
            required=True,
            content={"application/json": MediaType(
                media_type="application/json",
                schema={"$ref": "#/components/schemas/Item"},
            )},
            primary_media_type="application/json",
        ),
    )
    prepared = build_request(ep, "https://api.example", resolver=resolver)
    assert prepared.body is not None
    body = json.loads(prepared.body)
    assert body["name"] == "test"
    assert body["qty"] == 1


def test_build_request_prefers_explicit_example_over_generation():
    """Explicit media examples win over generated values even when a schema exists."""
    ep = Endpoint(
        "/items", "POST",
        has_body=True,
        request_body=RequestBody(
            required=True,
            content={"application/json": MediaType(
                media_type="application/json",
                schema={"type": "object", "properties": {"name": {"type": "string"}}},
                example={"name": "explicit-example"},
            )},
            primary_media_type="application/json",
        ),
    )
    prepared = build_request(ep, "https://api.example")
    assert json.loads(prepared.body) == {"name": "explicit-example"}


# --- Comparators fast-path fixes -------------------------------------------


def test_similarity_fast_path_equal_bodies():
    """Equal bodies score 1.0 without invoking difflib (fast path)."""
    body = json.dumps({"data": "x" * 100000})
    c = comparators.compare_http_responses(
        baseline_status=200, baseline_headers={}, baseline_body=body,
        candidate_status=200, candidate_headers={}, candidate_body=body,
    )
    assert c.body_equal
    assert c.similarity == 1.0
    assert c.equivalent


def test_similarity_different_shapes_avoids_sequence_matcher():
    """Different JSON shapes use the cheap length-ratio estimate."""
    base = json.dumps({"items": ["x" * 50000]})
    cand = json.dumps({"error": "y"})
    c = comparators.compare_http_responses(
        baseline_status=200, baseline_headers={}, baseline_body=base,
        candidate_status=200, candidate_headers={}, candidate_body=cand,
    )
    assert not c.shape_equal
    assert c.similarity < 0.5
    assert not c.equivalent


def test_similarity_capped_for_large_same_shape_bodies():
    """Large same-shape bodies compare a bounded sample, not the full text."""
    base = json.dumps({"items": ["x" * 200000], "n": 1})
    cand = json.dumps({"items": ["x" * 200000], "n": 2})
    c = comparators.compare_http_responses(
        baseline_status=200, baseline_headers={}, baseline_body=base,
        candidate_status=200, candidate_headers={}, candidate_body=cand,
    )
    # Same shape, tiny difference -> high similarity either way.
    assert c.shape_equal
    assert c.similarity >= 0.97
    assert c.equivalent


# --- Engine run_fn wiring ---------------------------------------------------


def test_default_registry_checks_are_executable():
    """Wired checks run through their adapters and produce coerced Findings."""
    registry = engine.default_registry()
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"count": 1}'))
    ep = Endpoint(
        "/items", "GET",
        parameters=[Parameter("count", "query", schema_type="integer", example=10)],
    )
    result = engine.run_engine(
        [ep], "https://api.example", session,
        registry=registry,
        scan_mode="safe_active",
        timeout=5,
    )
    ran = {cr.check_id: cr for cr in result.check_results}
    # parser_confusion numeric-overflow fires on 2xx for numeric params.
    assert "parser_confusion" in ran
    assert ran["parser_confusion"].notes == "completed"
    assert len(result.findings) >= 1
    # All aggregated findings are analyzer.Finding instances (coerced).
    assert all(isinstance(f, Finding) for f in result.findings)


def test_engine_authz_checks_noop_without_profiles():
    """BOLA/BFLA/BOPLA adapters no-op on single-identity scans."""
    registry = engine.default_registry()
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/documents/{id}", "GET", parameters=[Parameter("id", "path", example=1)])
    result = engine.run_engine(
        [ep], "https://api.example", session,
        registry=registry,
        scan_mode="safe_active",
        timeout=5,
        auth_header="Bearer single-token",
        disabled_checks={"parser_confusion", "sspp"},
    )
    ran = {cr.check_id: cr for cr in result.check_results}
    for check in ("bola", "bfla", "bopla"):
        assert check in ran
        assert ran[check].findings == []
    authz_findings = [f for f in result.findings if f.category in ("bola", "bfla", "bopla")]
    assert authz_findings == []


def test_engine_honors_disabled_checks():
    registry = engine.default_registry()
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"count": 1}'))
    ep = Endpoint(
        "/items", "GET",
        parameters=[Parameter("count", "query", schema_type="integer", example=10)],
    )
    result = engine.run_engine(
        [ep], "https://api.example", session,
        registry=registry,
        scan_mode="safe_active",
        timeout=5,
        disabled_checks={"parser_confusion", "sspp", "resource_consumption"},
    )
    ran = {cr.check_id for cr in result.check_results}
    assert "parser_confusion" not in ran
    assert "sspp" not in ran
