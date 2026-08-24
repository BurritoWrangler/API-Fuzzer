"""Phase 3 response_contract tests."""

from __future__ import annotations

import json

import response_contract
from response_contract import ResponseContractFinding
from spec_parser import Endpoint, MediaType, Response, SecurityRequirement
from tests.fakes import FakeResponse, FakeSession


def _ep_with_schema(path="/items/{id}", schema=None, security=None):
    responses = {}
    if schema:
        responses["200"] = Response(
            status_code="200",
            content={"application/json": MediaType(media_type="application/json", schema=schema)},
        )
    return Endpoint(
        path=path, method="GET",
        parameters=[__import__("spec_parser").Parameter("id", "path", example=1)],
        responses=responses,
        security=security or [],
    )


def test_validate_response_flags_type_mismatch():
    schema = {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}, "required": ["id"]}
    ep = _ep_with_schema(schema=schema)
    body = json.dumps({"id": "not-an-integer", "name": "test"})
    findings = response_contract.validate_response(ep, 200, {"Content-Type": "application/json"}, body, "https://api.example/items/1")
    type_issues = [f for f in findings if f.category == "contract_violation" and "type" in f.title]
    assert len(type_issues) >= 1
    assert type_issues[0].confidence == "strong"


def test_validate_response_flags_missing_required():
    schema = {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id", "name"]}
    ep = _ep_with_schema(schema=schema)
    body = json.dumps({"id": 1})
    findings = response_contract.validate_response(ep, 200, {"Content-Type": "application/json"}, body, "https://api.example/items/1")
    required_issues = [f for f in findings if "required" in f.title.lower()]
    assert len(required_issues) >= 1


def test_validate_response_clean_when_matching():
    schema = {"type": "object", "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}, "required": ["id"]}
    ep = _ep_with_schema(schema=schema)
    body = json.dumps({"id": 1, "name": "test"})
    findings = response_contract.validate_response(ep, 200, {"Content-Type": "application/json"}, body, "https://api.example/items/1")
    assert findings == []


def test_validate_response_detects_sensitive_data():
    schema = {"type": "object", "properties": {"id": {"type": "integer"}, "api_key": {"type": "string"}}}
    ep = _ep_with_schema(schema=schema)
    body = json.dumps({"id": 1, "api_key": "AKIAIOSFODNN7EXAMPLE"})
    findings = response_contract.validate_response(ep, 200, {"Content-Type": "application/json"}, body, "https://api.example/items/1")
    exposure = [f for f in findings if f.category == "data_exposure"]
    assert len(exposure) >= 1
    # Secrets should be redacted in evidence
    assert "AKIAIOSFODNN7EXAMPLE" not in exposure[0].evidence


def test_validate_response_no_schema_returns_empty():
    ep = _ep_with_schema(schema=None)
    findings = response_contract.validate_response(ep, 200, {}, '{"id": 1}', "https://api.example/items/1")
    assert findings == []


def test_compare_exposure_between_identities_flags_extra_sensitive():
    ep = _ep_with_schema()
    owner_body = json.dumps({"id": 1, "name": "alice"})
    other_body = json.dumps({"id": 1, "name": "alice", "balance": 9999, "role": "admin"})
    findings = response_contract.compare_exposure_between_identities(
        ep, owner_body, other_body, "owner", "attacker", "https://api.example/items/1",
    )
    assert len(findings) >= 1
    params = {f.parameter for f in findings}
    assert "balance" in params or "role" in params


def test_check_security_requirement_flags_anonymous_access():
    ep = _ep_with_schema(security=[SecurityRequirement(schemes={"bearerAuth": []})])
    finding = response_contract.check_security_requirement(ep, 200, "https://api.example/admin")
    assert finding is not None
    assert finding.category == "missing_auth"
    assert finding.owasp_api == "API2:2023"
    assert "anonymous" in finding.title.lower()


def test_check_security_requirement_no_finding_when_anonymous_blocked():
    ep = _ep_with_schema(security=[SecurityRequirement(schemes={"bearerAuth": []})])
    finding = response_contract.check_security_requirement(ep, 401, "https://api.example/admin")
    assert finding is None


def test_check_security_requirement_no_finding_when_no_security():
    ep = _ep_with_schema(security=[])
    finding = response_contract.check_security_requirement(ep, 200, "https://api.example/public")
    assert finding is None
