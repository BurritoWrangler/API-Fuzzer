"""Phase 5 graphql_adapter, blind_checks, and protocol_adapters tests."""

from __future__ import annotations

import json

import blind_checks
import graphql_adapter
import protocol_adapters
from oast import DisabledOASTProvider, MemoryOASTProvider
from spec_parser import Endpoint, Parameter
from tests.fakes import FakeResponse, FakeSession


# --- GraphQL tests ---


def test_introspection_detected():
    schema_response = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}})
    session = FakeSession(lambda m, u, k: FakeResponse(200, schema_response))
    findings = graphql_adapter.probe_introspection("https://api.example/graphql", session, timeout=5)
    assert len(findings) == 1
    assert "introspection" in findings[0].title.lower()


def test_introspection_no_finding_when_disabled():
    session = FakeSession(lambda m, u, k: FakeResponse(403, '{"errors": [{"message": "introspection disabled"}]}'))
    findings = graphql_adapter.probe_introspection("https://api.example/graphql", session, timeout=5)
    assert findings == []


def test_graphiql_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, "<html><title>GraphiQL</title></html>"))
    findings = graphql_adapter.probe_graphiql("https://api.example/graphql", session, timeout=5)
    assert len(findings) == 1
    assert "graphiql" in findings[0].title.lower()


def test_batching_dos_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": [{"__typename": "Query"}]}'))
    findings = graphql_adapter.probe_batching("https://api.example/graphql", session, timeout=5)
    assert len(findings) == 1
    assert "batch" in findings[0].title.lower()


def test_get_mutation_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": {"createUser": {"id": 1}}}'))
    findings = graphql_adapter.probe_get_mutation("https://api.example/graphql", session, timeout=5)
    assert len(findings) == 1
    assert "mutation" in findings[0].title.lower()
    assert findings[0].severity == "high"


# --- Blind OAST tests ---


def test_blind_ssrf_with_disabled_oast_returns_empty():
    oast = DisabledOASTProvider()
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/fetch", "POST", parameters=[Parameter("url", "query")], has_body=False)
    findings = blind_checks.probe_blind_ssrf(ep, "https://api.example", session, 5, oast)
    assert findings == []


def test_blind_ssrf_with_memory_oast_detects_callback():
    oast = MemoryOASTProvider(domain="oast.invalid")

    def responder(method, url, kwargs):
        # Record a callback for whichever token the probe just allocated.
        # The probe allocates internally; we inspect the last OAST allocation
        # via the provider's internal state to correlate the callback.
        for token in list(oast._interactions.keys()):
            oast.record_interaction(token, protocol="http", remote_address="10.0.0.1")
        return FakeResponse(200, '{"ok": true}', url=kwargs.get("url", ""))

    session = FakeSession(responder)
    ep = Endpoint("/fetch", "POST", parameters=[Parameter("url", "query")], has_body=False)
    findings = blind_checks.probe_blind_ssrf(ep, "https://api.example", session, 5, oast)
    assert len(findings) >= 1
    assert findings[0].confidence == "confirmed"
    assert findings[0].callback_received is True


def test_blind_command_injection_with_memory_oast():
    oast = MemoryOASTProvider(domain="oast.invalid")

    def responder(method, url, kwargs):
        # Record a DNS callback for whichever token the probe allocated.
        for token in list(oast._interactions.keys()):
            oast.record_interaction(token, protocol="dns")
        return FakeResponse(200, '{"results": []}')

    session = FakeSession(responder)
    ep = Endpoint("/search", "GET", parameters=[Parameter("q", "query", example="test")])
    findings = blind_checks.probe_blind_command_injection(ep, "https://api.example", session, 5, oast)
    assert len(findings) >= 1
    assert findings[0].severity == "critical"


def test_blind_xxe_with_disabled_oast():
    oast = DisabledOASTProvider()
    session = FakeSession(lambda m, u, k: FakeResponse(200, "<foo>data</foo>"))
    ep = Endpoint("/data", "POST", has_body=True, consumes_json=False, body_example={"data": "test"})
    findings = blind_checks.probe_blind_xxe(ep, "https://api.example", session, 5, oast)
    assert findings == []


# --- Protocol adapter tests ---


def test_protocol_adapters_return_clean_skip_when_tools_absent():
    # These tools are likely not installed in the test env, so adapters should skip cleanly
    findings = protocol_adapters.run_protocol_checks("https://api.example")
    # Should return only informational skips or nothing
    for f in findings:
        assert f.confidence == "informational" or f.skipped is True


def test_grpc_adapter_gated_on_capability():
    findings = protocol_adapters.probe_grpc_reflection("https://api.example:50051")
    if protocol_adapters.grpc_available():
        assert len(findings) >= 1
    else:
        assert findings == []


def test_soap_adapter_wsdl_detection():
    """SOAP adapter exposes WSDL when the definition document is served."""
    session = FakeSession(lambda m, u, k: FakeResponse(200, "<wsdl:definitions></wsdl:definitions>"))
    findings = protocol_adapters.probe_soap_wsdl("https://api.example/soap", session, timeout=5)
    assert len(findings) == 1
    assert findings[0].protocol == "soap"
    assert findings[0].confidence == "strong"


def test_soap_adapter_clean_when_wsdl_absent():
    session = FakeSession(lambda m, u, k: FakeResponse(404, "not found"))
    findings = protocol_adapters.probe_soap_wsdl("https://api.example/soap", session, timeout=5)
    assert findings == []
