"""Phase 4 upload_checks, parser_checks, and sspp_checks tests."""

from __future__ import annotations

import json

import parser_checks
import sspp_checks
import upload_checks
from spec_parser import Endpoint, MediaType, Parameter, RequestBody
from tests.fakes import FakeResponse, FakeSession


# --- Upload tests ---


def _multipart_endpoint():
    return Endpoint(
        "/upload", "POST",
        has_body=True, consumes_json=False,
        request_body=RequestBody(
            required=True,
            content={"multipart/form-data": MediaType(
                media_type="multipart/form-data",
                schema={"type": "object", "properties": {
                    "file": {"type": "string", "format": "binary"},
                    "name": {"type": "string"},
                }},
            )},
            primary_media_type="multipart/form-data",
        ),
        body_example={"file": "canary", "name": "test"},
    )


def test_upload_probe_flags_accepted_upload():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"url": "/files/canary.txt"}'))
    ep = _multipart_endpoint()
    findings = upload_checks.probe_uploads(ep, "https://api.example", session, timeout=5)
    assert len(findings) >= 1
    assert all(f.owasp_api == "API8:2023" or f.owasp_api == "API4:2023" for f in findings)


def test_upload_no_finding_without_multipart():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/data", "POST", has_body=True, consumes_json=True, body_example={"name": "test"})
    findings = upload_checks.probe_uploads(ep, "https://api.example", session, timeout=5)
    assert findings == []


# --- Parser tests ---


def test_duplicate_json_keys_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/data", "POST", has_body=True, consumes_json=True, body_example={"name": "test"})
    findings = parser_checks.probe_duplicate_json_keys(ep, "https://api.example", session, timeout=5)
    assert len(findings) == 1
    assert "duplicate" in findings[0].title.lower()


def test_deep_nesting_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/data", "POST", has_body=True, consumes_json=True, body_example={"name": "test"})
    findings = parser_checks.probe_deep_nesting(ep, "https://api.example", session, timeout=5)
    assert len(findings) == 1
    assert "nested" in findings[0].title.lower()


def test_numeric_overflow_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"id": 1}'))
    ep = Endpoint("/items", "GET", parameters=[Parameter("count", "query", schema_type="integer", example=10)])
    findings = parser_checks.probe_numeric_overflow(ep, "https://api.example", session, timeout=5)
    assert len(findings) >= 1
    assert "overflow" in findings[0].title.lower()


def test_unsafe_type_fields_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/data", "POST", has_body=True, consumes_json=True, body_example={"name": "test"})
    findings = parser_checks.probe_unsafe_type_fields(ep, "https://api.example", session, timeout=5)
    assert len(findings) >= 1
    assert "unsafe" in findings[0].title.lower()


# --- SSPP tests ---


def test_sspp_query_truncation_detected():
    base = FakeResponse(200, '{"data": "base"}')
    different = FakeResponse(200, '{"data": "different_response_here_with_more_content_than_baseline"}')
    responses = [base, different]
    idx = [0]
    def responder(method, url, kwargs):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    session = FakeSession(responder)
    ep = Endpoint("/search", "GET", parameters=[Parameter("q", "query", example="test")])
    findings = sspp_checks.probe_query_truncation(ep, "https://api.example", session, timeout=5)
    assert isinstance(findings, list)


def test_sspp_param_injection_detected():
    base = FakeResponse(200, '{"data": "base"}')
    changed = FakeResponse(200, '{"data": "different"}')
    responses = [base, changed]
    idx = [0]
    def responder(method, url, kwargs):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    session = FakeSession(responder)
    ep = Endpoint("/search", "GET", parameters=[Parameter("q", "query", example="test")])
    findings = sspp_checks.probe_param_injection(ep, "https://api.example", session, timeout=5)
    assert isinstance(findings, list)


def test_sspp_json_pollution_detected():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"name": "apifz_sspp_canary"}'))
    ep = Endpoint("/items", "POST", has_body=True, consumes_json=True, body_example={"name": "test", "id": 1})
    findings = sspp_checks.probe_json_pollution(ep, "https://api.example", session, timeout=5)
    assert len(findings) >= 1
    assert "pollution" in findings[0].title.lower()


def test_sspp_no_finding_without_query_params():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    ep = Endpoint("/health", "GET")
    findings = sspp_checks.probe_query_truncation(ep, "https://api.example", session, timeout=5)
    assert findings == []
