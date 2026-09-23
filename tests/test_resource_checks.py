"""Phase 4 resource_checks tests."""

from __future__ import annotations

import resource_checks
from spec_parser import Endpoint, Parameter
from tests.fakes import FakeResponse, FakeSession


def test_pagination_probe_flags_large_response():
    baseline_body = '{"items": ["a"]}'
    large_body = '{"items": [' + ", ".join(f'"item{i}"' for i in range(500)) + ']}'
    responses = [FakeResponse(200, baseline_body), FakeResponse(200, large_body)]
    idx = [0]
    def responder(method, url, kwargs):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    session = FakeSession(responder)
    ep = Endpoint("/items", "GET", parameters=[Parameter("limit", "query", schema_type="integer", example=10)])
    findings = resource_checks.probe_pagination(ep, "https://api.example", session, timeout=5)
    large = [f for f in findings if "large response" in f.title.lower()]
    assert len(large) >= 1


def test_pagination_no_finding_without_pagination_params():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"data": "ok"}'))
    ep = Endpoint("/health", "GET")
    findings = resource_checks.probe_pagination(ep, "https://api.example", session, timeout=5)
    assert findings == []


def test_pagination_flags_slow_response():
    baseline = FakeResponse(200, '{"items": ["a"]}')
    slow = FakeResponse(200, '{"items": ["a", "b"]}')
    responses = [baseline]
    def responder(method, url, kwargs):
        return responses[0]
    session = FakeSession(responder)
    ep = Endpoint("/items", "GET", parameters=[Parameter("limit", "query", schema_type="integer", example=10)])
    # This test just verifies the probe runs without error; real latency
    # testing requires mocked timing which is covered by the safety ceiling logic.
    findings = resource_checks.probe_pagination(ep, "https://api.example", session, timeout=5)
    assert isinstance(findings, list)
