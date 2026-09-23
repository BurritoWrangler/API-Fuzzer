"""Phase 6 workflow_engine, inventory, and kali_adapters tests."""

from __future__ import annotations

import json

import inventory
import kali_adapters
import workflow_engine
from inventory import ObservedEndpoint
from tests.fakes import FakeResponse, FakeSession


# --- Workflow engine tests ---


def test_workflow_parsing_and_execution():
    workflow_yaml = """
steps:
  - id: create
    method: POST
    path: /items
    body: {name: test-item}
    extract: {item_id: id}
    assertions:
      - status == 201
  - id: verify
    method: GET
    path: /items/${item_id}
    assertions:
      - status == 200
      - var:item_id is not None
"""
    workflow = workflow_engine.load_workflow(workflow_yaml)
    steps = workflow_engine.parse_steps(workflow)
    assert len(steps) == 2
    assert steps[0].id == "create"
    assert steps[0].method == "POST"
    assert steps[1].path == "/items/${item_id}"


def test_workflow_executes_and_extracts_variables():
    create_resp = FakeResponse(201, json.dumps({"id": 42, "name": "test-item"}))
    verify_resp = FakeResponse(200, json.dumps({"id": 42, "name": "test-item"}))
    responses = [create_resp, verify_resp]
    idx = [0]
    def responder(method, url, kwargs):
        r = responses[min(idx[0], len(responses) - 1)]
        idx[0] += 1
        return r
    session = FakeSession(responder)

    steps = [
        workflow_engine.WorkflowStep(id="create", method="POST", path="/items",
                                    body={"name": "test"}, extract={"item_id": "id"},
                                    assertions=["status == 201"]),
        workflow_engine.WorkflowStep(id="verify", method="GET", path="/items/${item_id}",
                                    assertions=["status == 200", "var:item_id is not None"]),
    ]
    report = workflow_engine.execute_workflow(steps, base_url="https://api.example",
                                               session=session, timeout=5)
    assert report.completed
    assert report.variables.get("item_id") == 42
    assert all(r.success for r in report.results)


def test_workflow_detects_assertion_failure():
    session = FakeSession(lambda m, u, k: FakeResponse(404, '{"error": "not found"}'))
    steps = [
        workflow_engine.WorkflowStep(id="get", method="GET", path="/items/999",
                                    assertions=["status == 200"]),
    ]
    report = workflow_engine.execute_workflow(steps, base_url="https://api.example",
                                               session=session, timeout=5)
    assert not report.completed or any(r.assertions_failed > 0 for r in report.results)
    assert len(report.findings) >= 1


def test_workflow_skip_if():
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"token": "abc123"}'))
    steps = [
        workflow_engine.WorkflowStep(id="step1", method="GET", path="/first",
                                    extract={"token": "token"}),
        workflow_engine.WorkflowStep(id="step2", method="GET", path="/second",
                                    skip_if="var:token"),
    ]
    report = workflow_engine.execute_workflow(steps, base_url="https://api.example",
                                               session=session, timeout=5)
    assert report.results[1].success
    assert report.results[1].assertions_passed == 1


def test_workflow_too_many_steps():
    raw = {"steps": [{"id": f"s{i}", "path": "/x"} for i in range(250)]}
    try:
        workflow_engine.parse_steps(raw)
        assert False, "Should have raised"
    except ValueError as exc:
        assert "too many" in str(exc).lower()


# --- Inventory tests ---


def test_inventory_detects_shadow_endpoint():
    documented = [ObservedEndpoint(method="GET", path="/users/{id}")]
    observed = [ObservedEndpoint(method="GET", path="/admin", status_code=200, source="discovered")]
    delta = inventory.compare_inventory(documented, observed)
    assert len(delta.observed_only) == 1
    shadow_findings = [f for f in delta.findings if "shadow" in f.lower() or "undocumented" in f.lower()]
    assert len(shadow_findings) >= 1


def test_inventory_detects_method_discrepancy():
    documented = [ObservedEndpoint(method="GET", path="/users/{id}")]
    observed = [ObservedEndpoint(method="GET", path="/users/1", source="spec"),
                 ObservedEndpoint(method="DELETE", path="/users/1", source="discovered")]
    delta = inventory.compare_inventory(documented, observed)
    assert len(delta.method_discrepancies) == 1
    assert "DELETE" in delta.findings[0]


def test_inventory_detects_documented_only():
    documented = [ObservedEndpoint(method="GET", path="/health")]
    observed = []
    delta = inventory.compare_inventory(documented, observed)
    assert len(delta.documented_only) == 1
    assert "not observed" in delta.findings[0].lower()


def test_inventory_no_delta_when_matching():
    documented = [ObservedEndpoint(method="GET", path="/users/{id}")]
    observed = [ObservedEndpoint(method="GET", path="/users/1", source="spec")]
    delta = inventory.compare_inventory(documented, observed)
    assert delta.observed_only == []
    assert delta.method_discrepancies == []


def test_inventory_flags_sensitive_exposure():
    documented = [ObservedEndpoint(method="GET", path="/users/{id}")]
    observed = [ObservedEndpoint(method="GET", path="/secrets", status_code=200,
                                 source="discovered", sensitive=True)]
    delta = inventory.compare_inventory(documented, observed)
    sensitive_findings = [f for f in delta.findings if "sensitive" in f.lower()]
    assert len(sensitive_findings) >= 1


# --- Kali adapter tests ---


def test_kali_available_tools_returns_dict():
    tools = kali_adapters.available_tools()
    assert isinstance(tools, dict)
    assert "testssl.sh" in tools
    assert "grpcurl" in tools
    assert "nmap" in tools


def test_kali_testssl_skips_when_unavailable():
    findings = kali_adapters.probe_testssl("example.com")
    if not kali_adapters._tool_available("testssl.sh"):
        assert len(findings) == 1
        assert findings[0].skipped is True
    else:
        assert isinstance(findings, list)


def test_kali_ffuf_skips_when_unavailable():
    findings = kali_adapters.probe_ffuf("https://api.example")
    if not kali_adapters._tool_available("ffuf"):
        assert len(findings) == 1
        assert findings[0].skipped is True


def test_kali_nmap_skips_when_unavailable():
    findings = kali_adapters.probe_nmap_scripts("example.com")
    if not kali_adapters._tool_available("nmap"):
        assert len(findings) == 1
        assert findings[0].skipped is True
