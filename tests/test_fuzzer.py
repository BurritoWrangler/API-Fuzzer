import fuzzer

from spec_parser import Endpoint, Parameter
from tests.fakes import FakeResponse, FakeSession


def scan_config(**overrides):
    values = {
        "base_url": "https://api.example",
        "categories": ["sql_injection"],
        "timeout": 1.0,
        "max_requests": 100,
        "detect_misconfig": False,
        "extra_mass_assignment": False,
        "extra_hpp": False,
        "extra_method_override": False,
        "extra_content_type_confusion": False,
        "extra_open_redirect": False,
        "extra_canary_reflection": False,
        "jwt_attacks": False,
        "schema_violations": False,
        "rate_limit_probe": False,
        "api_version_inventory": False,
    }
    values.update(overrides)
    return fuzzer.ScanConfig(**values)


def test_build_path_quotes_injected_values():
    path = fuzzer._build_path(
        "/users/{user_id}/files/{name}",
        {"user_id": 42, "name": "../report file"},
    )

    assert path == "/users/42/files/..%2Freport%20file"


def test_injection_targets_include_nested_body_types():
    endpoint = Endpoint(
        path="/items/{item_id}",
        method="POST",
        parameters=[
            Parameter("item_id", "path", schema_type="integer"),
            Parameter("trace", "header", schema_type="string"),
        ],
        has_body=True,
        body_example={
            "enabled": True,
            "price": 1.5,
            "nested": {"count": 1},
            "items": [{"name": "first"}],
        },
    )

    targets = fuzzer._injection_targets(endpoint)
    by_name = {target["name"]: target for target in targets}

    assert by_name["item_id"]["schema_type"] == "integer"
    assert by_name["trace"]["location"] == "header"
    assert by_name["enabled"]["schema_type"] == "boolean"
    assert by_name["price"]["schema_type"] == "number"
    assert by_name["nested.count"]["schema_type"] == "integer"
    assert by_name["items[0].name"]["schema_type"] == "string"


def test_set_body_leaf_handles_dicts_and_lists():
    body = {"items": [{"name": "first"}], "meta": {"enabled": True}}

    fuzzer._set_body_leaf(body, "items[0].name", "changed")
    fuzzer._set_body_leaf(body, "meta.enabled", False)

    assert body == {
        "items": [{"name": "changed"}],
        "meta": {"enabled": False},
    }


def test_request_estimate_uses_parameter_type_for_type_juggling():
    endpoint = Endpoint(
        path="/flags",
        method="GET",
        parameters=[Parameter("enabled", "query", schema_type="boolean")],
    )

    total = fuzzer.estimate_total_requests(
        [endpoint],
        ["auth_bypass", "type_juggling"],
    )

    assert total == 6 + 17


def test_run_scan_executes_payloads_and_records_findings(monkeypatch):
    endpoint = Endpoint(
        path="/search",
        method="GET",
        parameters=[Parameter("q", "query")],
    )

    def responder(method, url, kwargs):
        query = kwargs.get("params") or {}
        if query.get("q") == "test":
            return FakeResponse(200, "baseline", {"Content-Type": "application/json"})
        return FakeResponse(
            200,
            "You have an error in your SQL syntax",
            {"Content-Type": "text/plain"},
        )

    session = FakeSession(responder)
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-1")

    fuzzer.run_scan(state, [endpoint], scan_config())

    assert state.status == "completed"
    assert state.total_requests == 12
    assert state.completed_requests == 12
    assert len(state.findings) == 12
    assert all(finding.severity == "critical" for finding in state.findings)
    assert len(session.calls) == 13
    assert state.snapshot()["severity_counts"]["critical"] == 12


def test_run_scan_honors_payload_budget(monkeypatch):
    endpoint = Endpoint(
        path="/search",
        method="GET",
        parameters=[Parameter("q", "query")],
    )
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(
            200,
            "You have an error in your SQL syntax",
        )
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-budget")

    fuzzer.run_scan(state, [endpoint], scan_config(max_requests=2))

    assert state.status == "completed"
    assert state.completed_requests == 2
    assert len(state.findings) == 2
    assert any("Request budget (2) reached" in warning for warning in state.warnings)


def test_raw_body_endpoint_is_an_injection_target():
    endpoint = Endpoint(
        path="/raw",
        method="POST",
        has_body=True,
        body_example=None,
    )

    assert fuzzer._injection_targets(endpoint) == [
        {
            "name": "<body>",
            "location": "body",
            "kind": "raw_body",
            "schema_type": "string",
        }
    ]
