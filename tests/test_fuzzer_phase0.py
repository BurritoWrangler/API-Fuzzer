"""Phase 0 fuzzer regression tests: scan_mode default, no-target endpoints still
get a baseline, path-param substitution before specialized probes, scan
cancellation, request ledger/progress accounting, budget exhaustion counter,
passive-mode gating, finding->ledger linkage, and default-redacted to_dict.
"""

from __future__ import annotations

import fuzzer
from analyzer import Finding
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


def test_scan_config_defaults_to_safe_active():
    cfg = fuzzer.ScanConfig(base_url="https://api.example", categories=["sql_injection"])
    assert cfg.scan_mode == "safe_active"


def test_no_target_endpoint_still_gets_baseline(monkeypatch):
    endpoint = Endpoint(path="/health", method="GET", parameters=[])
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "ok", {"Content-Type": "application/json"})
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-notarget")
    fuzzer.run_scan(state, [endpoint], scan_config())
    snap = state.snapshot()
    assert state.status == "completed"
    # No injection targets -> endpoint counted as skipped for payload injection.
    assert snap["skipped_requests"] == 1
    # But a baseline request was still sent and accounted for in the ledger.
    assert snap["sent_requests"] == 1
    assert snap["succeeded_requests"] == 1
    assert snap["ledger_count"] == 1
    assert snap["completed_requests"] == 0  # no payloads
    assert snap["total_requests"] == 0      # estimate skips no-target endpoints
    assert len(session.calls) == 1
    assert session.calls[0]["url"].endswith("/health")


def test_path_params_substituted_before_specialized_probe(monkeypatch):
    endpoint = Endpoint(
        path="/users/{user_id}",
        method="GET",
        parameters=[Parameter("user_id", "path", schema_type="integer")],
    )
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "ok", {"Content-Type": "application/json"})
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-path")
    fuzzer.run_scan(state, [endpoint], scan_config(extra_method_override=True))
    urls = [c["url"] for c in session.calls]
    assert urls  # something ran
    # No unresolved template token should reach the wire.
    assert not any("{user_id}" in u for u in urls)
    # Baseline (and method-override probe) hit the resolved path /users/1.
    assert any(u.endswith("/users/1") for u in urls)


def test_scan_cancellation_stops_before_first_request(monkeypatch):
    endpoint = Endpoint(path="/search", method="GET", parameters=[Parameter("q", "query")])
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "You have an error in your SQL syntax")
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-cancel")
    state.cancel_event.set()
    fuzzer.run_scan(state, [endpoint], scan_config())
    snap = state.snapshot()
    assert state.status == "completed"
    assert snap["cancelled"] is True
    assert any("cancelled" in w.lower() for w in state.warnings)
    assert snap["completed_requests"] == 0
    assert len(session.calls) == 0


def test_ledger_and_progress_accounting(monkeypatch):
    endpoint = Endpoint(path="/search", method="GET", parameters=[Parameter("q", "query")])

    def responder(method, url, kwargs):
        query = kwargs.get("params") or {}
        if query.get("q") == "test":
            return FakeResponse(200, "baseline", {"Content-Type": "application/json"})
        return FakeResponse(200, "You have an error in your SQL syntax", {"Content-Type": "text/plain"})

    session = FakeSession(responder)
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-ledger")
    fuzzer.run_scan(state, [endpoint], scan_config())
    snap = state.snapshot()
    assert snap["planned_requests"] == 12
    assert snap["total_requests"] == 12
    assert snap["completed_requests"] == 12
    # 1 baseline + 12 payloads, all accounted for in the ledger.
    assert snap["sent_requests"] == 13
    assert snap["succeeded_requests"] == 13
    assert snap["ledger_count"] == 13
    assert snap["budget_exhausted"] == 0
    assert snap["skipped_requests"] == 0
    assert snap["scan_mode"] == "safe_active"


def test_findings_reference_ledger_entries(monkeypatch):
    endpoint = Endpoint(path="/search", method="GET", parameters=[Parameter("q", "query")])
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "You have an error in your SQL syntax")
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-link")
    fuzzer.run_scan(state, [endpoint], scan_config())
    assert state.findings
    # Every emitted finding references a ledger entry index and a prepared URL.
    for finding in state.findings:
        assert finding.ledger_index is not None
        assert finding.request_url.startswith("https://api.example/search?q=")
        assert finding.check_id == "sql_injection"
        assert finding.safety_level == "safe_active"
        assert finding.owasp_api == "API3:2023"
        assert finding.cwe == "CWE-89"


def test_budget_exhaustion_counter(monkeypatch):
    endpoint = Endpoint(path="/search", method="GET", parameters=[Parameter("q", "query")])
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "You have an error in your SQL syntax")
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-budget2")
    fuzzer.run_scan(state, [endpoint], scan_config(max_requests=2))
    snap = state.snapshot()
    assert snap["completed_requests"] == 2
    assert snap["budget_exhausted"] == 10  # 12 planned - 2 sent
    assert snap["sent_requests"] == 3       # 1 baseline + 2 payloads
    assert any("Request budget (2) reached" in w for w in state.warnings)


def test_passive_mode_skips_payload_injection(monkeypatch):
    endpoint = Endpoint(path="/search", method="GET", parameters=[Parameter("q", "query")])
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "ok", {"Content-Type": "application/json"})
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-passive")
    fuzzer.run_scan(state, [endpoint], scan_config(scan_mode="passive"))
    snap = state.snapshot()
    assert state.status == "completed"
    assert snap["scan_mode"] == "passive"
    # Passive mode: baseline runs, active injection is skipped.
    assert snap["completed_requests"] == 0
    assert snap["sent_requests"] == 1
    assert len(state.findings) == 0


def test_emitted_findings_are_redacted_in_to_dict(monkeypatch):
    endpoint = Endpoint(path="/search", method="GET", parameters=[Parameter("q", "query")])
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "You have an error in your SQL syntax")
    )
    monkeypatch.setattr(fuzzer, "UASession", lambda mode, custom: session)
    state = fuzzer.ScanState(scan_id="scan-redact")
    fuzzer.run_scan(state, [endpoint], scan_config(auth_header="Bearer s3cr3t"))
    assert state.findings
    d = state.findings[0].to_dict()
    # The auth header on recorded findings must be redacted by default.
    assert d["request_headers"].get("Authorization", "") in ("Bearer [REDACTED]", "")
    assert "s3cr3t" not in d["raw_request"]
    # The exact raw value is available via the opt-in.
    raw = state.findings[0].to_raw_dict()
    assert raw["request_headers"]["Authorization"] == "Bearer s3cr3t"


def test_build_path_delegates_to_request_builder():
    # Backward-compatible helper still produces identical encoding.
    path = fuzzer._build_path("/u/{id}/f/{name}", {"id": 42, "name": "../report file"})
    assert path == "/u/42/f/..%2Freport%20file"
