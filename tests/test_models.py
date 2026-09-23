"""Phase 0 model tests: scan modes, safety, confidence, auth profiles,
request templates/prepared requests, response observations, and the request ledger.
"""

from __future__ import annotations

import threading

from models import (
    AuthProfile,
    CheckResult,
    Confidence,
    CONFIDENCE_ORDER,
    DEFAULT_SCAN_MODE,
    LedgerEntry,
    PreparedRequest,
    RequestLedger,
    RequestTemplate,
    ResponseObservation,
    SafetyLevel,
    ScanMode,
    VALID_SCAN_MODES,
    normalize_confidence,
    normalize_scan_mode,
    safety_allowed,
)


def test_scan_mode_defaults_and_validation():
    assert DEFAULT_SCAN_MODE == "safe_active"
    assert VALID_SCAN_MODES == frozenset({"passive", "safe_active", "intrusive"})
    assert normalize_scan_mode("passive") == "passive"
    assert normalize_scan_mode("safe_active") == "safe_active"
    assert normalize_scan_mode("intrusive") == "intrusive"
    # Unknown modes fall back to the default.
    assert normalize_scan_mode("nope") == DEFAULT_SCAN_MODE
    assert normalize_scan_mode("") == DEFAULT_SCAN_MODE


def test_safety_allowed_gates_by_scan_mode():
    assert safety_allowed("passive", "passive") is True
    assert safety_allowed("safe_active", "passive") is False
    assert safety_allowed("intrusive", "passive") is False
    assert safety_allowed("passive", "safe_active") is True
    assert safety_allowed("safe_active", "safe_active") is True
    assert safety_allowed("intrusive", "safe_active") is False
    assert safety_allowed("intrusive", "intrusive") is True
    # Unknown safety defaults to safe_active; unknown mode to safe_active ceiling.
    assert safety_allowed("bogus", "safe_active") is True
    assert safety_allowed("bogus", "passive") is False


def test_confidence_order_and_normalization():
    assert CONFIDENCE_ORDER == (
        "confirmed", "high", "medium", "low", "informational",
    )
    assert normalize_confidence("high") == "high"
    assert normalize_confidence("confirmed") == "confirmed"
    assert normalize_confidence("CONFIRMED") == "informational"  # case-sensitive lookup
    assert normalize_confidence("??") == "informational"
    # str-enum values compare to plain strings (JSON-friendly).
    assert Confidence.HIGH == "high"


def test_auth_profile_anonymous_and_from_header():
    anon = AuthProfile.anonymous()
    assert anon.is_anonymous is True
    assert anon.name == "anonymous"

    bare = AuthProfile.from_header("user-a", "Bearer eyJabc")
    assert bare.is_anonymous is False
    assert bare.headers == {"Authorization": "Bearer eyJabc"}

    prefixed = AuthProfile.from_header("user-b", "Authorization: Basic dXNlcjpwYXNz")
    assert prefixed.headers == {"Authorization": "Basic dXNlcjpwYXNz"}

    empty = AuthProfile.from_header("user-c", "")
    assert empty.is_anonymous is True


def test_request_template_and_prepared_request_roundtrip():
    tmpl = RequestTemplate(
        method="get",
        path="/items/{id}",
        base_url="https://api.example",
        path_params={"id": 7},
        query_params={"q": "a b"},
    )
    assert tmpl.method == "GET" or tmpl.method == "get"
    pr = PreparedRequest(
        method="GET",
        url="https://api.example/items/7",
        query_params={"q": "a b"},
        encoded_url="https://api.example/items/7?q=a+b",
    )
    # encoded_url defaults to url when not supplied.
    pr2 = PreparedRequest(method="GET", url="https://api.example/x")
    assert pr2.encoded_url == "https://api.example/x"
    d = pr.to_dict()
    assert d["method"] == "GET"
    assert d["url"] == "https://api.example/items/7?q=a+b"


def test_response_observation_to_dict():
    obs = ResponseObservation(
        status_code=200, headers={"Content-Type": "application/json"},
        body="{}", latency_ms=12, url="https://api.example/x",
    )
    d = obs.to_dict()
    assert d["status_code"] == 200
    assert d["latency_ms"] == 12
    assert d["headers"] == {"Content-Type": "application/json"}


def test_request_ledger_records_and_counts():
    ledger = RequestLedger()
    e1 = ledger.record(method="GET", url="https://api.example/a", check_id="baseline", outcome=RequestLedger.OUTCOME_SUCCEEDED, status_code=200)
    e2 = ledger.record(method="GET", url="https://api.example/b", check_id="sql_injection", outcome=RequestLedger.OUTCOME_SUCCEEDED, status_code=500)
    e3 = ledger.record(method="GET", url="https://api.example/c", check_id="sql_injection", outcome=RequestLedger.OUTCOME_FAILED, error="timeout")
    assert e1.index == 0
    assert e2.index == 1
    assert e3.index == 2
    assert len(ledger) == 3
    summary = ledger.summary()
    assert summary["ledger_count"] == 3
    assert summary["sent"] == 3  # succeeded + failed
    assert summary["succeeded"] == 2
    assert summary["failed"] == 1
    snap = ledger.snapshot()
    assert len(snap) == 3
    assert snap[0]["outcome"] == "succeeded"


def test_request_ledger_trims_to_max_entries():
    ledger = RequestLedger(max_entries=3)
    for i in range(5):
        ledger.record(method="GET", url=f"https://api.example/{i}")
    assert len(ledger) == 3
    snap = ledger.snapshot()
    # The last 3 entries are retained (indices 2, 3, 4).
    assert [e["index"] for e in snap] == [2, 3, 4]


def test_request_ledger_is_thread_safe():
    ledger = RequestLedger()

    def worker():
        for i in range(50):
            ledger.record(method="GET", url=f"https://api.example/{i}")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ledger) == 200


def test_check_result_to_dict():
    cr = CheckResult(check_id="sql_injection", findings=[1, 2], request_count=3, safety_level="safe_active", owasp_api="API3:2023", cwe="CWE-89")
    d = cr.to_dict()
    assert d["check_id"] == "sql_injection"
    assert d["findings_count"] == 2
    assert d["request_count"] == 3
    assert d["owasp_api"] == "API3:2023"
