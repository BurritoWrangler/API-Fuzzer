from analyzer import (
    Finding,
    analyze,
    capture_body,
    format_raw_http_request,
    severity_counts,
    sort_findings,
    url_with_query,
)


def analyze_response(**overrides):
    values = {
        "category": "sql_injection",
        "payload": "'",
        "technique": "error probe",
        "endpoint_path": "/search",
        "method": "GET",
        "parameter": "q",
        "location": "query",
        "request_url": "https://api.example/search?q=%27",
        "request_headers": {"X-Test": "yes"},
        "request_body": None,
        "status_code": 200,
        "response_text": "",
        "response_time_ms": 20,
        "baseline_time_ms": 10,
        "response_headers": {},
    }
    values.update(overrides)
    return analyze(**values)


def test_url_with_query_handles_scalars_and_repeated_values():
    url = url_with_query(
        "https://api.example/items?existing=1",
        {"q": "a b", "tag": ["one", "two"]},
    )

    assert url == (
        "https://api.example/items?existing=1"
        "&q=a+b&tag=one&tag=two"
    )


def test_format_raw_http_request_adds_replay_headers_and_body():
    raw = format_raw_http_request(
        "post",
        "https://api.example/items?dry_run=true",
        {"Authorization": "Bearer token"},
        '{"name":"test"}',
    )

    assert raw.startswith("POST /items?dry_run=true HTTP/1.1\r\n")
    assert "Host: api.example\r\n" in raw
    assert "Authorization: Bearer token\r\n" in raw
    assert "Content-Type: application/json\r\n" in raw
    assert "Content-Length: 15\r\n" in raw
    assert raw.endswith('\r\n\r\n{"name":"test"}')


def test_finding_populates_raw_request():
    finding = Finding(
        severity="low",
        category="test",
        title="Test",
        endpoint="/health",
        method="GET",
        parameter="<n/a>",
        location="request",
        payload="",
        technique="test",
        evidence="test",
        status_code=200,
        response_time_ms=1,
        request_url="https://api.example/health",
    )

    assert finding.raw_request.startswith("GET /health HTTP/1.1\r\n")
    assert finding.to_dict()["title"] == "Test"


def test_sql_error_signature_is_critical():
    findings = analyze_response(
        response_text="You have an error in your SQL syntax near 'x'",
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].title == "SQL error disclosed in response"


def test_time_based_sql_detection_uses_baseline_delta():
    findings = analyze_response(
        payload="' AND SLEEP(5)--",
        technique="time-based blind",
        response_time_ms=5010,
        baseline_time_ms=50,
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "time-based" in findings[0].title.lower()


def test_reflected_xss_is_detected():
    findings = analyze_response(
        category="xss",
        payload="<script>alert(1)</script>",
        technique="classic script tag",
        response_text="<html><script>alert(1)</script></html>",
    )

    assert [(finding.severity, finding.category) for finding in findings] == [
        ("high", "xss")
    ]


def test_open_redirect_uses_location_header():
    findings = analyze_response(
        category="open_redirect",
        payload="https://evil.example.com/",
        technique="absolute URL",
        status_code=302,
        response_headers={"Location": "https://evil.example.com/login"},
    )

    assert len(findings) == 1
    assert findings[0].title == "Open redirect to attacker-controlled host"


def test_generic_server_error_is_low_severity():
    findings = analyze_response(
        category="ldap_injection",
        response_text="unexpected failure",
        status_code=503,
    )

    assert len(findings) == 1
    assert findings[0].severity == "low"


def test_sensitive_data_sweep_runs_for_every_category():
    findings = analyze_response(
        category="xss",
        response_text="-----BEGIN PRIVATE KEY-----\nsecret",
    )

    assert any("Sensitive data disclosed" in finding.title for finding in findings)


def test_capture_body_marks_truncation():
    captured, truncated = capture_body("abcdefghij", limit=5)

    assert captured.startswith("abcde")
    assert "truncated" in captured
    assert truncated is True


def test_sort_and_count_findings_by_severity():
    low = analyze_response(category="ldap_injection", status_code=500)[0]
    critical = analyze_response(
        response_text="You have an error in your SQL syntax",
    )[0]

    ordered = sort_findings([low, critical])

    assert [finding.severity for finding in ordered] == ["critical", "low"]
    assert severity_counts(ordered)["critical"] == 1
    assert severity_counts(ordered)["low"] == 1
