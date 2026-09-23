import misconfig

from tests.fakes import FakeResponse, FakeSession


SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def inspect(headers=None, cookies=None):
    return misconfig.inspect_response(
        response_headers=headers or {},
        set_cookies=cookies or [],
        status_code=200,
        request_url="https://api.example/health",
        endpoint="/health",
        method="GET",
        response_text="ok",
        is_https=True,
        response_time_ms=10,
    )


def test_missing_security_headers_are_reported():
    findings = inspect()

    titles = {finding.title for finding in findings}
    assert "Missing security header: Strict-Transport-Security" in titles
    assert "Missing security header: Content-Security-Policy" in titles
    assert len(findings) == len(misconfig.REQUIRED_HEADERS)


def test_secure_response_has_no_header_findings():
    assert inspect(headers=SECURE_HEADERS) == []


def test_cookie_flags_are_checked():
    findings = inspect(
        headers=SECURE_HEADERS,
        cookies=["session=abc123; Path=/"],
    )

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title
    assert "SameSite" in findings[0].title


def test_misconfiguration_dedupe_preserves_other_categories():
    duplicate_one = misconfig._mk(
        "low",
        "Duplicate",
        endpoint="/health",
        method="GET",
        request_url="https://api.example/health",
        evidence="one",
    )
    duplicate_two = misconfig._mk(
        "low",
        "Duplicate",
        endpoint="/health",
        method="GET",
        request_url="https://api.example/health",
        evidence="two",
    )
    other = misconfig._mk(
        "low",
        "Duplicate",
        endpoint="/health",
        method="GET",
        request_url="https://api.example/health",
        evidence="other category",
    )
    other.category = "xss"

    deduped = misconfig.dedupe([duplicate_one, duplicate_two, other])

    assert deduped == [duplicate_one, other]


def test_rate_limit_probe_reports_absent_signal():
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(200, "ok", {})
    )

    findings = misconfig.probe_rate_limit(
        "https://api.example",
        "/health",
        session,
        timeout=1.0,
        auth_header=None,
        burst=3,
    )

    assert len(findings) == 1
    assert findings[0].title == "No rate-limiting signal observed"
    assert len(session.calls) == 3


def test_rate_limit_probe_stops_on_429():
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(429, "slow down", {})
    )

    findings = misconfig.probe_rate_limit(
        "https://api.example",
        "/health",
        session,
        timeout=1.0,
        auth_header=None,
        burst=5,
    )

    assert findings == []
    assert len(session.calls) == 1


def test_authenticated_cache_control_requires_no_store():
    missing = misconfig.check_auth_cache_control(
        {},
        status_code=200,
        request_url="https://api.example/profile",
        endpoint="/profile",
        method="GET",
        used_auth=True,
    )
    safe = misconfig.check_auth_cache_control(
        {"Cache-Control": "private, no-store"},
        status_code=200,
        request_url="https://api.example/profile",
        endpoint="/profile",
        method="GET",
        used_auth=True,
    )

    assert len(missing) == 1
    assert safe == []
