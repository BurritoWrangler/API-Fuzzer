import extra_checks

from tests.fakes import FakeResponse, FakeSession


def test_open_redirect_probe_is_limited_to_url_parameters():
    session = FakeSession()

    findings = extra_checks.open_redirect_focused_probe(
        base_url="https://api.example",
        endpoint_path="/login",
        method="GET",
        parameter_name="username",
        parameter_location="query",
        benign_query={"username": "test"},
        session=session,
        timeout=1.0,
        auth_header=None,
    )

    assert findings == []
    assert session.calls == []


def test_open_redirect_probe_records_external_location():
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(
            302,
            "",
            {"Location": "https://evil.example.com/landing"},
        )
    )

    findings = extra_checks.open_redirect_focused_probe(
        base_url="https://api.example",
        endpoint_path="/login",
        method="GET",
        parameter_name="redirect_uri",
        parameter_location="query",
        benign_query={},
        session=session,
        timeout=1.0,
        auth_header=None,
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "redirect_uri=https%3A%2F%2Fevil.example.com%2F" in findings[0].request_url


def test_http_parameter_pollution_requires_reflected_canary():
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(
            200,
            "value=apifz_hpp_canary",
            {"Content-Type": "text/plain"},
        )
    )

    findings = extra_checks.http_parameter_pollution_probe(
        base_url="https://api.example",
        endpoint_path="/search",
        method="GET",
        benign_query={"q": "test"},
        session=session,
        timeout=1.0,
        auth_header=None,
    )

    assert len(findings) == 1
    assert findings[0].category == "http_parameter_pollution"
    assert "q=test&q=apifz_hpp_canary" in findings[0].request_url


def test_canary_reflection_probe_records_body_echo(monkeypatch):
    monkeypatch.setattr(extra_checks.secrets, "token_hex", lambda length: "1234abcd")
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(
            200,
            "echo: apifz_canary_1234abcd",
        )
    )

    findings = extra_checks.canary_reflection_probe(
        base_url="https://api.example",
        endpoint_path="/search",
        method="GET",
        parameter_name="q",
        parameter_location="query",
        benign_query={"q": "test"},
        benign_body=None,
        consumes_json=True,
        session=session,
        timeout=1.0,
        auth_header=None,
    )

    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].payload == "apifz_canary_1234abcd"


def test_content_type_confusion_records_accepted_form_body():
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(201, '{"created":true}')
    )

    findings = extra_checks.content_type_confusion_probe(
        base_url="https://api.example",
        endpoint_path="/items",
        method="POST",
        body_example={"name": "test"},
        consumes_json=True,
        session=session,
        timeout=1.0,
        auth_header=None,
    )

    assert len(findings) == 1
    assert findings[0].category == "content_type_confusion"
    assert session.calls[0]["headers"]["Content-Type"] == (
        "application/x-www-form-urlencoded"
    )
