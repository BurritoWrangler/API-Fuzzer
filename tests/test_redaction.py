"""Phase 0 redaction tests: headers, query params, JSON/form bodies, config
toggle, and Finding.to_dict/to_raw_dict integration.
"""

from __future__ import annotations

from analyzer import Finding
from redaction import (
    DEFAULT_REDACTION_CONFIG,
    REDACTED,
    RAW_EXPORT_CONFIG,
    RedactionConfig,
    redact_body_text,
    redact_headers,
    redact_url_query,
)


def test_redact_headers_keeps_scheme_but_hides_credential():
    out, redacted = redact_headers({"Authorization": "Bearer s3cr3t"}, DEFAULT_REDACTION_CONFIG)
    assert out["Authorization"] == "Bearer [REDACTED]"
    assert redacted == ["Authorization"]


def test_redact_headers_cookies_and_api_keys():
    out, redacted = redact_headers(
        {"Cookie": "session=xyz", "X-Api-Key": "k", "Accept": "*/*"},
        DEFAULT_REDACTION_CONFIG,
    )
    assert out["Cookie"] == REDACTED
    assert out["X-Api-Key"] == REDACTED
    assert out["Accept"] == "*/*"
    assert set(redacted) == {"Cookie", "X-Api-Key"}


def test_redact_headers_case_insensitive_and_disabled():
    out, redacted = redact_headers({"authorization": "Bearer x"}, RedactionConfig(enabled=False))
    assert out == {"authorization": "Bearer x"}
    assert redacted == []
    # Case-insensitive matching when enabled.
    out, redacted = redact_headers({"AUTHORIZATION": "Bearer x"}, DEFAULT_REDACTION_CONFIG)
    assert out["AUTHORIZATION"] == "Bearer [REDACTED]"


def test_redact_url_query_redacts_sensitive_params():
    url, redacted = redact_url_query(
        "https://api.example/u?access_token=secret&keep=1",
        DEFAULT_REDACTION_CONFIG,
    )
    assert "access_token=%5BREDACTED%5D" in url or "access_token=[REDACTED]" in url
    assert "keep=1" in url
    assert "secret" not in url
    assert "query.access_token" in redacted


def test_redact_url_query_no_query_unchanged():
    url, redacted = redact_url_query("https://api.example/u", DEFAULT_REDACTION_CONFIG)
    assert url == "https://api.example/u"
    assert redacted == []


def test_redact_body_text_json_and_nested():
    body, keys = redact_body_text('{"password":"p@ss","name":"x","nested":{"token":"t"}}', DEFAULT_REDACTION_CONFIG)
    assert '"password": "[REDACTED]"' in body
    assert '"token": "[REDACTED]"' in body  # key name kept, value hidden
    assert "p@ss" not in body
    assert set(keys) == {"password", "token"}


def test_redact_body_text_form_encoded():
    body, keys = redact_body_text("password=secret&name=x", DEFAULT_REDACTION_CONFIG)
    assert "secret" not in body
    # urlencode encodes the placeholder; accept either form.
    assert "%5BREDACTED%5D" in body or "[REDACTED]" in body
    assert "name=x" in body
    assert keys == ["password"]


def test_redact_body_text_non_structured_unchanged():
    body, keys = redact_body_text("just some text", DEFAULT_REDACTION_CONFIG)
    assert body == "just some text"
    assert keys == []


def test_raw_export_config_disables_redaction():
    out, _ = redact_headers({"Authorization": "Bearer s3cr3t"}, RAW_EXPORT_CONFIG)
    assert out["Authorization"] == "Bearer s3cr3t"


def test_finding_to_dict_redacts_by_default():
    finding = Finding(
        severity="critical",
        category="sql_injection",
        title="SQL error",
        endpoint="/u",
        method="GET",
        parameter="q",
        location="query",
        payload="'",
        technique="probe",
        evidence="sig",
        status_code=200,
        response_time_ms=10,
        request_url="https://api.example/u?access_token=t0psecret&q=%27",
        request_headers={"Authorization": "Bearer s3cr3t", "Accept": "*/*"},
        request_body='{"password":"hunter2"}',
    )
    d = finding.to_dict()
    assert d["request_headers"]["Authorization"] == "Bearer [REDACTED]"
    assert d["request_headers"]["Accept"] == "*/*"
    assert "t0psecret" not in d["request_url"]
    assert "[REDACTED]" in d["request_url"] or "%5BREDACTED%5D" in d["request_url"]
    assert "hunter2" not in d["request_body"]
    assert "request_headers.Authorization" in d["redacted_fields"]
    # raw_request rebuilt from redacted fields must not leak the secret.
    assert "s3cr3t" not in d["raw_request"]
    assert "t0psecret" not in d["raw_request"]
    assert "hunter2" not in d["raw_request"]


def test_finding_to_raw_dict_is_unredacted_opt_in():
    finding = Finding(
        severity="critical",
        category="sql_injection",
        title="SQL error",
        endpoint="/u",
        method="GET",
        parameter="q",
        location="query",
        payload="'",
        technique="probe",
        evidence="sig",
        status_code=200,
        response_time_ms=10,
        request_url="https://api.example/u?access_token=t0psecret",
        request_headers={"Authorization": "Bearer s3cr3t"},
    )
    raw = finding.to_raw_dict()
    assert raw["request_headers"]["Authorization"] == "Bearer s3cr3t"
    assert "t0psecret" in raw["request_url"]
