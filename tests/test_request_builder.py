"""Phase 0 request_builder tests: path substitution, query encoding, URL
building, body serialization per media type, and full prepared-request assembly.
"""

from __future__ import annotations

import request_builder
from models import AuthProfile, RequestTemplate


def test_substitute_path_percent_encodes_values():
    path = request_builder.substitute_path("/u/{id}/f/{name}", {"id": 42, "name": "../a b"})
    assert path == "/u/42/f/..%2Fa%20b"


def test_encode_query_handles_lists_bools_and_none():
    assert request_builder.encode_query({"q": "a b", "tag": ["one", "two"]}) == "q=a+b&tag=one&tag=two"
    assert request_builder.encode_query({"flag": True, "off": False}) == "flag=true&off=false"
    assert request_builder.encode_query({"skip": None, "keep": 1}) == "keep=1"
    assert request_builder.encode_query({}) == ""


def test_build_path_url_and_encoded_url():
    assert request_builder.build_path_url("https://api.example", "/u/{id}", {"id": 7}) == "https://api.example/u/7"
    assert request_builder.build_encoded_url("https://api.example", "/u/{id}", {"id": 7}, {"q": "x"}) == "https://api.example/u/7?q=x"
    # Multiple query params are joined with '&'.
    assert request_builder.build_encoded_url("https://api.example", "/u/{id}", {"id": 7}, {"q": "x", "p": 2}) == "https://api.example/u/7?q=x&p=2"
    # base_url trailing slash is stripped.
    assert request_builder.build_path_url("https://api.example/", "/health") == "https://api.example/health"


def test_serialize_body_per_media_type():
    assert request_builder.serialize_body({"a": 1}, "application/json") == '{"a": 1}'
    assert request_builder.serialize_body({"a": "b c"}, "application/x-www-form-urlencoded") == "a=b+c"
    assert request_builder.serialize_body("<x/>", "application/xml") == "<x/>"
    assert request_builder.serialize_body("plain", "text/plain") == "plain"
    assert request_builder.serialize_body(None, "application/json") is None
    # Unknown media type still JSON-encodes structured values.
    assert request_builder.serialize_body({"a": 1}, "") == '{"a": 1}'
    assert request_builder.serialize_body("raw-body", "multipart/form-data; boundary=x") == "raw-body"


def test_build_request_assembles_auth_headers_cookies_and_content_type():
    tmpl = RequestTemplate(
        method="post",
        path="/items/{id}",
        base_url="https://api.example",
        path_params={"id": 7},
        query_params={"q": "a b"},
        header_params={"X-Trace": "t"},
        cookie_params={"sid": "abc"},
        body={"name": "test"},
        media_type="application/json",
        has_body=True,
        auth_profile=AuthProfile.from_header("default", "Bearer s3cr3t"),
    )
    pr = request_builder.build_request(tmpl)
    assert pr.method == "POST"
    assert pr.url == "https://api.example/items/7"
    assert pr.encoded_url == "https://api.example/items/7?q=a+b"
    assert pr.headers["Authorization"] == "Bearer s3cr3t"
    assert pr.headers["X-Trace"] == "t"
    assert pr.headers["Content-Type"] == "application/json"
    assert pr.cookies == {"sid": "abc"}
    assert pr.body == '{"name": "test"}'
    assert pr.query_params == {"q": "a b"}


def test_build_request_omits_content_type_without_body():
    tmpl = RequestTemplate(method="get", path="/health", base_url="https://api.example", media_type="application/json", has_body=False)
    pr = request_builder.build_request(tmpl)
    assert "Content-Type" not in pr.headers
    assert pr.body is None
    assert pr.url == "https://api.example/health"
    assert pr.encoded_url == "https://api.example/health"
