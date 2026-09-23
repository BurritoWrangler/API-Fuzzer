"""Tests for spec_parser.py — OpenAPI/Swagger contract modeling (Phase 1).

These tests preserve the original baseline parser tests and add comprehensive
coverage for the Phase 1 contract model: local ``$ref`` resolution with cycle
diagnostics and caching, parameter override semantics, request/response content
maps and schemas, security requirements, recursive deterministic examples
(``allOf``/``oneOf``/``anyOf``, ``readOnly``/``writeOnly``/required, formats,
enums/defaults/const, nullable), cookie/form/multipart/XML media types, server
metadata, parser diagnostics, and golden prepared wire requests for every
supported location and media type.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from spec_parser import (
    Endpoint,
    RefResolver,
    Server,
    SpecParseError,
    build_request,
    generate_example,
    parse_spec_file,
    parse_spec_text,
    parse_spec_with_coverage,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    return parse_spec_file(str(FIXTURES / name))


def load_fixture_with_coverage(name: str):
    return parse_spec_with_coverage(
        (FIXTURES / name).read_text(encoding="utf-8"), name
    )


def _by_op(endpoints, operation_id: str) -> Endpoint:
    for ep in endpoints:
        if ep.operation_id == operation_id:
            return ep
    raise AssertionError(f"operation {operation_id!r} not found")


# ---------------------------------------------------------------------------
# Original baseline tests (preserved verbatim)
# ---------------------------------------------------------------------------


def test_parse_openapi3_parameters_and_json_body():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/users/{user_id}": {
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "post": {
                    "operationId": "updateUser",
                    "parameters": [
                        {
                            "name": "verbose",
                            "in": "query",
                            "schema": {"type": "boolean", "enum": [True, False]},
                        }
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "age": {"type": "integer"},
                                        "active": {"type": "boolean"},
                                        "tags": {"type": "array"},
                                    },
                                }
                            }
                        }
                    },
                },
            }
        },
    }

    endpoints = parse_spec_text(json.dumps(spec), "openapi.json")

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.path == "/users/{user_id}"
    assert endpoint.method == "POST"
    assert endpoint.operation_id == "updateUser"
    assert endpoint.has_body is True
    assert endpoint.consumes_json is True
    assert endpoint.body_example == {
        "name": "test",
        "age": 1,
        "active": True,
        "tags": ["test"],
    }
    assert [(p.name, p.location, p.schema_type) for p in endpoint.parameters] == [
        ("user_id", "path", "integer"),
        ("verbose", "query", "boolean"),
    ]


def test_parse_openapi3_form_body():
    spec = """
openapi: 3.0.0
paths:
  /login:
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                username:
                  type: string
                remember:
                  type: boolean
"""

    endpoint = parse_spec_text(spec, "openapi.yaml")[0]

    assert endpoint.has_body is True
    assert endpoint.consumes_json is False
    assert endpoint.body_example == {"username": "test", "remember": True}


def test_parse_swagger2_body_and_query_parameter():
    spec = {
        "swagger": "2.0",
        "paths": {
            "/items/{item_id}": {
                "put": {
                    "parameters": [
                        {
                            "name": "item_id",
                            "in": "path",
                            "required": True,
                            "type": "integer",
                        },
                        {
                            "name": "dry_run",
                            "in": "query",
                            "type": "boolean",
                        },
                        {
                            "name": "body",
                            "in": "body",
                            "required": True,
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "price": {"type": "number"},
                                },
                            },
                        },
                    ]
                }
            }
        },
    }

    endpoint = parse_spec_text(json.dumps(spec), "swagger.json")[0]

    assert endpoint.has_body is True
    assert endpoint.body_example == {"title": "test", "price": 1}
    assert [(p.name, p.location) for p in endpoint.parameters] == [
        ("item_id", "path"),
        ("dry_run", "query"),
    ]


def test_unknown_extension_falls_back_to_yaml():
    endpoints = parse_spec_text(
        "openapi: 3.0.0\npaths:\n  /health:\n    get: {}\n",
        "spec.txt",
    )

    assert [(ep.method, ep.path) for ep in endpoints] == [("GET", "/health")]


def test_non_object_spec_is_rejected():
    with pytest.raises(SpecParseError, match="root is not an object"):
        parse_spec_text("[]", "spec.json")


def test_non_http_path_members_are_ignored():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/health": {
                "summary": "Path metadata",
                "get": {},
            }
        },
    }

    endpoints = parse_spec_text(json.dumps(spec), "spec.json")

    assert len(endpoints) == 1
    assert endpoints[0].method == "GET"


# ---------------------------------------------------------------------------
# Local $ref resolution, cycles, external refs
# ---------------------------------------------------------------------------


def test_local_ref_resolved_and_cached():
    spec = {
        "openapi": "3.0.3",
        "components": {
            "schemas": {
                "Pet": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "example": "rex"}},
                }
            }
        },
        "paths": {
            "/pets": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Pet"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    endpoints, report = parse_spec_with_coverage(json.dumps(spec), "spec.json")
    ep = endpoints[0]
    assert ep.body_example == {"name": "rex"}
    # Schema is retained on the request body, not reduced to an example only.
    assert ep.request_body.content["application/json"].schema == {
        "type": "object",
        "properties": {"name": {"type": "string", "example": "rex"}},
    }
    assert report.unresolved_refs == []


def test_ref_resolver_caches_pointer_targets():
    root = {"components": {"schemas": {"X": {"type": "string"}}}}
    resolver = RefResolver(root)
    first = resolver.resolve("#/components/schemas/X")
    second = resolver.resolve("#/components/schemas/X")
    assert first is second
    assert resolver.report.unresolved_refs == []


def test_external_ref_disabled_and_reported():
    endpoints, report = load_fixture_with_coverage("external_ref.yaml")
    ep = _by_op(endpoints, "createThing")
    assert "./other.yaml#/components/schemas/Other" in report.unresolved_refs
    assert "https://example.com/specs/petstore.yaml#/Pet" in report.unresolved_refs
    # Local self-reference resolves and is not reported unresolved.
    assert "#/components/schemas/Thing" not in report.unresolved_refs
    assert ep.coverage is not None
    assert ep.coverage.resolved is False
    assert set(ep.coverage.unresolved_refs) == {
        "./other.yaml#/components/schemas/Other",
        "https://example.com/specs/petstore.yaml#/Pet",
    }


def test_cyclic_ref_detected_and_example_bounded():
    endpoints, report = load_fixture_with_coverage("cyclic.yaml")
    save = _by_op(endpoints, "saveTree")
    # Cycles are detected and recorded.
    assert report.cyclic_refs
    # Example generation terminates and produces a valid, depth-bounded object.
    assert isinstance(save.body_example, dict)
    assert save.body_example["id"] == "test"
    assert save.body_example["children"][0]["id"] == "test"
    assert save.body_example["children"][0]["children"] == []
    assert "parent" in save.body_example


# ---------------------------------------------------------------------------
# Parameter override semantics
# ---------------------------------------------------------------------------


def test_operation_parameter_overrides_path_level():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/widgets/{widget_id}": {
                "parameters": [
                    {"name": "widget_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                ],
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 50}}
                    ],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }
    ep = parse_spec_text(json.dumps(spec), "spec.json")[0]
    limits = [p for p in ep.parameters if p.name == "limit"]
    assert len(limits) == 1
    assert limits[0].maximum == 50
    assert limits[0].location == "query"
    # Path-level parameter survives.
    assert any(p.name == "widget_id" and p.location == "path" for p in ep.parameters)


def test_shared_parameter_ref_resolved():
    spec = {
        "openapi": "3.0.3",
        "components": {
            "parameters": {
                "PageParam": {"name": "page", "in": "query", "schema": {"type": "integer"}}
            }
        },
        "paths": {
            "/things": {
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/PageParam"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    ep = parse_spec_text(json.dumps(spec), "spec.json")[0]
    assert [(p.name, p.location, p.schema_type) for p in ep.parameters] == [
        ("page", "query", "integer")
    ]


# ---------------------------------------------------------------------------
# Request/response content maps and schemas
# ---------------------------------------------------------------------------


def test_request_body_retains_all_media_types_and_schema():
    endpoints, _ = load_fixture_with_coverage("openapi3.json")
    ep = _by_op(endpoints, "updatePet")
    assert ep.has_body is True
    assert ep.consumes_json is True
    content = ep.request_body.content
    assert set(content) == {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/xml",
    }
    assert ep.request_body.primary_media_type == "application/json"
    # JSON schema is retained (resolved Pet), not reduced to an example dict.
    assert "properties" in content["application/json"].schema


def test_responses_retained_with_schemas():
    endpoints, _ = load_fixture_with_coverage("openapi3.json")
    ep = _by_op(endpoints, "getPet")
    assert "200" in ep.responses
    resp = ep.responses["200"]
    assert resp.status_code == "200"
    assert "application/json" in resp.content
    assert "properties" in resp.content["application/json"].schema
    assert "404" in ep.responses


def test_swagger2_consumes_produces_and_body():
    endpoints, _ = load_fixture_with_coverage("openapi2.yaml")
    upd = _by_op(endpoints, "updateItem")
    assert upd.has_body is True
    assert upd.consumes_json is True
    assert upd.consumes == ["application/json"]
    assert upd.body_example == {"name": "test", "tags": ["test"]}
    assert upd.request_body.content["application/json"].schema is not None
    get = _by_op(endpoints, "getItem")
    assert get.produces == ["application/json"]
    assert "200" in get.responses
    assert get.responses["200"].content["application/json"].schema is not None


def test_swagger2_form_and_multipart_formdata():
    endpoints, _ = load_fixture_with_coverage("openapi2.yaml")
    create = _by_op(endpoints, "createItem")
    assert create.has_body is True
    assert create.consumes_json is False
    assert create.consumes == ["application/x-www-form-urlencoded"]
    assert create.body_example == {"name": "test", "active": True}
    # formData params are folded into the body, not left as standalone params.
    assert create.parameters == []
    upload = _by_op(endpoints, "upload")
    assert upload.has_body is True
    assert upload.consumes_json is False
    assert upload.consumes == ["multipart/form-data"]
    assert upload.body_example == {"file": "test", "label": "test"}


# ---------------------------------------------------------------------------
# Security requirements
# ---------------------------------------------------------------------------


def test_operation_security_and_untestable_schemes():
    endpoints, report = load_fixture_with_coverage("openapi3.json")
    get = _by_op(endpoints, "getPet")
    # No operation-level security -> inherits global bearer_auth.
    assert [name for req in get.security for name in req.schemes] == ["bearer_auth"]
    assert get.coverage.untestable_security == ["bearer_auth"]
    post = _by_op(endpoints, "updatePet")
    assert [name for req in post.security for name in req.schemes] == ["api_key"]
    assert post.coverage.untestable_security == ["api_key"]
    # Security schemes are modeled in the report.
    assert set(report.security_schemes) == {"bearer_auth", "api_key", "oauth"}
    assert report.security_schemes["oauth"].testable is False
    assert report.security_schemes["api_key"].testable is False
    assert report.security_schemes["bearer_auth"].testable is False


def test_swagger2_security_schemes_untestable():
    endpoints, report = load_fixture_with_coverage("openapi2.yaml")
    get = _by_op(endpoints, "getItem")
    assert [name for req in get.security for name in req.schemes] == ["api_key"]
    assert get.coverage.untestable_security == ["api_key"]
    assert set(report.security_schemes) == {"api_key", "basic_auth"}
    assert all(not s.testable for s in report.security_schemes.values())


# ---------------------------------------------------------------------------
# Deterministic example generation
# ---------------------------------------------------------------------------


def test_allof_merge():
    schema = {
        "allOf": [
            {"type": "object", "properties": {"a": {"type": "string"}}},
            {"type": "object", "properties": {"b": {"type": "integer"}}, "required": ["b"]},
        ]
    }
    assert generate_example(schema) == {"a": "test", "b": 1}


def test_oneof_picks_first_usable_branch():
    schema = {
        "oneOf": [
            {"type": "object", "properties": {"x": {"type": "string"}}},
            {"type": "object", "properties": {"y": {"type": "integer"}}},
        ]
    }
    assert generate_example(schema) == {"x": "test"}


def test_oneof_skips_null_branch():
    schema = {
        "oneOf": [
            {"type": "null"},
            {"type": "object", "properties": {"x": {"type": "string"}}},
        ]
    }
    assert generate_example(schema) == {"x": "test"}


def test_anyof_picks_first_usable_branch():
    schema = {
        "anyOf": [
            {"type": "object", "properties": {"x": {"type": "string"}}},
        ]
    }
    assert generate_example(schema) == {"x": "test"}


def test_readonly_omitted_in_request():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "readOnly": True}, "b": {"type": "integer"}},
    }
    assert generate_example(schema, context="request") == {"b": 1}


def test_readonly_required_still_present():
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "string", "readOnly": True}},
    }
    assert generate_example(schema, context="request") == {"a": "test"}


def test_writeonly_omitted_in_response():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "writeOnly": True}, "b": {"type": "integer"}},
    }
    assert generate_example(schema, context="response") == {"b": 1}


def test_writeonly_included_in_request():
    schema = {
        "type": "object",
        "properties": {"a": {"type": "string", "writeOnly": True}},
    }
    assert generate_example(schema, context="request") == {"a": "test"}


def test_required_cyclic_field_gets_minimal_value():
    root = {
        "components": {
            "schemas": {
                "Node2": {
                    "type": "object",
                    "required": ["next"],
                    "properties": {
                        "next": {"$ref": "#/components/schemas/Node2"},
                        "id": {"type": "string"},
                    },
                }
            }
        }
    }
    resolver = RefResolver(root)
    schema = {"$ref": "#/components/schemas/Node2"}
    example = generate_example(schema, resolver=resolver)
    assert example["id"] == "test"
    # Required cyclic field gets a valid minimal object, not None.
    assert example["next"] == {}


def test_formats_produce_deterministic_values():
    assert generate_example({"type": "string", "format": "date-time"}) == "2020-01-01T00:00:00Z"
    assert (
        generate_example({"type": "string", "format": "uuid"})
        == "00000000-0000-4000-8000-000000000000"
    )
    assert generate_example({"type": "string", "format": "email"}) == "user@example.com"
    assert generate_example({"type": "string", "format": "uri"}) == "https://example.com"


def test_example_default_enum_const_precedence():
    assert generate_example({"type": "string", "example": "ex", "default": "def", "enum": ["e1"]}) == "ex"
    assert generate_example({"type": "string", "default": "def", "enum": ["e1"]}) == "def"
    assert generate_example({"type": "string", "enum": ["a", "b"]}) == "a"
    assert generate_example({"const": "fixed"}) == "fixed"
    assert generate_example({"type": "string", "enum": ["a"], "const": "c"}) == "a"


def test_nullable_type_arrays_3_1():
    assert generate_example({"type": ["string", "null"]}) == "test"
    assert generate_example({"type": ["integer", "null"]}) == 1
    assert generate_example({"type": ["null"]}) is None


def test_nullable_3_0_keyword_ignored_for_example():
    assert generate_example({"type": "string", "nullable": True}) == "test"


def test_array_of_objects_example():
    schema = {
        "type": "array",
        "items": {"type": "object", "properties": {"x": {"type": "string"}}},
    }
    assert generate_example(schema) == [{"x": "test"}]


def test_nested_object_depth_bounded():
    schema = {
        "type": "object",
        "properties": {
            "a": {
                "type": "object",
                "properties": {
                    "b": {
                        "type": "object",
                        "properties": {"c": {"type": "string"}},
                    }
                },
            }
        },
    }
    example = generate_example(schema, max_depth=2)
    # depth 0 -> object, depth 1 -> object, depth 2 -> {} (bounded).
    assert example == {"a": {"b": {}}}


# ---------------------------------------------------------------------------
# Cookie / form / multipart / XML media types
# ---------------------------------------------------------------------------


def test_cookie_parameter_modeled():
    endpoints, _ = load_fixture_with_coverage("openapi3.json")
    ep = _by_op(endpoints, "updatePet")
    cookie = [p for p in ep.parameters if p.location == "cookie"]
    assert len(cookie) == 1
    assert cookie[0].name == "session"
    assert cookie[0].required is True


def test_xml_serialization_via_build_request():
    endpoints, _ = load_fixture_with_coverage("openapi3.json")
    ep = _by_op(endpoints, "updatePet")
    prepared = build_request(ep, base_url="https://api.test", media_type="application/xml")
    assert prepared.content_type == "application/xml"
    assert prepared.body == "<pet><name>test</name><species>test</species></pet>"


def test_multipart_files_via_build_request():
    endpoints, _ = load_fixture_with_coverage("openapi3.json")
    ep = _by_op(endpoints, "updatePet")
    prepared = build_request(ep, base_url="https://api.test", media_type="multipart/form-data")
    assert prepared.content_type == "multipart/form-data; boundary=apifuzzboundary"
    assert prepared.files == [("avatar", "avatar.txt", "apifuzz-canary", "text/plain")]
    assert 'name="avatar"; filename="avatar.txt"' in prepared.body
    assert "apifuzz-canary" in prepared.body
    assert 'name="name"' in prepared.body


def test_swagger2_multipart_upload_via_build_request():
    endpoints, _ = load_fixture_with_coverage("openapi2.yaml")
    ep = _by_op(endpoints, "upload")
    prepared = build_request(ep, base_url="https://api.test")
    assert prepared.content_type == "multipart/form-data; boundary=apifuzzboundary"
    assert prepared.files == [("file", "file.txt", "apifuzz-canary", "text/plain")]
    assert 'name="file"; filename="file.txt"' in prepared.body
    assert 'name="label"' in prepared.body


# ---------------------------------------------------------------------------
# Server metadata
# ---------------------------------------------------------------------------


def test_operation_servers_override_global():
    endpoints, _ = load_fixture_with_coverage("openapi3.json")
    search = _by_op(endpoints, "search")
    assert [s.url for s in search.servers] == ["https://search.example.com"]
    get = _by_op(endpoints, "getPet")
    # No operation-level servers -> inherits global servers.
    assert [s.url for s in get.servers] == [
        "https://api.example.com/v1",
        "https://{env}.api.example.com",
    ]


def test_server_resolved_url_substitutes_defaults():
    server = Server(url="https://{env}.api.example.com", variables={"env": {"default": "staging"}})
    assert server.resolved_url() == "https://staging.api.example.com"


def test_swagger2_host_basepath_servers():
    endpoints, _ = load_fixture_with_coverage("openapi2.yaml")
    ep = endpoints[0]
    assert [s.url for s in ep.servers] == ["https://api.example.com/v1"]


# ---------------------------------------------------------------------------
# Coverage report / parser diagnostics
# ---------------------------------------------------------------------------


def test_coverage_report_counts_operations():
    endpoints, report = load_fixture_with_coverage("openapi3.json")
    assert report.operation_count == len(endpoints)
    assert len(report.operations) == len(endpoints)
    assert all(isinstance(e, str) for e in report.unresolved_refs)


def test_unsupported_schema_keyword_surfaced():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/x": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string", "not": {"type": "integer"}}}
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    _, report = parse_spec_with_coverage(json.dumps(spec), "spec.json")
    assert "not" in report.unsupported_keywords


def test_missing_example_reported_for_schemaless_body():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/x": {
                "post": {
                    "requestBody": {"content": {"application/json": {}}},
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    endpoints, report = parse_spec_with_coverage(json.dumps(spec), "spec.json")
    ep = endpoints[0]
    assert ep.has_body is True
    assert ep.body_example is None
    assert "requestBody" in ep.coverage.missing_examples
    assert any("requestBody" in m for m in report.missing_examples)


def test_needs_user_values_for_required_path_header_cookie():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/o/{id}": {
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "get": {
                    "parameters": [
                        {"name": "X-Token", "in": "header", "required": True, "schema": {"type": "string"}},
                        {"name": "sid", "in": "cookie", "required": True, "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }
    endpoints, report = parse_spec_with_coverage(json.dumps(spec), "spec.json")
    ep = endpoints[0]
    assert "path:id" in ep.coverage.needs_user_values
    assert "header:X-Token" in ep.coverage.needs_user_values
    assert "cookie:sid" in ep.coverage.needs_user_values
    assert report.needs_user_values


def test_parse_spec_text_returns_list_of_endpoints():
    endpoints = parse_spec_text(json.dumps({"openapi": "3.0.0", "paths": {"/h": {"get": {}}}}), "s.json")
    assert isinstance(endpoints, list)
    assert isinstance(endpoints[0], Endpoint)


# ---------------------------------------------------------------------------
# Golden prepared wire requests (every location and media type)
# ---------------------------------------------------------------------------


GOLDEN_JSON_SPEC = {
    "openapi": "3.0.3",
    "paths": {
        "/widgets/{widget_id}": {
            "parameters": [
                {"name": "widget_id", "in": "path", "required": True, "schema": {"type": "integer"}},
            ],
            "post": {
                "operationId": "makeWidget",
                "parameters": [
                    {"name": "flag", "in": "query", "schema": {"type": "boolean"}},
                    {"name": "X-Region", "in": "header", "schema": {"type": "string"}},
                    {"name": "sid", "in": "cookie", "schema": {"type": "string"}},
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "label": {"type": "string"},
                                    "count": {"type": "integer"},
                                },
                            }
                        }
                    },
                },
                "responses": {"200": {"description": "ok"}},
            },
        }
    },
}


def test_golden_request_json_all_locations():
    ep = parse_spec_text(json.dumps(GOLDEN_JSON_SPEC), "spec.json")[0]
    prepared = build_request(ep, base_url="https://api.test")
    assert prepared.method == "POST"
    # No unresolved {parameter} tokens in the URL.
    assert "{widget_id}" not in prepared.url
    assert prepared.url == "https://api.test/widgets/1"
    assert prepared.query == [("flag", "true")]
    assert prepared.headers == {"X-Region": "test", "Cookie": "sid=test"}
    assert prepared.content_type == "application/json"
    assert prepared.body == '{"label":"test","count":1}'
    assert prepared.url_with_query() == "https://api.test/widgets/1?flag=true"


def test_golden_request_form():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "remember": {"type": "boolean"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    ep = parse_spec_text(json.dumps(spec), "spec.json")[0]
    prepared = build_request(ep, base_url="https://api.test")
    assert prepared.content_type == "application/x-www-form-urlencoded"
    assert prepared.body == "username=test&remember=true"


def test_golden_request_multipart():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/upload": {
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "file": {"type": "string", "format": "binary"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    ep = parse_spec_text(json.dumps(spec), "spec.json")[0]
    prepared = build_request(ep, base_url="https://api.test")
    assert prepared.content_type == "multipart/form-data; boundary=apifuzzboundary"
    assert prepared.files == [("file", "file.txt", "apifuzz-canary", "text/plain")]
    expected = (
        "--apifuzzboundary\r\n"
        'Content-Disposition: form-data; name="title"\r\n'
        "\r\n"
        "test\r\n"
        "--apifuzzboundary\r\n"
        'Content-Disposition: form-data; name="file"; filename="file.txt"\r\n'
        "Content-Type: text/plain\r\n"
        "\r\n"
        "apifuzz-canary\r\n"
        "--apifuzzboundary--\r\n"
    )
    assert prepared.body == expected


def test_golden_request_xml():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/xml": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/xml": {
                                "schema": {
                                    "type": "object",
                                    "xml": {"name": "widget"},
                                    "properties": {
                                        "name": {"type": "string"},
                                        "size": {"type": "integer"},
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    ep = parse_spec_text(json.dumps(spec), "spec.json")[0]
    prepared = build_request(ep, base_url="https://api.test")
    assert prepared.content_type == "application/xml"
    assert prepared.body == "<widget><name>test</name><size>1</size></widget>"


def test_golden_request_value_overrides():
    ep = parse_spec_text(json.dumps(GOLDEN_JSON_SPEC), "spec.json")[0]
    prepared = build_request(
        ep,
        base_url="https://api.test",
        values={"widget_id": 77, "flag": False, "X-Region": "eu", "sid": "abc", "label": "L"},
    )
    assert prepared.url == "https://api.test/widgets/77"
    assert prepared.query == [("flag", "false")]
    assert prepared.headers == {"X-Region": "eu", "Cookie": "sid=abc"}
    assert prepared.body == '{"label":"L","count":1}'


def test_golden_path_substitution_url_encodes():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/o/{name}": {
                "parameters": [{"name": "name", "in": "path", "required": True, "schema": {"type": "string"}}],
                "get": {"responses": {"200": {"description": "ok"}}},
            }
        },
    }
    ep = parse_spec_text(json.dumps(spec), "spec.json")[0]
    prepared = build_request(ep, base_url="https://api.test", values={"name": "a b/c"})
    assert prepared.url == "https://api.test/o/a%20b%2Fc"
    assert "{" not in prepared.url


# ---------------------------------------------------------------------------
# Fixture-based coverage (OpenAPI 2.0 / 3.0 / 3.1)
# ---------------------------------------------------------------------------


def test_fixture_openapi3_param_override_and_body():
    endpoints, report = load_fixture_with_coverage("openapi3.json")
    get = _by_op(endpoints, "getPet")
    limits = [p for p in get.parameters if p.name == "limit"]
    assert len(limits) == 1
    assert limits[0].maximum == 50
    post = _by_op(endpoints, "updatePet")
    assert post.body_example == {
        "name": "rex",
        "species": "dog",
        "born_at": "2020-01-01T00:00:00Z",
        "owner": {
            "email": "user@example.com",
            "uuid": "00000000-0000-4000-8000-000000000000",
            "role": "member",
        },
    }
    # readOnly id omitted from request example; writeOnly role included.
    assert "id" not in post.body_example
    search = _by_op(endpoints, "search")
    search_limit = [p for p in search.parameters if p.name == "limit"][0]
    assert search_limit.maximum == 100  # from shared LimitParam
    assert report.security_schemes["oauth"].testable is False


def test_fixture_openapi31_type_arrays_and_const():
    endpoints, report = load_fixture_with_coverage("openapi31.json")
    upd = _by_op(endpoints, "updateAccount")
    assert upd.body_example == {
        "id": "test",
        "kind": "account",
        "balance": 1,
        "currency": "USD",
        "label": "primary",
    }
    get = _by_op(endpoints, "getAccount")
    assert "200" in get.responses
    assert get.responses["200"].content["application/json"].schema is not None
    # Direct example generation for a nullable array schema.
    resolver = RefResolver(
        {"components": {"schemas": {"NullableList": {
            "type": ["array", "null"], "items": {"type": ["string", "null"]}
        }}}}
    )
    assert generate_example(
        {"$ref": "#/components/schemas/NullableList"}, resolver=resolver
    ) == ["test"]


def test_fixture_polymorphic_oneof_anyof():
    endpoints, report = load_fixture_with_coverage("polymorphic.yaml")
    create = _by_op(endpoints, "createPet")
    # oneOf picks the first branch (Dog); discriminator petType already present.
    assert create.body_example == {"petType": "test", "bark": True}
    any_pet = _by_op(endpoints, "createAny")
    # anyOf picks the first branch (Dog).
    assert any_pet.body_example == {"petType": "test", "bark": True}


def test_fixture_openapi2_endpoints_and_servers():
    endpoints, report = load_fixture_with_coverage("openapi2.yaml")
    assert {ep.operation_id for ep in endpoints} == {
        "getItem",
        "updateItem",
        "createItem",
        "upload",
    }
    assert all(ep.servers[0].url == "https://api.example.com/v1" for ep in endpoints)
    # TaggedItem allOf resolves to merged properties when used as a body.
    resolver = RefResolver(
        {"definitions": {
            "Item": {"type": "object", "properties": {"name": {"type": "string"}}},
            "TaggedItem": {"allOf": [
                {"$ref": "#/definitions/Item"},
                {"type": "object", "properties": {"tag": {"type": "string"}}},
            ]},
        }}
    )
    assert generate_example(
        {"$ref": "#/definitions/TaggedItem"}, resolver=resolver
    ) == {"name": "test", "tag": "test"}
