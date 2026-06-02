"""Lightweight OpenAPI / Swagger spec parser.

Supports OpenAPI 2.0 (Swagger) and 3.x in either JSON or YAML.
Returns a unified list of `Endpoint` records that the fuzzer iterates over.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


@dataclass
class Parameter:
    name: str
    location: str  # query | path | header | cookie | body
    required: bool = False
    schema_type: str = "string"
    example: Optional[Any] = None
    enum: Optional[List[Any]] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None


@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    parameters: List[Parameter] = field(default_factory=list)
    has_body: bool = False
    body_example: Optional[Dict[str, Any]] = None
    consumes_json: bool = True


class SpecParseError(Exception):
    pass


def _load_raw(content: str, filename: str) -> Dict[str, Any]:
    name = filename.lower()
    if name.endswith((".yaml", ".yml")):
        return yaml.safe_load(content)
    if name.endswith(".json"):
        return json.loads(content)
    # Try JSON then YAML.
    try:
        return json.loads(content)
    except Exception:
        try:
            return yaml.safe_load(content)
        except Exception as exc:  # pragma: no cover - error path
            raise SpecParseError(f"Could not parse spec as JSON or YAML: {exc}") from exc


def parse_spec_file(path: str) -> List[Endpoint]:
    p = Path(path)
    return parse_spec_text(p.read_text(encoding="utf-8"), p.name)


def parse_spec_text(content: str, filename: str = "spec.json") -> List[Endpoint]:
    raw = _load_raw(content, filename)
    if not isinstance(raw, dict):
        raise SpecParseError("Spec root is not an object")

    if "openapi" in raw and str(raw["openapi"]).startswith("3"):
        return _parse_openapi3(raw)
    if "swagger" in raw and str(raw["swagger"]).startswith("2"):
        return _parse_openapi2(raw)
    # Best-effort: assume v3 layout.
    return _parse_openapi3(raw)


# ---------------------------------------------------------------------------
# OpenAPI 3.x
# ---------------------------------------------------------------------------

def _parse_openapi3(spec: Dict[str, Any]) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common = _params_v3(item.get("parameters", []))
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            ep_params = list(common)
            ep_params.extend(_params_v3(op.get("parameters", [])))

            has_body = False
            body_example: Optional[Dict[str, Any]] = None
            consumes_json = True
            request_body = op.get("requestBody")
            if isinstance(request_body, dict):
                content = request_body.get("content") or {}
                if "application/json" in content:
                    has_body = True
                    media = content["application/json"]
                    body_example = _example_from_schema_v3(media.get("schema"))
                elif "application/x-www-form-urlencoded" in content:
                    has_body = True
                    consumes_json = False
                    media = content["application/x-www-form-urlencoded"]
                    body_example = _example_from_schema_v3(media.get("schema"))
                elif content:
                    has_body = True
                    consumes_json = False
                    first_media = next(iter(content.values()), {})
                    body_example = _example_from_schema_v3(first_media.get("schema"))

            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=op.get("operationId"),
                    summary=op.get("summary"),
                    parameters=ep_params,
                    has_body=has_body,
                    body_example=body_example,
                    consumes_json=consumes_json,
                )
            )
    return endpoints


def _params_v3(raw_params: Any) -> List[Parameter]:
    out: List[Parameter] = []
    if not isinstance(raw_params, list):
        return out
    for p in raw_params:
        if not isinstance(p, dict):
            continue
        schema = p.get("schema") if isinstance(p.get("schema"), dict) else {}
        out.append(
            Parameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=bool(p.get("required", False)),
                schema_type=schema.get("type", "string"),
                example=p.get("example"),
                enum=schema.get("enum") if isinstance(schema.get("enum"), list) else None,
                minimum=schema.get("minimum"),
                maximum=schema.get("maximum"),
                min_length=schema.get("minLength"),
                max_length=schema.get("maxLength"),
                pattern=schema.get("pattern"),
            )
        )
    return out


def _example_from_schema_v3(schema: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(schema, dict):
        return None
    if "example" in schema and isinstance(schema["example"], dict):
        return schema["example"]
    props = schema.get("properties")
    if isinstance(props, dict):
        return {name: _placeholder(props_def) for name, props_def in props.items()}
    return None


def _placeholder(prop: Any) -> Any:
    if not isinstance(prop, dict):
        return "test"
    t = prop.get("type", "string")
    if t == "integer" or t == "number":
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return ["test"]
    if t == "object":
        return {}
    return "test"


# ---------------------------------------------------------------------------
# OpenAPI 2.0 (Swagger)
# ---------------------------------------------------------------------------

def _parse_openapi2(spec: Dict[str, Any]) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common = _params_v2(item.get("parameters", []))
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params = list(common)
            params.extend(_params_v2(op.get("parameters", [])))

            has_body = any(p.location == "body" for p in params)
            body_example: Optional[Dict[str, Any]] = None
            if has_body:
                # In v2, body parameter schemas live on the parameter object itself.
                for raw in op.get("parameters", []) + item.get("parameters", []):
                    if isinstance(raw, dict) and raw.get("in") == "body":
                        body_example = _example_from_schema_v3(raw.get("schema"))
                        break
                # Remove the body param itself from parameters; we treat body separately.
                params = [p for p in params if p.location != "body"]

            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=op.get("operationId"),
                    summary=op.get("summary"),
                    parameters=params,
                    has_body=has_body,
                    body_example=body_example,
                    consumes_json=True,
                )
            )
    return endpoints


def _params_v2(raw_params: Any) -> List[Parameter]:
    out: List[Parameter] = []
    if not isinstance(raw_params, list):
        return out
    for p in raw_params:
        if not isinstance(p, dict):
            continue
        out.append(
            Parameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=bool(p.get("required", False)),
                schema_type=p.get("type", "string"),
                enum=p.get("enum") if isinstance(p.get("enum"), list) else None,
                minimum=p.get("minimum"),
                maximum=p.get("maximum"),
                min_length=p.get("minLength"),
                max_length=p.get("maxLength"),
                pattern=p.get("pattern"),
            )
        )
    return out
