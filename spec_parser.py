"""Lightweight OpenAPI / Swagger spec parser.

Supports OpenAPI 2.0 (Swagger) and OpenAPI 3.0 / practical 3.1 in JSON or YAML.
Returns a unified list of :class:`Endpoint` records that the fuzzer iterates
over, plus an optional pre-scan :class:`CoverageReport`.

Phase 1 (contract completeness) additions, all backward compatible:

* An internal JSON Pointer resolver for local ``$ref`` with cycle detection,
  diagnostics, and caching. External ``$ref`` fetching stays disabled by
  default; external references are reported as unresolved in the coverage
  report instead of being fetched.
* Request/response content maps, retained schemas, and operation-level
  security requirements rather than reducing bodies to a single example dict.
* Recursive deterministic example generation with depth and collection-size
  limits, honoring ``allOf``, bounded ``oneOf``/``anyOf``, arrays and nested
  objects, nullable values, formats, ``example``/``default``/``enum``,
  ``readOnly``/``writeOnly``, and required body fields.
* Cookie parameters, form encoding, multipart fields/files, XML media types,
  operation-specific servers/base paths, and Swagger 2 ``consumes``/``produces``.
* A pre-scan coverage report listing resolved operations, unsupported keywords,
  missing examples, unresolved references, untestable security schemes, and
  operations requiring user-supplied values.
* :func:`build_request` producing deterministic prepared wire requests for
  every supported parameter location and media type.

The public API (``parse_spec_text``/``parse_spec_file`` returning
``List[Endpoint]``) and the existing ``Endpoint``/``Parameter`` fields are
preserved so ``fuzzer.py``, ``schema_checks.py`` and ``extra_checks.py`` keep
working unchanged.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlencode

import yaml


HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

# Media types we know how to serialize deterministically.
JSON_MEDIA_TYPES = {"application/json"}
FORM_MEDIA_TYPES = {"application/x-www-form-urlencoded"}
MULTIPART_MEDIA_TYPES = {"multipart/form-data"}
XML_MEDIA_TYPES = {"application/xml", "text/xml", "application/atom+xml"}

# Schema keywords we do not fully model. Encountering them is recorded as a
# coverage diagnostic rather than silently mis-compiled.
UNSUPPORTED_SCHEMA_KEYWORDS = {
    "not",
    "patternProperties",
    "prefixItems",
    "contains",
    "minContains",
    "maxContains",
    "unevaluatedProperties",
    "unevaluatedItems",
    "contentMediaType",
    "contentEncoding",
    "contentSchema",
    "propertyNames",
    "$comment",
}

# Operation-level keywords we do not exercise.
UNSUPPORTED_OPERATION_KEYWORDS = {"callbacks", "links"}

# Depth/collection-size limits for deterministic example generation.
DEFAULT_MAX_DEPTH = 5
DEFAULT_ARRAY_SIZE = 1
DEFAULT_BINARY_CANARY = "apifuzz-canary"
MULTIPART_BOUNDARY = "apifuzzboundary"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


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
    # Phase 1 metadata (all optional, backward compatible).
    format: Optional[str] = None
    default: Optional[Any] = None
    schema: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    style: Optional[str] = None
    explode: Optional[bool] = None
    allow_empty_value: bool = False
    allow_reserved: bool = False
    deprecated: bool = False
    content: Optional[Dict[str, "MediaType"]] = None


@dataclass
class MediaType:
    media_type: str
    schema: Optional[Dict[str, Any]] = None
    example: Optional[Any] = None
    examples: Dict[str, Any] = field(default_factory=dict)
    encoding: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestBody:
    description: Optional[str] = None
    required: bool = False
    content: Dict[str, MediaType] = field(default_factory=dict)
    primary_media_type: Optional[str] = None


@dataclass
class Response:
    status_code: str  # "200", "2XX", "default"
    description: Optional[str] = None
    content: Dict[str, MediaType] = field(default_factory=dict)
    headers: Dict[str, Parameter] = field(default_factory=dict)


@dataclass
class SecurityRequirement:
    # scheme name -> list of required scopes (empty for non-oauth).
    schemes: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class SecurityScheme:
    name: str
    type: str  # apiKey | http | oauth2 | openIdConnect (v2: basic | apiKey | oauth2)
    description: Optional[str] = None
    scheme: Optional[str] = None  # http scheme (bearer, basic, digest...)
    bearer_format: Optional[str] = None
    location: Optional[str] = None  # in: query | header | cookie
    header_name: Optional[str] = None  # v3 ``name`` for apiKey
    flows: Dict[str, Any] = field(default_factory=dict)
    open_id_connect_url: Optional[str] = None
    testable: bool = True
    untestable_reason: Optional[str] = None


@dataclass
class Server:
    url: str
    description: Optional[str] = None
    variables: Dict[str, Any] = field(default_factory=dict)

    def resolved_url(self) -> str:
        url = self.url
        for name, var in (self.variables or {}).items():
            default = var.get("default", "") if isinstance(var, dict) else ""
            url = url.replace("{" + name + "}", str(default))
        return url


@dataclass
class CoverageEntry:
    operation: str  # "GET /foo"
    resolved: bool = True
    unresolved_refs: List[str] = field(default_factory=list)
    unsupported_keywords: List[str] = field(default_factory=list)
    missing_examples: List[str] = field(default_factory=list)
    needs_user_values: List[str] = field(default_factory=list)
    security: List[str] = field(default_factory=list)
    untestable_security: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class CoverageReport:
    operations: List[CoverageEntry] = field(default_factory=list)
    security_schemes: Dict[str, SecurityScheme] = field(default_factory=dict)
    unresolved_refs: List[str] = field(default_factory=list)
    unsupported_keywords: List[str] = field(default_factory=list)
    missing_examples: List[str] = field(default_factory=list)
    needs_user_values: List[str] = field(default_factory=list)
    cyclic_refs: List[List[str]] = field(default_factory=list)
    operation_count: int = 0

    def add_ref(self, ref: str) -> None:
        if ref and ref not in self.unresolved_refs:
            self.unresolved_refs.append(ref)

    def add_unsupported(self, kw: str) -> None:
        if kw and kw not in self.unsupported_keywords:
            self.unsupported_keywords.append(kw)

    def add_missing_example(self, label: str) -> None:
        if label and label not in self.missing_examples:
            self.missing_examples.append(label)

    def add_needs_user_value(self, label: str) -> None:
        if label and label not in self.needs_user_values:
            self.needs_user_values.append(label)


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
    # Phase 1 contract model (optional, backward compatible).
    request_body: Optional[RequestBody] = None
    responses: Dict[str, Response] = field(default_factory=dict)
    security: List[SecurityRequirement] = field(default_factory=list)
    servers: List[Server] = field(default_factory=list)
    consumes: List[str] = field(default_factory=list)  # Swagger 2
    produces: List[str] = field(default_factory=list)  # Swagger 2
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False
    description: Optional[str] = None
    coverage: Optional[CoverageEntry] = None


@dataclass
class PreparedRequest:
    """Deterministic prepared wire request derived from an Endpoint."""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    query: List[Tuple[str, str]] = field(default_factory=list)
    body: Optional[Any] = None
    content_type: Optional[str] = None
    files: Optional[List[Tuple[str, str, str, str]]] = None

    def url_with_query(self) -> str:
        if not self.query:
            return self.url
        return self.url + "?" + urlencode(self.query)


class SpecParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# Local $ref resolver
# ---------------------------------------------------------------------------


class RefResolver:
    """Resolve local JSON Pointer ``$ref`` against a single document.

    External references (anything not starting with ``#``) are never fetched.
    They are recorded as unresolved so the coverage report can surface them.
    Cycles are detected per-resolution chain and broken by substituting
    ``None``; the cycle path is recorded for diagnostics.

    The resolver returns the *raw* target node for a ref (one pointer lookup)
    rather than recursively de-referencing the whole subtree. Callers (notably
    :func:`generate_example`) resolve nested ``$ref`` lazily as they descend,
    which lets depth limits bound cyclic structures into valid examples.
    """

    def __init__(self, root: Dict[str, Any], report: Optional[CoverageReport] = None):
        self.root = root
        self.report = report or CoverageReport()
        self._cache: Dict[str, Any] = {}

    def resolve(self, ref: str, chain: Optional[List[str]] = None) -> Optional[Any]:
        if not isinstance(ref, str):
            self.report.add_ref("<non-string $ref>")
            return None
        if not ref.startswith("#"):
            # External reference: disabled by policy.
            self.report.add_ref(ref)
            return None
        active = list(chain or [])
        if ref in active:
            cycle = active[active.index(ref):] + [ref]
            if cycle not in self.report.cyclic_refs:
                self.report.cyclic_refs.append(cycle)
            return None  # break the cycle deterministically
        if ref in self._cache:
            return self._cache[ref]
        node = self._pointer(ref)
        if node is None:
            self.report.add_ref(ref)
            return None
        self._cache[ref] = node
        return node

    def _pointer(self, ref: str) -> Optional[Any]:
        if ref == "#":
            return self.root
        if not ref.startswith("#/"):
            self.report.add_ref(ref)
            return None
        node: Any = self.root
        for raw_part in ref[2:].split("/"):
            if not isinstance(node, dict):
                return None
            part = raw_part.replace("~1", "/").replace("~0", "~")
            node = node.get(part)
            if node is None:
                return None
        return node


# ---------------------------------------------------------------------------
# Loading and entry points
# ---------------------------------------------------------------------------


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
    return parse_spec_with_coverage(content, filename)[0]


def parse_spec_with_coverage(
    content: str, filename: str = "spec.json"
) -> Tuple[List[Endpoint], CoverageReport]:
    """Parse a spec and return endpoints plus a pre-scan coverage report."""
    raw = _load_raw(content, filename)
    if not isinstance(raw, dict):
        raise SpecParseError("Spec root is not an object")

    report = CoverageReport()
    resolver = RefResolver(raw, report)
    if "swagger" in raw and str(raw["swagger"]).startswith("2"):
        return _parse_openapi2(raw, resolver, report), report
    # OpenAPI 3.0/3.1 and best-effort fallback both use the v3 path.
    return _parse_openapi3(raw, resolver, report), report


# ---------------------------------------------------------------------------
# OpenAPI 3.x
# ---------------------------------------------------------------------------


def _parse_openapi3(
    spec: Dict[str, Any], resolver: RefResolver, report: CoverageReport
) -> List[Endpoint]:
    global_security = _security_v3(spec.get("security"))
    for name, scheme in _security_schemes_v3(
        spec.get("components", {}).get("securitySchemes") or {}
    ).items():
        report.security_schemes[name] = scheme
    global_servers = _servers_v3(spec.get("servers") or [], spec)

    endpoints: List[Endpoint] = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # Path item $ref (OpenAPI 3).
        if "$ref" in item and len(item) == 1:
            resolved = resolver.resolve(item["$ref"])
            if isinstance(resolved, dict):
                item = resolved
        common = _params_v3(item.get("parameters", []), resolver, report)
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            ref_before = len(report.unresolved_refs)
            op_params = _params_v3(op.get("parameters", []), resolver, report)
            ep_params = _merge_params(common, op_params)

            request_body = _request_body_v3(op.get("requestBody"), resolver, report)
            has_body = request_body is not None and bool(request_body.content)
            media_type = request_body.primary_media_type if request_body else None
            consumes_json = _is_json_media(media_type) if media_type else True
            body_example = _body_example_for(request_body, resolver, report)

            responses = _responses_v3(op.get("responses"), resolver, report)

            op_security_raw = op.get("security")
            security = (
                _security_v3(op_security_raw)
                if op_security_raw is not None
                else list(global_security)
            )

            op_servers = _servers_v3(op.get("servers") or [], spec) or list(global_servers)

            cov = CoverageEntry(
                operation=f"{method.upper()} {path}",
                resolved=True,
                security=[name for req in security for name in req.schemes],
                unresolved_refs=list(report.unresolved_refs[ref_before:]),
            )
            _record_param_coverage(cov, ep_params, report)
            if request_body and not body_example:
                cov.missing_examples.append("requestBody")
                report.add_missing_example(f"{method.upper()} {path}: requestBody")
            for name in cov.security:
                scheme = report.security_schemes.get(name)
                if scheme and not scheme.testable:
                    cov.untestable_security.append(name)
            _record_unsupported_for_op(cov, op, report)
            if cov.unresolved_refs:
                cov.resolved = False

            endpoint = Endpoint(
                path=path,
                method=method.upper(),
                operation_id=op.get("operationId"),
                summary=op.get("summary"),
                parameters=ep_params,
                has_body=has_body,
                body_example=body_example,
                consumes_json=consumes_json,
                request_body=request_body,
                responses=responses,
                security=security,
                servers=op_servers,
                tags=list(op.get("tags") or []),
                deprecated=bool(op.get("deprecated", False)),
                description=op.get("description"),
                coverage=cov,
            )
            endpoints.append(endpoint)
            report.operations.append(cov)

    report.operation_count = len(endpoints)
    return endpoints


def _params_v3(
    raw_params: Any, resolver: RefResolver, report: CoverageReport
) -> List[Parameter]:
    out: List[Parameter] = []
    if not isinstance(raw_params, list):
        return out
    for p in raw_params:
        if not isinstance(p, dict):
            continue
        if "$ref" in p:
            resolved = resolver.resolve(p["$ref"])
            if isinstance(resolved, dict):
                p = resolved
            else:
                continue
        out.append(_build_parameter_v3(p, resolver, report))
    return out


def _resolve_schema_ref(
    schema: Any, resolver: RefResolver
) -> Optional[Dict[str, Any]]:
    """Return a raw schema dict, following a top-level $ref if present."""
    if not isinstance(schema, dict):
        return None
    if "$ref" in schema:
        target = resolver.resolve(schema["$ref"])
        return target if isinstance(target, dict) else None
    return schema


def _build_parameter_v3(
    p: Dict[str, Any], resolver: RefResolver, report: CoverageReport
) -> Parameter:
    schema = _resolve_schema_ref(p.get("schema"), resolver) or {}
    _record_unsupported_schema(schema, report)

    example = p.get("example")
    if example is None and schema.get("example") is not None:
        example = schema["example"]
    if example is None and isinstance(p.get("examples"), dict) and p["examples"]:
        first = next(iter(p["examples"].values()))
        if isinstance(first, dict) and "value" in first:
            example = first["value"]

    content_map = _content_map_v3(p.get("content"), resolver, report)

    return Parameter(
        name=p.get("name", ""),
        location=p.get("in", "query"),
        required=bool(p.get("required", False)),
        schema_type=_schema_type(schema),
        example=example,
        enum=schema.get("enum") if isinstance(schema.get("enum"), list) else None,
        minimum=schema.get("minimum"),
        maximum=schema.get("maximum"),
        min_length=schema.get("minLength"),
        max_length=schema.get("maxLength"),
        pattern=schema.get("pattern"),
        format=schema.get("format"),
        default=schema.get("default"),
        schema=schema or None,
        description=p.get("description") or schema.get("description"),
        style=p.get("style"),
        explode=p.get("explode"),
        allow_empty_value=bool(p.get("allowEmptyValue", False)),
        allow_reserved=bool(p.get("allowReserved", False)),
        deprecated=bool(p.get("deprecated", False)),
        content=content_map or None,
    )


def _request_body_v3(
    raw: Any, resolver: RefResolver, report: CoverageReport
) -> Optional[RequestBody]:
    if not isinstance(raw, dict):
        return None
    if "$ref" in raw:
        resolved = resolver.resolve(raw["$ref"])
        if isinstance(resolved, dict):
            raw = resolved
        else:
            return RequestBody(required=False)
    content = _content_map_v3(raw.get("content"), resolver, report)
    primary = _pick_primary_media(content)
    return RequestBody(
        description=raw.get("description"),
        required=bool(raw.get("required", False)),
        content=content,
        primary_media_type=primary,
    )


def _content_map_v3(
    raw: Any, resolver: RefResolver, report: CoverageReport
) -> Dict[str, MediaType]:
    out: Dict[str, MediaType] = {}
    if not isinstance(raw, dict):
        return out
    for media, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        if "$ref" in entry:
            resolved = resolver.resolve(entry["$ref"])
            entry = resolved if isinstance(resolved, dict) else {}
        schema = _resolve_schema_ref(entry.get("schema"), resolver)
        if isinstance(schema, dict):
            _record_unsupported_schema(schema, report)
        example = entry.get("example")
        examples_raw = entry.get("examples") or {}
        examples: Dict[str, Any] = {}
        if isinstance(examples_raw, dict):
            for ename, eval_ in examples_raw.items():
                if isinstance(eval_, dict):
                    if "$ref" in eval_:
                        r = resolver.resolve(eval_["$ref"])
                        eval_ = r if isinstance(r, dict) else {}
                    examples[ename] = eval_.get("value")
                else:
                    examples[ename] = eval_
        encoding = entry.get("encoding") if isinstance(entry.get("encoding"), dict) else {}
        out[media] = MediaType(
            media_type=media,
            schema=schema,
            example=example,
            examples=examples,
            encoding=encoding or {},
        )
    return out


def _responses_v3(
    raw: Any, resolver: RefResolver, report: CoverageReport
) -> Dict[str, Response]:
    out: Dict[str, Response] = {}
    if not isinstance(raw, dict):
        return out
    for status, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        if "$ref" in entry:
            resolved = resolver.resolve(entry["$ref"])
            entry = resolved if isinstance(resolved, dict) else {}
        content = _content_map_v3(entry.get("content"), resolver, report)
        headers: Dict[str, Parameter] = {}
        for hname, hdef in (entry.get("headers") or {}).items():
            if not isinstance(hdef, dict):
                continue
            if "$ref" in hdef:
                r = resolver.resolve(hdef["$ref"])
                hdef = r if isinstance(r, dict) else {}
            headers[hname] = _build_parameter_v3(
                {"name": hname, "in": "header", "schema": hdef.get("schema"), **hdef},
                resolver,
                report,
            )
        out[str(status)] = Response(
            status_code=str(status),
            description=entry.get("description"),
            content=content,
            headers=headers,
        )
    return out


def _security_v3(raw: Any, resolver: Optional[RefResolver] = None) -> List[SecurityRequirement]:
    out: List[SecurityRequirement] = []
    if not isinstance(raw, list):
        return out
    for req in raw:
        if not isinstance(req, dict):
            continue
        schemes: Dict[str, List[str]] = {}
        for name, scopes in req.items():
            if isinstance(scopes, list):
                schemes[name] = [str(s) for s in scopes]
            else:
                schemes[name] = []
        out.append(SecurityRequirement(schemes=schemes))
    return out


def _security_schemes_v3(raw: Dict[str, Any]) -> Dict[str, SecurityScheme]:
    out: Dict[str, SecurityScheme] = {}
    if not isinstance(raw, dict):
        return out
    for name, definition in raw.items():
        if not isinstance(definition, dict):
            continue
        stype = definition.get("type", "http")
        testable = True
        reason: Optional[str] = None
        # oauth2 / openIdConnect require user credentials/endpoints to exercise.
        if stype in ("oauth2", "openIdConnect"):
            testable = False
            reason = "requires user-supplied credentials/flow configuration"
        elif stype == "http" and definition.get("scheme") in ("basic", "bearer"):
            testable = False
            reason = "requires user-supplied credentials"
        elif stype == "apiKey":
            testable = False
            reason = "requires user-supplied API key"
        out[name] = SecurityScheme(
            name=name,
            type=stype,
            description=definition.get("description"),
            scheme=definition.get("scheme"),
            bearer_format=definition.get("bearerFormat"),
            location=definition.get("in"),
            header_name=definition.get("name"),
            flows=definition.get("flows") or {},
            open_id_connect_url=definition.get("openIdConnectUrl"),
            testable=testable,
            untestable_reason=reason,
        )
    return out


def _servers_v3(raw: Any, spec: Dict[str, Any]) -> List[Server]:
    servers: List[Server] = []
    if isinstance(raw, list):
        for s in raw:
            if isinstance(s, dict) and s.get("url"):
                servers.append(
                    Server(
                        url=s["url"],
                        description=s.get("description"),
                        variables=s.get("variables") or {},
                    )
                )
    if not servers and isinstance(spec.get("url"), str) and spec["url"]:
        servers.append(Server(url=spec["url"]))
    return servers


# ---------------------------------------------------------------------------
# OpenAPI 2.0 (Swagger)
# ---------------------------------------------------------------------------


def _parse_openapi2(
    spec: Dict[str, Any], resolver: RefResolver, report: CoverageReport
) -> List[Endpoint]:
    global_security = _security_v2(spec.get("security"))
    for name, scheme in _security_schemes_v2(spec.get("securityDefinitions") or {}).items():
        report.security_schemes[name] = scheme
    global_servers = _servers_v2(spec)
    global_consumes = _media_list(spec.get("consumes"))
    global_produces = _media_list(spec.get("produces"))

    endpoints: List[Endpoint] = []
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common = _params_v2(item.get("parameters", []), resolver, report)
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            ref_before = len(report.unresolved_refs)
            op_params = _params_v2(op.get("parameters", []), resolver, report)
            ep_params = _merge_params(common, op_params)

            consumes = _media_list(op.get("consumes")) or list(global_consumes)
            produces = _media_list(op.get("produces")) or list(global_produces)

            has_body = any(p.location == "body" for p in ep_params)
            body_schema: Optional[Dict[str, Any]] = None
            body_required = False
            if has_body:
                for raw in op.get("parameters", []) + item.get("parameters", []):
                    if isinstance(raw, dict) and raw.get("in") == "body":
                        body_schema = _resolve_schema_ref(raw.get("schema"), resolver)
                        if isinstance(body_schema, dict):
                            _record_unsupported_schema(body_schema, report)
                        body_required = bool(raw.get("required", False))
                        break
                ep_params = [p for p in ep_params if p.location != "body"]

            # Swagger 2 formData parameters model a form/multipart body.
            form_params = [p for p in ep_params if p.location == "formData"]
            form_media: Optional[str] = None
            form_schema: Optional[Dict[str, Any]] = None
            if form_params and not has_body:
                has_body = True
                has_file = any(
                    p.schema_type == "file"
                    or (isinstance(p.schema, dict) and p.schema.get("type") == "file")
                    for p in form_params
                )
                form_media = (
                    "multipart/form-data" if has_file else "application/x-www-form-urlencoded"
                )
                if form_media not in consumes:
                    consumes = [form_media] + [m for m in consumes if m != form_media]
                body_required = any(p.required for p in form_params)
                ep_params = [p for p in ep_params if p.location != "formData"]
                form_schema = {
                    "type": "object",
                    "properties": {
                        p.name: (
                            {"type": "file", "format": "binary"}
                            if (
                                p.schema_type == "file"
                                or (isinstance(p.schema, dict) and p.schema.get("type") == "file")
                            )
                            else (p.schema or {"type": p.schema_type})
                        )
                        for p in form_params
                    },
                    "required": [p.name for p in form_params if p.required],
                }

            primary = _pick_primary_media_v2(consumes)
            consumes_json = _is_json_media(primary) if primary else True

            body_example: Optional[Dict[str, Any]] = None
            if body_schema is not None:
                generated = generate_example(
                    body_schema,
                    resolver=resolver,
                    context="request",
                    report=report,
                    label=f"{method.upper()} {path}: body",
                )
                body_example = generated if isinstance(generated, dict) else None
            elif form_params and form_media:
                body_example = {p.name: _param_placeholder(p) for p in form_params}

            responses = _responses_v2(op.get("responses"), produces, resolver, report)

            op_security_raw = op.get("security")
            security = (
                _security_v2(op_security_raw)
                if op_security_raw is not None
                else list(global_security)
            )
            op_servers = list(global_servers)

            request_body: Optional[RequestBody] = None
            if has_body:
                content: Dict[str, MediaType] = {}
                media_types = consumes or [form_media or "application/json"]
                for mt in media_types:
                    if form_media and mt == form_media:
                        content[mt] = MediaType(
                            media_type=mt, schema=form_schema, example=body_example
                        )
                    else:
                        content[mt] = MediaType(media_type=mt, schema=body_schema)
                request_body = RequestBody(
                    required=body_required,
                    content=content,
                    primary_media_type=primary or form_media or "application/json",
                )

            cov = CoverageEntry(
                operation=f"{method.upper()} {path}",
                resolved=True,
                security=[name for req in security for name in req.schemes],
                unresolved_refs=list(report.unresolved_refs[ref_before:]),
            )
            _record_param_coverage(cov, ep_params, report)
            if has_body and not body_example:
                cov.missing_examples.append("requestBody")
                report.add_missing_example(f"{method.upper()} {path}: body")
            for name in cov.security:
                scheme = report.security_schemes.get(name)
                if scheme and not scheme.testable:
                    cov.untestable_security.append(name)
            _record_unsupported_for_op(cov, op, report)
            if cov.unresolved_refs:
                cov.resolved = False

            endpoint = Endpoint(
                path=path,
                method=method.upper(),
                operation_id=op.get("operationId"),
                summary=op.get("summary"),
                parameters=ep_params,
                has_body=has_body,
                body_example=body_example,
                consumes_json=consumes_json,
                request_body=request_body,
                responses=responses,
                security=security,
                servers=op_servers,
                consumes=consumes,
                produces=produces,
                tags=list(op.get("tags") or []),
                deprecated=bool(op.get("deprecated", False)),
                description=op.get("description"),
                coverage=cov,
            )
            endpoints.append(endpoint)
            report.operations.append(cov)

    report.operation_count = len(endpoints)
    return endpoints


def _params_v2(
    raw_params: Any, resolver: RefResolver, report: CoverageReport
) -> List[Parameter]:
    out: List[Parameter] = []
    if not isinstance(raw_params, list):
        return out
    for p in raw_params:
        if not isinstance(p, dict):
            continue
        if "$ref" in p:
            resolved = resolver.resolve(p["$ref"])
            if isinstance(resolved, dict):
                p = resolved
            else:
                continue
        out.append(_build_parameter_v2(p, resolver, report))
    return out


def _build_parameter_v2(
    p: Dict[str, Any], resolver: RefResolver, report: CoverageReport
) -> Parameter:
    if p.get("in") == "body":
        body_schema = _resolve_schema_ref(p.get("schema"), resolver)
        if isinstance(body_schema, dict):
            _record_unsupported_schema(body_schema, report)
        return Parameter(
            name=p.get("name", "body"),
            location="body",
            required=bool(p.get("required", False)),
            schema_type="object",
            schema=body_schema,
            description=p.get("description"),
            example=p.get("example"),
            default=p.get("default"),
        )
    # Non-body v2 parameters carry schema keywords on the parameter itself.
    schema = {
        k: p[k]
        for k in ("type", "format", "enum", "minimum", "maximum", "minLength",
                  "maxLength", "pattern", "default", "items", "collectionFormat")
        if k in p
    }
    _record_unsupported_schema(schema, report)
    return Parameter(
        name=p.get("name", ""),
        location=p.get("in", "query"),
        required=bool(p.get("required", False)),
        schema_type=p.get("type", "string"),
        example=p.get("example"),
        enum=p.get("enum") if isinstance(p.get("enum"), list) else None,
        minimum=p.get("minimum"),
        maximum=p.get("maximum"),
        min_length=p.get("minLength"),
        max_length=p.get("maxLength"),
        pattern=p.get("pattern"),
        format=p.get("format"),
        default=p.get("default"),
        schema=schema or None,
        description=p.get("description"),
        deprecated=bool(p.get("deprecated", False)),
        allow_empty_value=bool(p.get("allowEmptyValue", False)),
    )


def _responses_v2(
    raw: Any, produces: List[str], resolver: RefResolver, report: CoverageReport
) -> Dict[str, Response]:
    out: Dict[str, Response] = {}
    if not isinstance(raw, dict):
        return out
    for status, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        if "$ref" in entry:
            resolved = resolver.resolve(entry["$ref"])
            entry = resolved if isinstance(resolved, dict) else {}
        content: Dict[str, MediaType] = {}
        schema = _resolve_schema_ref(entry.get("schema"), resolver)
        if isinstance(schema, dict):
            _record_unsupported_schema(schema, report)
        media_types = produces or (["application/json"] if schema else [])
        for mt in media_types:
            content[mt] = MediaType(media_type=mt, schema=schema)
        headers: Dict[str, Parameter] = {}
        for hname, hdef in (entry.get("headers") or {}).items():
            if isinstance(hdef, dict):
                headers[hname] = _build_parameter_v2(
                    {"name": hname, "in": "header", **hdef}, resolver, report
                )
        out[str(status)] = Response(
            status_code=str(status),
            description=entry.get("description"),
            content=content,
            headers=headers,
        )
    return out


def _security_v2(raw: Any) -> List[SecurityRequirement]:
    return _security_v3(raw)


def _security_schemes_v2(raw: Dict[str, Any]) -> Dict[str, SecurityScheme]:
    out: Dict[str, SecurityScheme] = {}
    if not isinstance(raw, dict):
        return out
    for name, definition in raw.items():
        if not isinstance(definition, dict):
            continue
        stype = definition.get("type", "basic")
        out[name] = SecurityScheme(
            name=name,
            type=stype,
            description=definition.get("description"),
            scheme="basic" if stype == "basic" else None,
            location=definition.get("in"),
            header_name=definition.get("name") if stype == "apiKey" else None,
            flows=definition.get("flow") or {},
            testable=False,
            untestable_reason="requires user-supplied credentials",
        )
    return out


def _servers_v2(spec: Dict[str, Any]) -> List[Server]:
    host = spec.get("host")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes") or ["http"]
    servers: List[Server] = []
    if host:
        for scheme in schemes:
            servers.append(Server(url=f"{scheme}://{host}{base_path}"))
    elif base_path:
        servers.append(Server(url=base_path))
    return servers


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _media_list(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(m) for m in raw if isinstance(m, str)]
    return []


def _is_json_media(media: Optional[str]) -> bool:
    if not media:
        return True
    return media == "application/json" or media.endswith("+json")


def _pick_primary_media(content: Dict[str, MediaType]) -> Optional[str]:
    if not content:
        return None
    for media in content:
        if _is_json_media(media):
            return media
    return next(iter(content))


def _pick_primary_media_v2(consumes: List[str]) -> Optional[str]:
    if not consumes:
        return None
    for media in consumes:
        if _is_json_media(media):
            return media
    return consumes[0]


def _schema_type(schema: Dict[str, Any]) -> str:
    t = schema.get("type")
    if isinstance(t, list):
        # OpenAPI 3.1 type arrays: pick the first non-null type.
        for candidate in t:
            if candidate and candidate != "null":
                return str(candidate)
        return "string"
    if isinstance(t, str):
        return t
    # Infer from composition/keywords when type is absent.
    if "properties" in schema or "additionalProperties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    if "allOf" in schema or "oneOf" in schema or "anyOf" in schema:
        return "object"
    return "string"


def _merge_params(
    common: List[Parameter], op_params: List[Parameter]
) -> List[Parameter]:
    """Merge path-item and operation parameters.

    Operation-level parameters override path-level definitions that share the
    same ``(name, in)`` pair; non-matching operation parameters are appended.
    Path-level ordering is preserved for surviving parameters.
    """
    by_key: Dict[Tuple[str, str], Parameter] = {}
    order: List[Tuple[str, str]] = []
    for p in common:
        key = (p.name, p.location)
        if key not in by_key:
            order.append(key)
        by_key[key] = p
    for p in op_params:
        key = (p.name, p.location)
        if key not in by_key:
            order.append(key)
        by_key[key] = p
    return [by_key[k] for k in order]


def _body_example_for(
    request_body: Optional[RequestBody],
    resolver: RefResolver,
    report: CoverageReport,
) -> Optional[Dict[str, Any]]:
    if not request_body or not request_body.content:
        return None
    media = request_body.content.get(
        request_body.primary_media_type or ""
    ) or next(iter(request_body.content.values()))
    if media is None:
        return None
    if isinstance(media.example, dict) and not media.schema:
        return copy.deepcopy(media.example)
    if isinstance(media.schema, dict):
        example = generate_example(
            media.schema,
            resolver=resolver,
            context="request",
            report=report,
            label=f"requestBody {media.media_type}",
        )
        return example if isinstance(example, dict) else None
    return None


def _record_param_coverage(
    cov: CoverageEntry, params: List[Parameter], report: CoverageReport
) -> None:
    for p in params:
        if p.location in ("path", "header", "cookie") and p.required:
            if p.example is None and p.default is None:
                label = f"{cov.operation}: {p.location}:{p.name}"
                cov.needs_user_values.append(f"{p.location}:{p.name}")
                report.add_needs_user_value(label)
        elif p.location == "path" and p.example is None and p.default is None:
            cov.needs_user_values.append(f"path:{p.name}")
            report.add_needs_user_value(f"{cov.operation}: path:{p.name}")


def _record_unsupported_schema(schema: Dict[str, Any], report: CoverageReport) -> None:
    if not isinstance(schema, dict):
        return
    for kw in UNSUPPORTED_SCHEMA_KEYWORDS:
        if kw in schema:
            report.add_unsupported(kw)


def _record_unsupported_for_op(
    cov: CoverageEntry, op: Dict[str, Any], report: CoverageReport
) -> None:
    for kw in UNSUPPORTED_OPERATION_KEYWORDS:
        if kw in op:
            report.add_unsupported(kw)
            if kw not in cov.unsupported_keywords:
                cov.unsupported_keywords.append(kw)


# ---------------------------------------------------------------------------
# Deterministic example generation
# ---------------------------------------------------------------------------


def generate_example(
    schema: Optional[Dict[str, Any]],
    *,
    resolver: Optional[RefResolver] = None,
    context: str = "request",
    depth: int = 0,
    max_depth: int = DEFAULT_MAX_DEPTH,
    array_size: int = DEFAULT_ARRAY_SIZE,
    report: Optional[CoverageReport] = None,
    label: str = "",
    chain: Optional[List[str]] = None,
) -> Any:
    """Generate a deterministic example value for a (possibly $ref'd) schema.

    ``context`` is ``"request"`` (omit ``readOnly`` fields) or ``"response"``
    (omit ``writeOnly`` fields). Depth and collection-size are bounded so
    recursive/cyclic structures terminate with valid minimal values.
    """
    if not isinstance(schema, dict):
        return "test"

    if "$ref" in schema:
        ref = schema["$ref"]
        active = list(chain or [])
        if resolver is None:
            return None
        target = resolver.resolve(ref, active)
        if target is None:
            return None  # cycle or unresolved
        return generate_example(
            target,
            resolver=resolver,
            context=context,
            depth=depth,
            max_depth=max_depth,
            array_size=array_size,
            report=report,
            label=label,
            chain=active + [ref],
        )

    # Explicit example/default/enum/const short-circuit type generation.
    if "example" in schema:
        return copy.deepcopy(schema["example"])
    if "default" in schema:
        return copy.deepcopy(schema["default"])
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return copy.deepcopy(schema["enum"][0])
    if "const" in schema:
        return copy.deepcopy(schema["const"])

    # Composition: allOf merges; oneOf/anyOf picks the first usable branch.
    if isinstance(schema.get("allOf"), list) and schema["allOf"]:
        merged = _merge_allof(schema["allOf"], resolver, chain)
        if merged:
            combined = {k: v for k, v in schema.items() if k != "allOf"}
            combined.update(merged)
            return generate_example(
                combined,
                resolver=resolver,
                context=context,
                depth=depth,
                max_depth=max_depth,
                array_size=array_size,
                report=report,
                label=label,
                chain=chain,
            )
    for compose_key in ("oneOf", "anyOf"):
        branches = schema.get(compose_key)
        if isinstance(branches, list) and branches:
            for branch in branches:
                resolved_branch = branch
                if (
                    resolver is not None
                    and isinstance(branch, dict)
                    and "$ref" in branch
                ):
                    resolved_branch = resolver.resolve(branch["$ref"], chain)
                value = generate_example(
                    resolved_branch if isinstance(resolved_branch, dict) else branch,
                    resolver=resolver,
                    context=context,
                    depth=depth,
                    max_depth=max_depth,
                    array_size=array_size,
                    report=report,
                    label=label,
                    chain=chain,
                )
                if value is not None:
                    disc = schema.get("discriminator")
                    if isinstance(disc, dict) and isinstance(value, dict):
                        prop = disc.get("propertyName")
                        if prop and prop not in value:
                            mapping = disc.get("mapping") or {}
                            value[prop] = (
                                next(iter(mapping), None)
                                or (branch.get("title") if isinstance(branch, dict) else None)
                                or "member"
                            )
                    return value
            if report is not None and label:
                report.add_missing_example(label)
            return None

    type_value = schema.get("type")
    if isinstance(type_value, list):
        types = [str(t) for t in type_value]
    elif isinstance(type_value, str):
        types = [type_value]
    else:
        types = []

    # Nullable: prefer a non-null type for the example.
    non_null_types = [t for t in types if t != "null"]
    primary_type = non_null_types[0] if non_null_types else (
        "null" if types else _inferred_type(schema)
    )

    if primary_type == "null":
        return None
    if primary_type == "object" or ("properties" in schema and not types):
        return _example_for_object(
            schema, resolver, context, depth, max_depth, array_size, report, label, chain
        )
    if primary_type == "array":
        return _example_for_array(
            schema, resolver, context, depth, max_depth, array_size, report, label, chain
        )
    return _example_for_scalar(primary_type, schema)


def _inferred_type(schema: Dict[str, Any]) -> str:
    if "properties" in schema or "additionalProperties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "string"


def _example_for_object(
    schema: Dict[str, Any],
    resolver: Optional[RefResolver],
    context: str,
    depth: int,
    max_depth: int,
    array_size: int,
    report: Optional[CoverageReport],
    label: str,
    chain: Optional[List[str]],
) -> Dict[str, Any]:
    if depth >= max_depth:
        return {}
    out: Dict[str, Any] = {}
    props = schema.get("properties")
    required = set(schema.get("required") or [])
    if isinstance(props, dict):
        for name, prop in props.items():
            # Resolve a top-level $ref on the property to inspect
            # readOnly/writeOnly metadata before deciding to skip it.
            prop_meta = prop
            if isinstance(prop, dict) and "$ref" in prop and resolver is not None:
                resolved_meta = resolver.resolve(prop["$ref"], chain)
                if isinstance(resolved_meta, dict):
                    prop_meta = resolved_meta
            is_readonly = bool(prop_meta.get("readOnly", False))
            is_writeonly = bool(prop_meta.get("writeOnly", False))
            if context == "request" and is_readonly and name not in required:
                continue
            if context == "response" and is_writeonly and name not in required:
                continue
            value = generate_example(
                prop,
                resolver=resolver,
                context=context,
                depth=depth + 1,
                max_depth=max_depth,
                array_size=array_size,
                report=report,
                label=f"{label}.{name}" if label else name,
                chain=chain,
            )
            if value is None:
                if name in required:
                    # Keep request examples valid even for cyclic/unresolvable
                    # required fields by falling back to a minimal typed value.
                    out[name] = _minimal_value_for(prop, resolver)
                # Optional cyclic/unresolvable fields are omitted.
                continue
            out[name] = value
    # Free-form object (additionalProperties without properties): one sample.
    ap = schema.get("additionalProperties")
    if isinstance(ap, dict) and ap and not props:
        sample = generate_example(
            ap,
            resolver=resolver,
            context=context,
            depth=depth + 1,
            max_depth=max_depth,
            array_size=array_size,
            report=report,
            label=label,
            chain=chain,
        )
        out["apifzExtra"] = sample
    return out


def _example_for_array(
    schema: Dict[str, Any],
    resolver: Optional[RefResolver],
    context: str,
    depth: int,
    max_depth: int,
    array_size: int,
    report: Optional[CoverageReport],
    label: str,
    chain: Optional[List[str]],
) -> List[Any]:
    if depth >= max_depth:
        return []
    items = schema.get("items")
    if isinstance(items, dict):
        item_schema = items
    elif isinstance(items, list) and items:
        # tuple validation: use the first item schema.
        item_schema = items[0]
    else:
        item_schema = {"type": "string"}
    value = generate_example(
        item_schema if isinstance(item_schema, dict) else {"type": "string"},
        resolver=resolver,
        context=context,
        depth=depth + 1,
        max_depth=max_depth,
        array_size=array_size,
        report=report,
        label=f"{label}[]" if label else "item",
        chain=chain,
    )
    if value is None:
        # Cyclic/unresolvable item: emit an empty array to stay type-valid.
        return []
    return [value] * array_size


def _example_for_scalar(type_value: str, schema: Dict[str, Any]) -> Any:
    if type_value == "integer":
        return 1
    if type_value == "number":
        return 1
    if type_value == "boolean":
        return True
    if type_value == "string":
        return _format_example(schema.get("format"), schema)
    if type_value == "array":
        return []
    if type_value == "object":
        return {}
    return "test"


def _minimal_value_for(
    schema: Any, resolver: Optional[RefResolver]
) -> Any:
    """Return a minimal valid value for a schema without recursing into cycles."""
    if isinstance(schema, dict) and "$ref" in schema and resolver is not None:
        target = resolver.resolve(schema["$ref"])
        if isinstance(target, dict):
            schema = target
        else:
            return {}
    if not isinstance(schema, dict):
        return "test"
    t = _schema_type(schema)
    if t == "array":
        return []
    if t == "object":
        return {}
    if t == "integer":
        return 1
    if t == "number":
        return 1
    if t == "boolean":
        return True
    return _format_example(schema.get("format"), schema)


def _format_example(fmt: Optional[str], schema: Dict[str, Any]) -> str:
    if fmt is None:
        return "test"
    f = fmt.lower()
    mapping = {
        "date-time": "2020-01-01T00:00:00Z",
        "datetime": "2020-01-01T00:00:00Z",
        "date": "2020-01-01",
        "time": "00:00:00Z",
        "duration": "P1D",
        "email": "user@example.com",
        "idn-email": "user@example.com",
        "uuid": "00000000-0000-4000-8000-000000000000",
        "uri": "https://example.com",
        "uri-reference": "/example",
        "uri-template": "/{id}",
        "iri": "https://example.com",
        "iri-reference": "/example",
        "hostname": "example.com",
        "idn-hostname": "example.com",
        "ipv4": "192.0.2.1",
        "ipv6": "2001:db8::1",
        "password": "test-pass-123",
        "regex": "test",
        "json-pointer": "/example",
        "relative-json-pointer": "1/example",
        "byte": "dGVzdA==",
        "binary": "test",
    }
    if f in mapping:
        return mapping[f]
    return "test"


def _merge_allof(
    all_of: List[Any],
    resolver: Optional[RefResolver],
    chain: Optional[List[str]],
) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    properties: Dict[str, Any] = {}
    required: List[Any] = []
    for sub in all_of:
        sub_schema = sub
        if (
            resolver is not None
            and isinstance(sub, dict)
            and "$ref" in sub
        ):
            sub_schema = resolver.resolve(sub["$ref"], chain)
        if not isinstance(sub_schema, dict):
            continue
        for k, v in sub_schema.items():
            if k == "properties" and isinstance(v, dict):
                properties.update(v)
            elif k == "required" and isinstance(v, list):
                required.extend(v)
            elif k == "allOf":
                inner = _merge_allof(v, resolver, chain)
                properties.update(inner.get("properties", {}))
                required.extend(inner.get("required", []))
                for ik, iv in inner.items():
                    if ik not in ("properties", "required"):
                        merged.setdefault(ik, iv)
            else:
                merged.setdefault(k, v)
    if properties:
        merged["properties"] = properties
    if required:
        seen: set = set()
        merged["required"] = [r for r in required if not (r in seen or seen.add(r))]
    return merged


# ---------------------------------------------------------------------------
# Prepared request builder (golden wire tests / contract model)
# ---------------------------------------------------------------------------


def _param_placeholder(param: Parameter) -> Any:
    if param.example is not None:
        return param.example
    if param.default is not None:
        return param.default
    if param.enum:
        return param.enum[0]
    return _example_for_scalar(param.schema_type, param.schema or {})


def _substitute_path(template: str, path_params: Dict[str, Any]) -> Tuple[str, List[str]]:
    out = template
    for name, value in path_params.items():
        out = out.replace("{" + name + "}", quote(str(value), safe=""))
    # Detect any remaining unresolved {token}s.
    missing: List[str] = []
    i = 0
    while i < len(out):
        if out[i] == "{":
            end = out.find("}", i)
            if end == -1:
                break
            missing.append(out[i + 1:end])
            i = end + 1
        else:
            i += 1
    return out, missing


def build_request(
    endpoint: Endpoint,
    base_url: str = "",
    *,
    values: Optional[Dict[str, Any]] = None,
    media_type: Optional[str] = None,
) -> PreparedRequest:
    """Build a deterministic prepared wire request from an Endpoint.

    ``values`` may override path/query/header/cookie parameter values by name
    and/or request body field values (by field name, or via the special
    ``__body__`` mapping to replace the whole body). ``media_type`` selects a
    specific request body media type; otherwise the operation's primary media
    type is used.
    """
    values = values or {}
    path_params: Dict[str, Any] = {}
    query: List[Tuple[str, str]] = []
    headers: Dict[str, str] = {}
    cookies: List[Tuple[str, str]] = []

    for p in endpoint.parameters:
        value = values.get(p.name, _param_placeholder(p))
        if p.location == "path":
            path_params[p.name] = value
        elif p.location == "query":
            query.append((p.name, _stringify(value)))
        elif p.location == "header":
            headers[p.name] = _stringify(value)
        elif p.location == "cookie":
            cookies.append((p.name, _stringify(value)))

    path, missing = _substitute_path(endpoint.path, path_params)
    url = base_url.rstrip("/") + path if base_url else path

    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies)

    prepared = PreparedRequest(method=endpoint.method, url=url, headers=headers, query=query)
    if missing and endpoint.coverage is not None:
        endpoint.coverage.notes.append(f"unresolved path tokens: {missing}")

    if endpoint.has_body and endpoint.request_body is not None:
        chosen = media_type or endpoint.request_body.primary_media_type
        media = endpoint.request_body.content.get(chosen or "") if chosen else None
        if media is None and endpoint.request_body.content:
            media = next(iter(endpoint.request_body.content.values()))
            chosen = media.media_type
        if media is not None:
            _populate_body(prepared, media, values)

    return prepared


def _populate_body(
    prepared: PreparedRequest, media: MediaType, values: Dict[str, Any]
) -> None:
    mt = media.media_type
    schema = media.schema
    if isinstance(media.example, dict) and not schema:
        example: Any = copy.deepcopy(media.example)
    elif isinstance(schema, dict):
        example = generate_example(schema, context="request")
    elif isinstance(media.example, (dict, list)):
        example = copy.deepcopy(media.example)
    else:
        example = None

    if isinstance(values.get("__body__"), dict) and isinstance(example, dict):
        example.update(values["__body__"])
    elif isinstance(example, dict):
        for k, v in values.items():
            if k in example:
                example[k] = v

    if mt in JSON_MEDIA_TYPES or _is_json_media(mt):
        prepared.content_type = "application/json"
        prepared.body = json.dumps(example, separators=(",", ":")) if example is not None else None
    elif mt in FORM_MEDIA_TYPES:
        prepared.content_type = "application/x-www-form-urlencoded"
        fields = example if isinstance(example, dict) else {}
        prepared.body = urlencode(_stringify_dict(fields))
    elif mt in MULTIPART_MEDIA_TYPES:
        prepared.content_type = f"multipart/form-data; boundary={MULTIPART_BOUNDARY}"
        fields = example if isinstance(example, dict) else {}
        prop_schemas = (schema or {}).get("properties", {}) if isinstance(schema, dict) else {}
        files: List[Tuple[str, str, str, str]] = []
        text_fields: Dict[str, str] = {}
        for fname, value in fields.items():
            ps = prop_schemas.get(fname, {})
            is_binary = (
                isinstance(ps, dict)
                and (ps.get("format") == "binary" or ps.get("type") == "file")
            )
            if is_binary:
                files.append((fname, f"{fname}.txt", DEFAULT_BINARY_CANARY, "text/plain"))
            else:
                text_fields[fname] = _stringify(value)
        prepared.files = files or None
        prepared.body = _serialize_multipart(text_fields, files)
    elif mt in XML_MEDIA_TYPES:
        prepared.content_type = "application/xml"
        prepared.body = _serialize_xml(example, schema) if example is not None else None
    else:
        prepared.content_type = mt
        if example is None:
            prepared.body = None
        elif isinstance(example, str):
            prepared.body = example
        else:
            prepared.body = json.dumps(example)


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _stringify_dict(d: Dict[str, Any]) -> List[Tuple[str, str]]:
    return [(k, _stringify(v)) for k, v in d.items()]


def _serialize_multipart(
    fields: Dict[str, str], files: List[Tuple[str, str, str, str]]
) -> str:
    parts: List[str] = []
    for name, value in fields.items():
        parts.append(f"--{MULTIPART_BOUNDARY}")
        parts.append(f'Content-Disposition: form-data; name="{name}"')
        parts.append("")
        parts.append(value)
    for name, filename, content, mime in files:
        parts.append(f"--{MULTIPART_BOUNDARY}")
        parts.append(
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"'
        )
        parts.append(f"Content-Type: {mime}")
        parts.append("")
        parts.append(content)
    parts.append(f"--{MULTIPART_BOUNDARY}--")
    parts.append("")
    return "\r\n".join(parts)


def _xml_tag(name: str, text: str, *, ns_prefix: Optional[str] = None) -> str:
    tag = f"{ns_prefix}:{name}" if ns_prefix else name
    return f"<{tag}>{text}</{tag}>"


def _serialize_xml(
    value: Any,
    schema: Optional[Dict[str, Any]],
    *,
    root: Optional[str] = None,
    depth: int = 0,
) -> str:
    if depth > DEFAULT_MAX_DEPTH:
        return ""
    xml_meta = schema.get("xml") if isinstance(schema, dict) else None
    ns = xml_meta.get("namespace") if isinstance(xml_meta, dict) else None
    prefix = xml_meta.get("prefix") if isinstance(xml_meta, dict) else None
    root_name = (
        root
        or (xml_meta.get("name") if isinstance(xml_meta, dict) else None)
        or (schema.get("title") if isinstance(schema, dict) else None)
        or "root"
    )

    if isinstance(value, dict):
        prop_schemas = (schema or {}).get("properties", {}) if isinstance(schema, dict) else {}
        children: List[str] = []
        for name, val in value.items():
            child_schema = prop_schemas.get(name, {})
            if isinstance(val, dict):
                children.append(_serialize_xml(val, child_schema, root=name, depth=depth + 1))
            elif isinstance(val, list):
                item_schema = child_schema.get("items", {}) if isinstance(child_schema, dict) else {}
                item_xml = child_schema.get("xml", {}) if isinstance(child_schema, dict) else {}
                item_name = item_xml.get("name", name) if isinstance(item_xml, dict) else name
                for item in val:
                    children.append(_serialize_xml(item, item_schema, root=item_name, depth=depth + 1))
            else:
                children.append(_xml_tag(name, _xml_escape(_stringify(val)), ns_prefix=prefix))
        tag = f"{prefix}:{root_name}" if prefix else root_name
        attr = f' xmlns:{prefix}="{ns}"' if (prefix and ns) else (f' xmlns="{ns}"' if ns else "")
        return f"<{tag}{attr}>{''.join(children)}</{tag}>"
    if isinstance(value, list):
        item_schema = schema.get("items", {}) if isinstance(schema, dict) else {}
        item_xml = schema.get("xml", {}) if isinstance(schema, dict) else {}
        item_name = item_xml.get("name", root) if isinstance(item_xml, dict) else root
        return "".join(
            _serialize_xml(item, item_schema, root=item_name, depth=depth + 1) for item in value
        )
    return _xml_tag(root_name, _xml_escape(_stringify(value)), ns_prefix=prefix)


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
