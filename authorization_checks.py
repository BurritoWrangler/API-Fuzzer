"""Differential authorization planning and evidence helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from comparators import ResponseComparison, compare_http_responses
from spec_parser import Endpoint


IDENTIFIER_KEYS = {
    "account",
    "account_id",
    "customer",
    "customer_id",
    "document_id",
    "id",
    "item_id",
    "object_id",
    "order_id",
    "owner_id",
    "record_id",
    "resource_id",
    "tenant_id",
    "user",
    "user_id",
    "uuid",
}
IGNORED_IDENTIFIER_KEYS = {
    "correlation_id",
    "request_id",
    "trace_id",
}
SENSITIVE_PROPERTY_WORDS = {
    "admin",
    "approved",
    "balance",
    "blocked",
    "credit",
    "internal",
    "is_admin",
    "is_staff",
    "owner",
    "permissions",
    "price",
    "role",
    "roles",
    "scope",
    "status",
    "tenant",
    "verified",
}


@dataclass(frozen=True)
class IdentifierCandidate:
    value: Any
    field_name: str
    json_path: str
    source_profile: str
    source_endpoint: str
    ownership_hint: bool = False


@dataclass(frozen=True)
class AuthorizationMutation:
    parameter: str
    location: str
    value: Any
    source_profile: str
    source_path: str


@dataclass(frozen=True)
class Observation:
    status_code: int
    headers: Mapping[str, str]
    body: str
    profile: str


@dataclass(frozen=True)
class AuthorizationEvidence:
    vulnerable: bool
    confidence: str
    reason: str
    owner_vs_attacker: ResponseComparison
    anonymous_vs_attacker: Optional[ResponseComparison] = None


@dataclass(frozen=True)
class PropertyCandidate:
    json_path: str
    name: str
    schema: Dict[str, Any]
    reason: str


def _looks_like_identifier(name: str) -> bool:
    lowered = name.lower()
    if lowered in IGNORED_IDENTIFIER_KEYS:
        return False
    return (
        lowered in IDENTIFIER_KEYS
        or lowered.endswith("_id")
        or lowered.endswith("uuid")
    )


def _valid_identifier_value(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, str):
        stripped = value.strip()
        return 1 <= len(stripped) <= 256
    return False


def discover_identifiers(
    value: Any,
    *,
    source_profile: str,
    source_endpoint: str,
    max_candidates: int = 100,
) -> List[IdentifierCandidate]:
    """Discover bounded object identifiers in a successful JSON response."""
    candidates: List[IdentifierCandidate] = []
    seen: Set[Tuple[str, str]] = set()

    def walk(node: Any, path: str) -> None:
        if len(candidates) >= max_candidates:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}" if path != "$" else f"$.{key}"
                if _looks_like_identifier(str(key)) and _valid_identifier_value(child):
                    marker = (str(key).lower(), str(child))
                    if marker not in seen:
                        seen.add(marker)
                        candidates.append(
                            IdentifierCandidate(
                                value=child,
                                field_name=str(key),
                                json_path=child_path,
                                source_profile=source_profile,
                                source_endpoint=source_endpoint,
                                ownership_hint=str(key).lower()
                                in {"owner_id", "user_id", "account_id", "tenant_id"},
                            )
                        )
                walk(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{path}[{index}]")

    walk(value, "$")
    return candidates


def plan_identifier_mutations(
    endpoint: Endpoint,
    candidates: Iterable[IdentifierCandidate],
    *,
    target_profile: str,
) -> List[AuthorizationMutation]:
    """Map identifiers learned from another profile onto endpoint parameters."""
    del target_profile  # profile is carried by the execution context, not the mutation
    mutations: List[AuthorizationMutation] = []
    seen: Set[Tuple[str, str, str]] = set()
    parameters = [
        parameter
        for parameter in endpoint.parameters
        if parameter.location in ("path", "query", "body")
        and _looks_like_identifier(parameter.name)
    ]
    for candidate in candidates:
        for parameter in parameters:
            exact_name = parameter.name.lower() == candidate.field_name.lower()
            compatible_generic = (
                parameter.name.lower() in {"id", "uuid"}
                or candidate.field_name.lower() in {"id", "uuid"}
            )
            if not (exact_name or compatible_generic):
                continue
            marker = (parameter.name, parameter.location, str(candidate.value))
            if marker in seen:
                continue
            seen.add(marker)
            mutations.append(
                AuthorizationMutation(
                    parameter=parameter.name,
                    location=parameter.location,
                    value=candidate.value,
                    source_profile=candidate.source_profile,
                    source_path=candidate.json_path,
                )
            )
    return mutations


def evaluate_object_access(
    *,
    owner: Observation,
    attacker: Observation,
    anonymous: Optional[Observation] = None,
    ignored_json_paths: Optional[Sequence[str]] = None,
) -> AuthorizationEvidence:
    """Evaluate whether an attacker received the owner's material response."""
    owner_comparison = compare_http_responses(
        baseline_status=owner.status_code,
        baseline_headers=owner.headers,
        baseline_body=owner.body,
        candidate_status=attacker.status_code,
        candidate_headers=attacker.headers,
        candidate_body=attacker.body,
        ignored_json_paths=ignored_json_paths,
    )
    anonymous_comparison: Optional[ResponseComparison] = None
    if anonymous is not None:
        anonymous_comparison = compare_http_responses(
            baseline_status=anonymous.status_code,
            baseline_headers=anonymous.headers,
            baseline_body=anonymous.body,
            candidate_status=attacker.status_code,
            candidate_headers=attacker.headers,
            candidate_body=attacker.body,
            ignored_json_paths=ignored_json_paths,
        )

    attacker_success = 200 <= attacker.status_code < 300
    owner_success = 200 <= owner.status_code < 300
    public_equivalent = bool(
        anonymous is not None
        and 200 <= anonymous.status_code < 300
        and anonymous_comparison is not None
        and anonymous_comparison.equivalent
    )
    vulnerable = (
        owner_success
        and attacker_success
        and owner_comparison.equivalent
        and not public_equivalent
    )
    if vulnerable:
        return AuthorizationEvidence(
            True,
            "strong",
            "A different authenticated profile received a response materially "
            "equivalent to the owning profile, while anonymous access was not equivalent.",
            owner_comparison,
            anonymous_comparison,
        )
    if owner_success and attacker_success and owner_comparison.shape_equal and not public_equivalent:
        return AuthorizationEvidence(
            False,
            "tentative",
            "Both identities received successful responses with the same shape, "
            "but the object content was not equivalent.",
            owner_comparison,
            anonymous_comparison,
        )
    return AuthorizationEvidence(
        False,
        "informational",
        "The attacker response did not reproduce the owner's protected response.",
        owner_comparison,
        anonymous_comparison,
    )


def _schema_properties(
    schema: Any,
    *,
    path: str = "$",
) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    if not isinstance(schema, dict):
        return
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            if not isinstance(child, dict):
                continue
            child_path = f"{path}.{name}" if path != "$" else f"$.{name}"
            yield child_path, str(name), child
            yield from _schema_properties(child, path=child_path)
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _schema_properties(items, path=f"{path}[*]")


def _request_property_paths(endpoint: Endpoint) -> Set[str]:
    paths: Set[str] = set()
    request_body = endpoint.request_body
    if request_body is None:
        return paths
    for media in request_body.content.values():
        for path, _, _ in _schema_properties(media.schema):
            paths.add(path)
    return paths


def derive_property_candidates(endpoint: Endpoint) -> List[PropertyCandidate]:
    """Derive response-only/read-only/sensitive properties for BOPLA probes."""
    request_paths = _request_property_paths(endpoint)
    candidates: List[PropertyCandidate] = []
    seen: Set[str] = set()
    for status, response in endpoint.responses.items():
        if not (str(status).startswith("2") or str(status).lower() == "default"):
            continue
        for media in response.content.values():
            for path, name, schema in _schema_properties(media.schema):
                lowered = name.lower()
                reasons = []
                if schema.get("readOnly") is True:
                    reasons.append("readOnly response property")
                if path not in request_paths:
                    reasons.append("response-only property")
                if lowered in SENSITIVE_PROPERTY_WORDS or any(
                    word in lowered for word in ("admin", "owner", "role", "tenant", "price")
                ):
                    reasons.append("authorization-sensitive name")
                if reasons and path not in seen:
                    seen.add(path)
                    candidates.append(
                        PropertyCandidate(
                            json_path=path,
                            name=name,
                            schema=dict(schema),
                            reason=", ".join(reasons),
                        )
                    )
    return candidates


def marker_value_for_property(candidate: PropertyCandidate) -> Any:
    """Return a harmless marker matching a candidate property's declared type."""
    schema_type = candidate.schema.get("type")
    if schema_type == "boolean":
        return True
    if schema_type == "integer":
        return 2147483000
    if schema_type == "number":
        return 2147483000.5
    if schema_type == "array":
        return ["apifuzz-marker"]
    if schema_type == "object":
        return {"apifuzz_marker": True}
    return "apifuzz-marker"
