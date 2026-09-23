"""Phase 3: Response contract validation and security requirement enforcement.

Validates observed responses against OpenAPI response schemas, detects
sensitive data exposure, compares property sets between identities, and
flags operations with non-empty security requirements that accept anonymous
requests. Uses the pure helpers in ``response_checks.py``.
"""

from __future__ import annotations

import json as jsonlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from analyzer import Finding
from models import AuthProfile
from response_checks import ContractIssue, SensitiveMatch, find_sensitive_json, validate_response_schema
from spec_parser import Endpoint


@dataclass
class ResponseContractFinding:
    category: str  # contract_violation | data_exposure | missing_auth
    severity: str
    confidence: str
    title: str
    endpoint: str
    method: str
    parameter: str
    evidence: str
    owasp_api: str
    cwe: str
    request_url: str
    status_code: int = 0


def _parse_json(body: Optional[str]) -> Any:
    if not body:
        return None
    try:
        return jsonlib.loads(body)
    except (jsonlib.JSONDecodeError, TypeError):
        return None


def _content_type(headers: Dict[str, str]) -> str:
    for name, value in headers.items():
        if name.lower() == "content-type":
            return str(value).split(";", 1)[0].strip().lower()
    return ""


def _schema_for_response(endpoint: Endpoint, status_code: int) -> Optional[Dict[str, Any]]:
    """Find the best-matching response schema for the observed status code."""
    responses = endpoint.responses
    if not responses:
        return None
    exact = responses.get(str(status_code))
    if exact:
        for media in exact.content.values():
            if media.schema:
                return media.schema
    # Try 2XX wildcard.
    wildcard = responses.get("2XX")
    if wildcard:
        for media in wildcard.content.values():
            if media.schema:
                return media.schema
    # Try default.
    default = responses.get("default")
    if default:
        for media in default.content.values():
            if media.schema:
                return media.schema
    return None


def validate_response(
    endpoint: Endpoint,
    status_code: int,
    headers: Dict[str, str],
    body: Optional[str],
    request_url: str,
) -> List[ResponseContractFinding]:
    """Validate a single response against the endpoint's declared schema."""
    findings: List[ResponseContractFinding] = []
    schema = _schema_for_response(endpoint, status_code)
    if schema is None:
        return findings

    parsed = _parse_json(body)
    issues = validate_response_schema(parsed, schema)
    for issue in issues:
        severity = "medium" if issue.code in ("type", "required") else "low"
        findings.append(ResponseContractFinding(
            category="contract_violation",
            severity=severity,
            confidence="strong",
            title=f"Response contract violation: {issue.code} at {issue.path}",
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter=issue.path,
            evidence=issue.message,
            owasp_api="API8:2023",
            cwe="CWE-20",
            request_url=request_url,
            status_code=status_code,
        ))

    # Sensitive data sweep on the response body.
    if parsed is not None:
        sensitive = find_sensitive_json(parsed)
        for match in sensitive:
            findings.append(ResponseContractFinding(
                category="data_exposure",
                severity="high" if match.confidence == "confirmed" else "medium",
                confidence=match.confidence,
                title=f"Sensitive data exposed: {match.kind} at {match.path}",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter=match.path,
                evidence=f"Matched {match.kind} ({match.confidence}): {match.redacted_value}",
                owasp_api="API3:2023",
                cwe="CWE-200",
                request_url=request_url,
                status_code=status_code,
            ))

    # Content-type mismatch check.
    declared_types = set()
    for resp in endpoint.responses.values():
        for media in resp.content:
            declared_types.add(media.split(";", 1)[0].strip().lower())
    if declared_types:
        actual_type = _content_type(headers)
        if actual_type and actual_type not in declared_types:
            findings.append(ResponseContractFinding(
                category="contract_violation",
                severity="low",
                confidence="strong",
                title=f"Response content-type mismatch: got {actual_type}",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter="Content-Type",
                evidence=f"Declared: {sorted(declared_types)}; observed: {actual_type}",
                owasp_api="API8:2023",
                cwe="CWE-436",
                request_url=request_url,
                status_code=status_code,
            ))

    return findings


def compare_exposure_between_identities(
    endpoint: Endpoint,
    owner_body: Optional[str],
    other_body: Optional[str],
    owner_profile: str,
    other_profile: str,
    request_url: str,
) -> List[ResponseContractFinding]:
    """Compare response property sets between identities to find excessive data exposure."""
    findings: List[ResponseContractFinding] = []
    owner_json = _parse_json(owner_body)
    other_json = _parse_json(other_body)
    if not isinstance(owner_json, dict) or not isinstance(other_json, dict):
        return findings

    owner_keys = set(owner_json.keys())
    other_keys = set(other_json.keys())
    extra = other_keys - owner_keys
    sensitive_names = {"password", "secret", "token", "api_key", "ssn", "credit_card", "balance", "role", "permissions"}
    for key in extra:
        if key.lower() in sensitive_names:
            findings.append(ResponseContractFinding(
                category="data_exposure",
                severity="high",
                confidence="strong",
                title=f"Excessive data exposure: '{key}' returned to '{other_profile}' but not '{owner_profile}'",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter=key,
                evidence=(
                    f"Property '{key}' present in {other_profile}'s response but absent in "
                    f"{owner_profile}'s response — possible field-level authorization gap."
                ),
                owasp_api="API3:2023",
                cwe="CWE-200",
                request_url=request_url,
                status_code=0,
            ))
    return findings


def check_security_requirement(
    endpoint: Endpoint,
    anonymous_status: int,
    request_url: str,
) -> Optional[ResponseContractFinding]:
    """Flag operations with non-empty security that accept anonymous requests."""
    if not endpoint.security:
        return None
    if 200 <= anonymous_status < 300:
        return ResponseContractFinding(
            category="missing_auth",
            severity="high",
            confidence="strong",
            title="Authentication bypass: secured operation accepts anonymous access",
            endpoint=endpoint.path,
            method=endpoint.method,
            parameter="<n/a>",
            evidence=(
                f"Operation declares security requirements "
                f"({[name for req in endpoint.security for name in req.schemes]}) "
                f"but anonymous request returned HTTP {anonymous_status}."
            ),
            owasp_api="API2:2023",
            cwe="CWE-306",
            request_url=request_url,
            status_code=anonymous_status,
        )
    return None
