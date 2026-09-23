"""Response contract and sensitive-data inspection helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ContractIssue:
    path: str
    code: str
    message: str
    expected: str = ""
    actual: str = ""


@dataclass(frozen=True)
class SensitiveMatch:
    path: str
    kind: str
    confidence: str
    redacted_value: str


_SENSITIVE_KEYS: Dict[str, str] = {
    "access_token": "access token",
    "apikey": "API key",
    "api_key": "API key",
    "authorization": "authorization credential",
    "client_secret": "client secret",
    "connection_string": "connection string",
    "password": "password",
    "passwd": "password",
    "private_key": "private key",
    "refresh_token": "refresh token",
    "secret": "secret",
    "session": "session token",
    "sessionid": "session token",
    "ssn": "government identifier",
}

_VALUE_PATTERNS: Sequence[Tuple[str, re.Pattern, str]] = (
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I),
        "confirmed",
    ),
    (
        "AWS access key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "strong",
    ),
    (
        "bearer token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.I),
        "strong",
    ),
    (
        "database connection string",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://"
            r"[^\s\"']+",
            re.I,
        ),
        "strong",
    ),
    (
        "email address",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "tentative",
    ),
    (
        "internal IPv4 address",
        re.compile(
            r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
            r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
        ),
        "tentative",
    ),
)


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    return True


def _child_path(path: str, key: Any) -> str:
    if isinstance(key, int):
        return f"{path}[{key}]"
    return f"{path}.{key}" if path != "$" else f"$.{key}"


def validate_response_schema(
    value: Any,
    schema: Optional[Dict[str, Any]],
    *,
    path: str = "$",
) -> List[ContractIssue]:
    """Validate the OpenAPI/JSON-Schema subset used by the scanner."""
    if not isinstance(schema, dict) or not schema:
        return []
    issues: List[ContractIssue] = []

    if value is None and schema.get("nullable") is True:
        return issues

    for subschema in schema.get("allOf") or []:
        issues.extend(validate_response_schema(value, subschema, path=path))

    one_of = schema.get("oneOf")
    if isinstance(one_of, list) and one_of:
        matches = [
            not validate_response_schema(value, subschema, path=path)
            for subschema in one_of
        ]
        if sum(matches) != 1:
            issues.append(
                ContractIssue(
                    path,
                    "oneOf",
                    "Response must match exactly one oneOf schema.",
                    "one matching schema",
                    f"{sum(matches)} matching schemas",
                )
            )
            return issues

    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and any_of:
        if not any(
            not validate_response_schema(value, subschema, path=path)
            for subschema in any_of
        ):
            issues.append(
                ContractIssue(
                    path,
                    "anyOf",
                    "Response does not match any allowed schema.",
                    "at least one matching schema",
                    "no matching schemas",
                )
            )
            return issues

    expected = schema.get("type")
    if isinstance(expected, list):
        type_ok = any(_type_matches(value, item) for item in expected)
        expected_label = "|".join(str(item) for item in expected)
    elif isinstance(expected, str):
        type_ok = _type_matches(value, expected)
        expected_label = expected
    else:
        type_ok = True
        expected_label = ""
    if not type_ok:
        issues.append(
            ContractIssue(
                path,
                "type",
                "Response value has the wrong type.",
                expected_label,
                _json_type(value),
            )
        )
        return issues

    if "enum" in schema and value not in schema.get("enum", []):
        issues.append(
            ContractIssue(
                path,
                "enum",
                "Response value is outside the declared enum.",
                repr(schema.get("enum")),
                repr(value),
            )
        )

    if isinstance(value, dict):
        properties = schema.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        for required in schema.get("required") or []:
            if required not in value:
                issues.append(
                    ContractIssue(
                        _child_path(path, required),
                        "required",
                        "Required response property is missing.",
                        "present",
                        "missing",
                    )
                )
        for key, child in value.items():
            if key in properties:
                issues.extend(
                    validate_response_schema(
                        child,
                        properties[key],
                        path=_child_path(path, key),
                    )
                )
            elif schema.get("additionalProperties") is False:
                issues.append(
                    ContractIssue(
                        _child_path(path, key),
                        "additional_property",
                        "Response contains an undocumented property.",
                        "declared property",
                        "undocumented property",
                    )
                )

    if isinstance(value, list):
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(value) < minimum:
            issues.append(
                ContractIssue(
                    path,
                    "minItems",
                    "Response array is shorter than declared.",
                    str(minimum),
                    str(len(value)),
                )
            )
        if isinstance(maximum, int) and len(value) > maximum:
            issues.append(
                ContractIssue(
                    path,
                    "maxItems",
                    "Response array is longer than declared.",
                    str(maximum),
                    str(len(value)),
                )
            )
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                issues.extend(
                    validate_response_schema(
                        item,
                        items,
                        path=_child_path(path, index),
                    )
                )

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        if isinstance(minimum, int) and len(value) < minimum:
            issues.append(
                ContractIssue(path, "minLength", "Response string is too short.", str(minimum), str(len(value)))
            )
        if isinstance(maximum, int) and len(value) > maximum:
            issues.append(
                ContractIssue(path, "maxLength", "Response string is too long.", str(maximum), str(len(value)))
            )
        if isinstance(pattern, str):
            try:
                if re.search(pattern, value) is None:
                    issues.append(
                        ContractIssue(path, "pattern", "Response string does not match the declared pattern.", pattern, "<redacted>")
                    )
            except re.error:
                pass
        if schema.get("format") == "email" and not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            value,
        ):
            issues.append(
                ContractIssue(path, "format", "Response string is not a valid email address.", "email", "<redacted>")
            )
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                issues.append(
                    ContractIssue(path, "format", "Response string is not a valid date-time.", "date-time", "<redacted>")
                )

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            issues.append(
                ContractIssue(path, "minimum", "Response number is below the declared minimum.", str(minimum), str(value))
            )
        if isinstance(maximum, (int, float)) and value > maximum:
            issues.append(
                ContractIssue(path, "maximum", "Response number exceeds the declared maximum.", str(maximum), str(value))
            )

    return issues


def _redacted(value: Any, kind: str) -> str:
    text = str(value)
    return f"<redacted:{kind.replace(' ', '_')}:{len(text)} chars>"


def _walk_json(value: Any, path: str = "$") -> Iterable[Tuple[str, Optional[str], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = _child_path(path, key)
            yield child_path, str(key), child
            yield from _walk_json(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = _child_path(path, index)
            yield child_path, None, child
            yield from _walk_json(child, child_path)


def find_sensitive_json(value: Any) -> List[SensitiveMatch]:
    """Return redacted sensitive-data candidates found in a JSON value."""
    matches: List[SensitiveMatch] = []
    seen = set()
    for path, key, child in _walk_json(value):
        key_kind = _SENSITIVE_KEYS.get((key or "").lower())
        if key_kind and child not in (None, "", [], {}):
            confidence = "strong" if key_kind not in ("government identifier",) else "tentative"
            item = SensitiveMatch(path, key_kind, confidence, _redacted(child, key_kind))
            marker = (item.path, item.kind)
            if marker not in seen:
                seen.add(marker)
                matches.append(item)

        if not isinstance(child, str):
            continue
        for kind, pattern, confidence in _VALUE_PATTERNS:
            if pattern.search(child):
                item = SensitiveMatch(path, kind, confidence, _redacted(child, kind))
                marker = (item.path, item.kind)
                if marker not in seen:
                    seen.add(marker)
                    matches.append(item)
    return matches
