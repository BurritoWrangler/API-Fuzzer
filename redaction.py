"""Case-insensitive redaction for credentials, headers, and sensitive JSON.

Phase 0 redacts ``Authorization`` headers, cookies, API keys, tokens, and
configured sensitive JSON paths from dashboard / status / export surfaces by
default. Exact raw export is only available through a separately labeled
opt-in (``RedactionConfig.raw_opt_in``), surfaced via ``Finding.to_raw_dict``.

This module deliberately does **not** import ``analyzer`` so that ``analyzer``
can import it without creating a cycle. It operates on plain dicts and strings
only.
"""

from __future__ import annotations

import json as jsonlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

REDACTED = "[REDACTED]"

DEFAULT_REDACTED_HEADER_PREFIXES: Tuple[str, ...] = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-secret",
    "api-key",
    "apikey",
)

DEFAULT_REDACTED_QUERY_PARAMS: Tuple[str, ...] = (
    "access_token",
    "api_key",
    "apikey",
    "token",
    "secret",
    "password",
    "passwd",
    "api-token",
    "auth",
)

DEFAULT_REDACTED_JSON_PATHS: Tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "token",
    "private_key",
    "privatekey",
    "ssn",
    "credit_card",
    "cardnumber",
    "cvv",
    "authorization",
)


@dataclass
class RedactionConfig:
    """Controls what gets redacted from a finding snapshot.

    ``enabled`` defaults to True so the default export path is redacted. Set
    ``raw_opt_in=True`` (with ``enabled=False``) for the separately labeled
    exact-raw export.
    """

    enabled: bool = True
    header_prefixes: Tuple[str, ...] = DEFAULT_REDACTED_HEADER_PREFIXES
    query_params: Tuple[str, ...] = DEFAULT_REDACTED_QUERY_PARAMS
    json_paths: Tuple[str, ...] = DEFAULT_REDACTED_JSON_PATHS
    raw_opt_in: bool = False


DEFAULT_REDACTION_CONFIG = RedactionConfig()
RAW_EXPORT_CONFIG = RedactionConfig(enabled=False, raw_opt_in=True)


def _matches_prefix(name: str, prefixes: Tuple[str, ...]) -> bool:
    lname = name.lower()
    for prefix in prefixes:
        prefix = prefix.lower()
        if lname == prefix or lname.startswith(prefix):
            return True
    return False


def _redact_header_value(name: str, value: str) -> str:
    lname = name.lower()
    if lname in ("authorization", "proxy-authorization"):
        # Keep the scheme (Bearer/Basic/...) but hide the credential.
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9\-_]*)\s+(.+)$", value or "")
        if match:
            return f"{match.group(1)} {REDACTED}"
        return REDACTED
    return REDACTED


def redact_headers(
    headers: Optional[Dict[str, str]],
    cfg: RedactionConfig,
) -> Tuple[Dict[str, str], List[str]]:
    """Return ``(redacted_headers, redacted_header_names)``."""
    if not cfg.enabled or not headers:
        return dict(headers or {}), []
    out: Dict[str, str] = {}
    redacted: List[str] = []
    for key, value in headers.items():
        if _matches_prefix(str(key), cfg.header_prefixes):
            out[str(key)] = _redact_header_value(str(key), str(value))
            redacted.append(str(key))
        else:
            out[str(key)] = str(value)
    return out, redacted


def redact_url_query(url: str, cfg: RedactionConfig) -> Tuple[str, List[str]]:
    """Redact sensitive query parameters in ``url``.

    Returns ``(redacted_url, redacted_field_names)`` where field names are
    ``query.<param>``.
    """
    if not cfg.enabled or not url:
        return url, []
    parsed = urlparse(url)
    if not parsed.query:
        return url, []
    names = {p.lower() for p in cfg.query_params}
    params = parse_qsl(parsed.query, keep_blank_values=True)
    new_params: List[Tuple[str, str]] = []
    redacted: List[str] = []
    for key, value in params:
        if key.lower() in names:
            new_params.append((key, REDACTED))
            redacted.append(f"query.{key}")
        else:
            new_params.append((key, value))
    new_query = urlencode(new_params)
    return urlunparse(parsed._replace(query=new_query)), redacted


def _redact_json_node(node: Any, names_lower: set) -> Tuple[Any, List[str]]:
    redacted: List[str] = []
    if isinstance(node, dict):
        out: Dict[str, Any] = {}
        for key, value in node.items():
            if str(key).lower() in names_lower:
                if value not in (None, "", [], {}):
                    out[key] = REDACTED
                    redacted.append(str(key))
                else:
                    out[key] = value
            else:
                child, child_redacted = _redact_json_node(value, names_lower)
                out[key] = child
                redacted.extend(child_redacted)
        return out, redacted
    if isinstance(node, list):
        out_list: List[Any] = []
        for item in node:
            child, child_redacted = _redact_json_node(item, names_lower)
            out_list.append(child)
            redacted.extend(child_redacted)
        return out_list, redacted
    return node, redacted


def redact_body_text(
    body: Optional[str],
    cfg: RedactionConfig,
) -> Tuple[Optional[str], List[str]]:
    """Redact sensitive keys in a JSON or form-encoded body string.

    Returns ``(redacted_body, redacted_keys)``. Non-structured bodies are
    returned unchanged.
    """
    if not cfg.enabled or body is None or body == "":
        return body, []
    names = {p.lower() for p in cfg.json_paths}
    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = jsonlib.loads(body)
        except (ValueError, TypeError):
            return body, []
        redacted, keys = _redact_json_node(parsed, names)
        return jsonlib.dumps(redacted), keys
    if "=" in stripped and not stripped.startswith("<"):
        params = parse_qsl(body, keep_blank_values=True)
        if params:
            new_params: List[Tuple[str, str]] = []
            keys: List[str] = []
            for key, value in params:
                if key.lower() in names:
                    new_params.append((key, REDACTED))
                    keys.append(key)
                else:
                    new_params.append((key, value))
            return urlencode(new_params), keys
    return body, []


__all__ = [
    "REDACTED",
    "RedactionConfig",
    "DEFAULT_REDACTION_CONFIG",
    "RAW_EXPORT_CONFIG",
    "redact_headers",
    "redact_url_query",
    "redact_body_text",
]
