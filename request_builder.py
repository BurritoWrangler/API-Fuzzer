"""Single source of truth for building outbound HTTP requests.

``request_builder`` turns a :class:`~models.RequestTemplate` into a
:class:`~models.PreparedRequest` that captures the exact encoded URL, headers,
and serialized body after preparation. The fuzzer routes its baseline and
payload traffic through this module so the wire representation is reproducible
and can be attached to findings and the request ledger.

Supported media types: ``application/json``,
``application/x-www-form-urlencoded``, ``multipart/form-data`` (body passed
through as-is), ``application/xml``/``text/xml``, ``text/plain``, and raw
strings. Path parameters are percent-encoded with the safe set empty so
template tokens like ``{user_id}`` are replaced with encodable values.
"""

from __future__ import annotations

import json as jsonlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests

from models import AuthProfile, PreparedRequest, RequestTemplate


def substitute_path(template: str, path_params: Dict[str, Any]) -> str:
    """Replace ``{name}`` tokens in ``template`` with percent-encoded values."""
    out = template
    for name, value in path_params.items():
        out = out.replace("{" + name + "}", requests.utils.quote(str(value), safe=""))
    return out


def _query_pairs(params: Optional[Dict[str, Any]]) -> List[Tuple[str, str]]:
    flat: List[Tuple[str, str]] = []
    for key, value in (params or {}).items():
        if isinstance(value, (list, tuple)):
            for item in value:
                flat.append((str(key), str(item)))
        elif isinstance(value, bool):
            # Booleans must be checked before int (bool is an int subclass).
            flat.append((str(key), "true" if value else "false"))
        elif value is None:
            continue
        else:
            flat.append((str(key), str(value)))
    return flat


def encode_query(params: Optional[Dict[str, Any]]) -> str:
    pairs = _query_pairs(params)
    return urlencode(pairs) if pairs else ""


def build_path_url(
    base_url: str,
    path: str,
    path_params: Optional[Dict[str, Any]] = None,
) -> str:
    base = (base_url or "").rstrip("/")
    return base + substitute_path(path, path_params or {})


def build_encoded_url(
    base_url: str,
    path: str,
    path_params: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, Any]] = None,
) -> str:
    url = build_path_url(base_url, path, path_params)
    query = encode_query(query_params)
    if query:
        url += ("&" if "?" in url else "?") + query
    return url


def serialize_body(body: Any, media_type: str) -> Optional[str]:
    """Serialize ``body`` for the given media type into a string."""
    if body is None:
        return None
    mt = (media_type or "").lower()
    if mt == "application/x-www-form-urlencoded":
        if isinstance(body, dict):
            return urlencode(_query_pairs(body))
        if isinstance(body, str):
            return body
        return None
    if mt in ("application/xml", "text/xml", "text/plain"):
        if isinstance(body, str):
            return body
        if isinstance(body, (dict, list)):
            return jsonlib.dumps(body)
        return str(body)
    # Default: application/json, multipart/form-data, or unknown.
    # multipart bodies are supplied as pre-encoded strings by later phases.
    if isinstance(body, (dict, list)):
        return jsonlib.dumps(body)
    if isinstance(body, str):
        return body
    return jsonlib.dumps(body)


def build_request(template: RequestTemplate) -> PreparedRequest:
    """Build a :class:`PreparedRequest` from a :class:`RequestTemplate`."""
    method = (template.method or "GET").upper()
    path_url = build_path_url(template.base_url, template.path, template.path_params)
    encoded_url = build_encoded_url(
        template.base_url,
        template.path,
        template.path_params,
        template.query_params,
    )

    headers: Dict[str, str] = {}
    profile = template.auth_profile
    if profile is not None:
        for key, value in profile.headers.items():
            headers[str(key)] = str(value)
    for key, value in template.header_params.items():
        headers[str(key)] = str(value)
    for key, value in template.extra_headers.items():
        headers[str(key)] = str(value)

    cookies: Dict[str, str] = {}
    if profile is not None:
        for key, value in profile.cookies.items():
            cookies[str(key)] = str(value)
    for key, value in template.cookie_params.items():
        cookies[str(key)] = str(value)

    media = (template.media_type or "").strip()
    body_str: Optional[str] = None
    if template.has_body:
        body_str = serialize_body(template.body, template.media_type)
        if media and not any(h.lower() == "content-type" for h in headers):
            headers["Content-Type"] = template.media_type

    return PreparedRequest(
        method=method,
        url=path_url,
        headers=headers,
        body=body_str,
        media_type=template.media_type,
        cookies=cookies,
        query_params=dict(template.query_params or {}),
        encoded_url=encoded_url,
        template=template,
    )


__all__ = [
    "substitute_path",
    "encode_query",
    "build_path_url",
    "build_encoded_url",
    "serialize_body",
    "build_request",
]
