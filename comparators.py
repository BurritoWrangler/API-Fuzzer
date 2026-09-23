"""Deterministic HTTP response comparison helpers.

Authorization and authentication checks need stronger evidence than a status
code. This module normalizes JSON/text responses, removes explicitly volatile
fields, and returns a structured comparison that later checks can cite.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple


DEFAULT_VOLATILE_KEYS = frozenset(
    {
        "created_at",
        "date",
        "expires_at",
        "nonce",
        "request_id",
        "requestid",
        "timestamp",
        "trace_id",
        "traceid",
        "updated_at",
    }
)

_ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b"
)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)


@dataclass(frozen=True)
class ResponseComparison:
    status_equal: bool
    content_type_equal: bool
    body_equal: bool
    shape_equal: bool
    similarity: float
    equivalent: bool
    baseline_status: int
    candidate_status: int
    baseline_length: int
    candidate_length: int
    summary: str


def _content_type(headers: Optional[Mapping[str, str]]) -> str:
    for name, value in (headers or {}).items():
        if name.lower() == "content-type":
            return str(value).split(";", 1)[0].strip().lower()
    return ""


def _parse_json(body: Optional[str], content_type: str = "") -> Tuple[Any, bool]:
    text = body or ""
    if "json" not in content_type and not text.lstrip().startswith(("{", "[")):
        return text, False
    try:
        return json.loads(text), True
    except (TypeError, ValueError):
        return text, False


def _path_parts(paths: Optional[Iterable[str]]) -> Set[Tuple[str, ...]]:
    result: Set[Tuple[str, ...]] = set()
    for path in paths or ():
        cleaned = str(path).strip().strip(".")
        if cleaned:
            result.add(tuple(part for part in cleaned.split(".") if part))
    return result


def _path_matches(current: Sequence[str], ignored: Set[Tuple[str, ...]]) -> bool:
    for candidate in ignored:
        if len(candidate) != len(current):
            continue
        if all(expected == "*" or expected == actual for expected, actual in zip(candidate, current)):
            return True
    return False


def normalize_json(
    value: Any,
    *,
    ignored_paths: Optional[Iterable[str]] = None,
    volatile_keys: Optional[Iterable[str]] = None,
) -> Any:
    """Return a deterministic JSON value with configured volatile data removed."""
    ignored = _path_parts(ignored_paths)
    volatile = {
        str(key).lower()
        for key in (DEFAULT_VOLATILE_KEYS if volatile_keys is None else volatile_keys)
    }

    def walk(node: Any, path: Tuple[str, ...]) -> Any:
        if isinstance(node, dict):
            normalized: Dict[str, Any] = {}
            for key in sorted(node, key=lambda item: str(item)):
                key_text = str(key)
                child_path = path + (key_text,)
                if key_text.lower() in volatile or _path_matches(child_path, ignored):
                    continue
                normalized[key_text] = walk(node[key], child_path)
            return normalized
        if isinstance(node, list):
            return [walk(item, path + (str(index),)) for index, item in enumerate(node)]
        return node

    return walk(value, ())


def json_shape(value: Any) -> Any:
    """Return a value-independent structural description of JSON data."""
    if isinstance(value, dict):
        return {str(key): json_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        unique = []
        for item in value:
            shape = json_shape(item)
            if shape not in unique:
                unique.append(shape)
        return {"list": unique}
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"


def _canonical_body(
    body: Optional[str],
    content_type: str,
    *,
    ignored_paths: Optional[Iterable[str]],
    volatile_keys: Optional[Iterable[str]],
) -> Tuple[str, Any]:
    parsed, is_json = _parse_json(body, content_type)
    if is_json:
        normalized = normalize_json(
            parsed,
            ignored_paths=ignored_paths,
            volatile_keys=volatile_keys,
        )
        return (
            json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            json_shape(normalized),
        )

    text = " ".join(str(parsed).split())
    text = _ISO_TIMESTAMP_RE.sub("<timestamp>", text)
    text = _UUID_RE.sub("<uuid>", text)
    return text, "text"


# Cap the text fed into difflib.SequenceMatcher. The ratio is only needed
# near the equivalence threshold; comparing the first 64 KiB per side keeps
# the O(n*m) matcher bounded for 1 MiB response bodies.
_SIMILARITY_SAMPLE_BYTES = 65536


def _response_similarity(
    baseline_text: str,
    candidate_text: str,
    *,
    body_equal: bool,
    shape_equal: bool,
) -> float:
    """Compute body similarity with fast paths that avoid quadratic cost.

    * Equal bodies score 1.0 without invoking difflib.
    * When shapes already differ (or either body is empty) the ratio cannot
      plausibly reach ~0.97 for structured data, so return a cheap
      length-based estimate instead of running the matcher.
    * Otherwise compare at most the first _SIMILARITY_SAMPLE_BYTES per side.
    """
    if body_equal:
        return 1.0
    if not baseline_text or not candidate_text:
        return 0.0
    if not shape_equal:
        # Different JSON shapes: the length ratio bounds similarity well
        # below any reasonable equivalence threshold.
        shorter, longer = sorted((len(baseline_text), len(candidate_text)))
        return (shorter / longer) * 0.5 if longer else 0.0
    sample_baseline = baseline_text[:_SIMILARITY_SAMPLE_BYTES]
    sample_candidate = candidate_text[:_SIMILARITY_SAMPLE_BYTES]
    return difflib.SequenceMatcher(None, sample_baseline, sample_candidate).ratio()


def compare_http_responses(
    *,
    baseline_status: int,
    baseline_headers: Optional[Mapping[str, str]],
    baseline_body: Optional[str],
    candidate_status: int,
    candidate_headers: Optional[Mapping[str, str]],
    candidate_body: Optional[str],
    ignored_json_paths: Optional[Iterable[str]] = None,
    volatile_keys: Optional[Iterable[str]] = None,
    equivalence_threshold: float = 0.97,
) -> ResponseComparison:
    """Compare two observations after deterministic normalization."""
    baseline_type = _content_type(baseline_headers)
    candidate_type = _content_type(candidate_headers)
    baseline_text, baseline_shape = _canonical_body(
        baseline_body,
        baseline_type,
        ignored_paths=ignored_json_paths,
        volatile_keys=volatile_keys,
    )
    candidate_text, candidate_shape = _canonical_body(
        candidate_body,
        candidate_type,
        ignored_paths=ignored_json_paths,
        volatile_keys=volatile_keys,
    )

    status_equal = baseline_status == candidate_status
    content_type_equal = baseline_type == candidate_type
    body_equal = baseline_text == candidate_text
    shape_equal = baseline_shape == candidate_shape
    similarity = _response_similarity(
        baseline_text, candidate_text, body_equal=body_equal,
        shape_equal=shape_equal,
    )
    equivalent = (
        status_equal
        and content_type_equal
        and shape_equal
        and (body_equal or similarity >= equivalence_threshold)
    )
    summary = (
        f"status {baseline_status}->{candidate_status}; "
        f"content-type {baseline_type or '<none>'}->{candidate_type or '<none>'}; "
        f"shape {'same' if shape_equal else 'different'}; "
        f"similarity {similarity:.3f}; "
        f"length {len(baseline_text)}->{len(candidate_text)}"
    )
    return ResponseComparison(
        status_equal=status_equal,
        content_type_equal=content_type_equal,
        body_equal=body_equal,
        shape_equal=shape_equal,
        similarity=similarity,
        equivalent=equivalent,
        baseline_status=baseline_status,
        candidate_status=candidate_status,
        baseline_length=len(baseline_text),
        candidate_length=len(candidate_text),
        summary=summary,
    )
