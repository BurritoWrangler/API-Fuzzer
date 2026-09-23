"""Spec-vs-observed API inventory comparison.

Phase 6 compares the uploaded OpenAPI contract with endpoints and methods
discovered during scanning or probing. The comparison separates informational
exposure (a reachable but undocumented endpoint) from confirmed vulnerability
(undocumented endpoint that returns sensitive data).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse


@dataclass(frozen=True)
class ObservedEndpoint:
    method: str
    path: str
    status_code: int = 0
    source: str = ""  # "spec" | "probed" | "discovered"
    response_size: int = 0
    sensitive: bool = False


@dataclass
class InventoryDelta:
    documented_only: List[ObservedEndpoint] = field(default_factory=list)
    observed_only: List[ObservedEndpoint] = field(default_factory=list)
    method_discrepancies: List[Tuple[str, str, FrozenSet[str], FrozenSet[str]]] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


def _normalize_path(path: str) -> str:
    """Normalize a path for comparison (strip trailing slash, lower-case)."""
    normalized = path or "/"
    if len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    return normalized.lower()


_TEMPLATE_PARAM_RE = re.compile(r"\{[^}]+\}")

_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_INT_SEGMENT_RE = re.compile(r"^\d+$")
_LONG_HASH_SEGMENT_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def _path_template_to_regex(template: str) -> str:
    """Convert an OpenAPI path template to a comparison key.

    ``/users/{id}/posts`` -> ``/users/{param}/posts``
    """
    return _TEMPLATE_PARAM_RE.sub("{param}", template)


def _normalize_concrete_path(path: str) -> str:
    """Normalize a concrete observed path for template comparison.

    Replaces ID-like path segments (integers, UUIDs, long hashes) with
    ``{param}`` so ``/users/42`` matches the documented template
    ``/users/{param}``.
    """
    parts = path.strip("/").split("/")
    normalized: list = []
    for part in parts:
        if (
            _UUID_SEGMENT_RE.match(part)
            or _INT_SEGMENT_RE.match(part)
            or _LONG_HASH_SEGMENT_RE.match(part)
        ):
            normalized.append("{param}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"


def compare_inventory(
    documented: List[ObservedEndpoint],
    observed: List[ObservedEndpoint],
) -> InventoryDelta:
    """Compare documented and observed endpoints.

    Returns an :class:`InventoryDelta` with:
      - endpoints only in the spec (undocumented-attack-surface hint)
      - endpoints only observed (potential shadow/hidden API)
      - method discrepancies (path exists but supports undocumented methods)
      - findings with severity-appropriate messages
    """
    delta = InventoryDelta()

    doc_map: Dict[str, ObservedEndpoint] = {}
    doc_methods: Dict[str, Set[str]] = {}
    for ep in documented:
        key = _normalize_path(_path_template_to_regex(ep.path))
        doc_map.setdefault(key, ep)
        doc_methods.setdefault(key, set()).add(ep.method.upper())

    obs_map: Dict[str, ObservedEndpoint] = {}
    obs_methods: Dict[str, Set[str]] = {}
    for ep in observed:
        # Observed paths are concrete; normalize ID-like segments to {param}
        # so /users/42 matches the documented template /users/{id}.
        key = _normalize_path(_normalize_concrete_path(ep.path))
        obs_map.setdefault(key, ep)
        obs_methods.setdefault(key, set()).add(ep.method.upper())

    doc_keys = set(doc_map)
    obs_keys = set(obs_map)

    for key in sorted(doc_keys - obs_keys):
        delta.documented_only.append(doc_map[key])
        delta.findings.append(
            f"Documented endpoint {doc_map[key].method} {doc_map[key].path} "
            f"was not observed during scanning."
        )

    for key in sorted(obs_keys - doc_keys):
        ep = obs_map[key]
        delta.observed_only.append(ep)
        severity = "potential sensitive exposure" if ep.sensitive else "shadow API endpoint"
        delta.findings.append(
            f"Undocumented {severity}: {ep.method} {ep.path} "
            f"returned HTTP {ep.status_code} (source: {ep.source})."
        )

    for key in sorted(doc_keys & obs_keys):
        doc_method_set = frozenset(doc_methods[key])
        obs_method_set = frozenset(obs_methods[key])
        extra = obs_method_set - doc_method_set
        if extra:
            delta.method_discrepancies.append(
                (doc_map[key].path, doc_map[key].method, doc_method_set, obs_method_set)
            )
            delta.findings.append(
                f"Method discrepancy on {doc_map[key].path}: documented {sorted(doc_method_set)}, "
                f"observed {sorted(obs_method_set)} — undocumented methods "
                f"{sorted(extra)} are reachable."
            )

    return delta
