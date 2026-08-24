"""Shared data models for the apifuzz execution framework (Phase 0).

This module introduces the contract-aware request/evidence/safety/confidence
foundation that later phases build on. Everything here is additive and backward
compatible: existing modules keep their legacy types, and new code can opt into
these richer models.

Models are plain dataclasses and ``str`` enums so they serialize cleanly to
JSON and stay compatible with Python 3.9.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# --- Scan modes / safety levels -------------------------------------------


class ScanMode(str, enum.Enum):
    """Coarse execution mode that gates which checks may run."""

    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    INTRUSIVE = "intrusive"


class SafetyLevel(str, enum.Enum):
    """How invasive an individual check is."""

    PASSIVE = "passive"          # observes already-sent traffic only
    SAFE_ACTIVE = "safe_active"  # sends non-destructive probes
    INTRUSIVE = "intrusive"      # may mutate state or send heavy traffic


DEFAULT_SCAN_MODE = ScanMode.SAFE_ACTIVE.value
VALID_SCAN_MODES = frozenset(m.value for m in ScanMode)

_SAFETY_RANK = {
    SafetyLevel.PASSIVE: 0,
    SafetyLevel.SAFE_ACTIVE: 1,
    SafetyLevel.INTRUSIVE: 2,
}

# Maximum safety level permitted by each scan mode.
_SCAN_MODE_CEILING = {
    ScanMode.PASSIVE.value: SafetyLevel.PASSIVE,
    ScanMode.SAFE_ACTIVE.value: SafetyLevel.SAFE_ACTIVE,
    ScanMode.INTRUSIVE.value: SafetyLevel.INTRUSIVE,
}


def safety_allowed(check_safety: str, scan_mode: str) -> bool:
    """Return True if a check of ``check_safety`` may run under ``scan_mode``.

    Unknown safety levels are treated as ``safe_active`` (conservative) and
    unknown scan modes default to the ``safe_active`` ceiling.
    """
    try:
        check = SafetyLevel(check_safety)
    except ValueError:
        check = SafetyLevel.SAFE_ACTIVE
    ceiling = _SCAN_MODE_CEILING.get(scan_mode, SafetyLevel.SAFE_ACTIVE)
    return _SAFETY_RANK[check] <= _SAFETY_RANK[ceiling]


def normalize_scan_mode(value: str) -> str:
    try:
        return ScanMode(value).value
    except ValueError:
        return DEFAULT_SCAN_MODE


# --- Confidence ------------------------------------------------------------


class Confidence(str, enum.Enum):
    """Certainty of a finding, independent of its severity (impact)."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


CONFIDENCE_ORDER: Tuple[str, ...] = tuple(
    c.value for c in (
        Confidence.CONFIRMED,
        Confidence.HIGH,
        Confidence.MEDIUM,
        Confidence.LOW,
        Confidence.INFORMATIONAL,
    )
)
CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCE_ORDER)}


def normalize_confidence(value: str) -> str:
    try:
        return Confidence(value).value
    except ValueError:
        return Confidence.INFORMATIONAL.value


# --- Auth profiles ---------------------------------------------------------


@dataclass
class AuthProfile:
    """A named identity used by differential checks (Phase 2+).

    Phase 0 introduces the model and preserves the one-header compatibility
    path used by the legacy ``auth_header`` setting. Credentials are held in
    memory only and never persisted.
    """

    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    expected_role: str = ""
    tenant_label: str = ""
    subject_id: str = ""

    @property
    def is_anonymous(self) -> bool:
        return not self.headers and not self.cookies

    @classmethod
    def anonymous(cls, name: str = "anonymous") -> "AuthProfile":
        return cls(name=name)

    @classmethod
    def from_header(cls, name: str, auth_header: Optional[str]) -> "AuthProfile":
        """Build a profile from the legacy single ``Authorization`` header.

        Accepts either the bare value (``Bearer eyJ...``) or the
        ``Authorization: Bearer eyJ...`` form the form field allows.
        """
        profile = cls(name=name)
        if not auth_header:
            return profile
        if auth_header.lower().startswith("authorization:"):
            _, _, value = auth_header.partition(":")
            value = value.strip()
            if value:
                profile.headers["Authorization"] = value
        else:
            profile.headers["Authorization"] = auth_header.strip()
        return profile

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "expected_role": self.expected_role,
            "tenant_label": self.tenant_label,
            "subject_id": self.subject_id,
            "is_anonymous": self.is_anonymous,
        }


# --- Request templates and prepared requests ------------------------------


@dataclass
class RequestTemplate:
    """Declarative description of a request to be built by request_builder."""

    method: str
    path: str                      # template with {param} placeholders
    base_url: str = ""
    path_params: Dict[str, Any] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    header_params: Dict[str, Any] = field(default_factory=dict)
    cookie_params: Dict[str, Any] = field(default_factory=dict)
    body: Any = None
    media_type: str = ""           # application/json, application/x-www-form-urlencoded, ...
    has_body: bool = False
    auth_profile: Optional[AuthProfile] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class PreparedRequest:
    """The exact prepared request used for transmission and reporting.

    Captures the encoded URL, headers, and serialized body AFTER preparation so
    the wire representation is reproducible and can be attached to findings and
    the request ledger.

    ``url`` is the absolute path-substituted URL WITHOUT the query string (the
    base passed to ``requests`` alongside ``query_params``); ``encoded_url`` is
    the exact URL with the query string baked in (what was/would be on the
    wire) and is what emitters record.
    """

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    media_type: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    encoded_url: str = ""
    template: Optional[RequestTemplate] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.encoded_url:
            self.encoded_url = self.url

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.encoded_url,
            "headers": dict(self.headers),
            "body": self.body,
            "media_type": self.media_type,
            "cookies": dict(self.cookies),
        }


@dataclass
class ResponseObservation:
    """A normalized observation of a single HTTP response."""

    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    body_truncated: bool = False
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body,
            "body_truncated": self.body_truncated,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "url": self.url,
        }


# --- Request ledger --------------------------------------------------------


# Hard cap on retained ledger entries to bound the Flask process's memory.
MAX_LEDGER_ENTRIES = 5000


@dataclass
class LedgerEntry:
    """A single row in the request ledger.

    Every outbound request (baseline, payload, optional check) appends one
    entry so the scan's request accounting is trustworthy.
    """

    index: int
    method: str
    url: str
    check_id: str = ""
    auth_profile: str = ""
    safety_level: str = SafetyLevel.SAFE_ACTIVE.value
    status_code: int = 0
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    outcome: str = "succeeded"  # succeeded | failed | skipped | budget_exhausted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "method": self.method,
            "url": self.url,
            "check_id": self.check_id,
            "auth_profile": self.auth_profile,
            "safety_level": self.safety_level,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "outcome": self.outcome,
        }


class RequestLedger:
    """Thread-safe, bounded record of every outbound request in a scan."""

    OUTCOME_SUCCEEDED = "succeeded"
    OUTCOME_FAILED = "failed"
    OUTCOME_SKIPPED = "skipped"
    OUTCOME_BUDGET_EXHAUSTED = "budget_exhausted"

    def __init__(self, max_entries: int = MAX_LEDGER_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._entries: List[LedgerEntry] = []
        self._max = max(0, int(max_entries))
        self._next_index = 0

    def record(
        self,
        *,
        method: str,
        url: str,
        check_id: str = "",
        auth_profile: str = "",
        safety_level: str = SafetyLevel.SAFE_ACTIVE.value,
        status_code: int = 0,
        latency_ms: Optional[int] = None,
        error: Optional[str] = None,
        outcome: str = OUTCOME_SUCCEEDED,
    ) -> LedgerEntry:
        with self._lock:
            entry = LedgerEntry(
                index=self._next_index,
                method=method,
                url=url,
                check_id=check_id,
                auth_profile=auth_profile,
                safety_level=safety_level,
                status_code=status_code,
                latency_ms=latency_ms,
                error=error,
                outcome=outcome,
            )
            self._next_index += 1
            self._entries.append(entry)
            if self._max and len(self._entries) > self._max:
                # Drop the oldest entries; indices are preserved on survivors.
                self._entries = self._entries[-self._max:]
            return entry

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def counts(self) -> Dict[str, int]:
        with self._lock:
            counts = {
                self.OUTCOME_SUCCEEDED: 0,
                self.OUTCOME_FAILED: 0,
                self.OUTCOME_SKIPPED: 0,
                self.OUTCOME_BUDGET_EXHAUSTED: 0,
            }
            for entry in self._entries:
                counts[entry.outcome] = counts.get(entry.outcome, 0) + 1
            return counts

    def summary(self) -> Dict[str, int]:
        counts = self.counts()
        sent = counts[self.OUTCOME_SUCCEEDED] + counts[self.OUTCOME_FAILED]
        return {
            "ledger_count": len(self),
            "sent": sent,
            "succeeded": counts[self.OUTCOME_SUCCEEDED],
            "failed": counts[self.OUTCOME_FAILED],
            "skipped": counts[self.OUTCOME_SKIPPED],
            "budget_exhausted": counts[self.OUTCOME_BUDGET_EXHAUSTED],
        }

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [entry.to_dict() for entry in self._entries]


# --- Check results ---------------------------------------------------------


@dataclass
class CheckResult:
    """Outcome of running a single check against one or more observations."""

    check_id: str
    findings: List[Any] = field(default_factory=list)
    request_count: int = 0
    safety_level: str = SafetyLevel.SAFE_ACTIVE.value
    owasp_api: str = ""
    cwe: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "findings_count": len(self.findings),
            "request_count": self.request_count,
            "safety_level": self.safety_level,
            "owasp_api": self.owasp_api,
            "cwe": self.cwe,
            "notes": self.notes,
        }
