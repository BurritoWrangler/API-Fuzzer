"""Out-of-band application security testing provider abstractions.

No provider is enabled by default. The generic HTTP provider is deliberately
limited to a user-controlled callback domain and polling API.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol
from urllib.parse import urlparse

import requests


class OASTDisabled(RuntimeError):
    pass


@dataclass(frozen=True)
class OASTAllocation:
    token: str
    http_url: str
    dns_name: str
    expires_at: float
    check_id: str = ""


@dataclass(frozen=True)
class OASTInteraction:
    token: str
    protocol: str
    observed_at: float
    remote_address: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class OASTProvider(Protocol):
    @property
    def available(self) -> bool:
        ...

    def allocate(self, check_id: str = "") -> OASTAllocation:
        ...

    def poll(self, allocation: OASTAllocation) -> List[OASTInteraction]:
        ...


class DisabledOASTProvider:
    @property
    def available(self) -> bool:
        return False

    def allocate(self, check_id: str = "") -> OASTAllocation:
        raise OASTDisabled("OAST is not configured for this scan.")

    def poll(self, allocation: OASTAllocation) -> List[OASTInteraction]:
        return []


class MemoryOASTProvider:
    """Deterministic local provider used by tests and offline integrations."""

    def __init__(
        self,
        domain: str = "oast.invalid",
        *,
        ttl_seconds: int = 300,
        clock=time.time,
        token_factory=None,
    ):
        self.domain = _validate_domain(domain)
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.clock = clock
        self.token_factory = token_factory or (lambda: secrets.token_hex(12))
        self._interactions: Dict[str, List[OASTInteraction]] = {}

    @property
    def available(self) -> bool:
        return True

    def allocate(self, check_id: str = "") -> OASTAllocation:
        token = self.token_factory()
        self._interactions.setdefault(token, [])
        hostname = f"{token}.{self.domain}"
        return OASTAllocation(
            token=token,
            http_url=f"https://{hostname}/",
            dns_name=hostname,
            expires_at=self.clock() + self.ttl_seconds,
            check_id=check_id,
        )

    def record_interaction(
        self,
        token: str,
        *,
        protocol: str,
        remote_address: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if token not in self._interactions:
            return
        self._interactions[token].append(
            OASTInteraction(
                token=token,
                protocol=str(protocol).lower(),
                observed_at=self.clock(),
                remote_address=remote_address,
                metadata=dict(metadata or {}),
            )
        )

    def poll(self, allocation: OASTAllocation) -> List[OASTInteraction]:
        if self.clock() > allocation.expires_at:
            self._interactions.pop(allocation.token, None)
            return []
        return list(self._interactions.get(allocation.token, ()))


class GenericHttpOASTProvider:
    """Poll a user-controlled generic interaction endpoint.

    The callback hostname is generated locally as ``<token>.<domain>``.
    Polling performs ``GET <api_base>/interactions?token=<token>`` and expects
    either a JSON list or ``{"interactions": [...]}``. No target request data
    is sent to the polling service.
    """

    def __init__(
        self,
        *,
        callback_domain: str,
        api_base: str,
        api_token: str = "",
        timeout: float = 5.0,
        ttl_seconds: int = 300,
        session: Optional[requests.Session] = None,
        clock=time.time,
        token_factory=None,
    ):
        self.callback_domain = _validate_domain(callback_domain)
        parsed = urlparse(api_base)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("OAST API base must be an absolute HTTP(S) URL.")
        self.api_base = api_base.rstrip("/")
        self.api_token = api_token.strip()
        self.timeout = max(0.1, float(timeout))
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.session = session or requests.Session()
        self.clock = clock
        self.token_factory = token_factory or (lambda: secrets.token_hex(16))

    @property
    def available(self) -> bool:
        return True

    def allocate(self, check_id: str = "") -> OASTAllocation:
        token = self.token_factory()
        hostname = f"{token}.{self.callback_domain}"
        return OASTAllocation(
            token=token,
            http_url=f"https://{hostname}/",
            dns_name=hostname,
            expires_at=self.clock() + self.ttl_seconds,
            check_id=check_id,
        )

    def poll(self, allocation: OASTAllocation) -> List[OASTInteraction]:
        if self.clock() > allocation.expires_at:
            return []
        headers = {"Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        response = self.session.get(
            f"{self.api_base}/interactions",
            headers=headers,
            params={"token": allocation.token},
            timeout=self.timeout,
            allow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
        raw_items = payload.get("interactions", []) if isinstance(payload, dict) else payload
        if not isinstance(raw_items, list):
            return []
        interactions: List[OASTInteraction] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            token = str(item.get("token") or allocation.token)
            if token != allocation.token:
                continue
            metadata = item.get("metadata")
            interactions.append(
                OASTInteraction(
                    token=allocation.token,
                    protocol=str(item.get("protocol") or "unknown").lower(),
                    observed_at=float(item.get("observed_at") or self.clock()),
                    remote_address=str(item.get("remote_address") or ""),
                    metadata=dict(metadata) if isinstance(metadata, dict) else {},
                )
            )
        return interactions


def _validate_domain(domain: str) -> str:
    value = (domain or "").strip().strip(".").lower()
    if not value or "/" in value or ":" in value or " " in value:
        raise ValueError("OAST callback domain must be a DNS name without a URL scheme.")
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise ValueError("OAST callback domain contains an invalid DNS label.")
    return value
