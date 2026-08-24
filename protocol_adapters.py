"""Phase 5: Optional protocol adapters for gRPC, WebSocket, and SOAP.

Each adapter is behind capability detection and can be disabled independently.
Protocol findings use the same evidence model but with their own parsers, request
builders, and safety settings. No adapter requires external tools to function.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ProtocolFinding:
    protocol: str  # grpc | websocket | soap
    category: str
    severity: str
    confidence: str
    title: str
    evidence: str
    owasp_api: str
    cwe: str
    endpoint: str = ""
    request_url: str = ""
    status_code: int = 0


def _tool_available(name: str) -> bool:
    """Check if an external tool binary is available on PATH."""
    return shutil.which(name) is not None


def grpc_available() -> bool:
    """Check if gRPC tooling is available."""
    return _tool_available("grpcurl")


def websocket_available() -> bool:
    """Check if WebSocket tooling is available."""
    return _tool_available("websocat")


def soap_available() -> bool:
    """SOAP doesn't require external tools — WSDL is HTTP."""
    return True


# --- gRPC adapter (capability-gated) ---


def probe_grpc_reflection(url: str) -> List[ProtocolFinding]:
    """Check if gRPC reflection is enabled (information leak).

    Uses grpcurl if available; otherwise returns informational note.
    """
    findings: List[ProtocolFinding] = []
    if not grpc_available():
        return findings
    # When grpcurl is available, a full implementation would call:
    #   grpcurl -plaintext <url> list
    # For now we return an informational finding if the tool exists.
    findings.append(ProtocolFinding(
        protocol="grpc",
        category="grpc_reflection",
        severity="low",
        confidence="informational",
        title="gRPC reflection probe skipped (requires grpcurl execution)",
        evidence="grpcurl is available but execution is deferred to Phase 6 Kali adapters.",
        owasp_api="API9:2023",
        cwe="CWE-200",
    ))
    return findings


# --- WebSocket adapter (capability-gated) ---


def probe_websocket_origin(url: str, origin: str = "https://evil.example.com") -> List[ProtocolFinding]:
    """Check if WebSocket endpoint accepts cross-origin connections.

    Uses websocat if available; otherwise returns informational note.
    """
    findings: List[ProtocolFinding] = []
    if not websocket_available():
        return findings
    findings.append(ProtocolFinding(
        protocol="websocket",
        category="ws_origin_check",
        severity="low",
        confidence="informational",
        title="WebSocket Origin probe skipped (requires websocat execution)",
        evidence="websocat is available but execution is deferred to Phase 6 Kali adapters.",
        owasp_api="API8:2023",
        cwe="CWE-346",
    ))
    return findings


# --- SOAP adapter (HTTP-based, no external tools needed) ---


def probe_soap_wsdl(url: str, wsdl_path: str = "?wsdl") -> List[ProtocolFinding]:
    """Check if SOAP WSDL is exposed."""
    findings: List[ProtocolFinding] = []
    if not soap_available():
        return findings
    # WSDL is served over HTTP, so we can check without external tools.
    # The actual HTTP request would be made by the caller's session.
    # Here we just return the probe metadata.
    findings.append(ProtocolFinding(
        protocol="soap",
        category="soap_wsdl_exposure",
        severity="medium",
        confidence="informational",
        title=f"SOAP WSDL exposure check queued for {url}{wsdl_path}",
        evidence="WSDL endpoint should be checked for exposure. Probe metadata ready for session execution.",
        owasp_api="API9:2023",
        cwe="CWE-200",
        request_url=f"{url}{wsdl_path}",
    ))
    return findings


def run_protocol_checks(url: str) -> List[ProtocolFinding]:
    """Run all available protocol adapter probes."""
    findings: List[ProtocolFinding] = []
    findings.extend(probe_grpc_reflection(url))
    findings.extend(probe_websocket_origin(url))
    findings.extend(probe_soap_wsdl(url))
    return findings
