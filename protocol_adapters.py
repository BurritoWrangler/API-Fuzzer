"""Protocol adapters: SOAP, WebSocket, and gRPC checks.

Each adapter is independent and capability-gated:
  * SOAP — plain HTTP, no external tools; SOAPAction spoofing and WSDL exposure
  * WebSocket — stdlib socket handshake with an evil Origin; no deps needed
  * gRPC — optional `grpc` package for channel readiness + reflection check

Findings share the ProtocolFinding evidence model. Adapters never alter REST
scans and can be disabled independently.
"""

from __future__ import annotations

import base64
import secrets
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


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


def grpc_available() -> bool:
    """True when the optional grpc package is importable."""
    try:
        import grpc  # noqa: F401
        return True
    except ImportError:
        return False


def websocket_available() -> bool:
    # WebSocket probing is stdlib — always available.
    return True


def soap_available() -> bool:
    return True


# ---------------------------------------------------------------------------
# SOAP (HTTP-based; session supplied by caller)
# ---------------------------------------------------------------------------

_SOAP_ENVELOPE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soap:Body><apifz:Ping xmlns:apifz="https://attacker.example/"/></soap:Body>'
    '</soap:Envelope>'
)


def probe_soap_wsdl(
    url: str,
    session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[ProtocolFinding]:
    """Check whether the WSDL document is exposed at ?wsdl / ?singlewsdl."""
    findings: List[ProtocolFinding] = []
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    for suffix in ("?wsdl", "?singlewsdl"):
        probe_url = url.rstrip("/") + suffix
        try:
            resp = session.get(probe_url, headers=headers, timeout=timeout, allow_redirects=False)
        except Exception:
            break
        if 200 <= resp.status_code < 300 and "<wsdl:definitions" in (resp.text or ""):
            findings.append(ProtocolFinding(
                protocol="soap",
                category="soap_wsdl_exposure",
                severity="medium",
                confidence="strong",
                title=f"SOAP WSDL exposed at {suffix}",
                evidence=f"WSDL definition document served at {probe_url} — full service contract is public.",
                owasp_api="API9:2023",
                cwe="CWE-200",
                request_url=probe_url,
                status_code=resp.status_code,
            ))
            break
    return findings


def probe_soap_action_spoofing(
    url: str,
    session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[ProtocolFinding]:
    """Send mismatched SOAPAction headers; 2xx on unknown actions suggests
    action-level authorization gaps."""
    findings: List[ProtocolFinding] = []
    headers = {"Content-Type": "text/xml; charset=utf-8"}
    if auth_header:
        headers["Authorization"] = auth_header
    spoofed = [
        "https://attacker.example/AdminOperation",
        '"' + url.rstrip("/") + "/Admin" + '"',
    ]
    for action in spoofed:
        send_headers = {**headers, "SOAPAction": action}
        try:
            resp = session.post(
                url, data=_SOAP_ENVELOPE.encode("utf-8"),
                headers=send_headers, timeout=timeout, allow_redirects=False,
            )
        except Exception:
            continue
        # Unknown actions usually yield a soap:Client fault (500); a 2xx
        # suggests the action header drove dispatch without authorization.
        if 200 <= resp.status_code < 300 and "soap:Client" not in (resp.text or ""):
            findings.append(ProtocolFinding(
                protocol="soap",
                category="soap_action_spoofing",
                severity="medium",
                confidence="tentative",
                title=f"SOAP endpoint accepted spoofed SOAPAction {action}",
                evidence=(
                    f"Request with SOAPAction {action} returned HTTP {resp.status_code}. "
                    f"Verify action-level authorization."
                ),
                owasp_api="API5:2023",
                cwe="CWE-285",
                request_url=url,
                status_code=resp.status_code,
            ))
            break
    return findings


# ---------------------------------------------------------------------------
# WebSocket (stdlib socket handshake; no external deps)
# ---------------------------------------------------------------------------


def _ws_handshake(
    host: str,
    port: int,
    path: str,
    extra_headers: Dict[str, str],
    use_tls: bool,
    timeout: float,
) -> Tuple[int, Dict[str, str]]:
    """Perform a WS upgrade handshake; return (status, response headers)."""
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    request_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}" + (f":{port}" if port not in (80, 443) else ""),
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ] + [f"{k}: {v}" for k, v in extra_headers.items()]
    raw = ("\r\n".join(request_lines) + "\r\n\r\n").encode()

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw)
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
        head = buffer.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="replace")
        lines = head.split("\r\n")
        status = 0
        if lines and lines[0].startswith("HTTP"):
            try:
                status = int(lines[0].split(" ")[1])
            except (IndexError, ValueError):
                status = 0
        resp_headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                resp_headers[k.strip().lower()] = v.strip()
        return status, resp_headers
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_websocket_origin(
    ws_url: str,
    timeout: float = 5.0,
    origin: str = "https://attacker.example",
) -> List[ProtocolFinding]:
    """Handshake with an evil Origin; 101 means cross-origin acceptance."""
    findings: List[ProtocolFinding] = []
    parsed = urlparse(ws_url)
    if parsed.scheme not in ("ws", "wss"):
        return findings
    use_tls = parsed.scheme == "wss"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    try:
        status, _headers = _ws_handshake(
            host, port, path, {"Origin": origin}, use_tls, timeout,
        )
    except (OSError, socket.timeout, ssl.SSLError):
        return findings
    if status == 101:
        findings.append(ProtocolFinding(
            protocol="websocket",
            category="ws_origin_bypass",
            severity="medium",
            confidence="strong",
            title="WebSocket accepts cross-origin handshake",
            evidence=(
                f"Handshake with Origin: {origin} completed (HTTP 101). Cross-site "
                f"data theft from the socket is viable unless the app protocol "
                f"enforces its own authorization."
            ),
            owasp_api="API8:2023",
            cwe="CWE-346",
            request_url=ws_url,
            status_code=status,
        ))
    return findings


def probe_websocket_auth(
    ws_url: str,
    timeout: float = 5.0,
) -> List[ProtocolFinding]:
    """Unauthenticated handshake succeeding is a message-authz prerequisite."""
    findings: List[ProtocolFinding] = []
    parsed = urlparse(ws_url)
    if parsed.scheme not in ("ws", "wss"):
        return findings
    use_tls = parsed.scheme == "wss"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    try:
        status, _headers = _ws_handshake(host, port, parsed.path or "/", {}, use_tls, timeout)
    except (OSError, socket.timeout, ssl.SSLError):
        return findings
    if status == 101:
        findings.append(ProtocolFinding(
            protocol="websocket",
            category="ws_no_auth",
            severity="medium",
            confidence="tentative",
            title="WebSocket handshake succeeds without credentials",
            evidence=f"{ws_url} completed upgrade with no auth; verify message-level authorization.",
            owasp_api="API2:2023",
            cwe="CWE-306",
            request_url=ws_url,
            status_code=status,
        ))
    return findings


# ---------------------------------------------------------------------------
# gRPC (optional grpc package)
# ---------------------------------------------------------------------------


def probe_grpc_reflection(url: str, timeout: float = 5.0) -> List[ProtocolFinding]:
    """Establish an insecure gRPC channel when the grpc package is available.

    A ready unauthenticated channel means no TLS/mTLS enforcement — a real
    finding. Reflection listing requires generated protos and is deferred;
    channel readiness is the bounded, dependency-light probe.
    """
    findings: List[ProtocolFinding] = []
    if not grpc_available():
        return findings
    try:
        import grpc
    except ImportError:  # pragma: no cover
        return findings

    parsed = urlparse(url if "://" in url else f"dns:/// {url}".replace(" ", ""))
    host = parsed.hostname or url.split(":")[0]
    port = parsed.port or (443 if url.startswith("https") else 50051)
    target = f"{host}:{port}"
    try:
        channel = grpc.insecure_channel(target)
        try:
            grpc.channel_ready_future(channel).result(timeout=timeout)
        except grpc.FutureTimeoutError:
            return findings
        findings.append(ProtocolFinding(
            protocol="grpc",
            category="grpc_unauthenticated_channel",
            severity="low",
            confidence="tentative",
            title="gRPC channel established without credentials",
            evidence=(
                f"An insecure channel to {target} became ready. Verify TLS/mTLS "
                f"requirements and that reflection is disabled in production."
            ),
            owasp_api="API8:2023",
            cwe="CWE-319",
            request_url=url,
        ))
        try:
            channel.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover - grpc runtime errors
        return findings
    return findings


# ---------------------------------------------------------------------------
# Aggregate runner
# ---------------------------------------------------------------------------


def run_protocol_checks(
    url: str,
    session=None,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
    ws_url: str = "",
    soap_url: str = "",
) -> List[ProtocolFinding]:
    """Run all available protocol adapters.

    SOAP and WebSocket run when URLs are supplied; gRPC runs when the grpc
    package is importable. Each adapter is independent and can be skipped by
    omitting its URL.
    """
    findings: List[ProtocolFinding] = []
    if soap_url and session is not None:
        findings.extend(probe_soap_wsdl(soap_url, session, timeout, auth_header))
        findings.extend(probe_soap_action_spoofing(soap_url, session, timeout, auth_header))
    if ws_url:
        findings.extend(probe_websocket_origin(ws_url, timeout))
        findings.extend(probe_websocket_auth(ws_url, timeout))
    findings.extend(probe_grpc_reflection(url, timeout))
    return findings
