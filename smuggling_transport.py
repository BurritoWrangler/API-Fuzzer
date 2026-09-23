"""Raw-socket HTTP transport for desynchronization probes.

``requests`` normalizes Content-Length / Transfer-Encoding, which makes
request-smuggling testing impossible through the normal pipeline. This module
speaks HTTP/1.1 (and optionally HTTP/2) directly over sockets with an
injectable socket factory so tests can fake the wire.

Safety: probes are detection-only — the smuggled prefix requests a
nonexistent path, so a successful desync disturbs only the attacker's own
connection. No connection pooling, one socket per probe, hard timeouts.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


SocketFactory = Callable[..., "socket.socket"]


@dataclass
class RawResponse:
    status_code: int = 0
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    raw: bytes = b""
    error: Optional[str] = None

    def header(self, name: str) -> str:
        lowered = name.lower()
        for k, v in self.headers:
            if k.lower() == lowered:
                return v
        return ""

    @property
    def is_http(self) -> bool:
        return self.status_code > 0


def default_socket_factory() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def parse_response(raw: bytes) -> RawResponse:
    """Parse a raw HTTP/1.1 response bytes blob (lenient, probe-grade)."""
    resp = RawResponse(raw=raw)
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - decode with replace never fails
        text = ""
    if not text:
        resp.error = "empty response"
        return resp

    # Locate header/body split (tolerate multiple responses concatenated).
    first_part = text.split("\r\n\r\n", 1)
    head = first_part[0]
    resp.body = first_part[1] if len(first_part) > 1 else ""

    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(" ", 2)
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP"):
        try:
            resp.status_code = int(parts[1])
        except ValueError:
            resp.status_code = 0
            resp.error = "unparseable status line"
    else:
        resp.error = "not an HTTP response"
        return resp

    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            resp.headers.append((k.strip(), v.strip()))
    return resp


class RawHTTPTransport:
    """Sends fully attacker-controlled byte sequences over one TCP socket."""

    def __init__(
        self,
        *,
        socket_factory: Optional[SocketFactory] = None,
        use_tls: bool = False,
    ) -> None:
        self.socket_factory = socket_factory or default_socket_factory
        self.use_tls = use_tls

    def send(
        self,
        host: str,
        port: int,
        raw_request: bytes,
        timeout: float = 5.0,
    ) -> RawResponse:
        """Send raw bytes and parse whatever comes back as one response."""
        sock: Optional[socket.socket] = None
        try:
            sock = self.socket_factory()
            sock.settimeout(timeout)
            sock.connect((host, port))
            if self.use_tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw_request)
            chunks: List[bytes] = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                # Stop once we have a complete response (header + body) and
                # the connection isn't going to yield more promptly.
                joined = b"".join(chunks)
                if b"\r\n\r\n" in joined:
                    head, _, body = joined.partition(b"\r\n\r\n")
                    cl = None
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                cl = int(line.split(b":", 1)[1].strip())
                            except ValueError:
                                cl = None
                    if cl is not None and len(body) >= cl:
                        break
                    if not cl and len(chunks) > 1:
                        break
            return parse_response(b"".join(chunks))
        except (OSError, socket.timeout) as exc:
            return RawResponse(error=f"{type(exc).__name__}: {exc}")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:  # pragma: no cover - close best-effort
                    pass


def split_hostport(url: str) -> Tuple[str, int, bool]:
    """Return (host, port, use_tls) from an http(s) URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    use_tls = parsed.scheme == "https"
    host = parsed.hostname or ""
    port = parsed.port or (443 if use_tls else 80)
    return host, port, use_tls
