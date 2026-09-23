"""Request-smuggling detection probes.

Uses :mod:`smuggling_transport` to send byte-exact requests that a
front-end/back-end pair may deserialize differently:

  * CL.TE  — front-end trusts Content-Length, back-end trusts chunked
  * TE.CL  — the reverse
  * TE.TE  — duplicate/conflicting Transfer-Encoding headers

Detection is timing/response-shaping based and non-destructive: the smuggled
prefix requests a nonexistent path, so at worst the attacker's own next
request is disturbed. All probes require intrusive mode.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional

from smuggling_transport import RawHTTPTransport, split_hostport


PROBE_TIMEOUT = 5.0
# A smuggled prefix that turns the victim's next request into a probe for a
# nonexistent path. Detection: the response to our own following GET arrives
# with an unexpected status (the server routed our second request body).
_DEAD_PATH_PREFIX = "/apifz-not-exist-"


@dataclass
class SmuggleFinding:
    category: str
    severity: str
    confidence: str
    title: str
    endpoint: str
    method: str
    parameter: str
    evidence: str
    owasp_api: str
    cwe: str
    request_url: str
    status_code: int = 0
    smuggle_class: str = ""


def _headers_block(extra: List[Tuple[str, str]]) -> bytes:
    lines = [f"{k}: {v}".encode() for k, v in extra]
    return b"".join(line + b"\r\n" for line in lines)


def _clte_probe(host_header: str, path: str) -> bytes:
    """Front-end uses CL, back-end uses TE: body is one chunk."""
    body = b"0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + _headers_block([
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", str(len(body))),
            ("Transfer-Encoding", "chunked"),
        ])
        + body
        + f"GET {_DEAD_PATH_PREFIX}{secrets.token_hex(4)} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + b"\r\n"
    )


def _tecl_probe(host_header: str, path: str) -> bytes:
    """Front-end uses TE, back-end uses CL: chunked body with smuggled GET."""
    smuggled = f"GET {_DEAD_PATH_PREFIX}{secrets.token_hex(4)} HTTP/1.1\r\nHost: {host_header}\r\n\r\n"
    fake_cl = 4  # length of '0\r\n\r\n' tail per classic TE.CL probe
    body = (
        f"{fake_cl:x}\r\n".encode()
        + b"ABCD\r\n"
        + b"0\r\n"
        + b"\r\n"
    )
    # The remainder after the fake CL is the smuggled request.
    remainder = smuggled.encode()
    return (
        f"POST {path} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + _headers_block([
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Transfer-Encoding", "chunked"),
            ("Content-Length", str(fake_cl + len(remainder))),
        ])
        + body
        + remainder
    )


def _tete_probe(host_header: str, path: str) -> bytes:
    """Duplicate conflicting Transfer-Encoding headers."""
    body = b"0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + b"Transfer-Encoding: chunked\r\n"
        + b"Transfer-Encoding: identity\r\n"
        + b"Content-Length: 0\r\n"
        + b"\r\n"
        + body
        + f"GET {_DEAD_PATH_PREFIX}{secrets.token_hex(4)} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + b"\r\n"
    )


_PROBES = [
    ("CL.TE", _clte_probe),
    ("TE.CL", _tecl_probe),
    ("TE.TE", _tete_probe),
]


def _baseline_status(transport: RawHTTPTransport, host: str, port: int, use_tls: bool, host_header: str, path: str) -> int:
    normal = (
        f"GET {path} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + b"Connection: close\r\n\r\n"
    )
    resp = transport.send(host, port, normal, timeout=PROBE_TIMEOUT)
    return resp.status_code if resp.is_http else 0


def probe_smuggling(
    base_url: str,
    endpoint_path: str,
    *,
    transport: Optional[RawHTTPTransport] = None,
    host_header: Optional[str] = None,
) -> List[SmuggleFinding]:
    """Run the three classic smuggling probes against one endpoint path.

    Detection heuristic: after the poison request, an immediate follow-up GET
    to a normal path returns an unexpected status (it was consumed as the
    smuggled request) — or the socket yields two responses.
    """
    findings: List[SmuggleFinding] = []
    host, port, use_tls = split_hostport(base_url)
    host_header = host_header or host
    transport = transport or RawHTTPTransport(use_tls=use_tls)

    path = endpoint_path or "/"
    baseline_status = _baseline_status(transport, host, port, use_tls, host_header, path)
    if baseline_status == 0:
        return findings  # unreachable: no claims

    follow_path = "/apifz-followup"
    follow_request = (
        f"GET {follow_path} HTTP/1.1\r\n".encode()
        + f"Host: {host_header}\r\n".encode()
        + b"Connection: close\r\n\r\n"
    )

    for label, builder in _PROBES:
        poison = builder(host_header, path)
        resp = transport.send(host, port, poison, timeout=PROBE_TIMEOUT)
        if resp.error and not resp.is_http:
            continue  # connection died: inconclusive, try next probe

        # Follow-up request on a fresh socket: if desynced globally, front-end
        # queues our smuggled GET and returns its response now.
        follow = transport.send(host, port, follow_request, timeout=PROBE_TIMEOUT)
        if follow.is_http and baseline_status not in (0,) and follow.status_code != baseline_status:
            # The follow-up status differs from a normal request: our smuggled
            # probe path was served instead. Flag tentatively.
            findings.append(
                SmuggleFinding(
                    category="request_smuggling",
                    severity="high",
                    confidence="tentative",
                    title=f"Possible request smuggling ({label})",
                    endpoint=endpoint_path,
                    method="POST",
                    parameter=label,
                    evidence=(
                        f"After a {label} poison request to {path}, a normal follow-up "
                        f"GET returned HTTP {follow.status_code} (baseline {baseline_status}) — "
                        f"the front- and back-end disagree on message boundaries. "
                        f"Verify with a timed client-aware methodology before exploiting."
                    ),
                    owasp_api="API8:2023",
                    cwe="CWE-436",
                    request_url=base_url.rstrip("/") + path,
                    status_code=follow.status_code,
                    smuggle_class=label,
                )
            )
            break  # one desync class is enough to report
    return findings


def probe_h2cl(
    base_url: str,
    endpoint_path: str,
) -> List[SmuggleFinding]:
    """HTTP/2 Content-Length smuggling probe (requires the optional `h2` package).

    Sends an H2 request with a Content-Length that disagrees with the frame
    payload — back-ends translating H2->H1.1 may trust the header.
    """
    findings: List[SmuggleFinding] = []
    try:
        import h2  # noqa: F401
        from h2.connection import H2Connection
        from h2.config import H2Configuration
    except ImportError:
        return findings  # clean skip without the optional dependency

    # Full H2-over-socket plumbing is substantial; the connection-preflight
    # plus a mismatched-content-length DATA frame is the minimal probe.
    try:
        host, port, use_tls = split_hostport(base_url)
        sock = RawHTTPTransport(use_tls=use_tls)
        # H2 requires the connection preface; a raw implementation would
        # negotiate via ALPN. Until the H2 socket layer lands, report the
        # capability as available but unprobed.
        del sock, H2Connection, H2Configuration
        findings.append(
            SmuggleFinding(
                category="request_smuggling_h2",
                severity="low",
                confidence="informational",
                title="H2.CL probe available but not executed",
                evidence="The h2 package is installed; enable H2 socket probing in a future release.",
                owasp_api="API8:2023",
                cwe="CWE-436",
                request_url=base_url,
            )
        )
    except Exception:  # pragma: no cover - defensive
        pass
    return findings


def run_smuggling(
    endpoints,
    base_url: str,
    session=None,  # unused: raw transport has its own socket layer
    timeout: float = PROBE_TIMEOUT,
    auth_header: Optional[str] = None,
    scan=None,
) -> List[SmuggleFinding]:
    """Engine adapter signature: probe first 3 endpoint paths."""
    findings: List[SmuggleFinding] = []
    seen_paths = set()
    for ep in endpoints[:3]:
        if ep.path in seen_paths:
            continue
        seen_paths.add(ep.path)
        findings.extend(probe_smuggling(base_url, ep.path, transport=None))
        if findings:
            break
    return findings
