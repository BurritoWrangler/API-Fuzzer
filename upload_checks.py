"""Phase 4: Safe file upload security probes.

Generates multipart upload requests and checks for MIME/extension mismatch,
filename traversal, Unicode normalization, double extensions, SVG/HTML active
content, and size enforcement. Does NOT send executable web shells — uses
harmless canary content only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

from spec_parser import Endpoint


CANARY_CONTENT = "apifuzz-upload-canary"
CANARY_FILENAME = "canary.txt"
MAX_UPLOAD_SIZE = 1024 * 1024  # 1 MiB safety ceiling


@dataclass
class UploadFinding:
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


def _has_file_field(endpoint: Endpoint) -> Optional[str]:
    """Return the name of the first file-type field if the endpoint supports multipart."""
    if not endpoint.request_body:
        return None
    for media_type, media in endpoint.request_body.content.items():
        if "multipart" not in media_type.lower():
            continue
        schema = media.schema or {}
        props = schema.get("properties") or {}
        for name, prop in props.items():
            if isinstance(prop, dict) and (
                prop.get("format") == "binary"
                or prop.get("type") == "file"
                or prop.get("type") == "string"
                and prop.get("format") == "binary"
            ):
                return name
    return None


def _build_multipart(
    field_name: str,
    filename: str,
    content: str,
    content_type: str = "text/plain",
) -> bytes:
    """Build a minimal multipart/form-data body."""
    boundary = "apifuzzboundary"
    parts = [
        f"--{boundary}",
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"',
        f"Content-Type: {content_type}",
        "",
        content,
        f"--{boundary}--",
        "",
    ]
    return "\r\n".join(parts).encode("utf-8")


def probe_uploads(
    endpoint: Endpoint,
    base_url: str,
    session: requests.Session,
    timeout: float,
    auth_header: Optional[str] = None,
) -> List[UploadFinding]:
    """Run safe file upload security probes."""
    findings: List[UploadFinding] = []
    file_field = _has_file_field(endpoint)
    if file_field is None:
        return findings

    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    url = base_url.rstrip("/") + endpoint.path

    probes: List[Tuple[str, str, str, str, str]] = [
        ("canary.txt", CANARY_CONTENT, "text/plain", "MIME type matches content"),
        ("canary.html", "<b>canary</b>", "text/html", "HTML active content uploaded"),
        ("canary.svg", "<svg onload='alert(1)'>", "image/svg+xml", "SVG with active content uploaded"),
        ("canary.jpg", CANARY_CONTENT, "image/jpeg", "MIME/extension mismatch: .jpg with text content"),
        ("canary.php.txt", CANARY_CONTENT, "text/plain", "Double extension attempt"),
        ("../../canary.txt", CANARY_CONTENT, "text/plain", "Filename traversal attempt"),
        ("canary\u0000.txt", CANARY_CONTENT, "text/plain", "Null byte in filename"),
        ("canary.exe", CANARY_CONTENT, "application/octet-stream", "Executable extension (harmless content)"),
    ]

    for filename, content, mime, label in probes:
        if len(content) > MAX_UPLOAD_SIZE:
            continue
        body = _build_multipart(file_field, filename, content, mime)
        headers["Content-Type"] = f"multipart/form-data; boundary=apifuzzboundary"
        try:
            resp = session.request(
                endpoint.method, url, headers=headers,
                data=body, timeout=timeout, allow_redirects=False,
            )
            if 200 <= resp.status_code < 300:
                severity = "high" if any(kw in label.lower() for kw in ("traversal", "active", "executable")) else "medium"
                findings.append(UploadFinding(
                    category="upload_misuse",
                    severity=severity,
                    confidence="tentative",
                    title=f"File upload accepted: {label}",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    parameter=file_field,
                    evidence=(
                        f"Uploaded '{filename}' (Content-Type: {mime}) was accepted "
                        f"with HTTP {resp.status_code}."
                    ),
                    owasp_api="API8:2023",
                    cwe="CWE-434",
                    request_url=url,
                    status_code=resp.status_code,
                ))
        except requests.exceptions.RequestException:
            continue

    # Oversize upload probe.
    oversize = "A" * (MAX_UPLOAD_SIZE + 1)
    body = _build_multipart(file_field, "oversize.txt", oversize, "text/plain")
    headers["Content-Type"] = f"multipart/form-data; boundary=apifuzzboundary"
    try:
        resp = session.request(
            endpoint.method, url, headers=headers,
            data=body, timeout=timeout, allow_redirects=False,
        )
        if 200 <= resp.status_code < 300:
            findings.append(UploadFinding(
                category="upload_misuse",
                severity="high",
                confidence="strong",
                title="Oversized file upload accepted",
                endpoint=endpoint.path,
                method=endpoint.method,
                parameter=file_field,
                evidence=f"File exceeding {MAX_UPLOAD_SIZE} bytes was accepted (HTTP {resp.status_code}).",
                owasp_api="API4:2023",
                cwe="CWE-400",
                request_url=url,
                status_code=resp.status_code,
            ))
    except requests.exceptions.RequestException:
        pass

    return findings
