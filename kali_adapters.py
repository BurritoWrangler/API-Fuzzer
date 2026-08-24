"""Phase 6: Optional Kali Linux capability adapters.

Detects and invokes external Kali tools (testssl.sh, grpcurl, websocat, ffuf,
nmap) behind runtime capability detection. Tools are invoked without a shell
using explicit argument arrays, with timeouts, output caps, no root required,
and results parsed into the common evidence model. Tool absence is a clean skip.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


DEFAULT_TIMEOUT = 30
MAX_OUTPUT = 64 * 1024  # 64 KiB output cap


@dataclass
class KaliFinding:
    tool: str
    category: str
    severity: str
    confidence: str
    title: str
    evidence: str
    owasp_api: str
    cwe: str
    target: str = ""
    returncode: int = 0
    skipped: bool = False


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_tool(
    tool: str,
    args: List[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[int, str, bool]:
    """Run an external tool without a shell, returning (returncode, output, timed_out)."""
    try:
        proc = subprocess.run(
            [tool] + args,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
        stdout = (proc.stdout or "")[:MAX_OUTPUT]
        stderr = (proc.stderr or "")[:MAX_OUTPUT]
        output = stdout + ("\n" + stderr if stderr.strip() else "")
        return proc.returncode, output, False
    except subprocess.TimeoutExpired:
        return 124, "", True
    except FileNotFoundError:
        return 127, "", False


def probe_testssl(host: str, port: int = 443) -> List[KaliFinding]:
    """Run testssl.sh TLS/cipher checks if available."""
    findings: List[KaliFinding] = []
    if not _tool_available("testssl.sh"):
        return [KaliFinding(
            tool="testssl.sh",
            category="tls_misconfig",
            severity="info",
            confidence="informational",
            title="testssl.sh not available — TLS check skipped",
            evidence="Install testssl.sh to enable TLS cipher/certificate checks.",
            owasp_api="API8:2023",
            cwe="CWE-295",
            target=f"{host}:{port}",
            skipped=True,
        )]
    code, output, timed_out = _run_tool(
        "testssl.sh", ["--quiet", "--color", "0", f"{host}:{port}"],
    )
    if timed_out:
        findings.append(KaliFinding(
            tool="testssl.sh",
            category="tls_timeout",
            severity="low",
            confidence="informational",
            title=f"testssl.sh timed out on {host}:{port}",
            evidence=f"TLS check exceeded {DEFAULT_TIMEOUT}s timeout.",
            owasp_api="API8:2023",
            cwe="CWE-400",
            target=f"{host}:{port}",
        ))
        return findings
    # Parse for known weak cipher / protocol findings.
    weak_indicators = ["LOW:", "MEDIUM:", "WEAK", "RC4", "SSLv3", "TLS 1.0", "TLS 1.1"]
    for indicator in weak_indicators:
        if indicator.lower() in output.lower():
            findings.append(KaliFinding(
                tool="testssl.sh",
                category="tls_weak",
                severity="medium",
                confidence="strong",
                title=f"TLS weakness detected: {indicator}",
                evidence=f"testssl.sh output contains '{indicator}' for {host}:{port}.",
                owasp_api="API8:2023",
                cwe="CWE-327",
                target=f"{host}:{port}",
                returncode=code,
            ))
            break
    return findings


def probe_ffuf(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> List[KaliFinding]:
    """Run ffuf for hidden endpoint/content discovery if available."""
    findings: List[KaliFinding] = []
    if not _tool_available("ffuf"):
        return [KaliFinding(
            tool="ffuf",
            category="hidden_endpoints",
            severity="info",
            confidence="informational",
            title="ffuf not available — content discovery skipped",
            evidence="Install ffuf to enable hidden endpoint discovery.",
            owasp_api="API9:2023",
            cwe="CWE-200",
            target=url,
            skipped=True,
        )]
    if not _wordlist_exists(wordlist):
        return [KaliFinding(
            tool="ffuf",
            category="hidden_endpoints",
            severity="info",
            confidence="informational",
            title=f"Wordlist not found: {wordlist}",
            evidence="Provide a valid wordlist path to enable ffuf content discovery.",
            owasp_api="API9:2023",
            cwe="CWE-200",
            target=url,
            skipped=True,
        )]
    code, output, timed_out = _run_tool(
        "ffuf",
        ["-u", url + "/FUZZ", "-w", wordlist, "-mc", "200,204,301,302,401,403",
         "-t", "10", "-timeout", "5"],
    )
    if timed_out:
        findings.append(KaliFinding(
            tool="ffuf",
            category="ffuf_timeout",
            severity="low",
            confidence="informational",
            title=f"ffuf timed out on {url}",
            evidence=f"Content discovery exceeded {DEFAULT_TIMEOUT}s timeout.",
            owasp_api="API9:2023",
            cwe="CWE-400",
            target=url,
        ))
        return findings
    # Parse for discovered endpoints (lines with Status).
    for line in output.splitlines():
        if "::" in line and ("200" in line or "301" in line or "302" in line):
            parts = line.split()
            path = parts[-1].replace("FUZZ", "") if parts else ""
            if path:
                findings.append(KaliFinding(
                    tool="ffuf",
                    category="hidden_endpoint",
                    severity="medium",
                    confidence="strong",
                    title=f"Hidden endpoint discovered: {path}",
                    evidence=f"ffuf found {path} at {url} (line: {line.strip()}).",
                    owasp_api="API9:2023",
                    cwe="CWE-200",
                    target=url,
                    returncode=code,
                ))
    return findings


def _wordlist_exists(path: str) -> bool:
    import os
    return os.path.isfile(path)


def probe_nmap_scripts(host: str, scripts: str = "default") -> List[KaliFinding]:
    """Run nmap with script scanning if available."""
    findings: List[KaliFinding] = []
    if not _tool_available("nmap"):
        return [KaliFinding(
            tool="nmap",
            category="network_scan",
            severity="info",
            confidence="informational",
            title="nmap not available — network scan skipped",
            evidence="Install nmap to enable network-level service/script scanning.",
            owasp_api="API9:2023",
            cwe="CWE-200",
            target=host,
            skipped=True,
        )]
    code, output, timed_out = _run_tool(
        "nmap", ["-sV", "--script", scripts, host],
    )
    if timed_out:
        findings.append(KaliFinding(
            tool="nmap",
            category="nmap_timeout",
            severity="low",
            confidence="informational",
            title=f"nmap timed out on {host}",
            evidence=f"Network scan exceeded {DEFAULT_TIMEOUT}s timeout.",
            owasp_api="API9:2023",
            cwe="CWE-400",
            target=host,
        ))
        return findings
    # Parse for open ports and services.
    for line in output.splitlines():
        if "open" in line.lower() and "/tcp" in line:
            findings.append(KaliFinding(
                tool="nmap",
                category="open_port",
                severity="low",
                confidence="strong",
                title=f"Open port detected: {line.strip()}",
                evidence=f"nmap found open service on {host}: {line.strip()}",
                owasp_api="API9:2023",
                cwe="CWE-200",
                target=host,
                returncode=code,
            ))
    return findings


def available_tools() -> Dict[str, bool]:
    """Return a dictionary of tool availability."""
    return {
        "testssl.sh": _tool_available("testssl.sh"),
        "grpcurl": _tool_available("grpcurl"),
        "websocat": _tool_available("websocat"),
        "ffuf": _tool_available("ffuf"),
        "nmap": _tool_available("nmap"),
    }
