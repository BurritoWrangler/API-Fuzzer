"""apifuzz Flask web app.

Routes:
    GET  /                          upload + scan config page
    POST /scan                      start a scan (multipart upload), returns redirect to /scan/<id>
    GET  /scan/<scan_id>            results dashboard
    GET  /scan/<scan_id>/status     scan progress JSON (polled by the dashboard)
    GET  /scan/<scan_id>/export     download standalone HTML report
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import threading
import uuid
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, render_template, request, Response

from analyzer import sort_findings
from fuzzer import ScanConfig, ScanState, run_scan
from http_session import UA_PRESET_LABELS, UA_PRESETS
from obfuscator import MODE_LABELS as OBFUSCATION_LABELS, MODES as OBFUSCATION_MODES, MODE_OFF
from payloads import CATEGORY_LABELS, available_categories
from spec_parser import SpecParseError, parse_spec_text


UA_MODES = set(UA_PRESETS.keys()) | {"random", "custom"}
OBFUSCATION_MODES_SET = set(OBFUSCATION_MODES)


__version__ = "1.10"


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB spec cap
MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("APIFUZZ_MAX_CONCURRENT_SCANS", "4")))
SCAN_TTL_SECONDS = max(60, int(os.environ.get("APIFUZZ_SCAN_TTL_SECONDS", "86400")))


@app.context_processor
def _inject_globals():
    return {"app_version": __version__}


def _validate_base_url(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (cleaned_url, error_message)."""
    if not raw:
        return None, "Base URL is required."
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        return None, "Base URL must start with http:// or https://."
    if not parsed.netloc:
        return None, "Base URL is missing a hostname."
    cleaned = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
    return cleaned.rstrip("/") or f"{parsed.scheme}://{parsed.netloc}", None


def _validate_auth_header(raw: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not raw:
        return None, None
    value = raw.strip()
    if "\n" in value or "\r" in value:
        return None, "Authorization header may not contain newlines."
    # Strip the literal "Authorization:" prefix if the user pasted it.
    if value.lower().startswith("authorization:"):
        value = value.split(":", 1)[1].strip()
    if not value:
        return None, "Authorization header value is empty."
    return value, None


# Thread-safe scan registry.
SCANS: Dict[str, ScanState] = {}
SCANS_LOCK = threading.Lock()

def _prune_scans_locked(now: Optional[float] = None) -> None:
    """Drop terminal scans after the configured in-memory retention period.

    The caller must hold ``SCANS_LOCK``.
    """
    import time

    current = time.time() if now is None else now
    expired = [
        scan_id
        for scan_id, state in SCANS.items()
        if state.status in ("completed", "failed")
        and state.finished_at
        and current - state.finished_at >= SCAN_TTL_SECONDS
    ]
    for scan_id in expired:
        del SCANS[scan_id]


def _active_scan_count_locked() -> int:
    """Return active scan count while the caller holds ``SCANS_LOCK``."""
    return sum(1 for state in SCANS.values() if state.status in ("pending", "running"))


@app.route("/")
def index():
    return render_template(
        "index.html",
        categories=[(c, CATEGORY_LABELS[c]) for c in available_categories()],
        detect_misconfig=True,
        ua_presets=UA_PRESET_LABELS,
        obfuscation_modes=OBFUSCATION_LABELS,
    )


@app.route("/scan", methods=["POST"])
def start_scan():
    spec_file = request.files.get("spec")
    if not spec_file or not spec_file.filename:
        return _error_response("Missing OpenAPI spec file."), 400

    try:
        spec_text = spec_file.read().decode("utf-8", errors="replace")
        endpoints = parse_spec_text(spec_text, filename=spec_file.filename)
    except SpecParseError as exc:
        return _error_response(f"Could not parse spec: {exc}"), 400
    except Exception as exc:  # pragma: no cover - defensive
        return _error_response(f"Spec error: {exc}"), 400

    if not endpoints:
        return _error_response("Spec parsed, but no endpoints were found."), 400

    base_url, url_err = _validate_base_url(request.form.get("base_url") or "")
    if url_err:
        return _error_response(url_err), 400

    auth_header, auth_err = _validate_auth_header(request.form.get("auth_header"))
    if auth_err:
        return _error_response(auth_err), 400

    try:
        timeout = float(request.form.get("timeout") or "10")
    except ValueError:
        return _error_response("Timeout must be a number."), 400
    if not (1.0 <= timeout <= 120.0):
        return _error_response("Timeout must be between 1 and 120 seconds."), 400

    unlimited_budget = request.form.get("unlimited_budget", "").lower() in ("on", "true", "1", "yes")
    if unlimited_budget:
        # Sentinel "no cap" — the fuzzer treats this as effectively unbounded.
        max_requests = 0
    else:
        try:
            max_requests = int(request.form.get("max_requests") or "2000")
        except ValueError:
            return _error_response("Request budget must be an integer."), 400
        if not (50 <= max_requests <= 20000):
            return _error_response("Request budget must be between 50 and 20000."), 400

    raw_categories = request.form.getlist("categories")
    categories = [c for c in raw_categories if c in CATEGORY_LABELS and c != "misconfiguration"]
    if not categories:
        return _error_response("Select at least one vulnerability class."), 400

    detect_misconfig = request.form.get("detect_misconfig", "").lower() in ("on", "true", "1", "yes")

    ua_mode = (request.form.get("user_agent_mode") or "default").lower().strip()
    if ua_mode not in UA_MODES:
        return _error_response(f"Unknown User-Agent mode: {ua_mode!r}."), 400
    ua_custom = (request.form.get("user_agent_custom") or "").strip()
    if ua_mode == "custom":
        if not ua_custom:
            return _error_response("Custom User-Agent value is empty."), 400
        if "\n" in ua_custom or "\r" in ua_custom:
            return _error_response("Custom User-Agent may not contain newlines."), 400
        if len(ua_custom) > 512:
            return _error_response("Custom User-Agent is too long (max 512 chars)."), 400

    obf_mode = (request.form.get("payload_obfuscation") or MODE_OFF).lower().strip()
    if obf_mode not in OBFUSCATION_MODES_SET:
        return _error_response(f"Unknown obfuscation mode: {obf_mode!r}."), 400

    def _on(name: str) -> bool:
        # Unchecked HTML checkboxes are omitted from the form entirely.
        return request.form.get(name, "").lower() in ("on", "true", "1", "yes")

    scan_id = uuid.uuid4().hex[:12]
    state = ScanState(scan_id=scan_id)
    with SCANS_LOCK:
        _prune_scans_locked()
        if _active_scan_count_locked() >= MAX_CONCURRENT_SCANS:
            return _error_response(
                f"Maximum concurrent scans ({MAX_CONCURRENT_SCANS}) reached. "
                "Wait for a running scan to finish."
            ), 429
        SCANS[scan_id] = state

    cfg = ScanConfig(
        base_url=base_url,
        categories=categories,
        auth_header=auth_header,
        timeout=timeout,
        max_requests=max_requests,
        detect_misconfig=detect_misconfig,
        user_agent_mode=ua_mode,
        user_agent_custom=ua_custom,
        payload_obfuscation=obf_mode,
        extra_mass_assignment=_on("extra_mass_assignment"),
        extra_hpp=_on("extra_hpp"),
        extra_method_override=_on("extra_method_override"),
        extra_content_type_confusion=_on("extra_content_type_confusion"),
        extra_open_redirect=_on("extra_open_redirect"),
        extra_canary_reflection=_on("extra_canary_reflection"),
        jwt_attacks=_on("jwt_attacks"),
        schema_violations=_on("schema_violations"),
        rate_limit_probe=_on("rate_limit_probe"),
        api_version_inventory=_on("api_version_inventory"),
    )

    worker = threading.Thread(
        target=run_scan,
        args=(state, endpoints, cfg),
        name=f"apifuzz-scan-{scan_id}",
        daemon=True,
    )
    worker.start()

    # If the caller is AJAX, return JSON. Otherwise redirect to the dashboard.
    if request.headers.get("X-Requested-With") == "fetch" or request.is_json:
        return jsonify({"scan_id": scan_id, "url": f"/scan/{scan_id}"})
    return Response(status=303, headers={"Location": f"/scan/{scan_id}"})


@app.route("/scan/<scan_id>")
def scan_dashboard(scan_id: str):
    state = _get_scan(scan_id)
    return render_template(
        "results.html",
        scan_id=scan_id,
        snapshot=state.snapshot(),
        category_labels=CATEGORY_LABELS,
        embed=False,
    )


@app.route("/scan/<scan_id>/status")
def scan_status(scan_id: str):
    state = _get_scan(scan_id)
    snap = state.snapshot()
    snap["findings"] = [f.to_dict() for f in state.findings]
    return jsonify(snap)


@app.route("/scan/<scan_id>/export")
def scan_export(scan_id: str):
    state = _get_scan(scan_id)
    css_path = os.path.join(app.static_folder or "static", "styles.css")
    try:
        with open(css_path, "r", encoding="utf-8") as fh:
            inline_css = fh.read()
    except OSError:
        inline_css = ""
    html = render_template(
        "results.html",
        scan_id=scan_id,
        snapshot=state.snapshot(),
        category_labels=CATEGORY_LABELS,
        embed=True,
        findings=[f.to_dict() for f in state.findings],
        inline_css=inline_css,
    )
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="apifuzz-{scan_id}.html"'},
    )


@app.route("/scan/<scan_id>/export.csv")
def scan_export_csv(scan_id: str):
    """v1.8: export all findings as a CSV with columns
    Severity, Affected Endpoint, Vulnerability Title, Raw Payload.
    """
    state = _get_scan(scan_id)
    buf = io.StringIO()
    # QUOTE_ALL keeps payloads containing commas, quotes, or newlines safe.
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(["Severity", "Affected Endpoint", "Vulnerability Title", "Raw Payload"])
    for f in sort_findings(list(state.findings)):
        affected = f"{f.method} {f.endpoint}".strip()
        writer.writerow([f.severity, affected, f.title, f.payload or ""])
    csv_text = buf.getvalue()
    return Response(
        csv_text,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="apifuzz-{scan_id}.csv"',
            "Content-Length": str(len(csv_text.encode("utf-8"))),
        },
    )


def _get_scan(scan_id: str) -> ScanState:
    with SCANS_LOCK:
        _prune_scans_locked()
        state = SCANS.get(scan_id)
    if state is None:
        abort(404)
    return state


def _error_response(msg: str):
    # Preserve user input on re-render so they don't have to retype.
    return render_template(
        "index.html",
        categories=[(c, CATEGORY_LABELS[c]) for c in available_categories()],
        error=msg,
        prev_base_url=(request.form.get("base_url") or "").strip(),
        prev_auth_header=(request.form.get("auth_header") or "").strip(),
        prev_timeout=(request.form.get("timeout") or "10").strip(),
        prev_max_requests=(request.form.get("max_requests") or "2000").strip(),
        prev_categories=set(request.form.getlist("categories")) or None,
        prev_detect_misconfig=request.form.get("detect_misconfig", "").lower()
        in ("on", "true", "1", "yes"),
        detect_misconfig=request.form.get("detect_misconfig", "").lower()
        in ("on", "true", "1", "yes"),
        prev_user_agent_mode=(request.form.get("user_agent_mode") or "default").lower().strip(),
        prev_user_agent_custom=(request.form.get("user_agent_custom") or "").strip(),
        prev_payload_obfuscation=(request.form.get("payload_obfuscation") or MODE_OFF).lower().strip(),
        ua_presets=UA_PRESET_LABELS,
        obfuscation_modes=OBFUSCATION_LABELS,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=f"apifuzz web UI (v{__version__})")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    parser.add_argument("--version", action="version", version=f"apifuzz {__version__}")
    args = parser.parse_args()
    print(f"apifuzz v{__version__} listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
