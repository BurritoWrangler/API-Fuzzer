import io

import app as webapp
from fuzzer import ScanState
from spec_parser import Endpoint, Parameter


class CapturingThread:
    created = []

    def __init__(self, *, target, args, name, daemon):
        self.target = target
        self.args = args
        self.name = name
        self.daemon = daemon
        self.started = False
        self.__class__.created.append(self)

    def start(self):
        self.started = True


def scan_form(**overrides):
    values = {
        "spec": (io.BytesIO(b"{}"), "spec.json"),
        "base_url": "https://api.example",
        "categories": "sql_injection",
        "timeout": "10",
        "max_requests": "100",
        "user_agent_mode": "default",
        "payload_obfuscation": "off",
    }
    values.update(overrides)
    return values


def setup_function():
    CapturingThread.created.clear()
    with webapp.SCANS_LOCK:
        webapp.SCANS.clear()


def test_unchecked_optional_scan_controls_are_disabled(monkeypatch):
    monkeypatch.setattr(
        webapp,
        "parse_spec_text",
        lambda content, filename: [
            Endpoint("/search", "GET", parameters=[Parameter("q", "query")])
        ],
    )
    monkeypatch.setattr(webapp.threading, "Thread", CapturingThread)
    client = webapp.app.test_client()

    response = client.post("/scan", data=scan_form())

    assert response.status_code == 303
    assert len(CapturingThread.created) == 1
    cfg = CapturingThread.created[0].args[2]
    assert cfg.detect_misconfig is False
    assert cfg.extra_mass_assignment is False
    assert cfg.extra_hpp is False
    assert cfg.extra_method_override is False
    assert cfg.extra_content_type_confusion is False
    assert cfg.extra_open_redirect is False
    assert cfg.extra_canary_reflection is False
    assert cfg.jwt_attacks is False
    assert cfg.schema_violations is False
    assert cfg.rate_limit_probe is False
    assert cfg.api_version_inventory is False


def test_concurrent_scan_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(
        webapp,
        "parse_spec_text",
        lambda content, filename: [
            Endpoint("/search", "GET", parameters=[Parameter("q", "query")])
        ],
    )
    monkeypatch.setattr(webapp.threading, "Thread", CapturingThread)
    monkeypatch.setattr(webapp, "MAX_CONCURRENT_SCANS", 1)
    with webapp.SCANS_LOCK:
        webapp.SCANS["running"] = ScanState(scan_id="running", status="running")
    client = webapp.app.test_client()

    response = client.post("/scan", data=scan_form())

    assert response.status_code == 429
    assert b"Maximum concurrent scans (1) reached" in response.data
    assert CapturingThread.created == []


def test_terminal_scans_are_pruned_after_ttl(monkeypatch):
    monkeypatch.setattr(webapp, "SCAN_TTL_SECONDS", 60)
    with webapp.SCANS_LOCK:
        webapp.SCANS["old"] = ScanState(
            scan_id="old",
            status="completed",
            finished_at=100.0,
        )
        webapp.SCANS["recent"] = ScanState(
            scan_id="recent",
            status="completed",
            finished_at=190.0,
        )
        webapp.SCANS["running"] = ScanState(
            scan_id="running",
            status="running",
            started_at=1.0,
        )
        webapp._prune_scans_locked(now=200.0)

    assert set(webapp.SCANS) == {"recent", "running"}
