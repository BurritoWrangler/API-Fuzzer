"""Tests for the Phase 2-6 engine and check registry."""

from __future__ import annotations

import engine
from engine import CheckRegistry, EngineScanResult, default_registry, run_engine
from models import SafetyLevel, safety_allowed
from spec_parser import Endpoint
from tests.fakes import FakeResponse, FakeSession


def test_default_registry_has_all_phase_checks():
    registry = default_registry()
    check_ids = {c.check_id for c in registry.all_checks()}
    assert "bola" in check_ids
    assert "bfla" in check_ids
    assert "bopla" in check_ids
    assert "response_contract" in check_ids
    assert "jwt_differential" in check_ids
    assert "token_session" in check_ids
    assert "resource_consumption" in check_ids
    assert "upload_safety" in check_ids
    assert "parser_confusion" in check_ids
    assert "sspp" in check_ids
    assert "blind_ssrf" in check_ids
    assert "graphql" in check_ids
    assert "inventory" in check_ids
    assert "workflow" in check_ids


def test_disabled_checks_are_excluded():
    registry = default_registry()
    # blind_ssrf and graphql are disabled by default (require config)
    enabled = {c.check_id for c in registry.get_enabled("safe_active")}
    assert "blind_ssrf" not in enabled
    assert "graphql" not in enabled
    assert "bola" in enabled


def test_passive_mode_excludes_active_checks():
    registry = default_registry()
    enabled = {c.check_id for c in registry.get_enabled("passive")}
    assert "response_contract" in enabled  # passive check
    assert "inventory" in enabled  # passive check
    assert "bola" not in enabled  # safe_active check
    assert "resource_consumption" not in enabled


def test_intrusive_mode_includes_intrusive_checks():
    registry = default_registry()
    all_checks = {c.check_id for c in registry.all_checks()}
    assert "workflow" in all_checks  # registered
    # workflow is disabled by default but is intrusive-level
    intrusive_enabled = {c.check_id for c in registry.get_enabled("intrusive")}
    assert "workflow" in intrusive_enabled  # enabled under intrusive mode


def test_run_engine_with_disabled_checks():
    registry = default_registry()
    session = FakeSession(lambda m, u, k: FakeResponse(200, '{"ok": true}'))
    result = run_engine(
        [], "https://api.example", session,
        registry=registry,
        scan_mode="passive",
        timeout=5,
        disabled_checks={"response_contract", "inventory"},
    )
    assert isinstance(result, EngineScanResult)
    ran_ids = {cr.check_id for cr in result.check_results}
    assert "response_contract" not in ran_ids
    assert "inventory" not in ran_ids


def test_run_engine_handles_no_endpoints():
    registry = default_registry()
    session = FakeSession()
    result = run_engine(
        [], "https://api.example", session,
        registry=registry,
        scan_mode="passive",
        timeout=5,
    )
    assert isinstance(result, EngineScanResult)


def test_check_registry_can_register_custom():
    registry = CheckRegistry()
    registry.register(
        check_id="custom",
        owasp_api="API1:2023",
        cwe="CWE-639",
        safety_level=SafetyLevel.SAFE_ACTIVE.value,
        max_requests=10,
    )
    assert len(registry) == 1
    enabled = registry.get_enabled("safe_active")
    assert len(enabled) == 1
    assert enabled[0].check_id == "custom"
