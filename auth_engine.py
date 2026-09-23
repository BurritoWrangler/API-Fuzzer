"""Phase 2: Differential authorization orchestration engine.

Orchestrates multi-identity baselines, identifier discovery, and BOLA/BFLA/BOPLA
probes using the pure helpers in ``authorization_checks.py`` and the response
comparison primitives in ``comparators.py``. The engine is opt-in and operates
against a provided session; it does not modify the legacy ``run_scan`` loop.
"""

from __future__ import annotations

import copy
import json as jsonlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import requests

from analyzer import Finding
from authorization_checks import (
    AuthorizationEvidence,
    AuthorizationMutation,
    IdentifierCandidate,
    Observation,
    PropertyCandidate,
    derive_property_candidates,
    discover_identifiers,
    evaluate_object_access,
    marker_value_for_property,
    plan_identifier_mutations,
)
from id_enrichment import enrich_candidates
from models import AuthProfile, SafetyLevel
from request_builder import build_encoded_url
from spec_parser import Endpoint


@dataclass
class AuthzConfig:
    profiles: List[AuthProfile] = field(default_factory=list)
    owner_profile: str = ""
    attacker_profile: str = ""
    ignored_json_paths: List[str] = field(default_factory=list)
    max_bola_probes: int = 50
    max_bopla_probes: int = 20
    enable_bola: bool = True
    enable_bfla: bool = True
    enable_bopla: bool = True
    enable_write_probes: bool = False  # state-changing probes default off


@dataclass
class AuthzFinding:
    category: str  # bola | bfla | bopla
    severity: str
    confidence: str
    title: str
    endpoint: str
    method: str
    parameter: str
    evidence: str
    auth_profile: str
    owasp_api: str
    cwe: str
    request_url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    status_code: int = 0


def _profile_headers(profile: Optional[AuthProfile]) -> Dict[str, str]:
    if profile is None:
        return {}
    return dict(profile.headers)


def _make_observation(resp: requests.Response, profile_name: str) -> Observation:
    return Observation(
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=resp.text or "",
        profile=profile_name,
    )


def _send_profiled(
    session: requests.Session,
    endpoint: Endpoint,
    base_url: str,
    profile: Optional[AuthProfile],
    timeout: float,
    *,
    method_override: Optional[str] = None,
    path_override: Optional[str] = None,
    body_override: Optional[Any] = None,
    param_overrides: Optional[Dict[str, Any]] = None,
) -> Optional[requests.Response]:
    """Send a request as a specific identity, returning the raw response.

    ``param_overrides`` maps parameter names to replacement values and is
    applied to whichever location the named parameter occupies (path, query,
    header, or top-level body field). This is how BOLA probes substitute a
    learned object identifier into the attacker's request.
    """
    method = (method_override or endpoint.method).upper()
    overrides = param_overrides or {}
    param_locations = {p.name: p.location for p in endpoint.parameters}

    path_params = {
        p.name: p.example if p.example is not None else 1
        for p in endpoint.parameters
        if p.location == "path"
    }
    path = path_override or endpoint.path
    query = {p.name: p.example if p.example is not None else "test" for p in endpoint.parameters if p.location == "query"}
    headers = _profile_headers(profile)
    for p in endpoint.parameters:
        if p.location == "header":
            headers[p.name] = str(p.example if p.example is not None else "test")

    # Apply overrides by parameter location.
    body_override_applied = body_override is not None
    for name, value in overrides.items():
        location = param_locations.get(name)
        if location == "path":
            path_params[name] = value
        elif location == "query":
            query[name] = value
        elif location == "header":
            headers[name] = str(value)
        elif location == "body" and not body_override_applied:
            # Apply to a copied body below; mark so body_override wins if both given.
            body_override_applied = False  # handled via _body_patch below

    url = build_encoded_url(base_url, path, path_params, query)
    try:
        kwargs: Dict[str, Any] = {
            "headers": headers,
            "params": query or None,
            "timeout": timeout,
            "allow_redirects": False,
        }
        body = body_override if body_override is not None else (
            copy.deepcopy(endpoint.body_example) if endpoint.has_body else None
        )
        if body is not None and not body_override_applied:
            # Apply body-located overrides to the copied body.
            for name, value in overrides.items():
                if param_locations.get(name) == "body" and isinstance(body, dict):
                    body[name] = value
        if body is not None:
            kwargs["json"] = body
        return session.request(method, url, **kwargs)
    except requests.exceptions.RequestException:
        return None


def _parse_json(body: Optional[str]) -> Any:
    if not body:
        return None
    try:
        return jsonlib.loads(body)
    except (jsonlib.JSONDecodeError, TypeError):
        return None


def run_bola_probes(
    endpoints: Sequence[Endpoint],
    base_url: str,
    session: requests.Session,
    cfg: AuthzConfig,
    timeout: float,
) -> List[AuthzFinding]:
    """Run BOLA (Broken Object Level Authorization) probes.

    For each endpoint with identifier-shaped parameters, discovers object IDs
    from the owner profile's responses and substitutes them into the attacker
    profile's request. Only flags when the attacker receives materially
    equivalent data and anonymous access is not equivalent.
    """
    findings: List[AuthzFinding] = []
    if not cfg.enable_bola or len(cfg.profiles) < 2:
        return findings

    owner = next((p for p in cfg.profiles if p.name == cfg.owner_profile), None)
    attacker = next((p for p in cfg.profiles if p.name == cfg.attacker_profile), None)
    anonymous = next((p for p in cfg.profiles if p.is_anonymous), None)
    if owner is None or attacker is None:
        return findings

    probe_count = 0
    for ep in endpoints:
        if probe_count >= cfg.max_bola_probes:
            break
        # Gather owner baseline and discover identifiers from the response.
        owner_resp = _send_profiled(session, ep, base_url, owner, timeout)
        if owner_resp is None or not (200 <= owner_resp.status_code < 300):
            continue
        owner_json = _parse_json(owner_resp.text)
        if owner_json is None:
            continue

        candidates = discover_identifiers(
            owner_json,
            source_profile=owner.name,
            source_endpoint=f"{ep.method} {ep.path}",
        )
        if not candidates:
            continue

        # ID enrichment: decode base64/hex-encoded integers and detect UUIDv1
        # identifiers so obfuscated IDs can still be enumerated.
        candidates = enrich_candidates(candidates)

        mutations = plan_identifier_mutations(ep, candidates, target_profile=attacker.name)
        if not mutations:
            continue

        # Anonymous baseline for this endpoint.
        anon_resp = _send_profiled(session, ep, base_url, anonymous, timeout)
        anon_obs = (
            _make_observation(anon_resp, anonymous.name)
            if anon_resp is not None
            else Observation(status_code=0, headers={}, body="", profile=anonymous.name)
        )
        owner_obs = _make_observation(owner_resp, owner.name)

        for mutation in mutations:
            if probe_count >= cfg.max_bola_probes:
                break
            probe_count += 1
            # Send attacker request with the owner's identifier substituted
            # into the parameter location the mutation targets. Previously the
            # mutation was computed but never applied, so the probe compared
            # the owner's response against the attacker's *benign* response.
            attacker_resp = _send_profiled(
                session, ep, base_url, attacker, timeout,
                param_overrides={mutation.parameter: mutation.value},
            )
            if attacker_resp is None:
                continue
            attacker_obs = _make_observation(attacker_resp, attacker.name)
            evidence = evaluate_object_access(
                owner=owner_obs,
                attacker=attacker_obs,
                anonymous=anon_obs if anon_resp is not None else None,
                ignored_json_paths=cfg.ignored_json_paths,
            )
            if evidence.vulnerable:
                findings.append(AuthzFinding(
                    category="bola",
                    severity="high",
                    confidence=evidence.confidence,
                    title="Broken Object Level Authorization: cross-profile object access",
                    endpoint=ep.path,
                    method=ep.method,
                    parameter=mutation.parameter,
                    evidence=evidence.reason,
                    auth_profile=attacker.name,
                    owasp_api="API1:2023",
                    cwe="CWE-639",
                    request_url=owner_resp.url,
                    request_headers=_profile_headers(attacker),
                    response_body=attacker_obs.body,
                    status_code=attacker_obs.status_code,
                ))
    return findings


def run_bfla_probes(
    endpoints: Sequence[Endpoint],
    base_url: str,
    session: requests.Session,
    cfg: AuthzConfig,
    timeout: float,
) -> List[AuthzFinding]:
    """Run BFLA (Broken Function Level Authorization) probes.

    Tests whether a lower-privilege profile can invoke operations that should
    be restricted to a higher-privilege profile, and whether alternate HTTP
    methods bypass function-level authorization.
    """
    findings: List[AuthzFinding] = []
    if not cfg.enable_bfla or len(cfg.profiles) < 2:
        return findings

    admin = next((p for p in cfg.profiles if "admin" in p.expected_role.lower()), None)
    normal = next((p for p in cfg.profiles if p.name != (admin.name if admin else "")), None)
    anonymous = next((p for p in cfg.profiles if p.is_anonymous), None)
    if admin is None or normal is None:
        return findings

    probe_count = 0
    for ep in endpoints:
        if probe_count >= cfg.max_bola_probes:
            break
        probe_count += 1

        # Admin baseline: does admin get 2xx?
        admin_resp = _send_profiled(session, ep, base_url, admin, timeout)
        if admin_resp is None or not (200 <= admin_resp.status_code < 300):
            continue

        # Normal user: should NOT get 2xx if this is admin-only.
        normal_resp = _send_profiled(session, ep, base_url, normal, timeout)
        if normal_resp is not None and 200 <= normal_resp.status_code < 300:
            # Check that anonymous doesn't also get 2xx (public endpoint).
            anon_resp = _send_profiled(session, ep, base_url, anonymous, timeout)
            anon_status = anon_resp.status_code if anon_resp else 0
            if not (200 <= anon_status < 300):
                findings.append(AuthzFinding(
                    category="bfla",
                    severity="high",
                    confidence="strong",
                    title="Broken Function Level Authorization: privileged operation accessible by lower role",
                    endpoint=ep.path,
                    method=ep.method,
                    parameter="<n/a>",
                    evidence=(
                        f"Admin profile '{admin.name}' received HTTP {admin_resp.status_code}; "
                        f"normal profile '{normal.name}' also received HTTP {normal_resp.status_code}; "
                        f"anonymous received HTTP {anon_status}. Function-level access control missing."
                    ),
                    auth_profile=normal.name,
                    owasp_api="API5:2023",
                    cwe="CWE-285",
                    request_url=normal_resp.url,
                    request_headers=_profile_headers(normal),
                    response_body=normal_resp.text,
                    status_code=normal_resp.status_code,
                ))

        # Method override test: try alternate methods on the same path.
        if ep.method.upper() == "GET" and cfg.enable_write_probes:
            for alt_method in ("POST", "PUT", "PATCH", "DELETE"):
                alt_resp = _send_profiled(
                    session, ep, base_url, normal, timeout, method_override=alt_method,
                )
                if alt_resp is not None and 200 <= alt_resp.status_code < 300:
                    findings.append(AuthzFinding(
                        category="bfla",
                        severity="medium",
                        confidence="tentative",
                        title=f"Broken Function Level Authorization: {alt_method} on {ep.path} accessible",
                        endpoint=ep.path,
                        method=alt_method,
                        parameter="<n/a>",
                        evidence=(
                            f"Profile '{normal.name}' received HTTP {alt_resp.status_code} "
                            f"for undocumented {alt_method} on {ep.path}."
                        ),
                        auth_profile=normal.name,
                        owasp_api="API5:2023",
                        cwe="CWE-285",
                        request_url=alt_resp.url,
                        request_headers=_profile_headers(normal),
                        response_body=alt_resp.text,
                        status_code=alt_resp.status_code,
                    ))
    return findings


def run_bopla_probes(
    endpoints: Sequence[Endpoint],
    base_url: str,
    session: requests.Session,
    cfg: AuthzConfig,
    timeout: float,
) -> List[AuthzFinding]:
    """Run BOPLA (Broken Object Property Level Authorization) probes.

    Derives sensitive property candidates from response schemas and tests
    whether they can be modified via mass-assignment-style writes.
    Write probes are disabled by default (enable_write_probes=False).
    """
    findings: List[AuthzFinding] = []
    if not cfg.enable_bopla:
        return findings

    owner = next((p for p in cfg.profiles if p.name == cfg.owner_profile), cfg.profiles[0] if cfg.profiles else None)
    if owner is None:
        return findings

    probe_count = 0
    for ep in endpoints:
        if probe_count >= cfg.max_bopla_probes:
            break
        candidates = derive_property_candidates(ep)
        if not candidates:
            continue

        # Read-only check: does the response expose sensitive properties?
        owner_resp = _send_profiled(session, ep, base_url, owner, timeout)
        if owner_resp is None or not (200 <= owner_resp.status_code < 300):
            continue
        owner_json = _parse_json(owner_resp.text)

        for candidate in candidates:
            if probe_count >= cfg.max_bopla_probes:
                break
            probe_count += 1

            # Check if the sensitive property appears in the response.
            if isinstance(owner_json, dict) and candidate.name in owner_json:
                value = owner_json[candidate.name]
                if value is not None and value != "":
                    findings.append(AuthzFinding(
                        category="bopla",
                        severity="medium",
                        confidence="strong",
                        title=f"Excessive Data Exposure: sensitive property '{candidate.name}' in response",
                        endpoint=ep.path,
                        method=ep.method,
                        parameter=candidate.name,
                        evidence=(
                            f"Response includes '{candidate.name}' ({candidate.reason}). "
                            f"Review whether this property should be exposed to this identity."
                        ),
                        auth_profile=owner.name,
                        owasp_api="API3:2023",
                        cwe="CWE-200",
                        request_url=owner_resp.url,
                        request_headers=_profile_headers(owner),
                        response_body=owner_resp.text,
                        status_code=owner_resp.status_code,
                    ))

            # Write probe: test if the property can be modified (opt-in only).
            if cfg.enable_write_probes and ep.has_body and isinstance(ep.body_example, dict):
                marker = marker_value_for_property(candidate)
                augmented = copy.deepcopy(ep.body_example)
                augmented[candidate.name] = marker
                write_resp = _send_profiled(
                    session, ep, base_url, owner, timeout, body_override=augmented,
                )
                if write_resp is not None and 200 <= write_resp.status_code < 300:
                    write_json = _parse_json(write_resp.text)
                    if isinstance(write_json, dict) and str(marker) in str(write_json.get(candidate.name, "")):
                        findings.append(AuthzFinding(
                            category="bopla",
                            severity="high",
                            confidence="strong",
                            title=f"Mass Assignment: sensitive property '{candidate.name}' is writable",
                            endpoint=ep.path,
                            method=ep.method,
                            parameter=candidate.name,
                            evidence=(
                                f"Setting '{candidate.name}' to a marker value was accepted "
                                f"(HTTP {write_resp.status_code}) and reflected in the response."
                            ),
                            auth_profile=owner.name,
                            owasp_api="API3:2023",
                            cwe="CWE-915",
                            request_url=write_resp.url,
                            request_headers=_profile_headers(owner),
                            response_body=write_resp.text,
                            status_code=write_resp.status_code,
                        ))
    return findings


def run_authorization_checks(
    endpoints: Sequence[Endpoint],
    base_url: str,
    session: requests.Session,
    cfg: AuthzConfig,
    timeout: float,
) -> List[AuthzFinding]:
    """Run all enabled authorization probes and return findings."""
    findings: List[AuthzFinding] = []
    findings.extend(run_bola_probes(endpoints, base_url, session, cfg, timeout))
    findings.extend(run_bfla_probes(endpoints, base_url, session, cfg, timeout))
    findings.extend(run_bopla_probes(endpoints, base_url, session, cfg, timeout))
    return findings
