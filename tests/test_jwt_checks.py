import json

import jwt_checks

from tests.fakes import FakeResponse, FakeSession


def test_parse_bearer_jwt_round_trips_header_and_payload():
    token = jwt_checks._build_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "user-1", "exp": 2_000_000_000},
        b"signature",
    )

    parsed = jwt_checks.parse_bearer_jwt(f"Authorization: Bearer {token}")

    assert parsed is not None
    header, payload, signature, raw = parsed
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert payload["sub"] == "user-1"
    assert signature == b"signature"
    assert raw == token


def test_parse_bearer_jwt_rejects_non_jwt_values():
    assert jwt_checks.parse_bearer_jwt(None) is None
    assert jwt_checks.parse_bearer_jwt("Bearer opaque-token") is None
    assert jwt_checks.parse_bearer_jwt("Bearer a.b.c") is None


def test_jwt_attack_records_alg_none_acceptance_only():
    original = jwt_checks._build_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "user-1", "exp": 2_000_000_000},
        b"signature",
    )

    def responder(method, url, kwargs):
        headers = kwargs.get("headers") or {}
        auth = headers.get("Authorization", "")
        if not auth:
            # Anonymous baseline request — return 401 so endpoint is "protected"
            return FakeResponse(401, '{"error":"unauthorized"}')
        token = auth.split(" ", 1)[1]
        encoded_header = token.split(".", 1)[0]
        header = json.loads(jwt_checks._b64url_decode(encoded_header))
        if header["alg"] == "none":
            return FakeResponse(200, '{"ok":true}')
        return FakeResponse(401, '{"error":"invalid token"}')

    findings = jwt_checks.run_jwt_attacks(
        auth_header=f"Bearer {original}",
        target_url="https://api.example/profile",
        target_method="GET",
        target_endpoint_path="/profile",
        baseline_status=200,
        session=FakeSession(responder),
        timeout=1.0,
    )

    alg_none = [f for f in findings if "alg:none" in f.title.lower()]
    assert len(alg_none) >= 1
    assert alg_none[0].severity == "critical"


def test_jwt_attacks_do_nothing_without_bearer_jwt():
    assert jwt_checks.run_jwt_attacks(
        auth_header="Basic dXNlcjpwYXNz",
        target_url="https://api.example/profile",
        target_method="GET",
        target_endpoint_path="/profile",
        baseline_status=401,
        session=FakeSession(),
        timeout=1.0,
    ) == []
