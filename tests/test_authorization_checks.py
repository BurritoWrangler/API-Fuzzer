from authorization_checks import (
    Observation,
    derive_property_candidates,
    discover_identifiers,
    evaluate_object_access,
    marker_value_for_property,
    plan_identifier_mutations,
)
from spec_parser import (
    Endpoint,
    MediaType,
    Parameter,
    RequestBody,
    Response,
)


JSON_HEADERS = {"Content-Type": "application/json"}


def test_identifier_discovery_tracks_source_and_ownership():
    identifiers = discover_identifiers(
        {
            "request_id": "noise",
            "users": [
                {"id": 7, "owner_id": "user-a"},
                {"id": 8, "owner_id": "user-b"},
            ],
        },
        source_profile="user-a",
        source_endpoint="/users",
    )

    assert {(item.field_name, item.value) for item in identifiers} == {
        ("id", 7),
        ("id", 8),
        ("owner_id", "user-a"),
        ("owner_id", "user-b"),
    }
    assert all(item.source_profile == "user-a" for item in identifiers)
    assert all(item.field_name != "request_id" for item in identifiers)
    assert any(item.ownership_hint for item in identifiers)


def test_identifier_discovery_is_bounded_and_deduplicated():
    identifiers = discover_identifiers(
        [{"id": index} for index in range(20)] + [{"id": 1}],
        source_profile="owner",
        source_endpoint="/items",
        max_candidates=5,
    )

    assert len(identifiers) == 5


def test_identifier_candidates_map_to_compatible_parameters():
    endpoint = Endpoint(
        "/users/{user_id}",
        "GET",
        parameters=[
            Parameter("user_id", "path"),
            Parameter("request_id", "query"),
        ],
    )
    identifiers = discover_identifiers(
        {"user_id": 42, "order_id": 99},
        source_profile="user-a",
        source_endpoint="/me",
    )

    mutations = plan_identifier_mutations(
        endpoint,
        identifiers,
        target_profile="user-b",
    )

    assert [(item.parameter, item.value) for item in mutations] == [
        ("user_id", 42)
    ]


def test_bola_evidence_requires_owner_equivalence_and_non_public_access():
    owner = Observation(200, JSON_HEADERS, '{"id":7,"name":"Alice"}', "user-a")
    attacker = Observation(200, JSON_HEADERS, '{"name":"Alice","id":7}', "user-b")
    anonymous = Observation(401, JSON_HEADERS, '{"error":"denied"}', "anonymous")

    evidence = evaluate_object_access(
        owner=owner,
        attacker=attacker,
        anonymous=anonymous,
    )

    assert evidence.vulnerable is True
    assert evidence.confidence == "strong"
    assert evidence.owner_vs_attacker.equivalent is True


def test_public_equivalent_response_suppresses_bola():
    owner = Observation(200, JSON_HEADERS, '{"id":7,"name":"Alice"}', "user-a")
    attacker = Observation(200, JSON_HEADERS, '{"id":7,"name":"Alice"}', "user-b")
    anonymous = Observation(200, JSON_HEADERS, '{"id":7,"name":"Alice"}', "anonymous")

    evidence = evaluate_object_access(
        owner=owner,
        attacker=attacker,
        anonymous=anonymous,
    )

    assert evidence.vulnerable is False


def test_property_candidates_derive_from_response_contract():
    endpoint = Endpoint(
        "/accounts/{id}",
        "PATCH",
        request_body=RequestBody(
            content={
                "application/json": MediaType(
                    "application/json",
                    schema={
                        "type": "object",
                        "properties": {"display_name": {"type": "string"}},
                    },
                )
            }
        ),
        responses={
            "200": Response(
                "200",
                content={
                    "application/json": MediaType(
                        "application/json",
                        schema={
                            "type": "object",
                            "properties": {
                                "display_name": {"type": "string"},
                                "is_admin": {
                                    "type": "boolean",
                                    "readOnly": True,
                                },
                                "balance": {"type": "number"},
                            },
                        },
                    )
                },
            )
        },
    )

    candidates = derive_property_candidates(endpoint)
    by_name = {candidate.name: candidate for candidate in candidates}

    assert "display_name" not in by_name
    assert "is_admin" in by_name
    assert "readOnly" in by_name["is_admin"].reason
    assert "balance" in by_name


def test_property_marker_values_preserve_declared_types():
    endpoint = Endpoint(
        "/accounts",
        "PATCH",
        responses={
            "200": Response(
                "200",
                content={
                    "application/json": MediaType(
                        "application/json",
                        schema={
                            "type": "object",
                            "properties": {
                                "is_admin": {"type": "boolean", "readOnly": True},
                                "roles": {"type": "array", "readOnly": True},
                            },
                        },
                    )
                },
            )
        },
    )
    candidates = {item.name: item for item in derive_property_candidates(endpoint)}

    assert marker_value_for_property(candidates["is_admin"]) is True
    assert marker_value_for_property(candidates["roles"]) == ["apifuzz-marker"]
