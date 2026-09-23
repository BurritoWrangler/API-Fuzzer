from response_checks import find_sensitive_json, validate_response_schema


def test_valid_response_matches_contract():
    schema = {
        "type": "object",
        "required": ["id", "name"],
        "additionalProperties": False,
        "properties": {
            "id": {"type": "integer", "minimum": 1},
            "name": {"type": "string", "minLength": 1},
            "roles": {
                "type": "array",
                "maxItems": 3,
                "items": {"type": "string"},
            },
        },
    }

    assert validate_response_schema(
        {"id": 7, "name": "Alice", "roles": ["user"]},
        schema,
    ) == []


def test_contract_reports_precise_nested_issues():
    schema = {
        "type": "object",
        "required": ["id", "profile"],
        "additionalProperties": False,
        "properties": {
            "id": {"type": "integer"},
            "profile": {
                "type": "object",
                "required": ["email"],
                "properties": {
                    "email": {"type": "string", "format": "email"},
                },
            },
        },
    }

    issues = validate_response_schema(
        {
            "id": "seven",
            "profile": {"email": "not-an-email"},
            "debug": True,
        },
        schema,
    )

    by_code = {(issue.path, issue.code) for issue in issues}
    assert ("$.id", "type") in by_code
    assert ("$.profile.email", "format") in by_code
    assert ("$.debug", "additional_property") in by_code


def test_contract_validates_array_items_and_limits():
    issues = validate_response_schema(
        [1, "two", 3],
        {
            "type": "array",
            "maxItems": 2,
            "items": {"type": "integer"},
        },
    )

    assert ("$", "maxItems") in {(issue.path, issue.code) for issue in issues}
    assert ("$[1]", "type") in {(issue.path, issue.code) for issue in issues}


def test_nullable_response_is_accepted():
    assert validate_response_schema(
        None,
        {"type": "string", "nullable": True},
    ) == []


def test_one_of_requires_exactly_one_match():
    issues = validate_response_schema(
        1,
        {
            "oneOf": [
                {"type": "integer"},
                {"type": "number"},
            ]
        },
    )

    assert len(issues) == 1
    assert issues[0].code == "oneOf"


def test_sensitive_json_matches_are_always_redacted():
    value = {
        "password": "correct horse battery staple",
        "profile": {"email": "alice@example.com"},
        "config": "postgresql://admin:password@db.internal/app",
        "aws": "AKIAABCDEFGHIJKLMNOP",
    }

    matches = find_sensitive_json(value)
    by_kind = {match.kind: match for match in matches}

    assert "password" in by_kind
    assert "email address" in by_kind
    assert "database connection string" in by_kind
    assert "AWS access key" in by_kind
    assert all("alice@example.com" not in match.redacted_value for match in matches)
    assert all("correct horse" not in match.redacted_value for match in matches)


def test_empty_sensitive_named_fields_are_ignored():
    assert find_sensitive_json(
        {"access_token": "", "secret": None, "password": ""}
    ) == []
