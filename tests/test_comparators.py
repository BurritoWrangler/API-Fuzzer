from comparators import compare_http_responses, json_shape, normalize_json


def test_normalize_json_removes_volatile_and_configured_paths():
    value = {
        "id": 7,
        "timestamp": "2026-08-24T10:00:00Z",
        "profile": {
            "name": "Alice",
            "secret": "remove-me",
        },
        "items": [
            {"request_id": "one", "value": 1},
            {"request_id": "two", "value": 2},
        ],
    }

    normalized = normalize_json(value, ignored_paths=["profile.secret"])

    assert normalized == {
        "id": 7,
        "items": [{"value": 1}, {"value": 2}],
        "profile": {"name": "Alice"},
    }


def test_wildcard_ignored_paths_match_array_positions():
    value = {"items": [{"token": "a", "id": 1}, {"token": "b", "id": 2}]}

    normalized = normalize_json(
        value,
        ignored_paths=["items.*.token"],
        volatile_keys=[],
    )

    assert normalized == {"items": [{"id": 1}, {"id": 2}]}


def test_json_shape_preserves_fields_but_not_values():
    first = {"id": 1, "active": True, "tags": ["a", "b"]}
    second = {"id": 99, "active": False, "tags": ["x"]}

    assert json_shape(first) == json_shape(second)


def test_equivalent_json_ignores_volatile_fields_and_key_order():
    comparison = compare_http_responses(
        baseline_status=200,
        baseline_headers={"Content-Type": "application/json"},
        baseline_body='{"id":7,"name":"Alice","request_id":"one"}',
        candidate_status=200,
        candidate_headers={"content-type": "application/json; charset=utf-8"},
        candidate_body='{"request_id":"two","name":"Alice","id":7}',
    )

    assert comparison.equivalent is True
    assert comparison.body_equal is True
    assert comparison.similarity == 1.0


def test_material_json_change_is_not_equivalent():
    comparison = compare_http_responses(
        baseline_status=200,
        baseline_headers={"Content-Type": "application/json"},
        baseline_body='{"id":7,"owner":"user-a","balance":100}',
        candidate_status=200,
        candidate_headers={"Content-Type": "application/json"},
        candidate_body='{"id":8,"owner":"user-b","balance":900}',
    )

    assert comparison.equivalent is False
    assert comparison.shape_equal is True
    assert "similarity" in comparison.summary


def test_text_normalization_removes_uuid_and_timestamp_noise():
    comparison = compare_http_responses(
        baseline_status=403,
        baseline_headers={"Content-Type": "text/plain"},
        baseline_body=(
            "Denied 123e4567-e89b-12d3-a456-426614174000 "
            "at 2026-08-24T10:00:00Z"
        ),
        candidate_status=403,
        candidate_headers={"Content-Type": "text/plain"},
        candidate_body=(
            "Denied 123e4567-e89b-12d3-a456-426614174001 "
            "at 2026-08-24T11:00:00Z"
        ),
    )

    assert comparison.equivalent is True


def test_status_change_prevents_equivalence():
    comparison = compare_http_responses(
        baseline_status=401,
        baseline_headers={"Content-Type": "application/json"},
        baseline_body='{"error":"denied"}',
        candidate_status=200,
        candidate_headers={"Content-Type": "application/json"},
        candidate_body='{"error":"denied"}',
    )

    assert comparison.equivalent is False
    assert comparison.status_equal is False
