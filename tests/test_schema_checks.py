import schema_checks

from spec_parser import Endpoint, Parameter
from tests.fakes import FakeResponse, FakeSession


def test_schema_checks_detect_accepted_query_violations():
    endpoint = Endpoint(
        path="/items",
        method="GET",
        parameters=[
            Parameter(
                name="count",
                location="query",
                required=True,
                schema_type="integer",
                enum=[1, 2],
                maximum=10,
            )
        ],
    )
    session = FakeSession(
        lambda method, url, kwargs: FakeResponse(
            200,
            '{"accepted":true}',
            {"Content-Type": "application/json"},
        )
    )

    findings = schema_checks.run_schema_checks(
        endpoint=endpoint,
        base_url="https://api.example",
        session=session,
        timeout=1.0,
        auth_header="Bearer test",
    )

    titles = {finding.title for finding in findings}
    assert "Required query parameter 'count' silently accepted as missing" in titles
    assert "Type mismatch silently accepted for 'count'" in titles
    assert "Enum violation silently accepted for 'count'" in titles
    assert "maximum violation silently accepted for 'count'" in titles
    assert all("Authorization" in finding.request_headers for finding in findings)


def test_schema_path_type_mismatch_uses_substituted_url():
    endpoint = Endpoint(
        path="/users/{user_id}",
        method="GET",
        parameters=[
            Parameter(
                name="user_id",
                location="path",
                required=True,
                schema_type="integer",
            )
        ],
    )
    session = FakeSession(lambda method, url, kwargs: FakeResponse(200, "ok"))

    findings = schema_checks.run_schema_checks(
        endpoint=endpoint,
        base_url="https://api.example",
        session=session,
        timeout=1.0,
        auth_header=None,
    )

    assert len(findings) == 1
    assert findings[0].request_url == "https://api.example/users/not_a_number_apifz"
    assert "{" not in session.calls[0]["url"]


def test_schema_checks_ignore_network_failures():
    class FailingSession:
        def request(self, *args, **kwargs):
            import requests

            raise requests.ConnectionError("offline")

    endpoint = Endpoint(
        path="/items",
        method="GET",
        parameters=[
            Parameter("count", "query", required=True, schema_type="integer")
        ],
    )

    findings = schema_checks.run_schema_checks(
        endpoint=endpoint,
        base_url="https://api.example",
        session=FailingSession(),
        timeout=1.0,
        auth_header=None,
    )

    assert findings == []
