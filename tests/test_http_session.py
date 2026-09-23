import requests

import http_session

from tests.fakes import FakeResponse


def test_static_user_agent_is_stamped_on_each_request(monkeypatch):
    captured = {}

    def fake_request(session, method, url, **kwargs):
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "request", fake_request)
    session = http_session.UASession("custom", "apifuzz-test/1.0")
    headers = {"X-Test": "yes"}

    session.request("GET", "https://api.example/health", headers=headers)

    assert headers["User-Agent"] == "apifuzz-test/1.0"
    assert captured["headers"]["User-Agent"] == "apifuzz-test/1.0"


def test_random_user_agent_rotates_per_request(monkeypatch):
    selected = iter(["ua-one", "ua-two", "ua-three"])
    monkeypatch.setattr(http_session.random, "choice", lambda choices: next(selected))
    monkeypatch.setattr(
        requests.Session,
        "request",
        lambda session, method, url, **kwargs: FakeResponse(),
    )
    session = http_session.UASession("random")
    first_headers = {}
    second_headers = {}

    session.request("GET", "https://api.example/one", headers=first_headers)
    session.request("GET", "https://api.example/two", headers=second_headers)

    assert first_headers["User-Agent"] == "ua-two"
    assert second_headers["User-Agent"] == "ua-three"


def test_unknown_user_agent_mode_uses_default():
    assert http_session.resolve_user_agent("unknown") == http_session.UA_PRESETS["default"]
    assert http_session.resolve_user_agent("custom", "") == http_session.UA_PRESETS["default"]
