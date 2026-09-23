import pytest

from oast import (
    DisabledOASTProvider,
    GenericHttpOASTProvider,
    MemoryOASTProvider,
    OASTDisabled,
)


class FakePollResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakePollSession:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return FakePollResponse(self.payload)


def test_disabled_provider_never_allocates():
    provider = DisabledOASTProvider()

    assert provider.available is False
    with pytest.raises(OASTDisabled):
        provider.allocate("ssrf")


def test_memory_provider_correlates_and_expires():
    now = [100.0]
    provider = MemoryOASTProvider(
        "callbacks.example",
        ttl_seconds=30,
        clock=lambda: now[0],
        token_factory=lambda: "scan123",
    )
    allocation = provider.allocate("blind-ssrf")

    assert allocation.http_url == "https://scan123.callbacks.example/"
    assert allocation.dns_name == "scan123.callbacks.example"
    provider.record_interaction(
        "scan123",
        protocol="DNS",
        remote_address="192.0.2.1",
        metadata={"query_type": "A"},
    )
    interactions = provider.poll(allocation)

    assert len(interactions) == 1
    assert interactions[0].protocol == "dns"
    assert interactions[0].token == allocation.token

    now[0] = 131.0
    assert provider.poll(allocation) == []


def test_memory_provider_ignores_unknown_tokens():
    provider = MemoryOASTProvider(token_factory=lambda: "known")
    allocation = provider.allocate()

    provider.record_interaction("unknown", protocol="http")

    assert provider.poll(allocation) == []


def test_generic_provider_polls_only_matching_token():
    session = FakePollSession(
        {
            "interactions": [
                {
                    "token": "scan123",
                    "protocol": "HTTP",
                    "observed_at": 110.0,
                    "remote_address": "198.51.100.5",
                },
                {"token": "different", "protocol": "dns"},
            ]
        }
    )
    provider = GenericHttpOASTProvider(
        callback_domain="callbacks.example",
        api_base="https://oast-api.example/v1",
        api_token="test-token",
        session=session,
        clock=lambda: 100.0,
        token_factory=lambda: "scan123",
    )
    allocation = provider.allocate("blind-command")

    interactions = provider.poll(allocation)

    assert len(interactions) == 1
    assert interactions[0].protocol == "http"
    call = session.calls[0]
    assert call["url"] == "https://oast-api.example/v1/interactions"
    assert call["params"] == {"token": "scan123"}
    assert call["headers"]["Authorization"] == "Bearer test-token"
    assert call["allow_redirects"] is False


@pytest.mark.parametrize(
    "domain",
    [
        "https://callbacks.example",
        "callbacks.example/path",
        "-bad.example",
        "bad label.example",
    ],
)
def test_invalid_callback_domains_are_rejected(domain):
    with pytest.raises(ValueError):
        MemoryOASTProvider(domain)


def test_invalid_poll_api_url_is_rejected():
    with pytest.raises(ValueError):
        GenericHttpOASTProvider(
            callback_domain="callbacks.example",
            api_base="file:///tmp/oast",
        )
