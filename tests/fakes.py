from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        text: str = "",
        headers: Optional[Dict[str, str]] = None,
        url: str = "",
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url
        self.raw = None


class FakeSession:
    def __init__(
        self,
        responder: Optional[Callable[[str, str, Dict[str, Any]], FakeResponse]] = None,
    ):
        self.responder = responder or (lambda method, url, kwargs: FakeResponse())
        self.calls: List[Dict[str, Any]] = []
        self.headers: Dict[str, str] = {}

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        call = {"method": method.upper(), "url": url, **kwargs}
        self.calls.append(call)
        return self.responder(method.upper(), url, kwargs)

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.request("POST", url, **kwargs)
