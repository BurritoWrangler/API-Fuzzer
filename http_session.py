"""HTTP session with configurable User-Agent.

apifuzz uses this to:
  * pin a static User-Agent (default / preset / custom) for the whole scan, OR
  * rotate a random browser-shaped User-Agent on every request for light
    obfuscation against trivial WAFs and rate-limit fingerprinting.

The class also stamps the chosen User-Agent into the caller's per-request
headers dict so the value ends up in every Finding's `request_headers` field
(and therefore the v1.5 raw HTTP request as well).
"""

from __future__ import annotations

import random
from typing import Dict, Optional

import requests


# Realistic browser UA strings. Updated to current real-world versions so the
# target sees a plausible API client. Update freely; the only requirement is
# that they look like a real browser so basic UA filtering doesn't drop the scan.
_CHROME_148 = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

UA_PRESETS: Dict[str, str] = {
    # "Default" was previously the literal string "apifuzz" which made API
    # servers reject the scan on UA filters and made every raw_request in the
    # dashboard look unconfigured. Default now ships a realistic Chrome UA.
    "default": _CHROME_148,
    "chrome": _CHROME_148,
    "firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
    "curl": "curl/8.10.1",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "ios-safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) "
                  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "android-chrome": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
}

# UI label for each preset key, displayed in the form's <select>.
UA_PRESET_LABELS: Dict[str, str] = {
    "default": "Default (Chrome 148, Windows)",
    "chrome": "Chrome 148 (Windows)",
    "firefox": "Firefox 131 (Linux)",
    "safari": "Safari 17 (macOS)",
    "edge": "Edge 148 (Windows)",
    "curl": "curl 8.10",
    "googlebot": "Googlebot",
    "ios-safari": "Safari (iOS)",
    "android-chrome": "Chrome (Android)",
}

# Pool used when `mode == "random"`. Drawn fresh per request for light
# obfuscation. Includes every browser-shaped preset above plus a handful of
# additional realistic UAs for variance.
RANDOM_UAS = [
    UA_PRESETS["chrome"],
    UA_PRESETS["firefox"],
    UA_PRESETS["safari"],
    UA_PRESETS["edge"],
    UA_PRESETS["ios-safari"],
    UA_PRESETS["android-chrome"],
    "Mozilla/5.0 (Windows NT 10.0; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]


def resolve_user_agent(mode: str, custom: str = "") -> str:
    """Return the User-Agent string for static modes; for `random`, returns a
    representative seed value (the actual UA is chosen per request).
    """
    mode = (mode or "default").lower()
    if mode == "custom":
        return (custom or "").strip() or UA_PRESETS["default"]
    if mode == "random":
        return RANDOM_UAS[0]  # display seed; rotation happens per request
    return UA_PRESETS.get(mode, UA_PRESETS["default"])


class UASession(requests.Session):
    """requests.Session that enforces a per-scan User-Agent policy.

    Modes:
      * `default` / preset name (`chrome`, `firefox`, ...) / `custom` \u2014 stamps
        a fixed User-Agent into `session.headers` AND into every per-request
        `headers` dict the caller passes in (so it lands in the recorded
        Finding's `request_headers` and the raw_request blob).
      * `random` \u2014 picks a fresh UA from RANDOM_UAS for every outbound
        request and stamps it into the caller's headers dict.
    """

    def __init__(self, mode: str = "default", custom_ua: str = ""):
        super().__init__()
        self.ua_mode = (mode or "default").lower()
        self.custom_ua = (custom_ua or "").strip()
        self._static_ua = self._initial_static_ua()
        # Always pin the session-level UA so requests.Session.merge_setting()
        # will inject it into every outbound request.
        initial_ua = self._static_ua or self._pick_ua()
        self.headers["User-Agent"] = initial_ua
        # Push the active UA into analyzer's raw_request fallback so every
        # Finding's displayed "Raw HTTP request" pane shows the actual UA
        # the server saw, not the old hardcoded "apifuzz".
        try:
            from analyzer import set_default_user_agent
            set_default_user_agent(initial_ua)
        except Exception:  # pragma: no cover - analyzer is always importable
            pass

    def _initial_static_ua(self) -> Optional[str]:
        if self.ua_mode == "custom":
            return self.custom_ua or UA_PRESETS["default"]
        if self.ua_mode == "random":
            return None  # set per-request
        return UA_PRESETS.get(self.ua_mode, UA_PRESETS["default"])

    def _pick_ua(self) -> str:
        if self.ua_mode == "random":
            return random.choice(RANDOM_UAS)
        return self._static_ua or UA_PRESETS["default"]

    def request(self, method, url, **kwargs):  # type: ignore[override]
        ua = self._pick_ua()
        # Keep the session-level header in sync so plain merging works (this
        # matters for random mode where each call picks a fresh UA).
        self.headers["User-Agent"] = ua
        # Also keep the analyzer's fallback in sync so raw_request panes for
        # findings whose request_headers don't include UA still display
        # something realistic instead of "apifuzz".
        try:
            from analyzer import set_default_user_agent
            set_default_user_agent(ua)
        except Exception:  # pragma: no cover
            pass
        headers = kwargs.get("headers")
        if headers is None:
            kwargs["headers"] = {"User-Agent": ua}
        else:
            # Always overwrite per-call headers so the caller's local dict
            # (which downstream Findings record as request_headers) reflects
            # the UA actually transmitted on the wire.
            headers["User-Agent"] = ua
        return super().request(method, url, **kwargs)
