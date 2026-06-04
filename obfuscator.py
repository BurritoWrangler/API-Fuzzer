"""Payload obfuscation for WAF evasion (Cloudflare, AWS WAF, ModSecurity, ...).

Modes:
    off        - no transformation. Payloads sent as authored.
    basic      - percent-encode every byte that's not unreserved.
    aggressive - apply a stack of transforms tuned per payload category
                 (case randomisation, inline SQL comments, IFS substitution,
                 HTML entity escaping, etc.).
    random     - pick a fresh transform per request from the category's
                 aggressive set plus the generic encoders.

API: `obfuscate(payload, category, mode)` returns the on-the-wire string.
The fuzzer records this exact string as the Finding's payload.
"""

from __future__ import annotations

import random
import re
import urllib.parse
from typing import Callable, Dict, List


MODE_OFF = "off"
MODE_BASIC = "basic"
MODE_AGGRESSIVE = "aggressive"
MODE_RANDOM = "random"
MODES = (MODE_OFF, MODE_BASIC, MODE_AGGRESSIVE, MODE_RANDOM)

MODE_LABELS: Dict[str, str] = {
    MODE_OFF: "Off (send as-is)",
    MODE_BASIC: "Basic (URL-encode every reserved byte)",
    MODE_AGGRESSIVE: "Aggressive (per-category WAF-evasion stack)",
    MODE_RANDOM: "Random (rotate transforms per request)",
}


# ---------------------------------------------------------------------------
# Atomic transforms
# ---------------------------------------------------------------------------

def url_encode(payload: str) -> str:
    """Percent-encode every byte that isn't unreserved per RFC 3986."""
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Percent-encode the URL-encoded form. Defeats decode-once WAFs."""
    return url_encode(url_encode(payload))


def random_case(payload: str) -> str:
    """Randomly upper/lowercase ASCII letters. Bypasses case-sensitive regex."""
    out = []
    for c in payload:
        if c.isalpha() and random.random() < 0.5:
            out.append(c.swapcase())
        else:
            out.append(c)
    return "".join(out)


_SQL_KEYWORDS = [
    "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
    "AND", "OR", "DROP", "TABLE", "INTO", "VALUES", "EXEC", "EXECUTE",
    "SLEEP", "WAITFOR", "BENCHMARK", "CONCAT", "CONVERT", "EXTRACTVALUE",
]


def sql_inline_comments(payload: str) -> str:
    """Split SQL keywords with /**/ inline comments and replace spaces.

    UNION SELECT -> UN/**/ION/**/SE/**/LECT. Defeats simple regex while still
    parsing as valid SQL on MySQL, PostgreSQL, MSSQL, Oracle.
    """
    out = payload
    for kw in _SQL_KEYWORDS:
        pattern = re.compile(r"\b" + kw + r"\b", re.IGNORECASE)

        def split(m):
            w = m.group(0)
            mid = len(w) // 2
            return w[:mid] + "/**/" + w[mid:]

        out = pattern.sub(split, out)
    out = out.replace(" ", "/**/")
    return out


def html_decimal_entities(payload: str) -> str:
    """Encode every char as &#N; decimal HTML entity (defeats <script> regex)."""
    return "".join("&#" + str(ord(c)) + ";" for c in payload)


def html_hex_entities(payload: str) -> str:
    """Encode every char as &#xNN; hex HTML entity."""
    return "".join("&#x" + format(ord(c), "x") + ";" for c in payload)


def xss_mixed_case_tag(payload: str) -> str:
    """Randomise the case of the first HTML tag (e.g. <ScRiPt>)."""
    def cb(m):
        return "<" + random_case(m.group(1))
    return re.sub(r"<([A-Za-z]+)", cb, payload, count=1)


def shell_ifs_obfuscate(payload: str) -> str:
    """Replace spaces with ${IFS} -- bash and most POSIX shells still split."""
    return payload.replace(" ", "${IFS}")


def shell_var_expansion(payload: str) -> str:
    """Insert empty ${x} between command bytes (id -> i${x}d).

    Defeats regex on literal `id`/`cat`/`whoami`; shell collapses the empty
    variable so the command still executes.
    """
    chars = list(payload)
    if len(chars) < 2:
        return payload
    pos = random.randint(1, len(chars) - 1)
    chars.insert(pos, "${x}")
    return "".join(chars)


def path_url_encode_slashes(payload: str) -> str:
    """URL-encode only `/` and `\\`. Defeats ../../ regex without breaking dots."""
    return payload.replace("/", "%2f").replace("\\", "%5c")


def path_double_encode_slashes(payload: str) -> str:
    """Double-URL-encode `/` and `\\` for path traversal evasion.

    A single pass gives `..%2f..%2f..%2fetc%2fpasswd`. To *double*-encode
    we then percent-encode the `%` characters so they become `%25`, yielding
    `..%252f..%252f..%252fetc%252fpasswd`. Re-running the slash-replace alone
    does nothing on the second pass since the slashes are already gone.
    """
    single = path_url_encode_slashes(payload)
    return single.replace("%", "%25")


# ---------------------------------------------------------------------------
# Per-category dispatch
# ---------------------------------------------------------------------------

def _aggressive_stack(category: str) -> List[Callable[[str], str]]:
    """Return the ordered transform stack for `aggressive` mode."""
    if category == "sql_injection":
        return [sql_inline_comments, random_case]
    if category == "xss":
        return [xss_mixed_case_tag]
    if category == "command_injection":
        return [shell_var_expansion, shell_ifs_obfuscate]
    if category == "path_traversal":
        return [path_double_encode_slashes]
    if category == "nosql_injection":
        return [url_encode]
    if category in ("ldap_injection", "xpath_injection"):
        return [url_encode]
    if category == "open_redirect":
        return [random_case]
    return [url_encode]


def _random_stack(category: str) -> List[Callable[[str], str]]:
    """All transforms available for `random` mode for the given category."""
    base = list(_aggressive_stack(category))
    if category == "sql_injection":
        extras = [url_encode, double_url_encode, random_case, sql_inline_comments]
    elif category == "xss":
        extras = [url_encode, double_url_encode, html_decimal_entities,
                  html_hex_entities, xss_mixed_case_tag]
    elif category == "command_injection":
        extras = [url_encode, double_url_encode, shell_ifs_obfuscate,
                  shell_var_expansion]
    elif category == "path_traversal":
        extras = [url_encode, double_url_encode,
                  path_url_encode_slashes, path_double_encode_slashes]
    else:
        extras = [url_encode, double_url_encode]
    seen = set()
    out = []
    for fn in base + extras:
        if fn not in seen:
            seen.add(fn)
            out.append(fn)
    return out


def obfuscate(payload: str, category: str, mode: str) -> str:
    """Apply the chosen obfuscation policy to `payload`."""
    if not payload:
        return payload
    mode = (mode or MODE_OFF).lower()
    if mode == MODE_OFF:
        return payload
    if mode == MODE_BASIC:
        try:
            return url_encode(payload)
        except Exception:
            return payload
    if mode == MODE_AGGRESSIVE:
        out = payload
        for fn in _aggressive_stack(category):
            try:
                out = fn(out)
            except Exception:
                pass
        return out
    if mode == MODE_RANDOM:
        choices = _random_stack(category)
        if not choices:
            return payload
        fn = random.choice(choices)
        try:
            return fn(payload)
        except Exception:
            return payload
    return payload
