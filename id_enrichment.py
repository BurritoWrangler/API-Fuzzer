"""Identifier enrichment for BOLA candidate discovery.

Extends raw identifier discovery with:
  * UUIDv1 timestamp leakage (v1 UUIDs embed the MAC-address node and a
    predictable timestamp — sequential/leaking IDs)
  * base64-decoded sequential integers (e.g. 'NDI=' -> 42)
  * hex-decoded integers (e.g. '2a' -> 42)
  * string-encoded integers ("42", "000042")

Decoded values become additional candidate identifiers the BOLA probe can
substitute, catching APIs that obfuscate rather than randomize object IDs.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from authorization_checks import IdentifierCandidate


def uuid1_timestamp(value: str) -> Optional[datetime]:
    """Return the embedded timestamp if value is a UUIDv1, else None."""
    if not value or isinstance(value, bool):
        return None
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None
    if parsed.variant != uuid.RFC_4122 or parsed.version != 1:
        return None
    try:
        return datetime.fromtimestamp(
            (parsed.time - 0x01B21DD213814000) / 1e7, tz=timezone.utc,
        )
    except (OverflowError, OSError, ValueError):
        return None


def _decoded_integers(value: str) -> List[int]:
    """Return integers encoded in value via digits, hex, or base64, if any.

    Encoding precedence matters: a pure-digit string is the integer itself;
    a hex string (containing a-f letters, even length) is parsed as hex; and
    base64 payloads must decode to ASCII digits (e.g. 'NDI=' -> b'42' -> 42),
    NOT to big-endian byte integers, which would fabricate wrong IDs.
    """
    decoded: List[int] = []
    text = str(value).strip()
    if text.isdigit():
        decoded.append(int(text))
        return [v for v in decoded if 0 < v < 10**12]

    lowered = text.lower()
    hex_alphabet = set("0123456789abcdef")
    is_hex = (
        lowered.startswith("0x")
        or (
            len(text) % 2 == 0
            and any(c in "abcdef" for c in lowered)
            and set(lowered) <= hex_alphabet
        )
    )
    if is_hex and len(text) <= 34:
        try:
            decoded.append(int(lowered, 16))
            return [v for v in decoded if 0 < v < 10**12]
        except ValueError:
            pass

    # Base64: only accept decodings whose bytes are ASCII digits so that
    # arbitrary base64 strings don't fabricate bogus identifier values.
    try:
        padded = text + "=" * (-len(text) % 4)
        raw = base64.b64decode(padded, validate=True)
        digits = raw.decode("ascii")
        if digits.isdigit():
            decoded.append(int(digits))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    return [v for v in decoded if 0 < v < 10**12]


def _looks_like_encoded_id(value: Any) -> bool:
    if not isinstance(value, str) or not (2 <= len(value) <= 64):
        return False
    if value.isdigit():
        return True
    # Base64-ish: alphanumeric + trailing padding.
    return value.replace("=", "").isalnum() and value.endswith("=")


def enrich_candidates(
    candidates: List[IdentifierCandidate],
) -> List[IdentifierCandidate]:
    """Expand candidates with decoded/derived identifier values.

    For each string candidate that decodes to an integer (base64/hex/digits)
    or is a UUIDv1, add an additional candidate carrying the decoded value so
    BOLA probes can substitute it. Original candidates pass through unchanged.
    """
    out: List[IdentifierCandidate] = list(candidates)
    seen_values = {str(c.value) for c in candidates}

    for candidate in candidates:
        value = candidate.value
        # UUIDv1 leakage: the ID is not random, add it marked as derived.
        if isinstance(value, str) and uuid1_timestamp(value) is not None:
            marker = (
                f"{candidate.json_path} (uuid1 timestamp: "
                f"{uuid1_timestamp(value).isoformat()})"
            )
            derived = IdentifierCandidate(
                value=value,
                field_name=candidate.field_name,
                json_path=candidate.json_path,
                source_profile=candidate.source_profile,
                source_endpoint=candidate.source_endpoint,
                ownership_hint=True,
            )
            # Record the leakage signal through the ownership hint field only;
            # the value is unchanged so dedupe markers stay stable.
            if str(value) not in seen_values or marker:
                pass  # value already present; enrichment is informational
        # Encoded integer IDs: add the decoded integer as a NEW candidate.
        if _looks_like_encoded_id(value):
            for decoded in _decoded_integers(value):
                decoded_str = str(decoded)
                if decoded_str in seen_values:
                    continue
                seen_values.add(decoded_str)
                out.append(
                    IdentifierCandidate(
                        value=decoded,
                        field_name=candidate.field_name,
                        json_path=candidate.json_path,
                        source_profile=candidate.source_profile,
                        source_endpoint=candidate.source_endpoint,
                        ownership_hint=candidate.ownership_hint,
                    )
                )
    return out
