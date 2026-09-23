import obfuscator


def test_off_mode_preserves_payload():
    assert obfuscator.obfuscate("' OR 1=1", "sql_injection", "off") == "' OR 1=1"


def test_basic_mode_url_encodes_reserved_bytes():
    assert obfuscator.obfuscate("' OR 1=1", "sql_injection", "basic") == (
        "%27%20OR%201%3D1"
    )


def test_aggressive_path_traversal_double_encodes_slashes():
    transformed = obfuscator.obfuscate(
        "../../etc/passwd",
        "path_traversal",
        "aggressive",
    )

    assert transformed == "..%252f..%252fetc%252fpasswd"


def test_aggressive_command_injection_removes_spaces(monkeypatch):
    monkeypatch.setattr(obfuscator.random, "randint", lambda start, end: 1)

    transformed = obfuscator.obfuscate(
        "; id",
        "command_injection",
        "aggressive",
    )

    assert "${IFS}" in transformed
    assert "${x}" in transformed


def test_random_mode_uses_selected_transform(monkeypatch):
    monkeypatch.setattr(
        obfuscator.random,
        "choice",
        lambda choices: obfuscator.double_url_encode,
    )

    assert obfuscator.obfuscate("/admin", "ssrf", "random") == "%252Fadmin"


def test_unknown_mode_and_empty_payload_are_safe():
    assert obfuscator.obfuscate("value", "xss", "unknown") == "value"
    assert obfuscator.obfuscate("", "xss", "aggressive") == ""
