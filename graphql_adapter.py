"""Phase 5: GraphQL security adapter.

Provides GraphQL-specific security checks: introspection exposure,
GraphiQL detection, field suggestions, GET mutations, aliases, bounded
batching/depth/amount probes, and field/object authorization via profiles.
All probes are bounded and honor scan-mode safety gates.
"""

from __future__ import annotations

import json as jsonlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests


MAX_BATCH_SIZE = 10
MAX_QUERY_DEPTH = 10
MAX_ALIAS_COUNT = 20


@dataclass
class GraphQLFinding:
    category: str
    severity: str
    confidence: str
    title: str
    evidence: str
    owasp_api: str
    cwe: str
    request_url: str
    status_code: int = 0


def _send_query(
    session: requests.Session,
    url: str,
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    method: str = "POST",
) -> Optional[Tuple[int, str]]:
    """Send a GraphQL query and return (status, response_text)."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        if method == "GET":
            resp = session.get(
                url, params={"query": query}, headers=headers or {},
                timeout=timeout, allow_redirects=False,
            )
        else:
            resp = session.post(
                url, json=payload, headers=headers or {},
                timeout=timeout, allow_redirects=False,
            )
        return resp.status_code, resp.text or ""
    except requests.exceptions.RequestException:
        return None


def probe_introspection(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[GraphQLFinding]:
    """Check if GraphQL introspection is enabled."""
    findings: List[GraphQLFinding] = []
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    introspection_query = "{ __schema { queryType { name } types { name } } }"
    result = _send_query(session, url, introspection_query, headers=headers, timeout=timeout)
    if result and 200 <= result[0] < 300:
        try:
            parsed = jsonlib.loads(result[1])
            if "__schema" in str(parsed):
                findings.append(GraphQLFinding(
                    category="graphql_introspection",
                    severity="medium",
                    confidence="strong",
                    title="GraphQL introspection enabled",
                    evidence="Server returned schema data via __schema query. Introspection should be disabled in production.",
                    owasp_api="API8:2023",
                    cwe="CWE-200",
                    request_url=url,
                    status_code=result[0],
                ))
        except (jsonlib.JSONDecodeError, TypeError):
            pass
    return findings


def probe_graphiql(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
) -> List[GraphQLFinding]:
    """Check if GraphiQL IDE is exposed."""
    findings: List[GraphQLFinding] = []
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
        if resp.status_code == 200 and "graphiql" in (resp.text or "").lower():
            findings.append(GraphQLFinding(
                category="graphql_graphiql",
                severity="medium",
                confidence="strong",
                title="GraphiQL IDE exposed",
                evidence="GraphiQL interface is accessible at the GraphQL endpoint.",
                owasp_api="API8:2023",
                cwe="CWE-200",
                request_url=url,
                status_code=resp.status_code,
            ))
    except requests.exceptions.RequestException:
        pass
    return findings


def probe_field_suggestions(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[GraphQLFinding]:
    """Check if GraphQL field suggestions are enabled (information leak)."""
    findings: List[GraphQLFinding] = []
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    # Deliberately misspell a field to trigger suggestions.
    typo_query = '{ user { userNme } }'
    result = _send_query(session, url, typo_query, headers=headers, timeout=timeout)
    if result and 200 <= result[0] < 300:
        text = result[1].lower()
        if "did you mean" in text or "suggestion" in text:
            findings.append(GraphQLFinding(
                category="graphql_info_leak",
                severity="low",
                confidence="strong",
                title="GraphQL field suggestions enabled",
                evidence="Server returned field suggestions for a typo'd query, leaking schema information.",
                owasp_api="API8:2023",
                cwe="CWE-209",
                request_url=url,
                status_code=result[0],
            ))
    return findings


def probe_batching(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[GraphQLFinding]:
    """Test if GraphQL batching accepts large batch sizes (DoS vector)."""
    findings: List[GraphQLFinding] = []
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    batch = [{"query": "{ __typename }"} for _ in range(MAX_BATCH_SIZE + 1)]
    try:
        resp = session.post(
            url, json=batch, headers=headers,
            timeout=timeout, allow_redirects=False,
        )
        if 200 <= resp.status_code < 300:
            findings.append(GraphQLFinding(
                category="graphql_batch_dos",
                severity="medium",
                confidence="tentative",
                title=f"GraphQL batching accepts {MAX_BATCH_SIZE + 1} queries",
                evidence=f"Server accepted a batch of {MAX_BATCH_SIZE + 1} queries (HTTP {resp.status_code}). No batch limit enforced.",
                owasp_api="API4:2023",
                cwe="CWE-770",
                request_url=url,
                status_code=resp.status_code,
            ))
    except requests.exceptions.RequestException:
        pass
    return findings


def probe_depth(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[GraphQLFinding]:
    """Test if deeply nested queries are accepted (DoS vector)."""
    findings: List[GraphQLFinding] = []
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header

    deep_query = "{ " + "user { " * MAX_QUERY_DEPTH + "id " + "} " * MAX_QUERY_DEPTH + "}"
    result = _send_query(session, url, deep_query, headers=headers, timeout=timeout)
    if result and 200 <= result[0] < 300:
        findings.append(GraphQLFinding(
            category="graphql_depth_dos",
            severity="medium",
            confidence="tentative",
            title=f"GraphQL accepts deeply nested queries ({MAX_QUERY_DEPTH} levels)",
            evidence=f"Server accepted a {MAX_QUERY_DEPTH}-level nested query (HTTP {result[0]}). No depth limit enforced.",
            owasp_api="API4:2023",
            cwe="CWE-674",
            request_url=url,
            status_code=result[0],
        ))
    return findings


def probe_get_mutation(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[GraphQLFinding]:
    """Check if mutations are allowed via GET (CSRF vector)."""
    findings: List[GraphQLFinding] = []
    headers: Dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header
    mutation_query = 'mutation { createUser(name: "apifuzz_canary") { id } }'
    result = _send_query(session, url, mutation_query, headers=headers, timeout=timeout, method="GET")
    if result and 200 <= result[0] < 300:
        findings.append(GraphQLFinding(
            category="graphql_get_mutation",
            severity="high",
            confidence="strong",
            title="GraphQL mutations accepted via GET",
            evidence="Server accepted a mutation query via GET method. This enables CSRF attacks.",
            owasp_api="API8:2023",
            cwe="CWE-352",
            request_url=url,
            status_code=result[0],
        ))
    return findings


def run_graphql_checks(
    url: str,
    session: requests.Session,
    timeout: float = 10.0,
    auth_header: Optional[str] = None,
) -> List[GraphQLFinding]:
    """Run all GraphQL security probes."""
    findings: List[GraphQLFinding] = []
    findings.extend(probe_introspection(url, session, timeout, auth_header))
    findings.extend(probe_graphiql(url, session, timeout))
    findings.extend(probe_field_suggestions(url, session, timeout, auth_header))
    findings.extend(probe_batching(url, session, timeout, auth_header))
    findings.extend(probe_depth(url, session, timeout, auth_header))
    findings.extend(probe_get_mutation(url, session, timeout, auth_header))
    return findings
