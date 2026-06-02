# apifuzz — v1.9

v1.9 adds:
- **Type-juggling payload class** that inspects each parameter's declared schema type in the OpenAPI spec (`boolean`, `integer`, `number`, `string`) and sends a curated list of “looks plausible but probably wrong” values per type. Boolean parameters get probed with `1`, `0`, `"yes"`, `"on"`, `[]`, `{}`, quoted-string `"true"`/`"false"`, etc.; integer/number parameters get `Infinity`, `NaN`, `9223372036854775808`, `0x41`, `"abc"`, scientific overflow, and friends; string parameters get a small set of edge values (empty, NUL byte, 10 KiB).
- The new analyzer branch only flags 2xx responses to clearly type-mismatched payloads (e.g. boolean parameter accepting `"yes"`), keeping noise low — numeric values that parse cleanly are skipped, and most string-shaped payloads aren't flagged at all unless they're edge cases.
- Body parameters inside JSON request bodies inherit their type from the example value's Python type (bool / int / float / str), so JSON-body fields are tested with the same type-aware payloads as query/path/header params.
v1.8 adds:
- **CSV export** of the complete scan results. A new **Download CSV** button next to the existing **Download HTML report** button on the dashboard saves `apifuzz-<scan_id>.csv` with one row per finding and four columns: `Severity`, `Affected Endpoint`, `Vulnerability Title`, `Raw Payload`. Rows are ordered by severity (critical → info). All fields are quoted, so payloads containing commas, quotes, or newlines (XSS, SQL injection, multi-line bodies) round-trip cleanly through Excel / pandas / etc.
- Direct endpoint: `GET /scan/<scan_id>/export.csv` — scriptable for CI exports.
v1.7 adds:
- **Payload appears in the Raw HTTP Request**. Findings produced by query-string injection (fuzzer payloads, canary reflection, focused open-redirect, HTTP parameter pollution, schema-violation negative tests) now bake the params back into the URL stored on the Finding, so the displayed *Raw HTTP request* line shows the actual `GET /endpoint?param=<payload>` you can paste straight into Burp Repeater.
- New helper `analyzer.url_with_query(url, params)` centralises the URL→URL+querystring assembly, so any future emitter that sends `params=` to `session.request` can use it to keep request_url accurate.
v1.6 adds:
- **Configurable User-Agent on the new-scan page**: pick from preset values (Chrome / Firefox / Safari / Edge / curl / Googlebot / iOS Safari / Android Chrome), enter a **custom** string, or choose **Random rotation** to pick a fresh browser-shaped UA for every outbound request (obfuscation against simple WAF/UA fingerprinting).
- The selected UA is enforced session-wide and also stamped into each Finding's request headers and v1.5 raw HTTP request, so what you see in the report is what was actually on the wire.
v1.5 adds:
- **Raw HTTP request in every finding** — each finding includes a Burp-Repeater-ready raw HTTP/1.1 request (method, path, Host, headers, body) built from the exact request that produced the finding. A **Copy for Burp Repeater** button beside the request copies it to the clipboard so you can paste straight into Burp's *Repeater → Raw* tab and replay it manually.
- Auto-filled headers when missing: `Host`, `Content-Length`, `Content-Type` (sniffed from body shape — JSON / form / XML), `Accept`, `User-Agent`, `Connection`.
v1.4 adds:
- **Full server response in every finding** — each finding now carries the complete response body (capped at 1 MiB) plus the full response header set, surfaced as scrollable panes in the expanded finding view. The cap and truncation marker are visible in the UI so you know when a response was clipped.
v1.3 quality-of-life additions:
- **Select all / Clear all** buttons next to the vulnerability classes block toggle every scan-option checkbox at once.
- **Unlimited request budget** checkbox next to the budget input — runs every check against every endpoint with no cap. Disables the numeric input when active.
- **Findings sort direction** on the dashboard: choose **Severity high → low** (default) or **Severity low → high**.

A small, self-contained API security fuzzer with a browser UI. Built to drop into
a Kali Linux VM and run entirely from a local web page.

You upload an OpenAPI / Swagger spec, point at a target base URL, choose which
vulnerability classes to exercise, and apifuzz iterates every endpoint and
parameter location injecting payloads. Findings are ranked
**Critical / High / Medium / Low / Info** and rendered in a live dashboard. You
can also export a standalone HTML report.

> ⚠️ Only fuzz systems you own or have explicit written permission to test.

## Features

- Parses OpenAPI 2.0 / 3.x in JSON or YAML.
- Injects into query, path, header, and JSON body parameters.
- Payload classes:
  - SQL Injection (error-based, boolean, time-blind)
  - Cross-Site Scripting (reflected)
  - Command Injection
  - Path Traversal
  - SSRF (cloud metadata + localhost)
  - Header Injection (CRLF)
  - Authentication Bypass
  - Information Disclosure / stack traces / sensitive data
  - **NoSQL Injection** (`$ne`, `$where`, `$regex`, operator smuggling) (new in v1.2)
  - **Server-Side Template Injection** (Jinja/Twig/Freemarker/ERB/Pug arithmetic) (new in v1.2)
  - **LDAP Injection** (filter break, wildcard) (new in v1.2)
  - **XPath Injection** (boolean tautologies, count probes) (new in v1.2)
  - **Prototype Pollution** (`__proto__`, `constructor.prototype`) (new in v1.2)
  - **Open Redirect** (Location-header analysis on URL-like params) (new in v1.2)
- Extended checks (new in v1.2):
  - **Mass assignment** — injects admin-flavoured fields into JSON bodies
  - **HTTP Parameter Pollution** — duplicates query parameters
  - **HTTP method override** — replays GET with `X-HTTP-Method-Override: DELETE`
  - **Content-Type confusion** — JSON↔form, JSON↔XML
  - **Canary reflection map** — unique per-parameter canary, looks for echoes in body or headers
  - **Schema-violation negative tests** — omit required fields, type-mismatch, enum out-of-range, oversize maxLength/maximum
  - **JWT attacks** — if Authorization is a Bearer JWT: `alg:none`, weak HMAC secrets, expired-token replay, kid path traversal
  - **Rate-limit probe** — N-burst against the first endpoint, flags absence of `Retry-After` / `RateLimit-*` / 429
  - **API version inventory** — probes `vN±1` siblings of declared `/vN/...` endpoints
  - **Cache-Control audit** — flags authenticated 2xx responses without `no-store`
- Misconfiguration detection (v1.1):
  - Plaintext HTTP target / TLS errors during preflight
  - Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
  - Permissive or reflected CORS (`Access-Control-Allow-Origin: *` with credentials, Origin echo, `null` origin)
  - Cookie flags missing `Secure` / `HttpOnly` / `SameSite`
  - Server / framework disclosure via `Server`, `X-Powered-By`, etc.
  - Exposed paths: `/.git/config`, `/.env`, `/swagger.json`, `/actuator`, `/metrics`, `/server-status`, `/phpinfo.php`, `/admin`, `/console`, …
  - Dangerous HTTP methods (TRACE)
- Hardened error handling (v1.1):
  - Base URL and Authorization header are validated server-side before launch.
  - Preflight reachability check; DNS / connection / TLS errors are surfaced as scan diagnostics.
  - Per-scan counter for failed requests plus a deduplicated error list shown in the dashboard.
  - If every reachable endpoint returns 401/403 on baseline the dashboard warns you that your auth header is likely wrong.
  - Hitting the request budget surfaces a warning so you know not all payloads ran.
- Live progress bar + severity counters + filterable findings list.
- Downloadable single-file HTML report (CSS + JS inlined).
- Background threading: launch multiple scans concurrently.

## Install on Kali

```
git clone <this repo> ~/apifuzz   # or copy the folder
cd ~/apifuzz
./setup.sh                        # creates .venv and installs Flask, requests, PyYAML
```

If `setup.sh` complains that `python3-venv` is missing:

```
sudo apt update && sudo apt install -y python3-venv
```

## Run

```
cd ~/apifuzz
./run.sh
```

Then open <http://127.0.0.1:5000> in the Kali browser.

To bind to a different host/port:

```
APIFUZZ_HOST=0.0.0.0 APIFUZZ_PORT=8080 ./run.sh
```

(Leave the default `127.0.0.1` unless you trust the surrounding network.)

## Workflow

1. Open the home page in your browser.
2. Upload the target's OpenAPI / Swagger spec (JSON or YAML).
3. Enter the base URL (e.g. `https://api.example.com`).
4. Optionally paste an `Authorization` header value.
5. Tick the vulnerability classes to test.
6. Click **Run Fuzz**.

The dashboard polls scan status every ~1.2s and updates the progress bar,
severity counters, and findings list in real time. When the scan completes,
click **Download HTML report** for a single self-contained file.

## Layout

```
~/apifuzz/
├── app.py            # Flask routes
├── fuzzer.py         # background scan engine
├── spec_parser.py    # OpenAPI 2.0/3.x parser
├── payloads.py       # payload library by category
├── analyzer.py       # detection signatures + severity
├── misconfig.py      # observational misconfig checks (v1.1)
├── extra_checks.py   # request-mutation checks: HPP, mass assignment, method override, etc. (v1.2)
├── jwt_checks.py     # JWT alg:none / weak-HMAC / kid / expired (v1.2)
├── schema_checks.py  # schema-violation negative tests (v1.2)
├── templates/        # Jinja templates (index, results, base)
├── static/styles.css # dashboard styling (also inlined into exports)
├── setup.sh          # one-shot venv + dependency install
├── run.sh            # activates venv, starts Flask
├── requirements.txt
└── README.md
```

## Tuning

- **Request budget** (form field): hard cap on payload requests per scan; lower
  for huge specs or rate-limited targets. Misconfig probes are *not* counted
  against this budget.
- **Per-request timeout** (form field): seconds before a request is abandoned.
  Time-blind detections need this to be ≥ payload sleep duration (default 5s).
- **Payload classes**: every class is on by default — disable noisy ones in the
  form for tighter scans.
- **Detect misconfigurations** (form field, new in v1.1): toggle to skip the
  preflight + observational checks if you only want raw fuzzing.

## Notes / Limitations

- Authoritative spec resolution only — `$ref` references that point outside the
  spec file are not fetched.
- Scans live in memory; restarting the server drops history. Use **Download HTML
  report** to persist results.
- All payloads are intentionally lightweight signatures. Validate every finding
  manually before reporting.
