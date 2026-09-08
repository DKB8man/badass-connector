# Security Model

This document describes what data the BADASS Connector handles, what it redacts, and what it uploads to BADASS Cloud. It is intended for security-conscious users, auditors, and teams performing due diligence before deploying the connector inside a private network.

---

## Architecture overview

```
Your network
┌─────────────────────────────────────────────┐
│                                             │
│   AI Endpoint (localhost / private IP)      │
│         ▲                                   │
│         │  HTTP (local)                     │
│         ▼                                   │
│   BADASS Connector (badass-runner)          │
│         │                                   │
└─────────┼───────────────────────────────────┘
          │  Outbound HTTPS only
          ▼
   BADASS Cloud (badass-sec.com)
```

- The connector makes **outbound HTTPS connections only**. No inbound port is opened.
- Your AI endpoint never needs a public IP address or open firewall port.
- BADASS Cloud dispatches test jobs to the connector; the connector executes them locally.

---

## What BADASS Cloud never receives from Mode 2

For runner-local execution (Mode 2), the connector is designed so the following
data never leaves your machine:

### Authentication credentials

| Data type | Handling |
|---|---|
| API keys | Provisioned locally into the OS keyring; injected into requests at runtime; never included in the job wire or uploaded transcripts |
| Bearer tokens | Stripped from all request and response data before upload |
| Basic auth credentials | Stripped from all request and response data before upload |
| Cookies | All cookie values replaced with `[REDACTED]`; cookie names are preserved for debugging |
| Raw `Authorization` headers | Removed from all uploaded turn data |
| `X-Api-Key` headers | Removed |
| `X-Auth-Token` headers | Removed |
| `X-Access-Token` headers | Removed |
| `X-Secret` headers | Removed |
| `Proxy-Authorization` headers | Removed |
| VPN credentials | Never read or transmitted by the connector |

### Secrets in body content and log text

The connector applies body-level and text-level redaction to catch secrets that appear outside of HTTP headers:

| Pattern | Example | Result |
|---|---|---|
| `Bearer <token>` in body or logs | `Bearer eyJhbGciOi...` | `Bearer [REDACTED]` |
| `Basic <token>` in body or logs | `Basic dXNlcjpw...` | `Basic [REDACTED]` |
| CSRF token in URL-encoded body | `csrf_token=abc123` | `csrf_token=[REDACTED]` |
| CSRF token in JSON body | `"csrf_token": "abc123"` | `"csrf_token": "[REDACTED]"` |
| API key in URL-encoded body | `api_key=sk-live-abc` | `api_key=[REDACTED]` |
| API key in JSON body | `"api_key": "sk-live-abc"` | `"api_key": "[REDACTED]"` |
| Cookie lines in log text | `Cookie: session=abc123; ga=1` | `Cookie: session=[REDACTED]; ga=[REDACTED]` |
| Quoted-assignment in logs | `api_key = "sk-live-abc"` | `api_key = '[REDACTED]'` |
| Quoted-assignment in logs | `bearer_token = "tok_..."` | `bearer_token = '[REDACTED]'` |

This text-level redaction (`redact_text()`) is applied to error messages before they are uploaded via the fail-job endpoint, ensuring that exceptions containing credential fragments do not reach the cloud.

---

## What is uploaded to BADASS Cloud

| Data | Detail |
|---|---|
| **Run status** | `DONE`, `FAILED`, or `CANCELLED` |
| **Sanitized turn sequences** | The messages sent to your endpoint and the replies received, with all auth headers stripped and body secrets redacted |
| **Endpoint metadata** | Base URL, HTTP method, path, auth type name (e.g. `"bearer"` or `"api_key"`) — never the auth value itself |
| **Validation evidence** | Pattern-match results used by the cloud to determine PASS or FAIL for each harness test |
| **Redacted error messages** | Failure reasons when a run cannot complete; passed through `redact_text()` before upload |
| **Runner metadata** | Runner name, connector version, heartbeat timestamps |

---

## Redaction layer — implementation notes

The redaction pipeline has four functions in `badass_runner/recorder/redact.py`:

| Function | Scope | Used for |
|---|---|---|
| `redact_headers(headers)` | HTTP header dict | All captured request/response headers |
| `redact_cookies(cookie_header)` | Cookie/Set-Cookie string | Cookie values within header strings |
| `redact_body(body)` | HTTP body text | Bearer/Basic tokens; CSRF, API-key fields in URL-encoded and JSON form |
| `redact_text(text)` | Arbitrary text (logs, tracebacks) | Everything above plus cookie lines and quoted-assignment patterns |

Headers are redacted by name against a fixed allowlist of always-redact names (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`, `x-auth-token`, `x-access-token`, `x-secret`, `api-key`) and a pattern that catches any header name containing `token`, `secret`, `key`, `password`, `passwd`, `credential`, or `auth`.

---

## Credential storage

The connector stores exactly two pieces of credential material locally:

1. **`runner_token`** — a long-lived bearer token (`badass_runner_…`) that authenticates job poll and result upload requests to the cloud. It does **not** grant access to the BADASS Cloud dashboard. It is stored in `~/.badass-runner/config.json` with file mode **0600**.

2. **Your Mode-2 endpoint credentials** (API keys, Bearer tokens, Basic auth
   credentials, or cookies) — provisioned on the runner host with
   `badass-runner cred set`, inspected as non-secret metadata with
   `badass-runner cred list`, and deleted with `badass-runner cred remove`.
   Secret input is accepted through a hidden prompt, standard input, or a local
   env-file; it is never accepted as a command-line argument. Values are stored
   in an approved OS keyring. The mode-0600 local JSON index contains only
   target/context references and auth metadata, never credential values.

### Mode 1: cloud-direct execution

Mode 1 is unchanged: when BADASS Cloud executes a cloud-direct test, the cloud
holds the target credentials needed for that cloud-side request. The
runner-local keyring guarantee does not apply to Mode 1.

### Mode 2: runner-local reference execution

For protected operations assigned to a local runner, BADASS Cloud sends a
schema-3 enforcement plan containing an opaque target scope (`targetref_…`) and
opaque credential references (`credref_…`), never credential values. The runner
resolves those references against its local OS-keyring-backed store, constructs
each request in memory, executes it against the target from the runner host, and
uploads only sanitized observations. Missing or mismatched references fail
before target HTTP.

This is an implemented and end-to-end verified boundary, not an aspirational
design claim. The R6 planted-secret capstone proves that a runner-local
credential reaches the controlled target while its raw and derived forms remain
absent from the schema-3 wire, result uploads, cloud persistence, runner/backend
logs, and test output.

---

## Network surface

| Connection | Direction | Protocol | Auth | Purpose |
|---|---|---|---|---|
| `badass-sec.com:443` | Outbound | HTTPS | `runner_token` (Bearer) | Heartbeat, job poll, result upload |
| Local AI endpoint | Loopback / LAN | HTTP/HTTPS | Your credentials (local only) | Harness test execution |
| Local status server (`:7890`) | Loopback only | HTTP | None | Local monitoring |

The local status server binds to `127.0.0.1` only. It is read-only and exposes no credential material.

---

## Job execution model

The connector executes harness jobs in-process. It does not fork subprocesses or spawn containers. The test sequence is delivered by the cloud as a list of message steps; the connector sends HTTP requests to your endpoint and records the responses.

The connector does not evaluate PASS or FAIL itself. It uploads sanitized turn data and the cloud performs the evaluation. This means no evaluation logic or test-detection logic is exposed to your endpoint.

---

## Threat model summary

| Threat | Mitigation |
|---|---|
| Cloud compromise exposes endpoint credentials | Credentials never sent to cloud; auth values are local only |
| Transcript upload leaks secrets | Redaction layer strips all known credential patterns before any upload |
| Config file read by another local user | File mode 0600; only the owning user can read it |
| Runner token stolen from config | Token authenticates only job poll and result upload; does not grant dashboard access; can be revoked from the dashboard |
| Malicious job payload exfiltrates data via SSRF | The cloud validates all target URLs before dispatching jobs |
| Connector acts as a pivot into the private network | Connector only initiates outbound connections; it does not proxy or relay arbitrary traffic |
| Secret appears in error message uploaded on failure | `redact_text()` applied to all error strings before the fail-job upload |

---

## Audit and transparency

The full connector source code is available in this repository. The redaction layer (`badass_runner/recorder/redact.py`) and the client upload methods (`badass_runner/client.py`) are the primary code paths relevant to data confidentiality and are covered by the connector's unit test suite.

To report a potential gap in the redaction layer or any other security concern, see [SECURITY.md](../SECURITY.md).
