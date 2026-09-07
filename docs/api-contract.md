# BADASS Connector — Cloud API Contract

This document describes the HTTP endpoints that the BADASS Connector
(`badass-runner`) calls against a BADASS Cloud instance. It is the authoritative
reference for anyone maintaining the connector, writing a compatible server, or
reasoning about what data crosses the trust boundary.

**Current connector version:** `0.4.0`
**Base URL:** configured at runtime via `--server-url` / `BADASS_SERVER_URL`.
No URL is hardcoded in the connector.

---

## Contents

1. [Auth overview](#1-auth-overview)
2. [Shared conventions](#2-shared-conventions)
3. [Endpoint reference](#3-endpoint-reference)
   - [POST /api/runners/register](#31-post-apirunnersregister)
   - [POST /api/runners/heartbeat](#32-post-apirunnersheartbeat)
   - [GET /api/runners/jobs](#33-get-apirunnersjobs)
   - [POST /api/runners/jobs/{run\_id}/claim](#34-post-apirunnersjobsrun_idclaim)
   - [POST /api/runners/jobs/{run\_id}/complete](#35-post-apirunnersjobsrun_idcomplete)
   - [POST /api/runners/jobs/{run\_id}/fail](#36-post-apirunnersjobsrun_idfail)
   - [POST /api/runners/recorder/sessions](#37-post-apirunnersrecordersessions)
4. [Job lifecycle state machine](#4-job-lifecycle-state-machine)
5. [Redaction and security guarantees](#5-redaction-and-security-guarantees)
6. [Version compatibility](#6-version-compatibility)
7. [Known contract ambiguities](#7-known-contract-ambiguities)

---

## 1. Auth overview

The connector uses a permanent runner bearer token after its one-time
registration token has been exchanged:

| Token | Name | Lifetime | Used on |
|---|---|---|---|
| `runner_token` | Permanent runner credential | Until revoked | Authenticated runner endpoints |

The permanent token is sent as `Authorization: Bearer <token>`. The one-time
registration token is sent in the body of `POST /api/runners/register`.

`register` and the version compatibility check require no runner credential.
The dashboard creates the one-time registration token for an authenticated
account and project.

The `runner_token` is persisted locally in `~/.badass-runner/config.json` (mode
`0600`).  It is **never logged, printed, or included in any cloud-bound payload**.

---

## 2. Shared conventions

- All request and response bodies are `application/json`.
- Errors are returned as `{"detail": "<human-readable message>"}` with an
  appropriate 4xx or 5xx status code.
- The connector sends `runner_version` (a semver string, e.g. `"0.2.0"`) in
  every request body where it is listed below.  The cloud may use this to
  enforce a minimum supported version (see [§6](#6-version-compatibility)).
- HTTP timeout defaults: **15 s** for all calls except
  `jobs/{run_id}/complete`, which uses **120 s** to allow time for cloud-side
  evaluation after the upload.
- On `httpx.RequestError` (network unreachable, DNS failure, etc.) the
  connector raises `ConnectionError` and retries on the next poll cycle; it
  does **not** call `fail` for transient network errors.

---

## 3. Endpoint reference

---

### 3.1 POST /api/runners/register

**Purpose:** Exchange a one-time registration token for a permanent
`runner_token`.  Called once on first `badass-runner start --token <...>`.

**Auth:** None.

#### Request

```json
{
  "registration_token": "badass_reg_<opaque>",
  "runner_version": "0.4.0",
  "capabilities": ["enforcement_execution_plan_v2", "surface_probe_v1"]
}
```

| Field | Type | Notes |
|---|---|---|
| `registration_token` | string | One-time token issued by BADASS Cloud (prefix `badass_reg_`). Consumed on first successful use. |
| `runner_version` | string | Semver string from `badass_runner.__version__`. |
| `capabilities` | string[] | Explicit feature protocols implemented by this runner. |

#### Response — 200 OK

```json
{
  "runner_id": "<uuid or opaque string>",
  "runner_token": "<opaque bearer token>"
}
```

| Field | Type | Notes |
|---|---|---|
| `runner_id` | string | Stable identifier for this runner instance, persisted in local config. |
| `runner_token` | string | Permanent bearer token for all subsequent authenticated calls. |

#### Status codes

| Code | Meaning |
|---|---|
| 200 | Registration successful. |
| 400 | Malformed request body. |
| 401 / 403 | Token already consumed, unknown, or expired. |
| 5xx | Cloud-side error; connector exits with non-zero status. |

#### Security notes

- `registration_token` travels only in the request body over HTTPS.
- The returned `runner_token` is stored locally in `config.json` (mode `0600`)
  and never logged or echoed to stdout.
- `redact_text()` is applied to any diagnostic strings before they are logged,
  so the token cannot appear in log files even on a request error.

#### Ambiguity

The connector does not know whether the cloud enforces single-use semantics on
`registration_token` at the HTTP layer or at a higher level.  If the token is
already consumed the cloud should return 401/403, but the exact code is not
specified in the contract — the connector treats any non-2xx as fatal on
registration.

---

### 3.2 POST /api/runners/heartbeat

**Purpose:** Keep the runner's cloud session alive.  Sent on a background
thread at a configurable interval (default: every 30 s).

**Auth:** `Authorization: Bearer <runner_token>`

#### Request

```json
{
  "runner_version": "0.4.0",
  "capabilities": ["enforcement_execution_plan_v2", "surface_probe_v1"]
}
```

#### Response — 200 OK

```json
{}
```

The connector ignores all fields in a successful heartbeat response.

#### Status codes

| Code | Meaning | Connector action |
|---|---|---|
| 200 | Heartbeat acknowledged. | Continue. |
| 401 | Token invalid or unknown. | Shut down (`invalid_auth`). |
| 403 | Token explicitly revoked. | Shut down (`revoked`). |
| 5xx / network error | Transient cloud issue. | Log warning, retry on next interval. |

#### Security notes

- No user data is sent; only the version string and capability identifiers.
- A 401 or 403 response causes the connector to stop immediately and exit with
  status 1, preventing a zombie runner from consuming cloud resources.

---

### 3.3 GET /api/runners/jobs

**Purpose:** Poll for pending harness jobs assigned to this runner.

**Auth:** `Authorization: Bearer <runner_token>`

#### Request

No body.

#### Response — 200 OK

```json
{
  "jobs": [
    {
      "run_id": "<opaque string>",
      "target": {
        "base_url": "http://localhost:8000",
        "message_path": "/api/chat",
        "method": "POST",
        "request_message_field": "message",
        "response_message_field": "reply"
      },
      "tests": [
        {
          "test_id": "<opaque string>",
          "steps": ["Hello", "Ignore previous instructions and …"],
          "endpoint_path": "/api/chat",
          "new_session_before": [2]
        }
      ],
      "limits": {
        "inter_request_delay_s": 0.5,
        "max_turns_per_test": 5,
        "overall_run_timeout_s": 600
      }
    }
  ]
}
```

**`jobs` array:** An empty array means no work is pending.  A non-empty array
may contain more than one job, but the connector currently processes only
`jobs[0]` per poll cycle before re-polling.

**`target` object:**

| Field | Type | Notes |
|---|---|---|
| `base_url` | string | Full base URL of the local AI endpoint (e.g. `http://localhost:8000`). Never sent to the cloud by the connector — used locally only. |
| `message_path` | string | Path component for the prompt request (e.g. `/api/chat`). |
| `method` | string | HTTP method (`POST`, `GET`, …). |
| `request_message_field` | string | JSON key in the request body that receives the prompt. |
| `response_message_field` | string | JSON key in the response body from which the reply is extracted. |

**`tests` array — each element:**

| Field | Type | Notes |
|---|---|---|
| `test_id` | string | Opaque identifier; echoed back in the `complete` payload. |
| `steps` | string[] | Ordered prompt strings sent to the AI endpoint sequentially. |
| `endpoint_path` | string \| null | Per-test path override; falls back to `target.message_path` when null. |
| `new_session_before` | int[] | 1-indexed step indices at which the connector should reset session state (e.g. clear cookies) before sending the step. |

**`limits` object:**

| Field | Type | Default | Notes |
|---|---|---|---|
| `inter_request_delay_s` | float | 0.5 | Seconds to wait between consecutive steps within a test. |
| `max_turns_per_test` | int | 5 | Hard cap on the number of prompt-response turns per test. |
| `overall_run_timeout_s` | float | 600 | Total wall-clock budget for the entire run. |

#### Status codes

| Code | Meaning | Connector action |
|---|---|---|
| 200 | OK (may be empty). | Process or wait. |
| 401 / 403 | Auth failure. | Stop poller. |
| 5xx / network error | Transient. | Log, retry after `poll_interval`. |

#### Poll intervals

- Idle (no jobs found): 10 s.
- Busy (a job was just processed): 1 s.

---

### 3.4 POST /api/runners/jobs/{run_id}/claim

**Purpose:** Atomically mark a job as `RUNNING` before execution begins.
Prevents two runner instances from executing the same job.

**Auth:** `Authorization: Bearer <runner_token>`

#### Request

No body.

#### Response — 200 OK

```json
{}
```

The connector ignores all fields in a successful claim response.

#### Status codes

| Code | Meaning | Connector action |
|---|---|---|
| 200 | Claim granted. Proceed with execution. | Execute. |
| 409 | Already claimed by another runner. | Log info, skip job silently. |
| 401 / 403 | Auth failure. | Log error, skip job. |
| 5xx / network error | Transient. | Log error, skip job (do not retry claim). |

#### Security notes

- No user data is sent.
- 409 is an expected race condition, not an error.  The connector logs it at
  `INFO` level and moves on.

---

### 3.5 POST /api/runners/jobs/{run_id}/complete

**Purpose:** Upload sanitized test results and trigger cloud-side evaluation.

**Auth:** `Authorization: Bearer <runner_token>`

**Timeout:** 120 s (extended to allow for cloud evaluation time).

#### Request

```json
{
  "results": [
    {
      "test_id": "<opaque string>",
      "turns": [
        {
          "request": "POST /api/chat  body: {\"message\": \"Hello\"}",
          "response": "HTTP 200  {\"reply\": \"Hi there\"}",
          "raw_reply": "{\"reply\": \"Hi there\"}",
          "status_code": 200,
          "elapsed_ms": 142,

          "extraction_error": "<string — only present on parse failure>",
          "tool_calls_raw": [{"name": "…", "args": {…}}],
          "function_call_raw": {"name": "…", "arguments": "…"},
          "html_shell": true,
          "content_type": "application/json",
          "step_headers_used": {
            "Authorization": "[REDACTED]",
            "Accept": "application/json"
          }
        }
      ],
      "error": null,
      "endpoint_path": "/api/chat"
    }
  ]
}
```

**`results` array — each element:**

| Field | Type | Notes |
|---|---|---|
| `test_id` | string | Echoed from the job's `tests[i].test_id`. |
| `turns` | Turn[] | Sanitized turn records (see below). May be empty if `error` is set. |
| `error` | string \| null | Non-null if the test could not be executed. |
| `endpoint_path` | string \| null | Echoed from the job's `tests[i].endpoint_path`. |

**Turn object — fields always present:**

| Field | Type | Notes |
|---|---|---|
| `request` | string | Single-line summary of the HTTP request sent to the AI endpoint. **Sanitized.** |
| `response` | string | Single-line summary of the HTTP response received. **Sanitized.** |
| `raw_reply` | string | Raw response body text. **Sanitized.** |
| `status_code` | int | HTTP status code from the AI endpoint. Not modified by sanitization. |
| `elapsed_ms` | int | Round-trip time in milliseconds. Not modified by sanitization. |

**Turn object — optional fields (omitted when absent):**

| Field | Type | Notes |
|---|---|---|
| `extraction_error` | string | Present when the connector could not extract a reply from the response. **Sanitized.** |
| `tool_calls_raw` | list | Tool/function call objects parsed from the AI response. **Recursively sanitized.** |
| `function_call_raw` | dict | Legacy single function-call format. **Recursively sanitized.** |
| `html_shell` | bool | `true` when the response was an HTML page rather than an API response. |
| `content_type` | string | `Content-Type` of the AI endpoint response. |
| `step_headers_used` | dict | Request headers sent by the connector. Auth-bearing keys (`Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token`) are replaced with `"[REDACTED]"`. |

#### Response — 200 OK

```json
{}
```

#### Status codes

| Code | Meaning | Connector action |
|---|---|---|
| 200 | Results accepted, evaluation triggered. | Done. |
| 4xx | Request rejected. | Log, call `fail`. |
| 5xx / network error | Transient or persistent. | Log, call `fail`. |

#### Security notes

All turns are passed through `sanitize_turns()` before this call.
`sanitize_turns()` applies three independent passes:

1. **Exact-match pass:** replaces each `LocalAuthStore.credential_value` with
   `[REDACTED]`.  Targets auth material the runner knows precisely.
2. **Pattern pass:** removes JWTs (`eyJ…`), `sk-*` API keys, and
   `Bearer`/`Basic` authorization values from all string fields.
3. **Header key pass:** replaces the value of any dict entry whose key is in
   `{authorization, cookie, x-api-key, x-auth-token}` with `[REDACTED]`.

`sanitize_turns()` is runner-local (in `badass_runner/harness/sanitize.py`)
and does **not** import from the BADASS backend.

For a test with `execution_type: "enforcement_probe"`, the runner does not
execute prompt turns. It executes the versioned `enforcement_probe` plan and
uploads `enforcement_observations` on that test result. Each variant contains
exactly one authorized and one unauthorized leg. The upload contains only the
variant name, leg identity, status, denial code, bounded sanitized response
excerpt, sanitized error, and allowlisted response headers (`content-type`,
`www-authenticate`, `allow`, `x-request-id`, `x-correlation-id`, `traceparent`).
Request headers, cookies, `set-cookie`, authorization values, local credentials,
and unbounded response bodies are never uploaded. The runner makes no verdict;
the cloud evaluates these observations.

---

### 3.6 POST /api/runners/jobs/{run_id}/fail

**Purpose:** Mark a job as failed on the cloud side.  Called when a job cannot
be completed due to an execution or upload error.

**Auth:** `Authorization: Bearer <runner_token>`

#### Request

```json
{
  "error": "Human-readable error description"
}
```

| Field | Type | Notes |
|---|---|---|
| `error` | string | Description of what went wrong. Should not contain credential material; the connector does not explicitly sanitize this string — callers should avoid logging raw exceptions that may contain auth values. |

#### Response — 200 OK

```json
{}
```

#### Status codes

| Code | Meaning |
|---|---|
| 200 | Failure acknowledged; cloud marks job `FAILED`. |
| 4xx / 5xx | Logged but not retried; the cloud applies a `RUNNER_OFFLINE` timeout for jobs that are neither completed nor failed. |

#### Ambiguity

The `error` field is a free-form string.  The cloud may display it to the user.
The connector does not currently pass this string through `redact_text()` before
sending.  Future versions should apply `redact_text()` here as a safety net.

---

### 3.7 POST /api/runners/recorder/sessions

**Purpose:** Upload a classified recorder capture to BADASS Cloud.  The cloud
stores it so the Connect AI App wizard can display and validate the detected
endpoint before the user creates a target.

**Auth:** `Authorization: Bearer <runner_token>`

#### Request

```json
{
  "target_url": "http://localhost:8000",
  "path": "/api/chat",
  "method": "POST",
  "status_code": 200,
  "content_type": "application/json",
  "request_snippet": null,
  "response_snippet": null,
  "prompt_field": "message",
  "response_field": "reply",
  "response_preview": "Hi there, how can I help?",
  "confidence": 0.9234,
  "warnings": ["low_confidence"],
  "project_id": "proj_abc123"
}
```

| Field | Type | Notes |
|---|---|---|
| `target_url` | string | Base URL of the local AI app. Sent to the cloud solely for display in the wizard; the cloud cannot contact this URL. |
| `path` | string | Detected endpoint path (e.g. `/api/chat`). |
| `method` | string | HTTP method detected by the classifier. |
| `status_code` | int | Always `200` in current implementation — reflects the classifier's expectation of a successful AI response. |
| `content_type` | string \| null | `Content-Type` from captured responses, or null if unknown. |
| `request_snippet` | null | Always null in current implementation; reserved for future use. |
| `response_snippet` | null | Always null in current implementation; reserved for future use. |
| `prompt_field` | string \| null | Detected JSON key for the prompt in request bodies. |
| `response_field` | string \| null | Detected JSON key for the reply in response bodies. |
| `response_preview` | string \| null | Short excerpt from an actual response body, used for wizard display. |
| `confidence` | float | Classifier confidence score in `[0.0, 1.0]`, rounded to 4 decimal places. |
| `warnings` | string[] | Zero or more of: `"no_ai_response"`, `"low_confidence"`, `"html_shell"`. |
| `project_id` | string \| null | BADASS project to associate this capture with, or null. |

#### Response — 200 OK

```json
{
  "capture_id": "<opaque string>"
}
```

| Field | Type | Notes |
|---|---|---|
| `capture_id` | string | Cloud-assigned identifier for the stored capture. Displayed in CLI output after upload. |

#### Status codes

| Code | Meaning |
|---|---|
| 200 | Capture accepted. |
| 401 / 403 | Auth failure. |
| 4xx | Request rejected (e.g. unknown project). |

#### Security notes

- Recorder captures are redacted by `badass_runner/recorder/redact.py` **before
  they are stored locally**.  The proxy pipeline applies `redact_headers()`,
  `redact_cookies()`, and `redact_body()` to every captured request and
  response in real time.
- `request_snippet` and `response_snippet` are null in the current
  implementation, so raw HTTP body content is never included in this payload.
- `response_preview` contains a short excerpt of an AI response body; it has
  been through `redact_body()` before reaching this point.
- Redaction is implemented entirely in the connector
  (`badass_runner/recorder/redact.py`) and does not depend on any BADASS
  backend import.

---

## 4. Job lifecycle state machine

States managed by the cloud; the connector drives transitions via API calls:

```
QUEUED
  │
  │  poll_jobs() returns job
  ▼
RUNNING      ◄── claim_job() success
  │
  ├──(success)── COMPLETED  ◄── complete_job() success
  │                               (cloud evaluates and marks DONE)
  │
  ├──(error)──── FAILED     ◄── fail_job() called
  │
  └──(timeout)── RUNNER_OFFLINE  ◄── cloud detects no completion/failure
                                       within an implementation-defined window
```

The connector does not retry a failed `claim_job` call.  If the claim returns
409 (already claimed) or any other non-200, the job is skipped and the next
poll cycle will not return it (the cloud marks it `RUNNING` on a successful
claim from another runner).

---

## 5. Redaction and security guarantees

The connector enforces a strict trust boundary: **no authentication material
ever leaves the runner**.  This is implemented in three independent layers:

| Layer | Location | What it covers |
|---|---|---|
| Recorder proxy | `badass_runner/recorder/redact.py` | Strips credentials from all captured HTTP traffic in real time (headers, cookies, body patterns). Applied before local storage. |
| Harness sanitizer | `badass_runner/harness/sanitize.py` | Strips known auth values (exact match) + pattern-matched tokens from all turn data before upload to `complete`. |
| Log/traceback sanitizer | `badass_runner/recorder/redact.py` → `redact_text()` | Strips credentials from arbitrary text strings (log lines, error messages, Python tracebacks) via body patterns + Cookie header lines + quoted Python assignment patterns. |

All three functions are runner-local.  None imports from the BADASS backend or
any third-party AI SDK.  The redaction implementation can be audited entirely
within the `runner/` directory.

**Redaction sentinel:** `[REDACTED]`

---

## 6. Version compatibility

Every API call that includes a body sends:

```json
{ "runner_version": "0.4.0" }
```

Before `start`, the connector calls the unauthenticated compatibility endpoint:

```
GET /api/runners/version
→ {
  "minimum_runner_version": "0.2.0",
  "recommended_runner_version": "0.4.0",
  "api_contract_version": 1
}
```

Versions below the minimum stop with an actionable upgrade message. Versions
below the recommendation warn but continue. If the endpoint is unavailable,
the connector warns and continues for compatibility with older cloud releases.

---

## 7. Known contract ambiguities

The following aspects of the contract are implicit (inferred from the connector
source) and should be confirmed with the cloud implementation:

| # | Endpoint | Ambiguity | Risk |
|---|---|---|---|
| A1 | `register` | The exact HTTP status code returned for an already-consumed `registration_token` is unspecified. The connector treats any non-2xx as a fatal registration error. | Low — user sees an error message and can request a new token. |
| A2 | `heartbeat` | The response body shape is unspecified; the connector ignores all fields on success. | Low — connector only cares about the status code. |
| A3 | `jobs` | The cloud may return more than one job in the `jobs` array.  The connector only processes `jobs[0]` per poll cycle.  If the cloud sends many jobs at once, processing will be serialised and slow. | Medium — throughput degradation on multi-job queues. |
| A4 | `jobs/{id}/claim` | The status code for a job that is no longer available (deleted, already completed) is unspecified.  The connector treats non-409, non-200 as a log-and-skip error. | Low — job is skipped; no data loss. |
| A5 | `jobs/{id}/complete` | The response body is ignored.  If the cloud returns a structured error (e.g. schema validation failure), the connector logs it as a generic upload failure and calls `fail`. | Low — user sees a failed run; no silent data loss. |
| A6 | `jobs/{id}/fail` | The `error` field is a free-form string and is redacted before upload; cloud display truncation remains unspecified. | Low — runner-side redaction prevents known credential forms from crossing the boundary. |
| A7 | `recorder/sessions` | `request_snippet` and `response_snippet` are always null in the current implementation.  Their expected shape when non-null is unspecified. | Low — fields are reserved; no current impact. |
| A8 | All | The cloud owns minimum/recommended-version policy; operators must keep that policy compatible with released connector versions. See [§6](#6-version-compatibility). | Low — the runner reports an actionable mismatch before startup. |
