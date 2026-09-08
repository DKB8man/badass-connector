# Changelog

All notable changes to the BADASS Connector are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.4.2] — 2026-09-08

### Changed

- Added the package README as the PyPI long description.
- Clarified the runner's outbound-only connection model, behavioral-testing
  scope, token-based registration, and redacted result handling.
- Added fail-closed reuse of an already-published, content-equivalent protocol
  release for runner-only patch publication.

---

## [0.4.1] — 2026-09-08

### Release status

- Not published. Its immutable private release tag completed only the guarded
  dry-run, preflight, and public protocol resolution stages; no public
  repository or PyPI mutation occurred.

---

## [0.4.0] — 2026-09-07

### Changed

- The canonical runner exposes only account-owned one-time-token registration.
- Installation and API documentation now match the runner's complete dependency,
  capability, compatibility-check, and credential behavior.

### Security

- Runner-capability ownership must originate from the authenticated account-side
  registration-token flow.

---

## [0.3.0] — 2026-09-03

### Added

- Independent gateway enforcement-probe execution for runner-backed targets.
- Paired authorized and insufficient-authorization requests with per-leg headers.
- Sanitized enforcement observations containing status, bounded body excerpts,
  denial codes, and allowlisted response headers only.
- Explicit `enforcement_probe_v1` capability reporting at registration and heartbeat.
- Runner-side destructive-operation and isolated-fixture safety enforcement.

### Security

- Local target credentials are used only while issuing authorized requests and
  are stripped from response bodies, errors, and allowlisted response-header
  values before upload. Request headers and unbounded bodies are never uploaded.

---

## [0.2.0] — 2026-06-10

### Added

- **Version compatibility check** — `badass-runner start` calls
  `GET /api/runners/version` before connecting. If the connector is below
  the cloud's declared `minimum_runner_version`, startup exits with a clear upgrade
  message. If below `recommended_runner_version`, a non-fatal warning is printed.
  If the endpoint is unreachable (old cloud or network issue), a warning is printed
  and startup continues.
- **`RunnerClient.check_version()`** — new unauthenticated method; safe to call
  before registration-token exchange.
- **`_parse_version()` helper** — semver string → comparable int tuple; strips `v`
  prefix; returns `(0, 0, 0)` on malformed input.

### Changed

- **`fail_job` error redaction** — the error string reported to the cloud when a
  run fails is now passed through `redact_text()` before upload. This prevents
  secrets accidentally captured in exception messages (e.g. `Bearer <token>` from
  HTTP error responses) from reaching BADASS Cloud.

### Security

- Error messages uploaded via `POST /api/runners/jobs/{run_id}/fail` are now
  redacted. Covers: Bearer/Basic tokens, Cookie header lines, API-key fields,
  and quoted-assignment patterns (e.g. `api_key = "value"`).

---

## [0.1.0] — initial release

### Added

- `badass-runner start` — foreground connector process. Registers the runner
  (if a `--token` is provided) or reconnects using saved credentials. Runs a
  heartbeat loop (30-second interval) and polls for harness jobs.
- `badass-runner start --token` — token-based registration flow for CI or headless
  environments. One-time registration token is exchanged for a long-lived runner
  credential.
- `badass-runner status` — shows whether a connector process is active locally.
- `badass-runner stop` — sends SIGTERM to the running connector process.
- `badass-runner recorder` — HTTP traffic recorder subcommand for capturing and
  classifying local endpoint traffic to assist with target discovery.
- Local status server — read-only HTTP status endpoint on localhost (default
  port 7890) for local monitoring integrations.
- Harness job execution — pulls adversarial test jobs from BADASS Cloud, executes
  them locally against the configured endpoint, strips authentication headers and
  credential values from all results, and uploads sanitized transcripts.
- Credential redaction layer — `redact_headers()`, `redact_cookies()`,
  `redact_body()`, and `redact_text()` ensure auth data is stripped from all
  outbound payloads. Covers: `Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key`, `X-Auth-Token`, `Proxy-Authorization`, Bearer/Basic body tokens,
  CSRF tokens, API-key fields, and quoted-assignment patterns.
- Config stored in `~/.badass-runner/config.json` with mode 0600. Location
  overridable via `$BADASS_RUNNER_HOME`.
- Environment variable support: `BADASS_SERVER_URL`, `BADASS_REG_TOKEN`,
  `BADASS_RUNNER_NAME`, `BADASS_RUNNER_HOME`, `BADASS_STATUS_PORT`.
