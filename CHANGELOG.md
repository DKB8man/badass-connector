# Changelog

All notable changes to the BADASS Connector are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.3.2] — 2026-06-12

### Fixed

- `__version__` in `badass_runner/__init__.py` now matches `pyproject.toml`. Previously the package reported `0.2.0` to BADASS Cloud even after upgrading, because the version string was hardcoded in the module and not updated alongside `pyproject.toml`.

### Documentation

- `docs/install.md`: added **"Starting a new terminal session"** section explaining that virtual environment users must run `source .venv/bin/activate` each time they open a new terminal before using `badass-runner`.
- `docs/install.md`: split **Upgrading** into two separate paths — PyPI (`pip install --upgrade`) and from source (`git pull` + `pip install .`), both including the required `stop` + `start` restart steps.
- `docs/install.md`: corrected version number in the verify example from `0.2.0` to `0.3.2`.

---

## [0.3.1] — 2026-06-12

### Fixed

- Added `readme = "README.md"` and `license` to `pyproject.toml` so PyPI displays the full project description and license on the package page.
- Removed `pytest` from main runtime dependencies (test-only; remains under `[project.optional-dependencies]`).

---

## [0.3.0] — 2026-06-11

### Changed

- Bumped version to 0.3.0.

---

## [0.2.0] — 2026-06-10

### Added

- **Version compatibility check** — `badass-runner login` and `badass-runner start`
  now call `GET /api/runners/version` before connecting. If the connector is below
  the cloud's declared `minimum_runner_version`, startup exits with a clear upgrade
  message. If below `recommended_runner_version`, a non-fatal warning is printed.
  If the endpoint is unreachable (old cloud or network issue), a warning is printed
  and startup continues.
- **`RunnerClient.check_version()`** — new unauthenticated method; safe to call
  before login or token exchange.
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

- `badass-runner login` — zero-config browser pairing with BADASS Cloud. Displays
  a short pairing code and polls for dashboard approval. Saves credentials to
  `~/.badass-runner/config.json` (mode 0600).
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
