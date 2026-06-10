# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the BADASS Connector, please **do not open a public GitHub issue**.

Report it privately to:

**security@badass-sec.com**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The connector version (`badass-runner --version`)
- Your operating system and Python version

We aim to acknowledge reports within **2 business days** and provide an initial assessment within **5 business days**.

We will coordinate disclosure timing with you. We ask that you give us reasonable time to issue a fix before any public disclosure.

---

## Supported Versions

| Version | Supported |
|---|---|
| 0.2.x | Yes — current release |
| < 0.2.0 | No — please upgrade |

Only the current release series receives security fixes. Older versions should be upgraded promptly.

---

## Data Handling Promise

The BADASS Connector is built on the principle that **your credentials and secrets stay on your machine**.

### What BADASS Cloud never receives by default

The connector applies a multi-layer redaction pipeline to all data before any upload:

- **API keys** — resolved locally at runtime; never included in uploaded results
- **Bearer tokens** — stripped from all request and response transcripts
- **Cookies** — all cookie values are replaced with `[REDACTED]`; keys are preserved for debugging
- **Raw `Authorization` headers** — removed from all uploaded turn data
- **`X-Api-Key`, `X-Auth-Token`, `X-Secret` and similar headers** — removed from all uploaded turn data
- **`Proxy-Authorization` headers** — removed
- **VPN credentials** — never read or transmitted by the connector
- **Quoted-assignment secrets in error strings** — caught by a text-level redactor (patterns such as `api_key = "value"` or `bearer_token = "value"`) before error messages are uploaded

### What is uploaded

| Data | Notes |
|---|---|
| Sanitized test turn sequences | Auth headers stripped; body secrets redacted |
| Run status | `DONE`, `FAILED`, `CANCELLED` |
| Endpoint metadata | Base URL, path, method, auth type — never auth values |
| Validation evidence | Pattern-match results used for PASS/FAIL determination |
| Redacted error messages | Passed through `redact_text()` before upload |

### Config file security

The connector stores its runtime credential (`runner_token`) in `~/.badass-runner/config.json`. This file is written with **mode 0600** (readable only by the file owner). The `runner_token` authenticates job polling and result uploads; it does not grant access to the BADASS Cloud dashboard.

### Outbound-only network model

The connector makes outbound HTTPS connections to BADASS Cloud only. It does not listen for inbound connections from the cloud. Your endpoint never needs a public IP address.

The optional local status server (default port 7890) binds to localhost only and is not reachable from outside the machine.

---

## Scope

The following are **in scope** for security reports:

- Credential or secret leakage in uploaded data
- Bypass of the redaction layer
- Insecure local storage of credentials
- Privilege escalation or sandbox escape during test execution
- Server-side request forgery through connector configuration
- Authentication bypass for job polling or result upload

The following are **out of scope**:

- Vulnerabilities in the BADASS Cloud backend itself (report via the same email but note they are handled separately)
- Denial-of-service against the local connector process
- Issues requiring physical access to the machine running the connector

---

## Disclosure Policy

We follow a coordinated disclosure model. When a fix is ready we will:

1. Release a patched version
2. Publish a security advisory in the repository
3. Credit reporters who wish to be named
