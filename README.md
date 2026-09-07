# BADASS Connector

> **Connect your local or private AI endpoints to BADASS Cloud for adversarial security testing.**

---

## What it is

The BADASS Connector (`badass-runner`) is a lightweight Python agent you run on your own machine or server. It creates a secure, outbound-only channel between a local AI endpoint and the BADASS Cloud testing platform.

Once connected, BADASS Cloud can dispatch adversarial harness tests against your endpoint, collect sanitized results, and surface findings — all without your endpoint ever being exposed to the public internet.

## Why it exists

Many AI systems under test run behind:

- corporate VPNs
- private cloud networks
- localhost development environments
- firewalls that block inbound connections

BADASS Cloud cannot reach these endpoints directly. The connector solves this by running **inside** your network and pulling jobs from the cloud rather than receiving inbound traffic.

Your endpoint never needs a public IP address. Your credentials never leave your machine.

---

## Requirements

- Python **3.11** or later
- Network access to `https://badass-sec.com` (outbound HTTPS only)
- The AI endpoint you want to test (reachable from the machine running the connector)

---

## Installation

### From PyPI (recommended)

```bash
pip install badass-runner
```

### From source

```bash
git clone https://github.com/DKB8man/badass-connector
cd badass-connector
pip install .
```

### Verify

```bash
badass-runner --version
```

See [docs/install.md](docs/install.md) for detailed install options, virtual environment setup, and environment variable reference.

---

## Quick start

### 1. Create a registration token

Open **Connect Runner** in BADASS Cloud, name the connector, and create its
one-time account-owned registration token.

### 2. Register and start the connector

```bash
badass-runner start \
  --server-url https://badass-sec.com \
  --token badass_reg_YOURTOKEN \
  --name my-private-ai-server
```

The one-time token is exchanged for a permanent local runner credential. The
connector runs in the foreground, sends a heartbeat to the cloud every 30
seconds, and polls for harness jobs assigned to it. Later starts use the saved
credential:

```bash
badass-runner start
```

Press **Ctrl-C** or run `badass-runner stop` (from another terminal) to shut it down.

### 3. Check status

```bash
badass-runner status
```

---

## Testing private and local AI apps

The connector targets any HTTP endpoint that accepts a text message and returns a text reply — the same interface used by most chat-completion, agent, and RAG APIs.

**Typical configuration in the BADASS Cloud dashboard:**

| Field | Example |
|---|---|
| Base URL | `http://localhost:8000` |
| Message path | `/api/chat` |
| Method | `POST` |
| Request field | `message` |
| Response field | `reply` |
| Auth type | `bearer` / `api_key` / `none` |

Credentials (API keys, Bearer tokens) are stored in the connector's **local auth store** on your machine and looked up at runtime. They are never sent to the cloud. See [Where credentials live](#where-credentials-live) below.

---

## Token-based registration for headless systems

CI pipelines and headless systems use the same account-owned one-time
registration-token flow:

```bash
badass-runner start \
  --server-url https://badass-sec.com \
  --token    badass_reg_YOURTOKEN \
  --name     my-ci-runner
```

The token is consumed on first use and replaced with a long-lived runner credential stored in the local config file.

---

## Where credentials live

All connector state is stored in `~/.badass-runner/` (overridable with `$BADASS_RUNNER_HOME`):

```
~/.badass-runner/
  config.json   # runner_id, runner_token, server_url, runner_name
  runner.pid    # PID of the running connector process
```

`config.json` is written with permissions **0600** (owner read/write only). It contains:

- `server_url` — the BADASS Cloud base URL
- `runner_name` — a human-readable label you chose
- `runner_id` — your runner's UUID assigned by the cloud
- `runner_token` — the long-lived bearer token used to authenticate job polls and result uploads

**Your API keys and endpoint credentials are never written to `config.json`.** They are managed separately through the BADASS Cloud dashboard and resolved by the connector at job execution time from your local auth store.

---

## What data is uploaded

When the connector completes a harness test, it uploads to BADASS Cloud:

| Data | Description |
|---|---|
| Run status | `DONE`, `FAILED`, or `CANCELLED` |
| Per-test turn sequences | The messages sent to and received from your endpoint, with auth headers stripped |
| Endpoint metadata | Base URL, method, path, auth type (not auth values) |
| Validation evidence | Pattern-match results used to determine PASS/FAIL |
| Error messages | Failure reasons, passed through credential redaction before upload |

## What is never uploaded

The connector is designed so the following data **never leaves your machine**:

| Data | Handling |
|---|---|
| API keys | Stored locally; injected into requests at runtime; never included in uploaded results |
| Bearer tokens | Stripped from all request/response transcripts before upload |
| Cookies | Stripped from all transcripts; cookie values are replaced with `[REDACTED]` |
| Raw `Authorization` headers | Removed from all uploaded turn data |
| `X-Api-Key`, `X-Auth-Token` headers | Removed from all uploaded turn data |
| Proxy or VPN credentials | Never read or transmitted by the connector |
| Quoted-assignment secrets in log lines | Caught and redacted by the text-level redactor before error strings are uploaded |

See [docs/security-model.md](docs/security-model.md) for the full technical description of the redaction layer.

---

## Commands

| Command | Description |
|---|---|
| `badass-runner start --token …` | Register a new connector with a dashboard-issued one-time token |
| `badass-runner start` | Start a previously registered connector (foreground) |
| `badass-runner status` | Show whether a connector process is running locally |
| `badass-runner stop` | Send SIGTERM to the running connector |
| `badass-runner recorder` | HTTP traffic recorder for endpoint discovery |
| `badass-runner --version` | Print connector version |
| `badass-runner --help` | Show all commands and options |

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `BADASS_SERVER_URL` | — | Cloud base URL (replaces `--server-url`) |
| `BADASS_REG_TOKEN` | — | One-time registration token (replaces `--token`) |
| `BADASS_RUNNER_NAME` | — | Runner label (replaces `--name`) |
| `BADASS_RUNNER_HOME` | `~/.badass-runner` | Override config directory |
| `BADASS_STATUS_PORT` | `7890` | Local status server port |

---

## Local status server

While running, the connector exposes a read-only HTTP status endpoint on localhost at port 7890 (configurable via `--port` or `BADASS_STATUS_PORT`). This is **not** accessible from outside the machine. It is intended for local monitoring integrations.

---

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities and our data handling commitments.

See [docs/security-model.md](docs/security-model.md) for a full description of what data the connector handles, what it redacts, and what it uploads.

---

## License

See `LICENSE` file.
