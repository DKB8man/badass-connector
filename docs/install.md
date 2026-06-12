# Installation

## Requirements

| Requirement | Minimum |
|---|---|
| Python | 3.11 |
| Operating system | Linux, macOS, Windows (WSL recommended on Windows) |
| Network | Outbound HTTPS to `https://badass-sec.com` |

The connector depends only on:
- [`click`](https://click.palletsprojects.com/) ≥ 8.0 — CLI framework
- [`httpx`](https://www.python-httpx.org/) ≥ 0.28.0 — HTTP client

Both are installed automatically.

---

## Install from PyPI

```bash
pip install badass-runner
```

Using a virtual environment is recommended:

```bash
python3.11 -m venv .venv
source .venv/bin/activate   # macOS / Linux
# .venv\Scripts\activate    # Windows
pip install badass-runner
```

---

## Install from source

```bash
git clone https://github.com/DKB8man/badass-connector
cd badass-connector
pip install .
```

For development (editable install with test dependencies):

```bash
pip install -e ".[dev]"
```

---

## Verify the installation

```bash
badass-runner --version
# badass-runner, version 0.3.2
```

```bash
badass-runner --help
```

---

## Starting a new terminal session

If you installed inside a virtual environment, you must activate it each time you open a new terminal before using `badass-runner`:

```bash
# macOS / Linux
source .venv/bin/activate   # or: source ~/.badass-runner-env/bin/activate

# Windows
.venv\Scripts\activate
```

Once activated, the prompt changes to show the venv name and `badass-runner` is available:

```bash
badass-runner start
```

---

## Upgrading

### Installed from PyPI

```bash
pip install --upgrade badass-runner
badass-runner stop
badass-runner start
```

### Installed from source

```bash
cd /path/to/badass-connector
git pull origin main
source .venv/bin/activate   # activate venv if using one
pip install .
badass-runner stop
badass-runner start
```

The connector checks its own version against the cloud's declared minimum on every `login` and `start`. If your installed version is below the minimum, startup will refuse with a clear upgrade message.

---

## Uninstalling

```bash
pip uninstall badass-runner
```

To remove all local connector state (credentials, config, PID file):

```bash
rm -rf ~/.badass-runner
```

If you used a custom `$BADASS_RUNNER_HOME`, remove that directory instead.

---

## Configuration directory

All connector state lives in `~/.badass-runner/` by default:

```
~/.badass-runner/
  config.json   # runner_id, runner_token, server_url, runner_name (mode 0600)
  runner.pid    # PID of the running connector process
```

Override the directory by setting `BADASS_RUNNER_HOME` before running any command:

```bash
export BADASS_RUNNER_HOME=/opt/badass-runner
badass-runner login --server-url https://badass-sec.com
```

---

## Environment variables

All `--option` flags can be supplied via environment variables. This is useful in CI pipelines and container environments.

| Variable | Replaces | Description |
|---|---|---|
| `BADASS_SERVER_URL` | `--server-url` | BADASS Cloud base URL |
| `BADASS_REG_TOKEN` | `--token` | One-time registration token (`badass_reg_…`) |
| `BADASS_RUNNER_NAME` | `--name` | Human-readable runner label |
| `BADASS_RUNNER_HOME` | — | Override config and PID file directory |
| `BADASS_STATUS_PORT` | `--port` | Local status server port (default: `7890`) |

### CI pipeline example

```bash
export BADASS_SERVER_URL=https://badass-sec.com
export BADASS_REG_TOKEN=badass_reg_YOURTOKEN
export BADASS_RUNNER_NAME=ci-runner-$CI_BUILD_ID

badass-runner start
```

---

## Running as a system service

### systemd (Linux)

Create `/etc/systemd/system/badass-runner.service`:

```ini
[Unit]
Description=BADASS Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=badass
Environment=BADASS_SERVER_URL=https://badass-sec.com
ExecStart=/usr/local/bin/badass-runner start
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now badass-runner
```

### launchd (macOS)

```bash
# Not covered here — see the BADASS Cloud documentation for a plist template.
```

---

## Firewall requirements

The connector makes **outbound-only** HTTPS connections. No inbound ports need to be opened on your firewall.

| Direction | Protocol | Destination | Port | Purpose |
|---|---|---|---|---|
| Outbound | HTTPS | `badass-sec.com` | 443 | Cloud API (heartbeat, job poll, result upload) |

The local status server (port 7890 by default) binds to `127.0.0.1` only and is not reachable from outside the machine. No firewall rule is needed for it.

---

## Proxy support

`httpx` respects the standard `HTTPS_PROXY` and `HTTP_PROXY` environment variables. If your network routes traffic through a proxy, set these before starting the connector:

```bash
export HTTPS_PROXY=https://proxy.corp.example.com:8080
badass-runner start
```

Note: proxy credentials included in the proxy URL are not transmitted to BADASS Cloud and do not pass through the connector's redaction layer. They are used only by the underlying HTTP client for the proxy handshake.
