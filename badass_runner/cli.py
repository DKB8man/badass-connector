"""BADASS Local Runner CLI.

Commands
--------
badass-runner login   Pair this machine with BADASS Cloud (no token required).
badass-runner start   Register (or reconnect) and run the heartbeat loop.
badass-runner status  Show whether a runner process is active locally.
badass-runner stop    Send SIGTERM to the running runner process.
"""

import os
import signal
import sys
import threading
import time
import uuid
import webbrowser
from pathlib import Path
from typing import Optional

import click
import httpx

from . import __version__
from .client import CloudAPIError, RunnerClient
from .config import (
    CONFIG_FILE,
    PID_FILE,
    RunnerConfig,
    clear_pid,
    load_config,
    read_pid,
    save_config,
    write_pid,
)
from .heartbeat import HeartbeatLoop
from .logs import get_logger, log
from .recorder_cli import recorder_group
from .status_server import LocalStatusServer

logger = get_logger()


# ---------------------------------------------------------------------------
# Version compatibility helpers
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple:
    """Parse a semver string into a comparable int tuple.

    Returns ``(0, 0, 0)`` on any parse failure so callers can safely compare
    without crashing on malformed version strings.
    """
    try:
        return tuple(int(x) for x in v.lstrip("v").split(".")[:3])
    except Exception:
        return (0, 0, 0)


def _check_cloud_version(client: "RunnerClient") -> None:
    """Check connector version compatibility with the cloud.

    * Below ``minimum_runner_version``: print an error and exit(1).
    * Below ``recommended_runner_version``: print a non-fatal upgrade warning.
    * Endpoint unreachable or missing (old cloud): warn only and continue.
    """
    try:
        info = client.check_version()
    except ConnectionError:
        click.echo(
            "Warning: Could not reach cloud version endpoint — "
            "proceeding without compatibility check.",
            err=True,
        )
        return
    except CloudAPIError:
        click.echo(
            "Warning: Cloud version endpoint unavailable — "
            "proceeding without compatibility check.",
            err=True,
        )
        return

    min_ver = info.get("minimum_runner_version", "")
    rec_ver = info.get("recommended_runner_version", "")

    if min_ver and _parse_version(__version__) < _parse_version(min_ver):
        click.echo(
            f"Error: connector v{__version__} is below the minimum required "
            f"version v{min_ver}.\n"
            "Upgrade with:  pip install --upgrade badass-runner",
            err=True,
        )
        sys.exit(1)

    if rec_ver and _parse_version(__version__) < _parse_version(rec_ver):
        click.echo(
            f"Warning: connector v{__version__} is below the recommended "
            f"version v{rec_ver}. "
            "Consider upgrading: pip install --upgrade badass-runner",
            err=True,
        )


# ---------------------------------------------------------------------------
# Shared runner state (mutated only from the main thread)
# ---------------------------------------------------------------------------

_state: dict = {
    "running": False,
    "runner_id": None,
    "runner_name": None,
    "status": "starting",
    "last_heartbeat_at": None,
    "version": __version__,
}


def _get_state() -> dict:
    return dict(_state)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="badass-runner")
def main() -> None:
    """BADASS Local Runner — connects your AI endpoints to BADASS Cloud."""


main.add_command(recorder_group)


# ---------------------------------------------------------------------------
# login  (Phase 8 — zero-config browser pairing)
# ---------------------------------------------------------------------------

_POLL_INTERVAL_S = 3
_LOGIN_TIMEOUT_S = 600  # 10 minutes (matches server-side session TTL)


@main.command()
@click.option(
    "--server-url", envvar="BADASS_SERVER_URL", required=True,
    help="BADASS Cloud base URL (e.g. https://badass-sec.com).",
)
@click.option(
    "--name", "runner_name", envvar="BADASS_RUNNER_NAME", default=None,
    help="Human-readable name for this runner (default: hostname).",
)
@click.option(
    "--config", "config_path", default=None, type=click.Path(),
    help="Path to runner config file.",
)
def login(
    server_url: str,
    runner_name: Optional[str],
    config_path: Optional[str],
) -> None:
    """Pair this machine with BADASS Cloud by approving in your browser.

    No token required.  Run once per machine.  After pairing, use
    ``badass-runner start`` to connect.
    """
    cfg_file = Path(config_path) if config_path else CONFIG_FILE
    existing = load_config(cfg_file)

    # Derive or reuse a stable device identifier for this machine.
    device_id = (existing and existing.device_id) or str(uuid.uuid4())

    effective_name = (
        runner_name
        or (existing and existing.runner_name)
        or os.uname().nodename if hasattr(os, "uname") else "my-runner"
    )

    client = RunnerClient(server_url.rstrip("/"))
    _check_cloud_version(client)

    # ---- Start pairing session -------------------------------------------
    click.echo("Starting pairing session with BADASS Cloud…")
    try:
        result = client.pair_start(device_id=device_id, runner_name=effective_name)
    except CloudAPIError as exc:
        click.echo(f"Error: {exc.detail} (HTTP {exc.status_code})", err=True)
        sys.exit(1)
    except ConnectionError as exc:
        click.echo(f"Cannot reach cloud: {exc}", err=True)
        sys.exit(1)

    code = result["pairing_code"]
    browser_url = result["browser_pair_url"]
    polling_token = result["polling_token"]
    expires_in = result.get("expires_in_seconds", 600)

    click.echo("")
    click.echo("╔══════════════════════════════════════╗")
    click.echo(f"║  Pairing code:  {code:<22}║")
    click.echo("╚══════════════════════════════════════╝")
    click.echo("")
    click.echo("A browser window will open automatically.")
    click.echo(f"If it doesn't open, visit:\n  {browser_url}")
    click.echo("")

    # ---- Open browser -------------------------------------------------------
    try:
        opened = webbrowser.open(browser_url, new=2, autoraise=True)
        if not opened:
            click.echo("(Could not open browser automatically — please visit the URL above.)")
    except Exception:
        click.echo("(Could not open browser automatically — please visit the URL above.)")

    # ---- Poll for approval --------------------------------------------------
    deadline = time.monotonic() + min(expires_in, _LOGIN_TIMEOUT_S)
    dots = 0

    click.echo("Waiting for approval", nl=False)

    while time.monotonic() < deadline:
        try:
            poll = client.pair_poll(polling_token)
        except CloudAPIError as exc:
            if exc.status_code == 429:
                # Rate limited — back off briefly
                time.sleep(_POLL_INTERVAL_S)
                continue
            if exc.status_code == 410:
                click.echo("")
                click.echo("Error: Pairing session expired or already used.", err=True)
                sys.exit(1)
            click.echo(f"\nPolling error ({exc.status_code}): {exc.detail}", err=True)
            sys.exit(1)
        except ConnectionError:
            time.sleep(_POLL_INTERVAL_S)
            continue

        if poll.get("status") == "approved":
            runner_token = poll["runner_token"]
            runner_id = poll["runner_id"]
            paired_name = poll.get("runner_name", effective_name)

            # Persist the paired config so ``badass-runner start`` works
            cfg = RunnerConfig(
                server_url=server_url.rstrip("/"),
                runner_name=paired_name,
                runner_id=runner_id,
                runner_token=runner_token,
                device_id=device_id,
            )
            save_config(cfg, cfg_file)

            click.echo("")
            click.echo("")
            click.echo(f"✓ Runner '{paired_name}' paired successfully! (id: {runner_id})")
            click.echo("")
            click.echo("Run the following to start the runner:")
            click.echo("  badass-runner start")
            return

        # Still pending — show progress dots
        dots = (dots + 1) % 4
        click.echo("." * (dots + 1) + " " * (3 - dots), nl=False)
        click.echo("\r" + "Waiting for approval" + "." * (dots + 1), nl=False)
        time.sleep(_POLL_INTERVAL_S)

    click.echo("")
    click.echo("Error: Timed out waiting for approval. Run `badass-runner login` again.", err=True)
    sys.exit(1)


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--server-url", envvar="BADASS_SERVER_URL",
    help="BADASS Cloud base URL (e.g. https://your-domain.com)",
)
@click.option(
    "--token", "reg_token", envvar="BADASS_REG_TOKEN",
    help="One-time registration token (badass_reg_…). Required on first start without prior login.",
)
@click.option(
    "--name", "runner_name", envvar="BADASS_RUNNER_NAME",
    help="Human-readable runner name.",
)
@click.option(
    "--port", default=None, type=int, envvar="BADASS_STATUS_PORT",
    help="Local status server port (default 7890).",
)
@click.option(
    "--config", "config_path", default=None, type=click.Path(),
    help="Path to runner config file.",
)
def start(
    server_url: Optional[str],
    reg_token: Optional[str],
    runner_name: Optional[str],
    port: Optional[int],
    config_path: Optional[str],
) -> None:
    """Start the BADASS Local Runner (foreground process).

    If you have already run ``badass-runner login``, no --token is required.
    """
    cfg_file = Path(config_path) if config_path else CONFIG_FILE
    existing = load_config(cfg_file)

    # ---- Build / validate config ----------------------------------------
    if reg_token:
        # Fresh registration — require server_url and name
        if not server_url:
            server_url = (existing and existing.server_url) or None
        if not server_url:
            click.echo("Error: --server-url is required for registration.", err=True)
            sys.exit(1)
        if not runner_name:
            runner_name = (existing and existing.runner_name) or "unnamed-runner"
        cfg = RunnerConfig(
            server_url=server_url,
            runner_name=runner_name,
            device_id=(existing and existing.device_id) or None,
            status_port=port or (existing.status_port if existing else 7890),
        )
    elif existing and existing.is_registered():
        cfg = existing
        if server_url:
            cfg.server_url = server_url
        if port:
            cfg.status_port = port
    else:
        click.echo(
            "Error: No runner credentials found.\n"
            "Run 'badass-runner login' to pair this machine, or\n"
            "use --token <badass_reg_...> to register with a one-time token.",
            err=True,
        )
        sys.exit(1)

    log(logger, "info", "BADASS Local Runner starting",
        version=__version__, server=cfg.server_url, name=cfg.runner_name)

    client = RunnerClient(cfg.server_url)
    _check_cloud_version(client)

    # ---- Register (if new token provided) --------------------------------
    if reg_token:
        log(logger, "info", "Registering runner with cloud")
        try:
            result = client.register(reg_token)
        except CloudAPIError as exc:
            log(logger, "error", "Registration failed",
                status=exc.status_code, detail=exc.detail)
            click.echo(f"Registration failed ({exc.status_code}): {exc.detail}", err=True)
            sys.exit(1)
        except ConnectionError as exc:
            log(logger, "error", "Cannot reach cloud server", error=str(exc))
            click.echo(f"Cannot reach cloud: {exc}", err=True)
            sys.exit(1)

        cfg.runner_id = result["runner_id"]
        cfg.runner_token = result["runner_token"]
        save_config(cfg, cfg_file)
        log(logger, "info", "Registration successful", runner_id=cfg.runner_id)

    client.runner_token = cfg.runner_token
    _state.update(
        running=True,
        runner_id=cfg.runner_id,
        runner_name=cfg.runner_name,
        status="connected",
    )

    # ---- Write PID -------------------------------------------------------
    write_pid(os.getpid(), PID_FILE)
    log(logger, "info", "PID written", pid=os.getpid())

    # ---- Shutdown event --------------------------------------------------
    shutdown_event = threading.Event()

    def _shutdown(reason: str) -> None:
        log(logger, "info", "Shutdown requested", reason=reason)
        _state["running"] = False
        _state["status"] = reason
        shutdown_event.set()

    def _handle_signal(signum, frame) -> None:
        _shutdown("shutdown")

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    # Ignore SIGHUP so the runner survives shell/terminal disconnection
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except (AttributeError, OSError):
        pass  # Windows or restricted env

    # ---- Heartbeat loop --------------------------------------------------
    heartbeat = HeartbeatLoop(
        client=client,
        interval=cfg.heartbeat_interval,
        on_revoked=lambda: _shutdown("revoked"),
        on_invalid_auth=lambda: _shutdown("invalid_auth"),
    )
    heartbeat.start()

    # ---- Local status server --------------------------------------------
    status_server = LocalStatusServer(port=cfg.status_port, get_state=_get_state)
    status_server.start()

    log(logger, "info", "Runner ready",
        runner_id=cfg.runner_id, status_port=cfg.status_port)
    click.echo(
        f"Runner '{cfg.runner_name}' started (id: {cfg.runner_id})\n"
        f"Status: http://127.0.0.1:{cfg.status_port}/status\n"
        f"Press Ctrl+C to stop."
    )

    # ---- Block until shutdown -------------------------------------------
    shutdown_event.wait()
    reason = _state.get("status", "shutdown")

    log(logger, "info", "Shutting down", reason=reason)
    heartbeat.stop()
    status_server.stop()
    clear_pid(PID_FILE)
    log(logger, "info", "Runner stopped")

    if reason in ("revoked", "invalid_auth"):
        click.echo(f"Runner stopped: {reason}.", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@main.command()
@click.option("--port", default=7890, envvar="BADASS_STATUS_PORT",
              help="Local status server port.")
def status(port: int) -> None:
    """Check whether a local runner is running."""
    pid = read_pid(PID_FILE)
    if pid is None:
        click.echo("No runner PID file found — runner is not running.")
        return

    # Check if PID is actually alive
    try:
        os.kill(pid, 0)
        alive = True
    except (ProcessLookupError, PermissionError):
        alive = False

    if not alive:
        click.echo(f"PID {pid} not found — runner may have crashed.")
        clear_pid(PID_FILE)
        return

    click.echo(f"Runner process alive (PID {pid})")

    # Try local status endpoint
    try:
        resp = httpx.get(f"http://127.0.0.1:{port}/status", timeout=3)
        if resp.is_success:
            import json
            data = resp.json()
            click.echo(f"Status   : {data.get('status', 'unknown')}")
            click.echo(f"Runner ID: {data.get('runner_id', 'unknown')}")
            click.echo(f"Name     : {data.get('runner_name', 'unknown')}")
            click.echo(f"Version  : {data.get('version', 'unknown')}")
            click.echo(f"Heartbeat: {data.get('last_heartbeat_at', 'never')}")
        else:
            click.echo(f"Status endpoint returned HTTP {resp.status_code}")
    except Exception:
        click.echo("(Status endpoint unreachable)")


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------

@main.command()
def stop() -> None:
    """Stop the running BADASS Local Runner."""
    pid = read_pid(PID_FILE)
    if pid is None:
        click.echo("No runner PID file found — runner is not running.")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"SIGTERM sent to runner process (PID {pid}).")
    except ProcessLookupError:
        click.echo(f"No process found with PID {pid}.")
        clear_pid(PID_FILE)
    except PermissionError:
        click.echo(f"Permission denied to stop PID {pid}.", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
