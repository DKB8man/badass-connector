"""BADASS Local Runner CLI.

Commands
--------
badass-runner start   Register with a one-time token, or reconnect with saved credentials.
badass-runner status  Show whether a runner process is active locally.
badass-runner stop    Send SIGTERM to the running runner process.
"""

import os
import signal
import sys
from threading import Event
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
from .harness.job_poller import JobPoller
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
# start
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--server-url", envvar="BADASS_SERVER_URL",
    help="BADASS Cloud base URL (e.g. https://your-domain.com)",
)
@click.option(
    "--token", "reg_token", envvar="BADASS_REG_TOKEN",
    help="One-time registration token (badass_reg_…). Required on first start.",
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

    Once registered, later starts use the saved permanent runner credentials.
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
            "Use --token <badass_reg_...> to register with a one-time token.",
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
    shutdown_event = Event()

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

    # ---- Harness job poller ----------------------------------------------
    def _on_job_start(run_id: str) -> None:
        _state.update(status="running_job", active_run_id=run_id)

    def _on_job_complete(run_id: str, success: bool) -> None:
        _state.update(
            status="connected",
            active_run_id=None,
            last_run_id=run_id,
            last_run_succeeded=success,
        )

    poller = JobPoller(
        client=client,
        on_job_start=_on_job_start,
        on_job_complete=_on_job_complete,
    )
    poller.start()

    log(logger, "info", "Runner ready",
        runner_id=cfg.runner_id, status_port=cfg.status_port)
    click.echo(
        f"Runner '{cfg.runner_name}' started (id: {cfg.runner_id})\n"
        f"Status: http://127.0.0.1:{cfg.status_port}/status\n"
        f"Press Ctrl+C to stop."
    )

    # ---- Block until shutdown -------------------------------------------
    while not shutdown_event.wait(timeout=1):
        if not poller.is_running():
            log(logger, "error", "Job poller stopped unexpectedly")
            _shutdown("poller_stopped")
            break
    reason = _state.get("status", "shutdown")

    log(logger, "info", "Shutting down", reason=reason)
    poller.stop()
    heartbeat.stop()
    status_server.stop()
    clear_pid(PID_FILE)
    log(logger, "info", "Runner stopped")

    if reason in ("revoked", "invalid_auth", "poller_stopped"):
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
