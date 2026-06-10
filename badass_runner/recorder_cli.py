"""Click subgroup: ``badass-runner recorder``

Commands
--------
badass-runner recorder start   --target-url URL [--port N] [--ttl N]
badass-runner recorder list
badass-runner recorder show    SESSION_ID
badass-runner recorder delete  SESSION_ID
"""

import json
import os
import signal
import sys
import threading
from typing import Optional

import click

from .classifier import classify_session
from .logs import get_logger, log
from .recorder.proxy import RecorderProxy
from .recorder.session import DEFAULT_TTL, store
from .recorder.storage import append_capture, delete_session_file, list_session_files, load_captures
from .target.builder import InvalidClassificationError, LocalAuthStore, TargetBuilder
from .target.validator import ValidationPreview

logger = get_logger()


@click.group("recorder")
def recorder_group() -> None:
    """Record local AI app traffic without routing through BADASS Cloud."""


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

@recorder_group.command("start")
@click.option(
    "--target-url", required=True, envvar="BADASS_TARGET_URL",
    help="Base URL of the AI app to record (e.g. http://localhost:8000).",
)
@click.option(
    "--port", default=8080, show_default=True, envvar="BADASS_RECORDER_PORT",
    help="Local port for the recorder proxy.",
)
@click.option(
    "--ttl", default=DEFAULT_TTL, show_default=True,
    help="Session lifetime in seconds before auto-expiry.",
)
def recorder_start(target_url: str, port: int, ttl: int) -> None:
    """Start a recorder proxy session (foreground — Ctrl+C to stop)."""
    session = store.create(target_url=target_url, port=port, ttl=ttl)

    log(
        logger, "info", "Recorder session created",
        session_id=session.session_id,
        target_url=target_url,
        proxy_port=port,
        ttl_seconds=ttl,
    )
    click.echo(
        f"\nRecorder session started\n"
        f"  Session ID : {session.session_id}\n"
        f"  Target     : {target_url}\n"
        f"  Proxy URL  : http://127.0.0.1:{port}\n"
        f"  Expires    : {session.expires_at.strftime('%H:%M:%S UTC')}\n"
        f"\nPoint your browser / client at http://127.0.0.1:{port}"
        f"\nPress Ctrl+C to stop and save captures.\n"
    )

    proxy = RecorderProxy(session_id=session.session_id, port=port)

    # Wrap add_capture to also persist to disk in real-time
    _orig_add = session.add_capture

    def _capturing_add(capture):
        result = _orig_add(capture)
        if result:
            append_capture(session.session_id, capture)
        return result

    session.add_capture = _capturing_add

    proxy.start()

    shutdown_event = threading.Event()

    def _handle_signal(signum, frame) -> None:
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except (AttributeError, OSError):
        pass

    # Block until TTL or signal
    shutdown_event.wait(timeout=float(ttl))

    reason = "TTL expired" if not shutdown_event.is_set() else "stopped by user"
    proxy.stop()
    store.remove(session.session_id)

    n = len(session.captures)
    log(
        logger, "info", "Recorder session ended",
        session_id=session.session_id, reason=reason, captures=n,
    )
    click.echo(
        f"\nSession {session.session_id} ended ({reason}). "
        f"{n} capture(s) saved.\n"
        f"Run: badass-runner recorder show {session.session_id}"
    )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@recorder_group.command("list")
def recorder_list() -> None:
    """List recorder sessions that have stored captures on disk."""
    sessions = list_session_files()
    if not sessions:
        click.echo("No recorder sessions found.")
        return
    click.echo(f"{'SESSION ID':<12}  CAPTURES")
    click.echo("-" * 30)
    for sid in sessions:
        captures = load_captures(sid)
        click.echo(f"{sid:<12}  {len(captures)}")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

@recorder_group.command("show")
@click.argument("session_id")
@click.option("--limit", default=20, show_default=True, help="Max captures to display.")
@click.option("--json-output", is_flag=True, default=False, help="Output raw JSON.")
def recorder_show(session_id: str, limit: int, json_output: bool) -> None:
    """Display captured requests for SESSION_ID."""
    captures = load_captures(session_id)
    if not captures:
        click.echo(f"No captures found for session '{session_id}'.")
        return

    if json_output:
        click.echo(json.dumps(captures[:limit], indent=2))
        return

    click.echo(f"Session {session_id} — {len(captures)} capture(s) (showing {min(limit, len(captures))})\n")
    for i, c in enumerate(captures[:limit], 1):
        req = c.get("request", {})
        resp = c.get("response", {})
        status = resp.get("status", resp.get("error", "?"))
        click.echo(
            f"  [{i:>3}] {req.get('method','?')} {req.get('path','?')}  →  {status}"
            f"  ({req.get('content_type','') or resp.get('content_type','')})"
        )


# ---------------------------------------------------------------------------
# build-target
# ---------------------------------------------------------------------------

@recorder_group.command("build-target")
@click.argument("session_id")
@click.option("--base-url", default=None, envvar="BADASS_TARGET_URL",
              help="Base URL of the target app (defaults to session target_url).")
@click.option("--name", default=None, help="Human-readable target name.")
@click.option("--prompt-field", default=None, help="Override detected prompt field name.")
@click.option("--response-field", default=None, help="Override detected response field name.")
@click.option("--path", "path_override", default=None, help="Override endpoint path.")
@click.option("--probe", default=None,
              help="Custom probe text for validation (default: 'What is 2+2?').")
@click.option("--run-validation", is_flag=True, default=False,
              help="Send a harmless probe to verify the endpoint is reachable.")
@click.option("--json-output", is_flag=True, default=False, help="Output raw JSON.")
def recorder_build_target(
    session_id: str,
    base_url: Optional[str],
    name: Optional[str],
    prompt_field: Optional[str],
    response_field: Optional[str],
    path_override: Optional[str],
    probe: Optional[str],
    run_validation: bool,
    json_output: bool,
) -> None:
    """Build a runner target from a recorded session SESSION_ID."""
    raw_captures = load_captures(session_id)
    if not raw_captures:
        click.echo(f"No captures found for session '{session_id}'.", err=True)
        raise SystemExit(1)

    sc = classify_session(raw_captures)
    if sc.best is None or not sc.best.likely_ai:
        click.echo("No likely-AI endpoint found in this session. Run 'classify' to inspect.", err=True)
        raise SystemExit(1)

    # Resolve base_url: prefer explicit flag, fall back to session target_url stored in metadata
    resolved_base_url = base_url
    if not resolved_base_url:
        click.echo("--base-url is required (or set BADASS_TARGET_URL).", err=True)
        raise SystemExit(1)

    try:
        target = TargetBuilder.from_classification(
            sc.best,
            base_url=resolved_base_url,
            name=name,
            source_session_id=session_id,
            prompt_field_override=prompt_field,
            response_field_override=response_field,
            path_override=path_override,
        )
    except InvalidClassificationError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    validation_result = None
    if run_validation:
        vp = ValidationPreview(probe_text=probe) if probe else ValidationPreview()
        validation_result = vp.run(target)

    if json_output:
        import dataclasses
        output = {
            "target": target.to_cloud_payload(),
            "validation": dataclasses.asdict(validation_result) if validation_result else None,
        }
        click.echo(json.dumps(output, indent=2, default=str))
        return

    click.echo(f"\nTarget built from session {session_id}\n")
    click.echo(f"  Target ID      : {target.target_id}")
    click.echo(f"  Name           : {target.name}")
    click.echo(f"  Base URL       : {target.base_url}")
    click.echo(f"  Endpoint       : {target.endpoint_path}")
    click.echo(f"  Method         : {target.method}")
    click.echo(f"  Content-Type   : {target.content_type or '(unknown)'}")
    click.echo(f"  Prompt field   : {target.prompt_field}")
    click.echo(f"  Response field : {target.response_field}")
    click.echo(f"  Runner-required: {target.runner_required}")
    click.echo(f"  Confidence     : {sc.best.confidence:.2f}")

    if target.safe_headers:
        click.echo(f"  Safe headers   : {', '.join(target.safe_headers.keys())}")

    if validation_result is not None:
        status_label = "OK" if validation_result.success else "FAILED"
        click.echo(f"\nValidation [{status_label}]  HTTP {validation_result.status_code}")
        if validation_result.error:
            click.echo(f"  Error: {validation_result.error}")
        elif validation_result.extracted_response:
            click.echo(f"  Probe    : {validation_result.probe_sent}")
            click.echo(f"  Response : {validation_result.extracted_response[:120]}")

    click.echo(
        f"\nCloud-safe payload (no credentials):\n"
        f"  Run with --json-output to export the full payload."
    )


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------

@recorder_group.command("classify")
@click.argument("session_id")
@click.option("--json-output", is_flag=True, default=False, help="Output raw JSON.")
def recorder_classify(session_id: str, json_output: bool) -> None:
    """Classify recorded traffic for SESSION_ID and show the best AI candidate."""
    raw_captures = load_captures(session_id)
    if not raw_captures:
        click.echo(f"No captures found for session '{session_id}'.")
        return

    sc = classify_session(raw_captures)

    if json_output:
        import dataclasses

        def _serial(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            raise TypeError(f"Not serialisable: {type(obj)}")

        click.echo(json.dumps(dataclasses.asdict(sc), indent=2, default=str))
        return

    click.echo(f"\nClassifier results for session {session_id} ({len(raw_captures)} capture(s))\n")
    click.echo(f"{'#':<4} {'CONF':>6}  {'AI?':<5}  {'METHOD':<7}  PATH")
    click.echo("-" * 60)
    for i, r in enumerate(sc.all_results, 1):
        ai_flag = "YES" if r.likely_ai else "no"
        click.echo(f"{i:<4} {r.confidence:>6.2f}  {ai_flag:<5}  {r.method:<7}  {r.path}")

    if sc.best:
        b = sc.best
        click.echo(f"\nBest candidate:")
        click.echo(f"  Path           : {b.path}")
        click.echo(f"  Method         : {b.method}")
        click.echo(f"  Confidence     : {b.confidence:.2f}")
        click.echo(f"  Prompt field   : {b.detected_prompt_field or '(none)'}")
        click.echo(f"  Response field : {b.detected_response_field or '(none)'}")
        click.echo(f"  Content-Type   : {b.content_type or '(unknown)'}")
        if b.response_preview:
            click.echo(f"  Response prev. : {b.response_preview[:120]}")
    else:
        click.echo("\nNo AI candidate found.")


# ---------------------------------------------------------------------------
# upload
# ---------------------------------------------------------------------------

@recorder_group.command("upload")
@click.argument("session_id")
@click.option(
    "--project-id", default=None, envvar="BADASS_PROJECT_ID",
    help="Project ID to associate this capture with in BADASS Cloud.",
)
@click.option(
    "--server-url", default=None, envvar="BADASS_SERVER_URL",
    help="BADASS Cloud URL (defaults to server_url from runner config).",
)
def recorder_upload(session_id: str, project_id: Optional[str], server_url: Optional[str]) -> None:
    """Classify a recorded session and upload the best candidate to BADASS Cloud.

    The uploaded capture is shown in the BADASS web app on the Connector setup
    page so you can review the detected endpoint before creating a target.
    """
    from .config import load_config
    from .client import RunnerClient, CloudAPIError
    import dataclasses

    config = load_config()
    if not config or not config.is_registered():
        click.echo(
            "Runner is not registered. Run 'badass-runner start' first to register.",
            err=True,
        )
        sys.exit(1)

    raw_captures = load_captures(session_id)
    if not raw_captures:
        click.echo(f"No captures found for session '{session_id}'.", err=True)
        sys.exit(1)

    sc = classify_session(raw_captures)
    if not sc.best:
        click.echo(
            "No AI endpoint detected in this session. "
            "Try sending a message to an AI endpoint and record again.",
            err=True,
        )
        sys.exit(1)

    b = sc.best
    warnings = []
    if not b.likely_ai:
        warnings.append("no_ai_response")
    if b.confidence < 0.5:
        warnings.append("low_confidence")
    if b.content_type and "html" in b.content_type.lower():
        warnings.append("html_shell")

    # session target_url not directly accessible on the classification result;
    # fall back to the raw capture's request origin header if present
    target_url = ""
    if raw_captures:
        first_req = raw_captures[0].get("request", {})
        target_url = first_req.get("target_base_url", "")

    payload = {
        "target_url":      target_url,
        "path":            b.path,
        "method":          b.method,
        "status_code":     200,
        "content_type":    b.content_type,
        "request_snippet": None,
        "response_snippet": None,
        "prompt_field":    b.detected_prompt_field,
        "response_field":  b.detected_response_field,
        "response_preview": b.response_preview,
        "confidence":      round(b.confidence, 4),
        "warnings":        warnings,
        "project_id":      project_id,
    }

    effective_url = server_url or config.server_url
    client = RunnerClient(server_url=effective_url, runner_token=config.runner_token)

    try:
        result = client.upload_capture(payload)
    except (CloudAPIError, ConnectionError) as exc:
        click.echo(f"Upload failed: {exc}", err=True)
        sys.exit(1)

    click.echo(
        f"\nCapture uploaded (ID: {result.get('capture_id', '?')})\n"
        f"  Endpoint  : {b.method} {b.path}\n"
        f"  Confidence: {b.confidence:.0%}\n"
        f"  Prompt    : {b.detected_prompt_field or '(auto)'}\n"
        f"  Response  : {b.detected_response_field or '(auto)'}\n"
        + (f"  Warnings  : {', '.join(warnings)}\n" if warnings else "")
        + "\nOpen the BADASS web app Connector setup page to review and create a target.\n"
    )


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@recorder_group.command("delete")
@click.argument("session_id")
def recorder_delete(session_id: str) -> None:
    """Delete stored captures for SESSION_ID."""
    delete_session_file(session_id)
    click.echo(f"Deleted captures for session '{session_id}'.")
