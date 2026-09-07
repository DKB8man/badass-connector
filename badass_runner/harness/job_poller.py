"""Job poller — polls the BADASS Cloud for pending harness jobs.

The poller runs as a daemon thread alongside the heartbeat loop.  When a
``HarnessRun`` is created for a runner-required target, the cloud queues it
for the registered runner.  This poller:

1. Polls  ``GET /api/runners/jobs``          every N seconds.
2. Claims ``POST /api/runners/jobs/{id}/claim`` — prevents duplicate execution.
3. Executes each test locally via ``LocalTestExecutor``.
4. Sanitizes the resulting turns (strips credentials).
5. Uploads  ``POST /api/runners/jobs/{id}/complete``  with sanitized results.
6. On any failure: ``POST /api/runners/jobs/{id}/fail``  with an error message.

Job lifecycle (runner side)
---------------------------
QUEUED       → runner polls and finds the job
RUNNING      → claim succeeds; runner starts executing
COMPLETED    → complete endpoint called; cloud evaluates and marks DONE
FAILED       → fail endpoint called; cloud marks FAILED
RUNNER_OFFLINE → lazy detection on cloud: RUNNING + no completion after timeout

Design constraints
------------------
* Auth credentials never leave the runner — ``LocalAuthStore`` is not serialized.
* The cloud sends test *steps* (prompt strings); evaluation logic stays cloud-side.
* Out of scope: distributed runners, autoscaling, streaming replay.
"""
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ..client import CloudAPIError, RunnerClient
from ..logs import get_logger, log
from ..target.builder import LocalAuthStore
from .executor import LocalTestExecutor
from .sanitize import sanitize_turns
from badass_runner_protocol import sanitize_enforcement_observations
from badass_runner_protocol import validate_job_envelope, validate_job_results

logger = get_logger()

_POLL_INTERVAL = 10        # seconds between idle polls
_POLL_INTERVAL_BUSY = 1    # seconds between polls when a job was just processed


# ---------------------------------------------------------------------------
# JobPoller
# ---------------------------------------------------------------------------

class JobPoller:
    """Background daemon thread that polls for and executes local harness jobs.

    Parameters
    ----------
    client:
        Authenticated :class:`~badass_runner.client.RunnerClient`.
    auth_store:
        Optional :class:`~badass_runner.target.builder.LocalAuthStore`
        providing local auth credentials.  If ``None`` the executor runs
        unauthenticated.
    poll_interval:
        Seconds between idle poll requests.
    on_job_start:
        Called with ``run_id`` when a job is claimed.
    on_job_complete:
        Called with ``(run_id, success: bool)`` when a job finishes.
    """

    def __init__(
        self,
        client: RunnerClient,
        auth_store: Optional[LocalAuthStore] = None,
        poll_interval: int = _POLL_INTERVAL,
        on_job_start: Optional[Callable[[str], None]] = None,
        on_job_complete: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        self.client = client
        self.auth_store = auth_store
        self.poll_interval = poll_interval
        self._on_job_start = on_job_start or (lambda _: None)
        self._on_job_complete = on_job_complete or (lambda _run_id, _ok: None)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="badass-job-poller"
        )
        self._thread.start()
        log(logger, "info", "Job poller started", poll_interval_s=self.poll_interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        log(logger, "info", "Job poller stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                jobs = self.client.poll_jobs()
            except CloudAPIError as exc:
                if exc.status_code in (401, 403):
                    log(logger, "error", "Job poll auth failure — stopping poller",
                        status=exc.status_code)
                    return
                log(logger, "warning", "Job poll API error",
                    status=exc.status_code, detail=exc.detail)
                self._stop_event.wait(self.poll_interval)
                continue
            except ConnectionError as exc:
                log(logger, "warning", "Job poll connection error", error=str(exc))
                self._stop_event.wait(self.poll_interval)
                continue
            except Exception as exc:
                log(logger, "warning", "Job poll unexpected error", error=str(exc))
                self._stop_event.wait(self.poll_interval)
                continue

            if not jobs:
                self._stop_event.wait(self.poll_interval)
                continue

            # Process the first available job, then immediately re-poll
            job = jobs[0]
            run_id = job.get("run_id", "")
            if run_id:
                log(logger, "info", "Pending job found", run_id=run_id)
                self._execute_job(job)

            self._stop_event.wait(_POLL_INTERVAL_BUSY)

    # ------------------------------------------------------------------
    # Job execution
    # ------------------------------------------------------------------

    def _execute_job(self, job: Dict[str, Any]) -> None:
        # Validate the shared public contract while preserving the received
        # dictionary exactly (ordinary prompt tests intentionally omit mode).
        validate_job_envelope(job)
        run_id = job["run_id"]
        target_cfg: Dict = job.get("target", {})
        tests: List[Dict] = job.get("tests", [])
        limits: Dict = job.get("limits", {})

        # ── Claim ──────────────────────────────────────────────────────────
        try:
            self.client.claim_job(run_id)
        except CloudAPIError as exc:
            if exc.status_code == 409:
                log(logger, "info", "Job already claimed", run_id=run_id)
            else:
                log(logger, "error", "Claim failed",
                    run_id=run_id, status=exc.status_code, detail=exc.detail)
            return
        except Exception as exc:
            log(logger, "error", "Claim error", run_id=run_id, error=str(exc))
            return

        log(logger, "info", "Job claimed", run_id=run_id, test_count=len(tests))
        self._on_job_start(run_id)

        # ── Build executor ─────────────────────────────────────────────────
        _auth_type: str = target_cfg.get("auth_type") or ""
        _dynamic_auth_types = {"oauth_client_credentials", "login_cookie"}
        _uses_dynamic_auth: bool = _auth_type in _dynamic_auth_types

        _extra_body = target_cfg.get("extra_body_fields") or {}
        executor = LocalTestExecutor(
            base_url=target_cfg.get("base_url", ""),
            message_path=target_cfg.get("message_path", "/"),
            method=target_cfg.get("method", "POST"),
            request_message_field=target_cfg.get("request_message_field", "message"),
            response_message_field=target_cfg.get("response_message_field", "reply"),
            auth_store=self.auth_store,
            inter_step_delay=float(limits.get("inter_request_delay_s", 0.5)),
            extra_body_fields=_extra_body if isinstance(_extra_body, dict) else {},
            body_format=target_cfg.get("body_format", "flat"),
            can_cause_side_effects=bool(target_cfg.get("can_cause_side_effects", False)),
        )

        # Collect credential values for sanitization — never uploaded
        auth_secrets: List[str] = []
        if self.auth_store and self.auth_store.credential_value:
            auth_secrets.append(self.auth_store.credential_value)

        max_turns = int(limits.get("max_turns_per_test", 5))
        run_timeout = float(limits.get("overall_run_timeout_s", 600))
        run_start = time.time()

        results: List[Dict] = []

        for test in tests:
            if self._stop_event.is_set():
                break

            if time.time() - run_start > run_timeout:
                log(logger, "warning", "Run timeout reached", run_id=run_id)
                break

            test_id = test.get("test_id", "")
            steps: List[str] = test.get("steps", [])
            endpoint_path: Optional[str] = test.get("endpoint_path")
            new_session_before: List[int] = test.get("new_session_before") or []
            execution_type = test.get("execution_type", "model_turns")

            log(logger, "info", "Executing test",
                run_id=run_id, test_id=test_id, steps=len(steps))

            try:
                if execution_type == "enforcement_probe":
                    raw_observations = executor.execute_enforcement_probe(
                        test.get("enforcement_probe")
                    )
                    safe_observations = sanitize_enforcement_observations(
                        raw_observations, auth_secrets
                    )
                    results.append({
                        "test_id": test_id,
                        "turns": [],
                        "enforcement_observations": safe_observations,
                        "error": None,
                        "endpoint_path": endpoint_path,
                    })
                    log(
                        logger,
                        "info",
                        "Enforcement observations ready",
                        run_id=run_id,
                        test_id=test_id,
                        observation_count=len(safe_observations),
                    )
                elif execution_type == "surface_probe":
                    raw_observations = executor.execute_surface_probe(
                        test.get("surface_probe_paths") or []
                    )
                    scrub_turns = sanitize_turns(
                        [
                            {
                                "request": item["path"],
                                "response": item.get("response_excerpt", ""),
                                "raw_reply": item.get("response_excerpt", ""),
                                "status_code": item["status_code"],
                                "elapsed_ms": item.get("elapsed_ms", 0),
                                "extraction_error": item.get("error"),
                            }
                            for item in raw_observations
                        ],
                        auth_secrets,
                    )
                    safe_observations = [
                        {
                            "path": raw["path"],
                            "status_code": raw["status_code"],
                            "response_excerpt": safe.get("response", ""),
                            "elapsed_ms": raw.get("elapsed_ms", 0),
                            "error": safe.get("extraction_error"),
                        }
                        for raw, safe in zip(raw_observations, scrub_turns)
                    ]
                    results.append({
                        "test_id": test_id,
                        "turns": [],
                        "surface_observations": safe_observations,
                        "error": None,
                        "endpoint_path": endpoint_path,
                    })
                else:
                    raw_turns = executor.execute_test(
                        test_id=test_id,
                        steps=steps,
                        max_turns=max_turns,
                        new_session_before=new_session_before,
                        path_override=endpoint_path,
                    )
                    safe_turns = sanitize_turns(raw_turns, auth_secrets)
                    results.append({
                        "test_id": test_id,
                        "turns": safe_turns,
                        "error": None,
                        "endpoint_path": endpoint_path,
                    })
                    log(logger, "info", "Test complete",
                        run_id=run_id, test_id=test_id, turns=len(safe_turns))

            except Exception as exc:
                err_msg = str(exc)
                log(logger, "error", "Test execution error",
                    run_id=run_id, test_id=test_id, error=err_msg)
                if execution_type == "enforcement_probe":
                    results.append({
                        "test_id": test_id,
                        "turns": [],
                        "enforcement_observations": [],
                        "error": None,
                        "endpoint_path": endpoint_path,
                    })
                elif execution_type == "surface_probe":
                    results.append({
                        "test_id": test_id,
                        "turns": [],
                        "surface_observations": [],
                        "error": None,
                        "endpoint_path": endpoint_path,
                    })
                else:
                    results.append({
                        "test_id": test_id,
                        "turns": [],
                        "error": err_msg,
                        "endpoint_path": endpoint_path,
                    })

        # ── Upload results ─────────────────────────────────────────────────
        # Report auth_status="ok" for dynamic-auth targets that reached this
        # point — the runner successfully authenticated before running tests.
        _upload_auth_status: Optional[str] = "ok" if _uses_dynamic_auth else None
        try:
            validate_job_results(results)
            self.client.complete_job(run_id, results, auth_status=_upload_auth_status)
            log(logger, "info", "Results uploaded",
                run_id=run_id, result_count=len(results))
            self._on_job_complete(run_id, True)
        except Exception as exc:
            log(logger, "error", "Upload failed", run_id=run_id, error=str(exc))
            try:
                # auth_status omitted — the cloud infers "failed" from a
                # stuck "logging_in" marker written at claim time.
                self.client.fail_job(run_id, f"Upload failed: {exc}")
            except Exception:
                pass
            self._on_job_complete(run_id, False)
