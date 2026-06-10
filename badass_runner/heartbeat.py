import threading
from typing import Callable, Optional

from .client import CloudAPIError, RunnerClient
from .logs import get_logger, log

logger = get_logger()

_INITIAL_BACKOFF = 5
_MAX_BACKOFF = 300


class HeartbeatLoop:
    """Background thread that sends periodic heartbeats to BADASS Cloud.

    Stops permanently on 401 (invalid token) or 403 (revoked).
    Retries with exponential back-off on transient errors.
    """

    def __init__(
        self,
        client: RunnerClient,
        interval: int = 30,
        on_revoked: Optional[Callable] = None,
        on_invalid_auth: Optional[Callable] = None,
        initial_backoff: int = _INITIAL_BACKOFF,
    ) -> None:
        self.client = client
        self.interval = interval
        self._initial_backoff = initial_backoff
        self._on_revoked = on_revoked or (lambda: None)
        self._on_invalid_auth = on_invalid_auth or (lambda: None)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="badass-heartbeat"
        )
        self._thread.start()
        log(logger, "info", "Heartbeat loop started", interval_seconds=self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        log(logger, "info", "Heartbeat loop stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        backoff = self._initial_backoff
        while not self._stop_event.is_set():
            try:
                self.client.heartbeat()
                log(logger, "info", "Heartbeat sent")
                backoff = _INITIAL_BACKOFF
                self._stop_event.wait(self.interval)
            except CloudAPIError as exc:
                if exc.status_code == 403:
                    log(logger, "error", "Runner has been revoked — stopping permanently")
                    self._on_revoked()
                    return
                if exc.status_code == 401:
                    log(logger, "error", "Invalid runner token — stopping permanently")
                    self._on_invalid_auth()
                    return
                log(logger, "warning", "Heartbeat HTTP error", status=exc.status_code,
                    detail=exc.detail, retry_in=backoff)
                self._stop_event.wait(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
            except ConnectionError as exc:
                log(logger, "warning", "Heartbeat connection error", error=str(exc),
                    retry_in=backoff)
                self._stop_event.wait(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
            except Exception as exc:
                log(logger, "warning", "Heartbeat unexpected error", error=str(exc),
                    retry_in=backoff)
                self._stop_event.wait(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF)
