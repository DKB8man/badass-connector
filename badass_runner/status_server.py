import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional

from .logs import get_logger, log

logger = get_logger()

STATUS_PATH = "/status"


def _make_handler(get_state: Callable) -> type:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != STATUS_PATH:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(get_state()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass  # suppress default access log noise

    return _Handler


class LocalStatusServer:
    """Tiny HTTP server exposing a /status endpoint on localhost."""

    def __init__(self, port: int, get_state: Callable) -> None:
        self.port = port
        self.get_state = get_state
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = _make_handler(self.get_state)
        self._server = HTTPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="badass-status"
        )
        self._thread.start()
        log(logger, "info", "Local status endpoint ready",
            url=f"http://127.0.0.1:{self.port}{STATUS_PATH}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=3)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
