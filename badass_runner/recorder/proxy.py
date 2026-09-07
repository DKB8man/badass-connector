"""Local recorder proxy.

Architecture
------------
Browser ──► RecorderProxy (HTTPServer on 127.0.0.1:PORT)
                │  captures metadata (redacted)
                ▼
          Target App  (session.target_url)

The proxy is a *reverse* proxy to a single registered target URL per session.
Forward-proxy-style requests (absolute URLs in the request line) are rejected
to prevent cross-domain abuse.
"""

import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import urlparse

import httpx

from ..logs import get_logger, log
from .redact import redact_body, redact_cookies, redact_headers, redact_text
from .session import Capture, store

logger = get_logger()

BODY_SNIPPET_MAX = 500  # chars
_SKIP_RESPONSE_HEADERS = frozenset({"transfer-encoding", "content-encoding"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_handler(session_id: str) -> type:
    """Return a handler class bound to *session_id*."""

    class _Handler(BaseHTTPRequestHandler):
        _session_id = session_id

        # ------------------------------------------------------------------ #
        # Internal helpers
        # ------------------------------------------------------------------ #

        def _get_session(self):
            return store.get_active(self._session_id)

        def _reject(self, code: int, message: str) -> None:
            self.send_error(code, message)

        def _proxy(self) -> None:
            # ---- guard: forward-proxy / cross-domain request --------
            if self.path.startswith(("http://", "https://")):
                self._reject(
                    403,
                    "Cross-domain proxy requests are not allowed. "
                    "Use relative paths only.",
                )
                return

            # ---- guard: session validity ----------------------------
            session = self._get_session()
            if session is None:
                self._reject(410, "Recorder session expired or not found")
                return

            # ---- read request body ----------------------------------
            content_length = int(self.headers.get("Content-Length", 0) or 0)
            body_bytes = self.rfile.read(content_length) if content_length > 0 else b""
            body_str = body_bytes.decode("utf-8", errors="replace")

            # ---- build request metadata (redacted) ------------------
            raw_headers = dict(self.headers)
            cookie_header = self.headers.get("Cookie", "")
            content_type = self.headers.get("Content-Type", "")
            path_only = self.path.split("?", 1)[0]
            query = self.path.split("?", 1)[1] if "?" in self.path else ""

            upstream_url = f"{session.target_url}{self.path}"

            req_meta = {
                "method": self.command,
                "path": path_only,
                "url": upstream_url,
                "query": query,
                "content_type": content_type,
                "headers": redact_headers(raw_headers),
                "cookies": redact_cookies(cookie_header),
                "body_snippet": redact_body(body_str, BODY_SNIPPET_MAX),
                "timestamp": _now_iso(),
            }

            # ---- forward to upstream --------------------------------
            fwd_headers = {
                k: v for k, v in raw_headers.items()
                if k.lower() not in ("host", "content-length")
            }
            parsed = urlparse(session.target_url)
            fwd_headers["Host"] = parsed.netloc

            try:
                upstream_resp = httpx.request(
                    method=self.command,
                    url=upstream_url,
                    headers=fwd_headers,
                    content=body_bytes,
                    timeout=30,
                    follow_redirects=True,
                )
            except Exception as exc:
                safe_error = redact_text(str(exc))
                log(logger, "warning", "Recorder proxy upstream error", error=safe_error)
                self._reject(502, f"Upstream error: {safe_error}")
                session.add_capture(
                    Capture(
                        request=req_meta,
                        response={"error": safe_error, "timestamp": _now_iso()},
                    )
                )
                return

            # ---- build response metadata ----------------------------
            resp_text = upstream_resp.content.decode("utf-8", errors="replace")
            resp_meta = {
                "status": upstream_resp.status_code,
                "content_type": upstream_resp.headers.get("content-type", ""),
                "body_snippet": redact_body(resp_text, BODY_SNIPPET_MAX),
                "timestamp": _now_iso(),
            }

            session.add_capture(Capture(request=req_meta, response=resp_meta))
            log(
                logger,
                "info",
                "Request captured",
                session_id=self._session_id,
                method=self.command,
                path=path_only,
                status=upstream_resp.status_code,
            )

            # ---- stream response back to browser --------------------
            self.send_response(upstream_resp.status_code)
            for hdr_name, hdr_val in upstream_resp.headers.items():
                if hdr_name.lower() in _SKIP_RESPONSE_HEADERS:
                    continue
                self.send_header(hdr_name, hdr_val)
            resp_bytes = resp_text.encode("utf-8")
            self.send_header("Content-Length", str(len(resp_bytes)))
            self.end_headers()
            self.wfile.write(resp_bytes)

        # ------------------------------------------------------------------ #
        # HTTP method dispatch
        # ------------------------------------------------------------------ #

        def do_GET(self) -> None:
            self._proxy()

        def do_POST(self) -> None:
            self._proxy()

        def do_HEAD(self) -> None:
            self._proxy()

        def do_PUT(self) -> None:
            self._proxy()

        def do_DELETE(self) -> None:
            self._proxy()

        def log_message(self, *args) -> None:
            pass  # suppress default HTTP access log noise

    return _Handler


class RecorderProxy:
    """Reverse-proxy server that records traffic for a single recorder session."""

    def __init__(self, session_id: str, port: int) -> None:
        self.session_id = session_id
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = _make_handler(self.session_id)
        self._server = HTTPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name=f"recorder-proxy-{self.session_id}",
        )
        self._thread.start()
        log(
            logger,
            "info",
            "Recorder proxy listening",
            session_id=self.session_id,
            port=self.port,
        )

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=3)
        log(logger, "info", "Recorder proxy stopped", session_id=self.session_id)

    @property
    def bound_address(self) -> str:
        """Return the IP address the proxy socket is bound to."""
        if self._server:
            return self._server.socket.getsockname()[0]
        return ""

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
