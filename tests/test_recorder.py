"""Phase 3 Local Recorder Proxy tests.

All upstream HTTP calls are mocked — no real external server required.
The recorder proxy itself runs as a real HTTPServer on ephemeral ports.
"""

import json
import socket
import sys
import time
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# Path bootstrap — runner package only
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx

from badass_runner.recorder.redact import (
    REDACTED,
    redact_body,
    redact_cookies,
    redact_headers,
)
from badass_runner.recorder.session import (
    Capture,
    RecorderSession,
    SessionStore,
    store as global_store,
)
from badass_runner.recorder.proxy import RecorderProxy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ok_upstream(status: int = 200, body: str = '{"ok":true}', ct: str = "application/json"):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body.encode()
    resp.headers = {"content-type": ct}
    return resp


def _make_session(store: SessionStore, port: int, ttl: int = 3600, target: str = "http://target.local"):
    return store.create(target_url=target, port=port, ttl=ttl)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def session_store():
    """Fresh in-process store per test (avoids global state pollution)."""
    return SessionStore()


@pytest.fixture()
def proxy_session(session_store):
    """Live proxy + session pair bound to an ephemeral port."""
    port = _free_port()
    session = _make_session(session_store, port=port)

    proxy = RecorderProxy(session_id=session.session_id, port=port)

    # Inject store into proxy handler (the proxy uses the global store by default;
    # we patch it to use our test store)
    import badass_runner.recorder.proxy as proxy_module
    original_store = proxy_module.store
    proxy_module.store = session_store

    proxy.start()
    time.sleep(0.08)  # let the server bind

    yield proxy, session, port

    proxy.stop()
    proxy_module.store = original_store


# ---------------------------------------------------------------------------
# 1. Redaction unit tests
# ---------------------------------------------------------------------------

class TestRedaction:

    def test_authorization_header_redacted(self):
        headers = {"Authorization": "Bearer secret-token-123", "Content-Type": "application/json"}
        result = redact_headers(headers)
        assert result["Authorization"] == REDACTED
        assert result["Content-Type"] == "application/json"

    def test_cookie_header_redacted(self):
        headers = {"Cookie": "session=abc; csrf=xyz", "Accept": "application/json"}
        result = redact_headers(headers)
        assert result["Cookie"] == REDACTED
        assert result["Accept"] == "application/json"

    def test_x_api_key_redacted(self):
        headers = {"X-Api-Key": "supersecret", "X-Request-ID": "req-1"}
        result = redact_headers(headers)
        assert result["X-Api-Key"] == REDACTED
        assert result["X-Request-ID"] == "req-1"

    def test_custom_token_header_redacted(self):
        headers = {"X-My-Auth-Token": "tok123", "User-Agent": "test"}
        result = redact_headers(headers)
        assert result["X-My-Auth-Token"] == REDACTED
        assert result["User-Agent"] == "test"

    def test_cookie_values_redacted_keys_preserved(self):
        result = redact_cookies("session=abc123; _ga=GA1.1.xyz")
        assert f"session={REDACTED}" in result
        assert f"_ga={REDACTED}" in result
        assert "abc123" not in result

    def test_empty_cookie_header(self):
        assert redact_cookies("") == ""

    def test_bearer_token_in_body_redacted(self):
        body = '{"Authorization": "Bearer supersecret123"}'
        result = redact_body(body)
        assert "supersecret123" not in result
        assert REDACTED in result

    def test_basic_auth_in_body_redacted(self):
        body = "auth=Basic dXNlcjpwYXNz"
        result = redact_body(body)
        assert "dXNlcjpwYXNz" not in result
        assert REDACTED in result

    def test_safe_body_unchanged(self):
        body = '{"message": "hello world", "model": "gpt-4"}'
        assert redact_body(body) == body


# ---------------------------------------------------------------------------
# 2. Session store
# ---------------------------------------------------------------------------

class TestSessionStore:

    def test_create_session(self):
        s = SessionStore()
        sess = s.create(target_url="http://myapp.local", port=8080)
        assert sess.session_id
        assert sess.target_url == "http://myapp.local"
        assert not sess.is_expired()

    def test_expired_session_not_returned_by_get_active(self):
        s = SessionStore()
        sess = s.create(target_url="http://x.local", port=9000, ttl=0)
        # Force expiry
        sess.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert s.get_active(sess.session_id) is None

    def test_active_session_returned(self):
        s = SessionStore()
        sess = s.create(target_url="http://x.local", port=9001)
        assert s.get_active(sess.session_id) is not None

    def test_max_captures_cap(self):
        from badass_runner.recorder.session import MAX_CAPTURES
        s = SessionStore()
        sess = s.create(target_url="http://x.local", port=9002)
        for _ in range(MAX_CAPTURES + 5):
            sess.add_capture(Capture(request={"x": 1}))
        assert len(sess.captures) == MAX_CAPTURES


# ---------------------------------------------------------------------------
# 3. Proxy — GET captured
# ---------------------------------------------------------------------------

class TestProxyGetCapture:

    def test_get_request_captured(self, proxy_session):
        proxy, session, port = proxy_session

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body='{"answer":"42"}')
            resp = httpx.get(f"http://127.0.0.1:{port}/api/ask?q=hello", timeout=5)

        assert resp.status_code == 200
        assert len(session.captures) == 1
        cap = session.captures[0]
        assert cap.request["method"] == "GET"
        assert cap.request["path"] == "/api/ask"
        assert cap.request["query"] == "q=hello"
        assert cap.response["status"] == 200

    def test_get_response_snippet_present(self, proxy_session):
        proxy, session, port = proxy_session
        body = '{"result": "ok"}'

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=body)
            httpx.get(f"http://127.0.0.1:{port}/ping", timeout=5)

        assert session.captures[0].response["body_snippet"] == body


# ---------------------------------------------------------------------------
# 4. Proxy — POST JSON captured
# ---------------------------------------------------------------------------

class TestProxyPostJson:

    def test_post_json_captured(self, proxy_session):
        proxy, session, port = proxy_session

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            resp = httpx.post(
                f"http://127.0.0.1:{port}/api/chat",
                json={"message": "hello"},
                timeout=5,
            )

        assert resp.status_code == 200
        cap = session.captures[0]
        assert cap.request["method"] == "POST"
        assert cap.request["path"] == "/api/chat"
        assert "hello" in cap.request["body_snippet"]
        assert "application/json" in cap.request["content_type"]

    def test_post_json_body_not_truncated_within_limit(self, proxy_session):
        proxy, session, port = proxy_session
        small_body = {"msg": "x" * 100}

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            httpx.post(f"http://127.0.0.1:{port}/api/chat", json=small_body, timeout=5)

        assert "x" * 100 in session.captures[0].request["body_snippet"]


# ---------------------------------------------------------------------------
# 5. Proxy — POST form-urlencoded captured
# ---------------------------------------------------------------------------

class TestProxyPostForm:

    def test_post_form_captured(self, proxy_session):
        proxy, session, port = proxy_session

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            resp = httpx.post(
                f"http://127.0.0.1:{port}/submit",
                data={"query": "What is AI?", "lang": "en"},
                timeout=5,
            )

        assert resp.status_code == 200
        cap = session.captures[0]
        assert cap.request["method"] == "POST"
        assert "application/x-www-form-urlencoded" in cap.request["content_type"]
        assert "What+is+AI" in cap.request["body_snippet"] or "What%20is%20AI" in cap.request["body_snippet"] or "What is AI" in cap.request["body_snippet"]


# ---------------------------------------------------------------------------
# 6. Proxy — redaction in transit
# ---------------------------------------------------------------------------

class TestProxyRedaction:

    def test_authorization_header_not_forwarded_raw(self, proxy_session):
        proxy, session, port = proxy_session

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            httpx.get(
                f"http://127.0.0.1:{port}/secure",
                headers={"Authorization": "Bearer very-secret-token"},
                timeout=5,
            )

        cap = session.captures[0]
        captured_auth = cap.request["headers"].get("Authorization", "")
        assert "very-secret-token" not in captured_auth
        assert captured_auth == REDACTED

    def test_cookie_value_redacted_in_capture(self, proxy_session):
        proxy, session, port = proxy_session

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            httpx.get(
                f"http://127.0.0.1:{port}/profile",
                headers={"Cookie": "session=supersecret99"},
                timeout=5,
            )

        cap = session.captures[0]
        assert "supersecret99" not in cap.request["cookies"]
        assert REDACTED in cap.request["cookies"]

    def test_bearer_token_in_body_redacted(self, proxy_session):
        proxy, session, port = proxy_session
        body_with_secret = json.dumps({"auth": "Bearer topsecretkey9999"})

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            httpx.post(
                f"http://127.0.0.1:{port}/api",
                content=body_with_secret.encode(),
                headers={"Content-Type": "application/json"},
                timeout=5,
            )

        cap = session.captures[0]
        assert "topsecretkey9999" not in cap.request["body_snippet"]
        assert REDACTED in cap.request["body_snippet"]


# ---------------------------------------------------------------------------
# 7. Cross-domain proxy blocked
# ---------------------------------------------------------------------------

class TestCrossDomainBlocked:

    def test_absolute_url_request_rejected(self, proxy_session):
        """Absolute-URL requests (forward-proxy style) must be blocked."""
        proxy, session, port = proxy_session

        # httpx doesn't send absolute URLs naturally; we use a raw socket
        import socket as _sock
        s = _sock.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(
                b"GET http://evil.example.com/steal HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        finally:
            s.close()

        assert b"403" in response or b"Forbidden" in response


# ---------------------------------------------------------------------------
# 7b. Loopback-only binding
# ---------------------------------------------------------------------------

class TestLocalBindOnly:

    def test_proxy_bound_to_loopback_only(self, proxy_session):
        """Proxy socket must be bound to 127.0.0.1, not 0.0.0.0."""
        proxy, session, port = proxy_session
        assert proxy.bound_address == "127.0.0.1", (
            f"Expected 127.0.0.1 but got {proxy.bound_address!r}"
        )

    def test_non_loopback_connection_refused(self, proxy_session):
        """Connecting via any non-loopback address must be refused."""
        import socket as _sock
        proxy, session, port = proxy_session

        # Resolve the machine's outward-facing IP (not loopback)
        try:
            machine_ip = _sock.gethostbyname(_sock.gethostname())
        except OSError:
            pytest.skip("Cannot resolve machine hostname")

        if machine_ip.startswith("127."):
            pytest.skip("Hostname resolves to loopback — single-interface environment")

        with pytest.raises((_sock.error, OSError)):
            _sock.create_connection((machine_ip, port), timeout=2)


# ---------------------------------------------------------------------------
# 8. Expired session rejected
# ---------------------------------------------------------------------------

class TestExpiredSession:

    def test_expired_session_returns_410(self):
        local_store = SessionStore()
        port = _free_port()
        session = local_store.create(target_url="http://x.local", port=port, ttl=1)
        # Force expiry
        session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert session.is_expired()

        import badass_runner.recorder.proxy as proxy_module
        original_store = proxy_module.store
        proxy_module.store = local_store

        proxy = RecorderProxy(session_id=session.session_id, port=port)
        proxy.start()
        time.sleep(0.08)

        try:
            resp = httpx.get(f"http://127.0.0.1:{port}/test", timeout=5)
            assert resp.status_code == 410
        finally:
            proxy.stop()
            proxy_module.store = original_store


# ---------------------------------------------------------------------------
# 9. Response snippet capped at BODY_SNIPPET_MAX
# ---------------------------------------------------------------------------

class TestSnippetCap:

    def test_response_body_snippet_capped(self, proxy_session):
        from badass_runner.recorder.proxy import BODY_SNIPPET_MAX
        proxy, session, port = proxy_session

        big_body = "X" * (BODY_SNIPPET_MAX * 2)

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=big_body, ct="text/plain")
            httpx.get(f"http://127.0.0.1:{port}/big", timeout=5)

        cap = session.captures[0]
        assert len(cap.response["body_snippet"]) == BODY_SNIPPET_MAX

    def test_request_body_snippet_capped(self, proxy_session):
        from badass_runner.recorder.proxy import BODY_SNIPPET_MAX
        proxy, session, port = proxy_session

        big_body = ("Y" * (BODY_SNIPPET_MAX * 2)).encode()

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            httpx.post(
                f"http://127.0.0.1:{port}/upload",
                content=big_body,
                headers={"Content-Type": "text/plain"},
                timeout=5,
            )

        cap = session.captures[0]
        assert len(cap.request["body_snippet"]) == BODY_SNIPPET_MAX


# ---------------------------------------------------------------------------
# 11. Response body redaction (Leak 1 regression)
# ---------------------------------------------------------------------------

class TestResponseBodyRedaction:
    """Verify that the recorder proxy redacts secrets in the *response* body snippet."""

    def test_bearer_token_in_response_body_redacted(self, proxy_session):
        proxy, session, port = proxy_session
        secret_body = '{"token": "Bearer ultra-secret-token", "status": "ok"}'

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=secret_body)
            httpx.get(f"http://127.0.0.1:{port}/api/response", timeout=5)

        cap = session.captures[0]
        assert "ultra-secret-token" not in cap.response["body_snippet"]
        assert REDACTED in cap.response["body_snippet"]

    def test_csrf_cookie_in_response_body_redacted(self, proxy_session):
        proxy, session, port = proxy_session
        # CSRF-key returning a session token value — caught by the CSRF JSON pattern
        secret_body = '{"csrf_token": "super-secret-cookie", "user": "alice"}'

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=secret_body)
            httpx.get(f"http://127.0.0.1:{port}/api/response", timeout=5)

        cap = session.captures[0]
        assert "super-secret-cookie" not in cap.response["body_snippet"]
        assert REDACTED in cap.response["body_snippet"]

    def test_csrf_token_in_response_body_redacted(self, proxy_session):
        proxy, session, port = proxy_session
        secret_body = '{"csrf_token": "hidden-csrf", "user": "alice"}'

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=secret_body)
            httpx.get(f"http://127.0.0.1:{port}/api/response", timeout=5)

        cap = session.captures[0]
        assert "hidden-csrf" not in cap.response["body_snippet"]
        assert REDACTED in cap.response["body_snippet"]

    def test_safe_response_body_preserved(self, proxy_session):
        proxy, session, port = proxy_session
        safe_body = '{"answer": "4", "model": "gpt-4"}'

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=safe_body)
            httpx.get(f"http://127.0.0.1:{port}/api/ask", timeout=5)

        cap = session.captures[0]
        assert cap.response["body_snippet"] == safe_body

    def test_api_key_in_response_body_redacted(self, proxy_session):
        proxy, session, port = proxy_session
        secret_body = '{"x-api-key": "secret-key", "message": "ok"}'

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream(body=secret_body)
            httpx.get(f"http://127.0.0.1:{port}/api/response", timeout=5)

        cap = session.captures[0]
        assert "secret-key" not in cap.response["body_snippet"]


# ---------------------------------------------------------------------------
# 12. CSRF token redaction in request / response bodies (Leak 3 regression)
# ---------------------------------------------------------------------------

class TestCSRFBodyRedaction:
    """Verify that CSRF tokens are redacted from body snippets by redact_body()."""

    def test_csrf_token_urlencoded_redacted(self):
        body = "message=hello&csrf_token=hidden-csrf&lang=en"
        result = redact_body(body)
        assert "hidden-csrf" not in result
        assert REDACTED in result

    def test_csrfmiddlewaretoken_redacted(self):
        body = "csrfmiddlewaretoken=hidden-csrf&data=foo"
        result = redact_body(body)
        assert "hidden-csrf" not in result

    def test_underscore_token_redacted(self):
        body = "_token=hidden-csrf&message=hi"
        result = redact_body(body)
        assert "hidden-csrf" not in result

    def test_csrf_token_json_redacted(self):
        body = '{"csrf_token": "hidden-csrf", "query": "hello"}'
        result = redact_body(body)
        assert "hidden-csrf" not in result
        assert REDACTED in result

    def test_x_csrf_token_urlencoded_redacted(self):
        body = "x-csrf-token=hidden-csrf&action=submit"
        result = redact_body(body)
        assert "hidden-csrf" not in result

    def test_csrf_in_proxy_request_body_capture(self, proxy_session):
        proxy, session, port = proxy_session
        form_with_csrf = "csrf_token=hidden-csrf&message=hello+world"

        with patch("badass_runner.recorder.proxy.httpx.request") as mock_req:
            mock_req.return_value = _ok_upstream()
            httpx.post(
                f"http://127.0.0.1:{port}/submit",
                content=form_with_csrf.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5,
            )

        cap = session.captures[0]
        assert "hidden-csrf" not in cap.request["body_snippet"]
        assert REDACTED in cap.request["body_snippet"]
        assert "hello+world" in cap.request["body_snippet"] or "hello world" in cap.request["body_snippet"]

    def test_safe_body_with_token_field_in_name_unchanged(self):
        body = '{"access_token_count": 3, "message": "ok"}'
        result = redact_body(body)
        assert result == body


# ---------------------------------------------------------------------------
# 10. Existing runner behaviour unchanged
# ---------------------------------------------------------------------------

class TestRunnerUnchanged:

    def test_runner_cli_still_importable(self):
        from badass_runner.cli import main  # noqa
        from badass_runner.heartbeat import HeartbeatLoop  # noqa
        from badass_runner.client import RunnerClient  # noqa

    def test_recorder_package_does_not_break_runner_imports(self):
        from badass_runner.recorder.session import store  # noqa
        from badass_runner.recorder.redact import redact_headers  # noqa
        from badass_runner.recorder.proxy import RecorderProxy  # noqa

    def test_runner_client_uses_api_runners_prefix(self):
        """RunnerClient must target /api/runners/ — documents the runner-cloud contract."""
        import inspect
        import badass_runner.client as client_module
        source = inspect.getsource(client_module)
        assert "/api/runners/" in source, (
            "RunnerClient must use /api/runners/ for all cloud calls"
        )

    def test_recorder_proxy_independent_of_cloud_runner(self):
        """Recorder can be used without a cloud runner session."""
        s = SessionStore()
        sess = s.create(target_url="http://local.app", port=_free_port())
        # No runner registration, no bearer token needed
        assert sess.session_id is not None
        assert not sess.is_expired()
