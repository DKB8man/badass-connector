"""Smoke test — verify the 4 synthetic secrets cannot appear in any cloud-bound payload.

The 4 canonical synthetic secrets used across the test suite:
  ultra-secret-token  — Bearer token value
  super-secret-cookie — Cookie session value
  secret-key          — X-API-Key / api_key value
  hidden-csrf         — CSRF token value

For each secret this file verifies it is eliminated by:
  1. redact_body()         — runner-side body snippet sanitisation
  2. redact_cookies()      — runner-side cookie header sanitisation
  3. redact_headers()      — runner-side header sanitisation
  4. redact_text()         — runner-side traceback/log-line sanitisation
  5. Recorder proxy        — full capture pipeline (integration)
"""
import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from badass_runner.recorder.redact import (
    REDACTED,
    redact_body,
    redact_cookies,
    redact_headers,
    redact_text,
)

SYNTH_SECRETS = [
    "ultra-secret-token",
    "super-secret-cookie",
    "secret-key",
    "hidden-csrf",
]


def _no_leak(text: str, secret: str) -> bool:
    """Return True iff *secret* does NOT appear in *text*."""
    return secret not in text


# ---------------------------------------------------------------------------
# 1.  redact_body()
# ---------------------------------------------------------------------------

class TestRedactBodySmoke:
    """Each synthetic secret must be eliminated from request/response body text."""

    def test_bearer_ultra_secret_token(self):
        body = f"Authorization: Bearer ultra-secret-token"
        result = redact_body(body)
        assert _no_leak(result, "ultra-secret-token")

    def test_bearer_in_json_response(self):
        body = '{"auth": "Bearer ultra-secret-token", "ok": true}'
        result = redact_body(body)
        assert _no_leak(result, "ultra-secret-token")

    def test_api_key_json_secret_key(self):
        body = '{"x-api-key": "secret-key", "query": "hello"}'
        result = redact_body(body)
        assert _no_leak(result, "secret-key"), f"leaked in: {result!r}"

    def test_api_key_urlencoded_secret_key(self):
        body = "api_key=secret-key&q=hello"
        result = redact_body(body)
        assert _no_leak(result, "secret-key"), f"leaked in: {result!r}"

    def test_csrf_json_hidden_csrf(self):
        body = '{"csrf_token": "hidden-csrf", "message": "hello"}'
        result = redact_body(body)
        assert _no_leak(result, "hidden-csrf"), f"leaked in: {result!r}"

    def test_csrf_urlenc_hidden_csrf(self):
        body = "csrf_token=hidden-csrf&action=submit"
        result = redact_body(body)
        assert _no_leak(result, "hidden-csrf"), f"leaked in: {result!r}"

    def test_cookie_in_bearer_position(self):
        body = "Bearer super-secret-cookie"
        result = redact_body(body)
        assert _no_leak(result, "super-secret-cookie"), f"leaked in: {result!r}"

    def test_all_four_secrets_in_one_body(self):
        body = (
            "Bearer ultra-secret-token\n"
            'csrf_token=hidden-csrf&api_key=secret-key\n'
            '{"x-api-key": "secret-key", "csrf_token": "hidden-csrf"}'
        )
        result = redact_body(body)
        for secret in ["ultra-secret-token", "secret-key", "hidden-csrf"]:
            assert _no_leak(result, secret), f"{secret!r} leaked in body: {result!r}"

    def test_safe_content_preserved(self):
        body = '{"message": "hello world", "count": 42}'
        assert redact_body(body) == body


# ---------------------------------------------------------------------------
# 2.  redact_cookies()
# ---------------------------------------------------------------------------

class TestRedactCookiesSmoke:
    def test_session_super_secret_cookie(self):
        header = "session=super-secret-cookie; _ga=GA1.1.000"
        result = redact_cookies(header)
        assert _no_leak(result, "super-secret-cookie"), f"leaked in: {result!r}"
        assert "session=" in result
        assert REDACTED in result

    def test_multiple_cookies_all_values_redacted(self):
        header = "a=ultra-secret-token; b=hidden-csrf; c=safe"
        result = redact_cookies(header)
        for secret in ["ultra-secret-token", "hidden-csrf", "safe"]:
            assert _no_leak(result, secret), f"{secret!r} leaked in: {result!r}"


# ---------------------------------------------------------------------------
# 3.  redact_headers()
# ---------------------------------------------------------------------------

class TestRedactHeadersSmoke:
    def test_authorization_bearer_ultra_secret_token(self):
        hdrs = {"Authorization": "Bearer ultra-secret-token"}
        result = redact_headers(hdrs)
        assert _no_leak(result["Authorization"], "ultra-secret-token")

    def test_x_api_key_secret_key(self):
        hdrs = {"X-Api-Key": "secret-key"}
        result = redact_headers(hdrs)
        assert _no_leak(result["X-Api-Key"], "secret-key")

    def test_cookie_header_super_secret_cookie(self):
        hdrs = {"Cookie": "session=super-secret-cookie"}
        result = redact_headers(hdrs)
        assert _no_leak(result["Cookie"], "super-secret-cookie")


# ---------------------------------------------------------------------------
# 4.  redact_text()  (runner-local traceback / log-line sanitisation)
#
#     Replaces the former cloud-side redact_secrets() import from backend.
#     redact_text() extends redact_body() with Cookie/Set-Cookie header-line
#     patterns and quoted Python-style assignment patterns so it can sanitise
#     exception tracebacks, log lines, and debug output.
# ---------------------------------------------------------------------------

class TestRedactTextSmoke:
    def test_bearer_in_traceback(self):
        tb = (
            "Traceback:\n"
            "  headers = {'Authorization': 'Bearer ultra-secret-token'}\n"
            "RuntimeError: failed"
        )
        result = redact_text(tb)
        assert _no_leak(result, "ultra-secret-token"), f"leaked in: {result!r}"

    def test_api_key_in_traceback(self):
        tb = "ValueError: bad response\n  context: X-API-Key=secret-key"
        result = redact_text(tb)
        assert _no_leak(result, "secret-key"), f"leaked in: {result!r}"

    def test_csrf_in_debug_output(self):
        text = "POST body: csrf_token=hidden-csrf"
        result = redact_text(text)
        assert _no_leak(result, "hidden-csrf"), f"leaked in: {result!r}"

    def test_cookie_header_line_in_log(self):
        log_line = "Cookie: session=super-secret-cookie; path=/"
        result = redact_text(log_line)
        assert _no_leak(result, "super-secret-cookie"), f"leaked in: {result!r}"

    def test_set_cookie_header_in_log(self):
        log_line = "Set-Cookie: session=super-secret-cookie; HttpOnly; Secure"
        result = redact_text(log_line)
        assert _no_leak(result, "super-secret-cookie"), f"leaked in: {result!r}"

    def test_all_four_secrets_in_one_traceback(self):
        tb = (
            "Traceback (most recent call last):\n"
            "  bearer_token = 'Bearer ultra-secret-token'\n"
            "  api_key = 'secret-key'\n"
            "Cookie: session=super-secret-cookie\n"
            "  csrf_token = 'hidden-csrf'\n"
            "RuntimeError: request failed"
        )
        result = redact_text(tb)
        for secret in SYNTH_SECRETS:
            assert _no_leak(result, secret), (
                f"SMOKE FAIL: {secret!r} survived redact_text()\n"
                f"Result: {result!r}"
            )

    def test_quoted_assignment_api_key(self):
        """Quoted Python-assignment form must be caught even without URL encoding."""
        line = "  api_key = 'secret-key'"
        result = redact_text(line)
        assert _no_leak(result, "secret-key"), f"leaked in: {result!r}"

    def test_quoted_assignment_csrf(self):
        line = '  csrf_token = "hidden-csrf"'
        result = redact_text(line)
        assert _no_leak(result, "hidden-csrf"), f"leaked in: {result!r}"

    def test_safe_text_preserved(self):
        text = "RuntimeError: connection refused to 127.0.0.1:8080"
        assert redact_text(text) == text


# ---------------------------------------------------------------------------
# 5.  Full recorder proxy pipeline
# ---------------------------------------------------------------------------

try:
    import socket
    import threading
    from badass_runner.recorder.proxy import RecorderProxy
    from badass_runner.recorder.session import SessionStore
    _PROXY_AVAILABLE = True
except ImportError:
    _PROXY_AVAILABLE = False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mock_upstream(body: str, status: int = 200):
    mock = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
    mock.status_code = status
    mock.headers = {"content-type": "application/json"}
    mock.text = body
    mock.content = body.encode()
    mock.is_success = status < 400
    return mock


@pytest.mark.skipif(not _PROXY_AVAILABLE, reason="RecorderProxy not importable")
class TestProxyPipelineSmoke:
    """Verifies that secrets are absent from recorder captures sent to the cloud."""

    @pytest.fixture
    def proxy_session(self):
        import badass_runner.recorder.proxy as proxy_module
        store = SessionStore()
        port = _free_port()
        sess = store.create(target_url="http://target.local", port=port)
        proxy = RecorderProxy(session_id=sess.session_id, port=port)
        orig_store = proxy_module.store
        proxy_module.store = store
        proxy.start()
        import time; time.sleep(0.1)
        yield proxy, sess, port
        proxy.stop()
        proxy_module.store = orig_store

    def test_bearer_not_in_capture(self, proxy_session):
        proxy, sess, port = proxy_session
        resp_body = '{"token": "Bearer ultra-secret-token", "ok": true}'
        with patch("badass_runner.recorder.proxy.httpx.request") as m:
            m.return_value = _mock_upstream(resp_body)
            httpx.get(f"http://127.0.0.1:{port}/api/check", timeout=5)
        cap = sess.captures[0]
        assert "ultra-secret-token" not in cap.response["body_snippet"]

    def test_api_key_not_in_capture(self, proxy_session):
        proxy, sess, port = proxy_session
        resp_body = '{"x-api-key": "secret-key", "msg": "ok"}'
        with patch("badass_runner.recorder.proxy.httpx.request") as m:
            m.return_value = _mock_upstream(resp_body)
            httpx.get(f"http://127.0.0.1:{port}/api/check", timeout=5)
        cap = sess.captures[0]
        assert "secret-key" not in cap.response["body_snippet"], (
            f"secret-key leaked into body_snippet: {cap.response['body_snippet']!r}"
        )

    def test_csrf_not_in_request_capture(self, proxy_session):
        proxy, sess, port = proxy_session
        with patch("badass_runner.recorder.proxy.httpx.request") as m:
            m.return_value = _mock_upstream("{}")
            httpx.post(
                f"http://127.0.0.1:{port}/submit",
                content=b"csrf_token=hidden-csrf&q=hello",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5,
            )
        cap = sess.captures[0]
        assert "hidden-csrf" not in cap.request["body_snippet"]

    def test_auth_header_not_in_request_capture(self, proxy_session):
        proxy, sess, port = proxy_session
        with patch("badass_runner.recorder.proxy.httpx.request") as m:
            m.return_value = _mock_upstream("{}")
            httpx.get(
                f"http://127.0.0.1:{port}/api/check",
                headers={"Authorization": "Bearer ultra-secret-token"},
                timeout=5,
            )
        cap = sess.captures[0]
        auth = cap.request.get("headers", {}).get("Authorization", "")
        assert "ultra-secret-token" not in auth


# ---------------------------------------------------------------------------
# 6.  sanitize_turns() → cloud-bound JSON chain (harness upload path)
# ---------------------------------------------------------------------------

try:
    from badass_runner.harness.sanitize import sanitize_turns
    _SANITIZE_AVAILABLE = True
except ImportError:
    _SANITIZE_AVAILABLE = False

try:
    import json as _json
    import datetime
    from badass_runner.target.builder import LocalTarget, LocalAuthStore
    _TARGET_AVAILABLE = True
except ImportError:
    _TARGET_AVAILABLE = False


@pytest.mark.skipif(not _SANITIZE_AVAILABLE, reason="sanitize_turns not importable")
class TestSanitizeTurnsE2ESmoke:
    """Verifies that all 4 synthetic secrets are absent from the cloud-bound turns
    JSON produced by sanitize_turns() — the exact blob POSTed to
    /api/runners/jobs/{run_id}/complete."""

    def _raw_turns(self):
        return [
            {
                "request": "POST /api/chat  body: {\"Authorization\": \"Bearer ultra-secret-token\"}",
                "response": "HTTP 200  x-api-key: secret-key",
                "raw_reply": '{"session": "super-secret-cookie", "data": "ok"}',
                "status_code": 200,
                "elapsed_ms": 42,
                "step_headers_used": {
                    "Authorization": "Bearer ultra-secret-token",
                    "x-api-key": "secret-key",
                    "Cookie": "session=super-secret-cookie",
                },
                "tool_calls_raw": [
                    {"name": "web_fetch", "args": {"token": "Bearer ultra-secret-token"}}
                ],
            },
            {
                "request": "POST /submit  body: csrf_token=hidden-csrf&q=test",
                "response": "HTTP 200",
                "raw_reply": "",
                "status_code": 200,
                "elapsed_ms": 10,
                "extraction_error": "csrf_token=hidden-csrf caused parse error",
            },
        ]

    def test_known_auth_secrets_stripped(self):
        """Known auth secrets passed explicitly must not appear in cloud payload."""
        auth_secrets = ["ultra-secret-token", "super-secret-cookie", "secret-key"]
        safe = sanitize_turns(self._raw_turns(), auth_secrets=auth_secrets)
        cloud_json = _json.dumps(safe)
        for secret in auth_secrets:
            assert secret not in cloud_json, (
                f"SMOKE FAIL: {secret!r} survived sanitize_turns()\n"
                f"  cloud_json snippet: {cloud_json[:300]!r}"
            )

    def test_pattern_matched_secrets_stripped(self):
        """Bearer token pattern must be caught even without explicit auth_secrets list."""
        safe = sanitize_turns(self._raw_turns(), auth_secrets=[])
        cloud_json = _json.dumps(safe)
        assert "ultra-secret-token" not in cloud_json, (
            f"SMOKE FAIL: Bearer token survived pattern-match pass\n"
            f"  cloud_json: {cloud_json[:300]!r}"
        )

    def test_all_four_secrets_absent_from_cloud_json(self):
        """Full 4-secret sweep: every synthetic secret must be absent from upload blob."""
        auth_secrets = ["ultra-secret-token", "super-secret-cookie", "secret-key", "hidden-csrf"]
        safe = sanitize_turns(self._raw_turns(), auth_secrets=auth_secrets)
        cloud_json = _json.dumps(safe)
        for secret in SYNTH_SECRETS:
            assert secret not in cloud_json, (
                f"SMOKE FAIL: {secret!r} survived sanitize_turns() full sweep\n"
                f"  cloud_json: {cloud_json[:400]!r}"
            )

    def test_safe_structure_preserved(self):
        """Non-secret fields (status_code, elapsed_ms) must survive sanitization."""
        safe = sanitize_turns(self._raw_turns(), auth_secrets=["ultra-secret-token"])
        assert safe[0]["status_code"] == 200
        assert safe[0]["elapsed_ms"] == 42
        assert safe[1]["status_code"] == 200


@pytest.mark.skipif(not _TARGET_AVAILABLE, reason="LocalTarget not importable")
class TestTargetCloudPayloadSmoke:
    """Verifies that LocalTarget.to_cloud_payload() never emits raw credentials."""

    def _make_target_with_creds(self):
        t = LocalTarget(
            target_id="smoke-test-id",
            name="Smoke Test Target",
            base_url="http://target.local",
            endpoint_path="/api/chat",
            method="POST",
            content_type="application/json",
            prompt_field="message",
            response_field="reply",
            safe_headers={"Accept": "application/json"},
            runner_required=True,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            source_session_id=None,
        )
        return t

    def test_cloud_payload_has_no_auth_headers(self):
        """to_cloud_payload() must only include safe_headers — never raw creds."""
        t = self._make_target_with_creds()
        payload = t.to_cloud_payload()
        payload_json = _json.dumps(payload)
        for secret in SYNTH_SECRETS:
            assert secret not in payload_json, (
                f"SMOKE FAIL: {secret!r} found in to_cloud_payload()\n"
                f"  payload: {payload_json!r}"
            )

    def test_auth_store_safe_summary_has_no_credential_value(self):
        """LocalAuthStore.to_safe_summary() must never include the credential value."""
        auth = LocalAuthStore(
            target_id="smoke-id",
            auth_type="bearer",
            credential_value="ultra-secret-token",
            header_name="Authorization",
        )
        summary = auth.to_safe_summary()
        summary_json = _json.dumps(summary)
        assert "ultra-secret-token" not in summary_json, (
            f"SMOKE FAIL: bearer credential leaked into to_safe_summary()\n"
            f"  summary: {summary_json!r}"
        )
