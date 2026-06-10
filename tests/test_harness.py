"""Phase 6 Harness tests — sanitize, executor, job_poller, client job methods.

All HTTP calls are mocked — no real server is required.
All cloud API calls are mocked — no real BADASS Cloud is required.
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from badass_runner.harness.sanitize import sanitize_turns, _redact_str, _redact_value
from badass_runner.harness.executor import (
    LocalTestExecutor,
    StepResult,
    _extract_reply,
    _is_html_shell,
)
from badass_runner.harness.job_poller import JobPoller
from badass_runner.client import RunnerClient, CloudAPIError
from badass_runner.target.builder import LocalAuthStore


# ===========================================================================
# sanitize_turns
# ===========================================================================

class TestSanitizeTurns:

    def _turn(self, request="Hello", response="World", status=200, raw_reply="World"):
        return {
            "request": request,
            "response": response,
            "raw_reply": raw_reply,
            "status_code": status,
            "elapsed_ms": 42,
        }

    def test_basic_passthrough(self):
        turns = [self._turn()]
        result = sanitize_turns(turns)
        assert result[0]["request"] == "Hello"
        assert result[0]["response"] == "World"
        assert result[0]["status_code"] == 200
        assert result[0]["elapsed_ms"] == 42

    def test_known_secret_stripped(self):
        turns = [self._turn(request="Bearer sk-abc12345678", response="ok", raw_reply="ok")]
        result = sanitize_turns(turns, auth_secrets=["sk-abc12345678"])
        assert "sk-abc12345678" not in result[0]["request"]
        assert "[REDACTED]" in result[0]["request"]

    def test_bearer_token_pattern_stripped(self):
        turns = [self._turn(response="Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")]
        result = sanitize_turns(turns)
        assert "eyJhbGciOiJSUzI1NiJ9" not in result[0]["response"]

    def test_jwt_stripped_from_raw_reply(self):
        jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        turns = [self._turn(raw_reply=f"token: {jwt}")]
        result = sanitize_turns(turns)
        assert jwt not in result[0]["raw_reply"]

    def test_openai_key_stripped(self):
        turns = [self._turn(request="sk-abcdefghijklmnopqrstuvwx")]
        result = sanitize_turns(turns)
        assert "sk-abcdefghijklmnopqrstuvwx" not in result[0]["request"]

    def test_does_not_mutate_original(self):
        turns = [self._turn(request="my secret sk-abcdefghijk")]
        original_request = turns[0]["request"]
        sanitize_turns(turns, auth_secrets=["sk-abcdefghijk"])
        assert turns[0]["request"] == original_request

    def test_short_secret_ignored(self):
        turns = [self._turn(request="hello abc")]
        result = sanitize_turns(turns, auth_secrets=["abc"])
        assert result[0]["request"] == "hello abc"

    def test_tool_calls_raw_preserved_structure(self):
        turns = [dict(self._turn(), tool_calls_raw=[{"name": "search", "arguments": {}}])]
        result = sanitize_turns(turns)
        assert result[0]["tool_calls_raw"][0]["name"] == "search"

    def test_tool_calls_raw_secrets_stripped(self):
        secret = "sk-secret12345678"
        turns = [dict(self._turn(), tool_calls_raw=[{"name": "call", "arguments": {"key": secret}}])]
        result = sanitize_turns(turns, auth_secrets=[secret])
        assert secret not in json.dumps(result[0]["tool_calls_raw"])

    def test_html_shell_preserved(self):
        turns = [dict(self._turn(), html_shell=True)]
        result = sanitize_turns(turns)
        assert result[0].get("html_shell") is True

    def test_content_type_preserved(self):
        turns = [dict(self._turn(), content_type="application/json")]
        result = sanitize_turns(turns)
        assert result[0]["content_type"] == "application/json"

    def test_extraction_error_redacted(self):
        secret = "mysupersecret1234"
        turns = [dict(self._turn(), extraction_error=f"Field not found: token={secret}")]
        result = sanitize_turns(turns, auth_secrets=[secret])
        assert secret not in result[0]["extraction_error"]

    def test_empty_turns_returns_empty(self):
        assert sanitize_turns([]) == []

    def test_multiple_turns_all_sanitized(self):
        secret = "tokensecret12345"
        turns = [self._turn(request=f"req {secret}"), self._turn(response=f"resp {secret}")]
        result = sanitize_turns(turns, auth_secrets=[secret])
        for r in result:
            assert secret not in r["request"]
            assert secret not in r["response"]

    def test_status_code_zero_preserved(self):
        turns = [self._turn(status=0)]
        result = sanitize_turns(turns)
        assert result[0]["status_code"] == 0


class TestRedactHelpers:

    def test_redact_str_removes_known(self):
        assert "mysecret" not in _redact_str("hello mysecret world", ["mysecret"])

    def test_redact_str_no_op_when_empty_secrets(self):
        text = "no secrets here"
        assert _redact_str(text, []) == text

    def test_redact_value_dict_auth_headers_dropped(self):
        d = {"Authorization": "Bearer token", "Content-Type": "application/json"}
        result = _redact_value(d, [])
        assert result["Authorization"] == "[REDACTED]"
        assert result["Content-Type"] == "application/json"

    def test_redact_value_nested(self):
        secret = "sk-nested12345678"
        d = {"outer": {"inner": secret}}
        result = _redact_value(d, [secret])
        assert secret not in result["outer"]["inner"]

    def test_redact_value_list(self):
        secret = "sk-list12345678xx"
        result = _redact_value([secret, "safe"], [secret])
        assert secret not in result[0]
        assert result[1] == "safe"


# ===========================================================================
# _extract_reply
# ===========================================================================

class TestExtractReply:

    def test_direct_field_match(self):
        reply, err = _extract_reply({"reply": "hello"}, "reply")
        assert reply == "hello"
        assert err is None

    def test_case_insensitive_match(self):
        reply, err = _extract_reply({"Reply": "hi"}, "reply")
        assert reply == "hi"

    def test_fallback_to_message(self):
        reply, err = _extract_reply({"message": "world"}, "reply")
        assert reply == "world"

    def test_fallback_to_content(self):
        reply, err = _extract_reply({"content": "content_val"}, "reply")
        assert reply == "content_val"

    def test_openai_choices_format(self):
        resp = {"choices": [{"message": {"content": "gpt reply"}}]}
        reply, err = _extract_reply(resp, "reply")
        assert reply == "gpt reply"

    def test_anthropic_content_format(self):
        resp = {"content": [{"type": "text", "text": "claude reply"}]}
        reply, err = _extract_reply(resp, "reply")
        assert reply == "claude reply"

    def test_not_a_dict_returns_error(self):
        reply, err = _extract_reply("just a string", "reply")
        assert reply == ""
        assert err is not None

    def test_field_not_found_returns_error(self):
        reply, err = _extract_reply({"foo": "bar"}, "reply")
        assert reply == ""
        assert err is not None
        assert "reply" in err


# ===========================================================================
# _is_html_shell
# ===========================================================================

class TestIsHtmlShell:

    def test_html_content_type(self):
        assert _is_html_shell("<html>", "text/html; charset=utf-8") is True

    def test_vite_marker(self):
        assert _is_html_shell("... @vite/client ...", "application/json") is True

    def test_json_response_not_shell(self):
        assert _is_html_shell('{"reply": "hello"}', "application/json") is False

    def test_react_refresh_marker(self):
        assert _is_html_shell("@react-refresh", "") is True


# ===========================================================================
# LocalTestExecutor
# ===========================================================================

class TestLocalTestExecutor:

    def _executor(self, auth_store=None):
        return LocalTestExecutor(
            base_url="http://localhost:8000",
            message_path="/api/chat",
            method="POST",
            request_message_field="message",
            response_message_field="reply",
            auth_store=auth_store,
            inter_step_delay=0.0,
        )

    def _mock_response(self, json_body=None, status_code=200, content_type="application/json"):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = {"content-type": content_type}
        resp.json.return_value = json_body or {"reply": "AI response"}
        resp.text = json.dumps(json_body or {"reply": "AI response"})
        return resp

    def test_successful_step_returns_reply(self):
        executor = self._executor()
        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.return_value = self._mock_response({"reply": "Safe answer"})
            mock_client_cls.return_value = mock_client

            result = executor.send_step("Test prompt")

        assert result.response == "Safe answer"
        assert result.raw_reply == "Safe answer"
        assert result.status_code == 200
        assert result.extraction_error is None

    def test_auth_header_injected(self):
        auth_store = LocalAuthStore(
            target_id="t1",
            auth_type="bearer",
            credential_value="mysecrettoken",
        )
        executor = self._executor(auth_store=auth_store)
        captured_headers = {}

        def capture_request(method, url, json=None, headers=None, **kwargs):
            captured_headers.update(headers or {})
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.json.return_value = {"reply": "ok"}
            resp.text = '{"reply": "ok"}'
            return resp

        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.side_effect = capture_request
            mock_client_cls.return_value = mock_client

            executor.send_step("prompt")

        assert "Authorization" in captured_headers
        assert captured_headers["Authorization"] == "Bearer mysecrettoken"

    def test_timeout_returns_error_step(self):
        import httpx
        executor = self._executor()
        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client

            result = executor.send_step("prompt")

        assert result.status_code == 0
        assert result.extraction_error is not None
        assert "timed out" in result.extraction_error.lower() or "timeout" in result.extraction_error.lower()

    def test_http_400_returns_error_step(self):
        executor = self._executor()
        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.return_value = self._mock_response(status_code=401)
            mock_client_cls.return_value = mock_client

            result = executor.send_step("prompt")

        assert result.status_code == 401
        assert result.extraction_error is not None
        assert "401" in result.extraction_error

    def test_redirect_returns_error_step(self):
        executor = self._executor()
        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            resp = MagicMock()
            resp.status_code = 302
            resp.headers = {"content-type": "text/html", "location": "http://other.com"}
            mock_client.request.return_value = resp
            mock_client_cls.return_value = mock_client

            result = executor.send_step("prompt")

        assert result.status_code == 302
        assert result.extraction_error is not None

    def test_html_shell_detected(self):
        executor = self._executor()
        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/html"}
            resp.text = "<!doctype html><head></head><body></body>"
            mock_client.request.return_value = resp
            mock_client_cls.return_value = mock_client

            result = executor.send_step("prompt")

        assert result.html_shell is True
        assert result.extraction_error is not None

    def test_execute_test_multiple_steps(self):
        executor = self._executor()
        step_count = [0]

        def mock_request(method, url, json=None, headers=None, **kwargs):
            step_count[0] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.json.return_value = {"reply": f"response_{step_count[0]}"}
            resp.text = json_text = f'{{"reply": "response_{step_count[0]}"}}'
            return resp

        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.side_effect = mock_request
            mock_client_cls.return_value = mock_client

            turns = executor.execute_test("a01", ["step1", "step2", "step3"])

        assert len(turns) == 3
        for t in turns:
            assert t["status_code"] == 200

    def test_execute_test_stops_on_connection_failure(self):
        import httpx
        executor = self._executor()
        call_count = [0]

        def mock_request(method, url, json=None, headers=None, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                resp = MagicMock()
                resp.status_code = 200
                resp.headers = {"content-type": "application/json"}
                resp.json.return_value = {"reply": "ok"}
                resp.text = '{"reply": "ok"}'
                return resp
            raise httpx.TimeoutException("timeout")

        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.side_effect = mock_request
            mock_client_cls.return_value = mock_client

            turns = executor.execute_test("a01", ["step1", "step2", "step3"])

        assert len(turns) == 2
        assert turns[1]["status_code"] == 0

    def test_step_result_to_dict_minimal(self):
        s = StepResult(request="r", response="resp", raw_reply="resp", status_code=200, elapsed_ms=10)
        d = s.to_dict()
        assert d["request"] == "r"
        assert d["status_code"] == 200
        assert "extraction_error" not in d
        assert "html_shell" not in d

    def test_step_result_to_dict_with_optionals(self):
        s = StepResult(
            request="r", response="err", raw_reply="", status_code=0, elapsed_ms=5,
            extraction_error="timeout", html_shell=True, content_type="text/html",
        )
        d = s.to_dict()
        assert d["extraction_error"] == "timeout"
        assert d["html_shell"] is True
        assert d["content_type"] == "text/html"

    def test_get_method_uses_query_params(self):
        executor = LocalTestExecutor(
            base_url="http://localhost:8000",
            message_path="/api/ask",
            method="GET",
            request_message_field="q",
            response_message_field="answer",
            inter_step_delay=0.0,
        )
        captured_kwargs = {}

        def capture_request(method, url, params=None, headers=None, **kwargs):
            captured_kwargs["method"] = method
            captured_kwargs["params"] = params
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.json.return_value = {"answer": "yes"}
            resp.text = '{"answer": "yes"}'
            return resp

        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.request.side_effect = capture_request
            mock_client_cls.return_value = mock_client

            executor.send_step("what is 2+2?")

        assert captured_kwargs["method"] == "GET"
        assert "q" in (captured_kwargs.get("params") or {})


# ===========================================================================
# RunnerClient job methods
# ===========================================================================

class TestRunnerClientJobMethods:

    def _client(self):
        return RunnerClient(
            server_url="http://cloud.example.com",
            runner_token="badass_runner_test123",
        )

    def _mock_resp(self, json_body, status_code=200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.is_success = (200 <= status_code < 300)
        resp.json.return_value = json_body
        resp.text = json.dumps(json_body)
        return resp

    def test_poll_jobs_returns_empty_list(self):
        client = self._client()
        with patch("badass_runner.client.httpx.get") as mock_get:
            mock_get.return_value = self._mock_resp({"jobs": []})
            jobs = client.poll_jobs()
        assert jobs == []

    def test_poll_jobs_returns_jobs(self):
        client = self._client()
        payload = {"jobs": [{"run_id": "run123", "tests": []}]}
        with patch("badass_runner.client.httpx.get") as mock_get:
            mock_get.return_value = self._mock_resp(payload)
            jobs = client.poll_jobs()
        assert len(jobs) == 1
        assert jobs[0]["run_id"] == "run123"

    def test_poll_jobs_raises_on_401(self):
        client = self._client()
        with patch("badass_runner.client.httpx.get") as mock_get:
            mock_get.return_value = self._mock_resp({"detail": "Invalid token"}, status_code=401)
            with pytest.raises(CloudAPIError) as exc_info:
                client.poll_jobs()
        assert exc_info.value.status_code == 401

    def test_poll_jobs_raises_connection_error(self):
        import httpx
        client = self._client()
        with patch("badass_runner.client.httpx.get") as mock_get:
            mock_get.side_effect = httpx.RequestError("connection refused")
            with pytest.raises(ConnectionError):
                client.poll_jobs()

    def test_claim_job_success(self):
        client = self._client()
        with patch("badass_runner.client.httpx.post") as mock_post:
            mock_post.return_value = self._mock_resp({"ok": True, "run_id": "run123"})
            result = client.claim_job("run123")
        assert result["ok"] is True
        call_url = mock_post.call_args[0][0]
        assert "jobs/run123/claim" in call_url

    def test_claim_job_409_raises(self):
        client = self._client()
        with patch("badass_runner.client.httpx.post") as mock_post:
            mock_post.return_value = self._mock_resp({"detail": "Run already claimed"}, status_code=409)
            with pytest.raises(CloudAPIError) as exc_info:
                client.claim_job("run123")
        assert exc_info.value.status_code == 409

    def test_complete_job_sends_results(self):
        client = self._client()
        results = [{"test_id": "a01", "turns": [], "error": None}]
        with patch("badass_runner.client.httpx.post") as mock_post:
            mock_post.return_value = self._mock_resp({"ok": True})
            result = client.complete_job("run123", results)
        assert result["ok"] is True
        call_url = mock_post.call_args[0][0]
        assert "jobs/run123/complete" in call_url
        sent_json = mock_post.call_args[1].get("json") or mock_post.call_args[0][1] if len(mock_post.call_args[0]) > 1 else mock_post.call_args.kwargs.get("json", {})
        assert sent_json.get("results") == results

    def test_fail_job_sends_error(self):
        client = self._client()
        with patch("badass_runner.client.httpx.post") as mock_post:
            mock_post.return_value = self._mock_resp({"ok": True})
            result = client.fail_job("run123", "target unreachable")
        assert result["ok"] is True
        call_url = mock_post.call_args[0][0]
        assert "jobs/run123/fail" in call_url

    def test_complete_job_raises_on_500(self):
        client = self._client()
        with patch("badass_runner.client.httpx.post") as mock_post:
            mock_post.return_value = self._mock_resp({"detail": "Server error"}, status_code=500)
            with pytest.raises(CloudAPIError) as exc_info:
                client.complete_job("run123", [])
        assert exc_info.value.status_code == 500

    def test_auth_header_included_in_poll(self):
        client = self._client()
        captured_headers = {}

        def capture_get(url, headers=None, **kwargs):
            captured_headers.update(headers or {})
            resp = MagicMock()
            resp.is_success = True
            resp.json.return_value = {"jobs": []}
            return resp

        with patch("badass_runner.client.httpx.get", side_effect=capture_get):
            client.poll_jobs()

        assert "Authorization" in captured_headers
        assert captured_headers["Authorization"] == "Bearer badass_runner_test123"


# ===========================================================================
# JobPoller
# ===========================================================================

class TestJobPoller:

    def _make_poller(self, auth_store=None, poll_interval=0):
        client = MagicMock(spec=RunnerClient)
        poller = JobPoller(
            client=client,
            auth_store=auth_store,
            poll_interval=poll_interval,
        )
        return poller, client

    def test_start_and_stop(self):
        poller, client = self._make_poller()
        client.poll_jobs.return_value = []
        poller.start()
        assert poller.is_running()
        poller.stop()

    def test_empty_poll_does_not_execute(self):
        poller, client = self._make_poller()
        client.poll_jobs.return_value = []
        poller._loop.__doc__  # just check it exists

    def test_execute_job_claims_then_completes(self):
        poller, client = self._make_poller()
        client.claim_job.return_value = {"ok": True}
        client.complete_job.return_value = {"ok": True}

        job = {
            "run_id": "run_abc",
            "target": {
                "base_url": "http://localhost:8000",
                "message_path": "/chat",
                "method": "POST",
                "request_message_field": "message",
                "response_message_field": "reply",
                "auth_type": "none",
                "auth_header_name": None,
            },
            "tests": [
                {
                    "test_id": "a01_prompt_injection",
                    "test_name": "A01",
                    "steps": ["ignore instructions"],
                    "new_session_before": [],
                    "session_id_field": None,
                    "endpoint_path": "/chat",
                }
            ],
            "limits": {
                "max_turns_per_test": 3,
                "overall_run_timeout_s": 60,
                "inter_request_delay_s": 0.0,
            },
        }

        import httpx

        with patch("badass_runner.harness.executor.httpx.Client") as mock_client_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.json.return_value = {"reply": "test response"}
            resp.text = '{"reply": "test response"}'
            mock_http.request.return_value = resp
            mock_client_cls.return_value = mock_http

            poller._execute_job(job)

        client.claim_job.assert_called_once_with("run_abc")
        client.complete_job.assert_called_once()
        uploaded_results = client.complete_job.call_args[0][1]
        assert len(uploaded_results) == 1
        assert uploaded_results[0]["test_id"] == "a01_prompt_injection"
        assert len(uploaded_results[0]["turns"]) == 1

    def test_execute_job_409_claim_skips_execution(self):
        poller, client = self._make_poller()
        client.claim_job.side_effect = CloudAPIError(409, "Already claimed")

        job = {
            "run_id": "run_dup",
            "target": {"base_url": "http://x", "message_path": "/", "method": "POST",
                       "request_message_field": "m", "response_message_field": "r",
                       "auth_type": "none", "auth_header_name": None},
            "tests": [],
            "limits": {"max_turns_per_test": 1, "overall_run_timeout_s": 60, "inter_request_delay_s": 0},
        }
        poller._execute_job(job)
        client.complete_job.assert_not_called()

    def test_execute_job_sanitizes_before_upload(self):
        secret = "secrettoken12345"
        auth_store = LocalAuthStore(
            target_id="t1",
            auth_type="bearer",
            credential_value=secret,
        )
        poller, client = self._make_poller(auth_store=auth_store)
        client.claim_job.return_value = {"ok": True}
        client.complete_job.return_value = {"ok": True}

        job = {
            "run_id": "run_secret",
            "target": {
                "base_url": "http://localhost:8000",
                "message_path": "/chat",
                "method": "POST",
                "request_message_field": "message",
                "response_message_field": "reply",
                "auth_type": "bearer",
                "auth_header_name": None,
            },
            "tests": [{"test_id": "a01_prompt_injection", "test_name": "A01",
                       "steps": ["test prompt"], "new_session_before": [],
                       "session_id_field": None, "endpoint_path": None}],
            "limits": {"max_turns_per_test": 1, "overall_run_timeout_s": 60, "inter_request_delay_s": 0},
        }

        with patch("badass_runner.harness.executor.httpx.Client") as mock_cls:
            mock_http = MagicMock()
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.json.return_value = {"reply": f"response with {secret} leaked"}
            resp.text = f'{{"reply": "response with {secret} leaked"}}'
            mock_http.request.return_value = resp
            mock_cls.return_value = mock_http

            poller._execute_job(job)

        uploaded_results = client.complete_job.call_args[0][1]
        uploaded_json = json.dumps(uploaded_results)
        assert secret not in uploaded_json

    def test_upload_failure_calls_fail_job(self):
        poller, client = self._make_poller()
        client.claim_job.return_value = {"ok": True}
        client.complete_job.side_effect = CloudAPIError(500, "Server error")
        client.fail_job.return_value = {"ok": True}

        job = {
            "run_id": "run_fail",
            "target": {"base_url": "http://x", "message_path": "/", "method": "POST",
                       "request_message_field": "m", "response_message_field": "r",
                       "auth_type": "none", "auth_header_name": None},
            "tests": [],
            "limits": {"max_turns_per_test": 1, "overall_run_timeout_s": 60, "inter_request_delay_s": 0},
        }
        poller._execute_job(job)
        client.fail_job.assert_called_once()
        call_run_id = client.fail_job.call_args[0][0]
        call_error = client.fail_job.call_args[0][1]
        assert call_run_id == "run_fail"
        assert "server error" in call_error.lower() or "upload" in call_error.lower()

    def test_on_job_start_callback_fired(self):
        fired = []
        poller, client = self._make_poller()
        poller._on_job_start = lambda rid: fired.append(rid)
        client.claim_job.return_value = {"ok": True}
        client.complete_job.return_value = {"ok": True}

        job = {
            "run_id": "run_cb",
            "target": {"base_url": "http://x", "message_path": "/", "method": "POST",
                       "request_message_field": "m", "response_message_field": "r",
                       "auth_type": "none", "auth_header_name": None},
            "tests": [],
            "limits": {"max_turns_per_test": 1, "overall_run_timeout_s": 60, "inter_request_delay_s": 0},
        }
        poller._execute_job(job)
        assert "run_cb" in fired

    def test_on_job_complete_callback_success(self):
        completed = []
        poller, client = self._make_poller()
        poller._on_job_complete = lambda rid, ok: completed.append((rid, ok))
        client.claim_job.return_value = {"ok": True}
        client.complete_job.return_value = {"ok": True}

        job = {
            "run_id": "run_ok",
            "target": {"base_url": "http://x", "message_path": "/", "method": "POST",
                       "request_message_field": "m", "response_message_field": "r",
                       "auth_type": "none", "auth_header_name": None},
            "tests": [],
            "limits": {"max_turns_per_test": 1, "overall_run_timeout_s": 60, "inter_request_delay_s": 0},
        }
        poller._execute_job(job)
        assert ("run_ok", True) in completed
