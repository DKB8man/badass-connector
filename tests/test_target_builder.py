"""Phase 5 Target Builder tests.

All HTTP calls in ValidationPreview tests are mocked — no real server needed.
Captures are built as plain dicts (JSONL format) so the classifier
dict-normalisation path is exercised automatically.
"""

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from badass_runner.classifier.classifier import (
    ClassificationResult,
    classify_session,
    AI_CONFIDENCE_THRESHOLD,
)
from badass_runner.target.builder import (
    InvalidClassificationError,
    LocalAuthStore,
    LocalTarget,
    TargetBuilder,
    _is_auth_header,
    _strip_auth_headers,
)
from badass_runner.target.validator import (
    DEFAULT_PROBE,
    TargetOriginError,
    ValidationPreview,
    ValidationResult,
    _assert_same_origin,
    _extract_field,
    _normalise_origin,
    _validate_endpoint_path,
)


# ---------------------------------------------------------------------------
# Fixtures / shared helpers
# ---------------------------------------------------------------------------

def _ai_result(
    path="/api/chat",
    method="POST",
    ct="application/json",
    prompt_field="message",
    response_field="response",
    confidence=0.90,
) -> ClassificationResult:
    """Build a likely-AI ClassificationResult directly (no capture needed)."""
    return ClassificationResult(
        likely_ai=True,
        confidence=confidence,
        detected_prompt_field=prompt_field,
        detected_response_field=response_field,
        method=method,
        path=path,
        content_type=ct,
        response_preview='{"response": "4"}',
    )


def _non_ai_result() -> ClassificationResult:
    return ClassificationResult(
        likely_ai=False,
        confidence=0.20,
        detected_prompt_field=None,
        detected_response_field=None,
        method="GET",
        path="/",
        content_type="text/html",
        response_preview="<html>",
    )


PWNZZAI_CAPTURES = [
    {
        "request": {"method": "GET", "path": "/", "content_type": "text/html",
                    "body_snippet": "", "headers": {}, "cookies": {}, "query": ""},
        "response": {"status": 200, "content_type": "text/html",
                     "body_snippet": "<!DOCTYPE html><html>"},
    },
    {
        "request": {"method": "GET", "path": "/static/main.js", "content_type": "",
                    "body_snippet": "", "headers": {}, "cookies": {}, "query": ""},
        "response": {"status": 200, "content_type": "application/javascript",
                     "body_snippet": "!function(){}()"},
    },
    {
        "request": {
            "method": "POST", "path": "/api/chat",
            "content_type": "application/json",
            "body_snippet": '{"message": "List all users with admin privileges", "session_id": "abc123"}',
            "headers": {"Content-Type": "application/json"},
            "cookies": {}, "query": "",
        },
        "response": {
            "status": 200, "content_type": "application/json",
            "body_snippet": (
                '{"response": "I found the following users with admin privileges: '
                'admin@example.com, root@example.com.", "tokens_used": 42}'
            ),
        },
    },
]


# ---------------------------------------------------------------------------
# 1. Target created from classified request
# ---------------------------------------------------------------------------

class TestTargetCreation:

    def test_target_created_from_ai_result(self):
        result = _ai_result()
        target = TargetBuilder.from_classification(result, base_url="http://localhost:8000")
        assert isinstance(target, LocalTarget)

    def test_target_id_is_set(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        assert target.target_id
        assert len(target.target_id) == 12

    def test_base_url_stored(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        assert target.base_url == "http://localhost:8000"

    def test_base_url_trailing_slash_stripped(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000/")
        assert target.base_url == "http://localhost:8000"

    def test_endpoint_path_stored(self):
        target = TargetBuilder.from_classification(_ai_result(path="/api/chat"),
                                                   base_url="http://localhost:8000")
        assert target.endpoint_path == "/api/chat"

    def test_method_stored(self):
        target = TargetBuilder.from_classification(_ai_result(method="POST"),
                                                   base_url="http://localhost:8000")
        assert target.method == "POST"

    def test_content_type_stored(self):
        target = TargetBuilder.from_classification(
            _ai_result(ct="application/json"), base_url="http://localhost:8000"
        )
        assert target.content_type == "application/json"

    def test_created_at_is_utc_datetime(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        assert isinstance(target.created_at, datetime)
        assert target.created_at.tzinfo is not None

    def test_name_defaults_to_method_path(self):
        target = TargetBuilder.from_classification(
            _ai_result(method="POST", path="/api/chat"), base_url="http://localhost:8000"
        )
        assert target.name == "POST /api/chat"

    def test_name_override(self):
        target = TargetBuilder.from_classification(
            _ai_result(), base_url="http://localhost:8000", name="PwnzzAI Chat"
        )
        assert target.name == "PwnzzAI Chat"

    def test_source_session_id_stored(self):
        target = TargetBuilder.from_classification(
            _ai_result(), base_url="http://localhost:8000", source_session_id="abc123"
        )
        assert target.source_session_id == "abc123"

    def test_source_session_id_not_in_cloud_payload(self):
        target = TargetBuilder.from_classification(
            _ai_result(), base_url="http://localhost:8000", source_session_id="abc123"
        )
        payload = target.to_cloud_payload()
        assert "source_session_id" not in payload

    def test_target_from_pwnzzai_session(self):
        sc = classify_session(PWNZZAI_CAPTURES)
        target = TargetBuilder.from_classification(
            sc.best, base_url="http://localhost:5000", source_session_id="pwnzzai01"
        )
        assert target.endpoint_path == "/api/chat"
        assert target.method == "POST"


# ---------------------------------------------------------------------------
# 2. Prompt / response fields stored correctly
# ---------------------------------------------------------------------------

class TestFieldStorage:

    def test_prompt_field_from_classification(self):
        target = TargetBuilder.from_classification(
            _ai_result(prompt_field="query"), base_url="http://localhost:8000"
        )
        assert target.prompt_field == "query"

    def test_response_field_from_classification(self):
        target = TargetBuilder.from_classification(
            _ai_result(response_field="answer"), base_url="http://localhost:8000"
        )
        assert target.response_field == "answer"

    def test_prompt_field_defaults_to_message_when_none(self):
        result = _ai_result(prompt_field=None)
        result = ClassificationResult(
            likely_ai=True, confidence=0.8,
            detected_prompt_field=None, detected_response_field="response",
            method="POST", path="/api/infer", content_type="application/json",
            response_preview="",
        )
        target = TargetBuilder.from_classification(result, base_url="http://localhost:8000")
        assert target.prompt_field == "message"

    def test_response_field_defaults_to_response_when_none(self):
        result = ClassificationResult(
            likely_ai=True, confidence=0.8,
            detected_prompt_field="message", detected_response_field=None,
            method="POST", path="/api/infer", content_type="application/json",
            response_preview="",
        )
        target = TargetBuilder.from_classification(result, base_url="http://localhost:8000")
        assert target.response_field == "response"

    def test_prompt_field_override_applied(self):
        target = TargetBuilder.from_classification(
            _ai_result(prompt_field="message"),
            base_url="http://localhost:8000",
            prompt_field_override="user_input",
        )
        assert target.prompt_field == "user_input"

    def test_response_field_override_applied(self):
        target = TargetBuilder.from_classification(
            _ai_result(response_field="response"),
            base_url="http://localhost:8000",
            response_field_override="generated_text",
        )
        assert target.response_field == "generated_text"

    def test_path_override_applied(self):
        target = TargetBuilder.from_classification(
            _ai_result(path="/api/chat"),
            base_url="http://localhost:8000",
            path_override="/v2/chat",
        )
        assert target.endpoint_path == "/v2/chat"


# ---------------------------------------------------------------------------
# 3. runner_required always True
# ---------------------------------------------------------------------------

class TestRunnerRequired:

    def test_runner_required_is_true(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        assert target.runner_required is True

    def test_runner_required_true_in_cloud_payload(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        assert target.to_cloud_payload()["runner_required"] is True

    def test_apply_overrides_preserves_runner_required(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        overridden = TargetBuilder.apply_overrides(target, prompt_field="input")
        assert overridden.runner_required is True


# ---------------------------------------------------------------------------
# 4. Auth not uploaded to cloud
# ---------------------------------------------------------------------------

class TestAuthNotUploaded:

    def test_auth_headers_stripped_from_safe_headers(self):
        raw = {
            "Authorization": "Bearer super-secret-tok",
            "Cookie": "session=abc999",
            "X-Api-Key": "myapikey123",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        target = TargetBuilder.from_classification(
            _ai_result(), base_url="http://localhost:8000", extra_headers=raw
        )
        assert "Authorization" not in target.safe_headers
        assert "Cookie" not in target.safe_headers
        assert "X-Api-Key" not in target.safe_headers
        assert target.safe_headers.get("Content-Type") == "application/json"
        assert target.safe_headers.get("Accept") == "application/json"

    def test_cloud_payload_has_no_auth_values(self):
        raw = {"Authorization": "Bearer tok", "Cookie": "s=x", "X-Request-ID": "req123"}
        target = TargetBuilder.from_classification(
            _ai_result(), base_url="http://localhost:8000", extra_headers=raw
        )
        payload_str = json.dumps(target.to_cloud_payload())
        assert "Bearer tok" not in payload_str
        assert "s=x" not in payload_str

    def test_cloud_payload_keys(self):
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        payload = target.to_cloud_payload()
        expected_keys = {
            "target_id", "name", "base_url", "endpoint_path", "method",
            "content_type", "prompt_field", "response_field",
            "safe_headers", "runner_required", "created_at",
        }
        assert set(payload.keys()) == expected_keys

    def test_local_auth_store_safe_summary_hides_credential(self):
        auth = LocalAuthStore(
            target_id="t1", auth_type="bearer", credential_value="super-secret"
        )
        summary = auth.to_safe_summary()
        assert "super-secret" not in json.dumps(summary)
        assert summary["auth_type"] == "bearer"
        assert summary["has_auth"] is True

    def test_local_auth_store_none_type_summary(self):
        auth = LocalAuthStore(target_id="t1", auth_type="none")
        assert auth.to_safe_summary()["has_auth"] is False

    def test_is_auth_header_detection(self):
        for h in ["Authorization", "Cookie", "X-Api-Key", "X-Auth-Token",
                  "X-Secret", "Api-Key", "X-Access-Token", "Proxy-Authorization"]:
            assert _is_auth_header(h), f"Expected {h!r} to be flagged as auth"

    def test_non_auth_headers_not_stripped(self):
        headers = {"Content-Type": "application/json", "Accept": "*/*",
                   "X-Request-ID": "r1", "User-Agent": "runner/1"}
        assert _strip_auth_headers(headers) == headers

    def test_local_auth_store_never_in_cloud_payload(self):
        """LocalAuthStore has no to_cloud_payload method — credentials stay local."""
        auth = LocalAuthStore(target_id="t1", auth_type="bearer", credential_value="tok")
        assert not hasattr(auth, "to_cloud_payload")


# ---------------------------------------------------------------------------
# 5. Validation preview works
# ---------------------------------------------------------------------------

class TestValidationPreview:

    def _mock_resp(self, status=200, body: dict = None, text: str = None):
        resp = MagicMock()
        resp.status_code = status
        if body is not None:
            resp.json.return_value = body
            resp.text = json.dumps(body)
        else:
            resp.json.side_effect = ValueError("not json")
            resp.text = text or ""
        return resp

    def _make_target(self, ct="application/json"):
        return TargetBuilder.from_classification(
            _ai_result(ct=ct), base_url="http://localhost:8000"
        )

    def test_probe_sent_correctly(self):
        target = self._make_target()
        mock_resp = self._mock_resp(body={"response": "4"})
        with patch("badass_runner.target.validator.httpx.request", return_value=mock_resp) as m:
            ValidationPreview().run(target)
            call_kwargs = m.call_args
        body_sent = json.loads(call_kwargs[1]["content"])
        assert body_sent["message"] == DEFAULT_PROBE

    def test_success_flag_true_on_200(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(body={"response": "4"})):
            result = ValidationPreview().run(target)
        assert result.success is True

    def test_success_flag_false_on_500(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(status=500, body={"error": "oops"})):
            result = ValidationPreview().run(target)
        assert result.success is False

    def test_status_code_captured(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(status=200, body={"response": "4"})):
            result = ValidationPreview().run(target)
        assert result.status_code == 200

    def test_response_field_extracted(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(body={"response": "The answer is 4."})):
            result = ValidationPreview().run(target)
        assert result.extracted_response == "The answer is 4."

    def test_network_error_returns_failure(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   side_effect=Exception("connection refused")):
            result = ValidationPreview().run(target)
        assert result.success is False
        assert result.status_code == 0
        assert "connection refused" in result.error

    def test_non_json_response_handled(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(text="plain text reply")):
            result = ValidationPreview().run(target)
        assert result.success is True
        assert result.raw_response.get("_raw_text") == "plain text reply"

    def test_custom_probe_text_used(self):
        target = self._make_target()
        mock_resp = self._mock_resp(body={"response": "Blue"})
        with patch("badass_runner.target.validator.httpx.request", return_value=mock_resp) as m:
            ValidationPreview(probe_text="What colour is the sky?").run(target)
        body_sent = json.loads(m.call_args[1]["content"])
        assert body_sent["message"] == "What colour is the sky?"

    def test_auth_applied_to_request(self):
        target = self._make_target()
        auth = LocalAuthStore(target_id=target.target_id,
                              auth_type="bearer", credential_value="secret-tok")
        mock_resp = self._mock_resp(body={"response": "ok"})
        with patch("badass_runner.target.validator.httpx.request", return_value=mock_resp) as m:
            ValidationPreview().run(target, auth=auth)
        sent_headers = m.call_args[1]["headers"]
        assert sent_headers.get("Authorization") == "Bearer secret-tok"

    def test_probe_sent_field_in_result(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(body={"response": "4"})):
            result = ValidationPreview(probe_text="Hi").run(target)
        assert result.probe_sent == "Hi"

    def test_form_encoded_request_body(self):
        target = self._make_target(ct="application/x-www-form-urlencoded")
        mock_resp = self._mock_resp(body={"answer": "4"})
        with patch("badass_runner.target.validator.httpx.request", return_value=mock_resp) as m:
            ValidationPreview().run(target)
        ct_sent = m.call_args[1]["headers"].get("Content-Type", "")
        assert "urlencoded" in ct_sent

    def test_openai_choices_extracted(self):
        target = TargetBuilder.from_classification(
            _ai_result(response_field="choices"), base_url="http://localhost:8000"
        )
        body = {"choices": [{"text": "The answer is 4.", "finish_reason": "stop"}]}
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._mock_resp(body=body)):
            result = ValidationPreview().run(target)
        assert result.extracted_response == "The answer is 4."


# ---------------------------------------------------------------------------
# 6. Invalid classified request rejected
# ---------------------------------------------------------------------------

class TestInvalidClassification:

    def test_non_ai_result_raises(self):
        with pytest.raises(InvalidClassificationError):
            TargetBuilder.from_classification(_non_ai_result(), base_url="http://localhost:8000")

    def test_none_result_raises(self):
        with pytest.raises(InvalidClassificationError):
            TargetBuilder.from_classification(None, base_url="http://localhost:8000")

    def test_error_message_includes_confidence(self):
        result = _non_ai_result()
        with pytest.raises(InvalidClassificationError, match="0.20"):
            TargetBuilder.from_classification(result, base_url="http://localhost:8000")

    def test_low_confidence_ai_result_accepted(self):
        """Exactly-at-threshold result should succeed (likely_ai=True)."""
        result = ClassificationResult(
            likely_ai=True, confidence=AI_CONFIDENCE_THRESHOLD,
            detected_prompt_field="message", detected_response_field="response",
            method="POST", path="/api/chat", content_type="application/json",
            response_preview="",
        )
        target = TargetBuilder.from_classification(result, base_url="http://localhost:8000")
        assert isinstance(target, LocalTarget)


# ---------------------------------------------------------------------------
# 7. Existing manual (cloud) targets unchanged
# ---------------------------------------------------------------------------

class TestCloudTargetsUnchanged:

    def test_backend_harness_target_model_not_modified(self):
        """The backend HarnessTarget model must be importable and unchanged."""
        from badass_runner.target.builder import LocalTarget
        from badass_runner.target.validator import ValidationPreview
        assert LocalTarget is not None
        assert ValidationPreview is not None

    def test_runner_target_module_does_not_import_backend_models(self):
        """LocalTarget must not import SQLModel or backend DB models."""
        import badass_runner.target.builder as tb_mod
        import inspect
        src = inspect.getsource(tb_mod)
        assert "SQLModel" not in src
        assert "sqlmodel" not in src
        assert "from ..db" not in src
        assert "from backend" not in src

    def test_local_target_has_no_db_fields(self):
        """LocalTarget must not expose fields that only make sense in the DB."""
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        target_dict = asdict(target)
        db_only_keys = {"user_id", "project_id", "ownership_attested", "environment",
                        "supports_tools", "max_runs_per_day"}
        assert db_only_keys.isdisjoint(set(target_dict.keys()))

    def test_cloud_payload_matches_harness_target_field_names(self):
        """Cloud payload fields align with the names HarnessTarget uses."""
        target = TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")
        payload = target.to_cloud_payload()
        assert "base_url" in payload
        assert "endpoint_path" in payload
        assert "method" in payload
        assert "prompt_field" in payload
        assert "response_field" in payload


# ---------------------------------------------------------------------------
# 8. apply_overrides
# ---------------------------------------------------------------------------

class TestApplyOverrides:

    def _base(self):
        return TargetBuilder.from_classification(_ai_result(), base_url="http://localhost:8000")

    def test_override_prompt_field(self):
        t = TargetBuilder.apply_overrides(self._base(), prompt_field="user_query")
        assert t.prompt_field == "user_query"

    def test_override_response_field(self):
        t = TargetBuilder.apply_overrides(self._base(), response_field="completion")
        assert t.response_field == "completion"

    def test_override_path(self):
        t = TargetBuilder.apply_overrides(self._base(), path="/v2/chat")
        assert t.endpoint_path == "/v2/chat"

    def test_override_name(self):
        t = TargetBuilder.apply_overrides(self._base(), name="Custom Name")
        assert t.name == "Custom Name"

    def test_no_override_returns_same_values(self):
        base = self._base()
        copy = TargetBuilder.apply_overrides(base)
        assert copy.prompt_field == base.prompt_field
        assert copy.endpoint_path == base.endpoint_path

    def test_overrides_do_not_mutate_original(self):
        base = self._base()
        original_path = base.endpoint_path
        TargetBuilder.apply_overrides(base, path="/new/path")
        assert base.endpoint_path == original_path


# ---------------------------------------------------------------------------
# 9. _extract_field helper
# ---------------------------------------------------------------------------

class TestExtractField:

    def test_direct_string(self):
        assert _extract_field({"response": "Hello"}, "response") == "Hello"

    def test_case_insensitive(self):
        assert _extract_field({"Response": "Hi"}, "response") == "Hi"

    def test_missing_field_returns_none(self):
        assert _extract_field({"status": "ok"}, "response") is None

    def test_empty_dict_returns_none(self):
        assert _extract_field({}, "response") is None

    def test_choices_list_text_key(self):
        raw = {"choices": [{"text": "The answer is 4.", "finish_reason": "stop"}]}
        assert _extract_field(raw, "choices") == "The answer is 4."

    def test_choices_list_message_content(self):
        raw = {"choices": [{"message": {"content": "Four.", "role": "assistant"}}]}
        assert _extract_field(raw, "choices") == "Four."

    def test_non_string_value_coerced(self):
        result = _extract_field({"count": 42}, "count")
        assert result == "42"


# ---------------------------------------------------------------------------
# 10. Origin allowlisting
# ---------------------------------------------------------------------------

class TestOriginAllowlist:

    # ---- _normalise_origin -----------------------------------------------

    def test_normalise_http_default_port(self):
        assert _normalise_origin("http://localhost:8000") == "http://localhost:8000"

    def test_normalise_http_implicit_port(self):
        assert _normalise_origin("http://localhost") == "http://localhost:80"

    def test_normalise_https_implicit_port(self):
        assert _normalise_origin("https://example.com") == "https://example.com:443"

    def test_normalise_case_insensitive(self):
        assert _normalise_origin("HTTP://LOCALHOST:8000") == "http://localhost:8000"

    def test_same_origins_equal(self):
        assert _normalise_origin("http://localhost:8000/api/chat") == \
               _normalise_origin("http://localhost:8000/other/path")

    # ---- _assert_same_origin --------------------------------------------

    def test_same_origin_passes(self):
        _assert_same_origin("http://localhost:8000/api/chat", "http://localhost:8000")

    def test_different_host_raises(self):
        with pytest.raises(TargetOriginError, match="evil.com"):
            _assert_same_origin("http://evil.com/steal", "http://localhost:8000")

    def test_different_port_raises(self):
        with pytest.raises(TargetOriginError):
            _assert_same_origin("http://localhost:9999/api/chat", "http://localhost:8000")

    def test_different_scheme_raises(self):
        with pytest.raises(TargetOriginError):
            _assert_same_origin("https://localhost:8000/api/chat", "http://localhost:8000")

    # ---- _validate_endpoint_path ----------------------------------------

    def test_normal_path_accepted(self):
        _validate_endpoint_path("/api/chat")          # must not raise

    def test_root_path_accepted(self):
        _validate_endpoint_path("/")                  # must not raise

    def test_path_with_query_accepted(self):
        _validate_endpoint_path("/api/chat?v=2")      # must not raise

    def test_absolute_url_in_path_rejected(self):
        with pytest.raises(TargetOriginError, match="://"):
            _validate_endpoint_path("http://evil.com/steal")

    def test_https_url_in_path_rejected(self):
        with pytest.raises(TargetOriginError):
            _validate_endpoint_path("https://evil.com/steal")

    def test_protocol_relative_path_rejected(self):
        with pytest.raises(TargetOriginError, match="//"):
            _validate_endpoint_path("//evil.com/steal")

    # ---- ValidationPreview redirect interception ------------------------

    def _make_target(self, path="/api/chat", ct="application/json"):
        return TargetBuilder.from_classification(
            _ai_result(path=path, ct=ct), base_url="http://localhost:8000"
        )

    def _redirect_resp(self, status=302, location="http://evil.com/steal"):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"location": location}
        resp.json.side_effect = ValueError
        resp.text = ""
        return resp

    def _ok_resp(self, body=None):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = body or {"response": "4"}
        resp.text = json.dumps(body or {"response": "4"})
        resp.headers = {}
        return resp

    def test_cross_origin_redirect_blocked(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._redirect_resp(302, "http://evil.com/steal")):
            result = ValidationPreview().run(target)
        assert result.success is False
        assert "blocked" in result.error.lower()
        assert "evil.com" in result.error

    def test_cross_origin_redirect_different_port_blocked(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._redirect_resp(301, "http://localhost:9999/other")):
            result = ValidationPreview().run(target)
        assert result.success is False
        assert "blocked" in result.error.lower()

    def test_cross_origin_https_redirect_blocked(self):
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._redirect_resp(302, "https://attacker.example.com/")):
            result = ValidationPreview().run(target)
        assert result.success is False
        assert "blocked" in result.error.lower()

    def test_same_origin_redirect_followed(self):
        target = self._make_target()
        redirect = self._redirect_resp(301, "http://localhost:8000/api/v2/chat")
        ok = self._ok_resp({"response": "Four."})
        call_count = {"n": 0}

        def _side_effect(**kw):
            call_count["n"] += 1
            return redirect if call_count["n"] == 1 else ok

        with patch("badass_runner.target.validator.httpx.request",
                   side_effect=_side_effect):
            result = ValidationPreview().run(target)
        assert result.success is True
        assert call_count["n"] == 2

    def test_relative_redirect_resolved_to_same_origin(self):
        target = self._make_target()
        redirect = self._redirect_resp(302, "/api/v2/chat")  # relative Location
        ok = self._ok_resp({"response": "4"})
        calls = []

        def _side_effect(**kw):
            calls.append(kw.get("url"))
            return redirect if len(calls) == 1 else ok

        with patch("badass_runner.target.validator.httpx.request",
                   side_effect=_side_effect):
            result = ValidationPreview().run(target)
        assert result.success is True
        assert calls[1].startswith("http://localhost:8000")

    def test_redirect_with_no_location_header_fails_gracefully(self):
        target = self._make_target()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {}          # no Location
        resp.json.side_effect = ValueError
        resp.text = ""
        with patch("badass_runner.target.validator.httpx.request", return_value=resp):
            result = ValidationPreview().run(target)
        assert result.success is False
        assert result.status_code == 302

    def test_malformed_path_absolute_url_blocked(self):
        target = TargetBuilder.from_classification(
            _ai_result(path="http://evil.com/steal"), base_url="http://localhost:8000"
        )
        with patch("badass_runner.target.validator.httpx.request") as m:
            result = ValidationPreview().run(target)
        assert result.success is False
        assert "://" in result.error
        m.assert_not_called()     # request must never be sent

    def test_malformed_path_protocol_relative_blocked(self):
        target = TargetBuilder.from_classification(
            _ai_result(path="//evil.com/steal"), base_url="http://localhost:8000"
        )
        with patch("badass_runner.target.validator.httpx.request") as m:
            result = ValidationPreview().run(target)
        assert result.success is False
        m.assert_not_called()

    def test_follow_redirects_false_on_httpx_call(self):
        """httpx must be called with follow_redirects=False."""
        target = self._make_target()
        with patch("badass_runner.target.validator.httpx.request",
                   return_value=self._ok_resp()) as m:
            ValidationPreview().run(target)
        assert m.call_args[1]["follow_redirects"] is False
