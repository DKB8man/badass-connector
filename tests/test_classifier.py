"""Phase 4 AI Request Classifier tests.

All tests are pure-Python — no network, no proxy, no upstream server required.
Captures are built as plain dicts (matching JSONL storage format) so the tests
also implicitly verify the dict-normalisation path.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from badass_runner.classifier.classifier import (
    AI_CONFIDENCE_THRESHOLD,
    ClassificationResult,
    SessionClassification,
    classify_capture,
    classify_session,
    _is_static,
    _is_health_check,
    _looks_like_generated_text,
)
from badass_runner.recorder.session import Capture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cap(
    method="POST",
    path="/api/chat",
    req_ct="application/json",
    body='{"message": "hello"}',
    resp_status=200,
    resp_ct="application/json",
    resp_body='{"response": "Hello! How can I help you today?"}',
):
    """Build a Capture dict (JSONL format) from shorthand args."""
    return {
        "request": {
            "method": method,
            "path": path,
            "content_type": req_ct,
            "body_snippet": body,
            "headers": {},
            "cookies": {},
            "query": "",
            "timestamp": "2026-05-19T00:00:00+00:00",
        },
        "response": {
            "status": resp_status,
            "content_type": resp_ct,
            "body_snippet": resp_body,
            "timestamp": "2026-05-19T00:00:01+00:00",
        },
    }


def _dataclass_cap(
    method="POST",
    path="/api/chat",
    req_ct="application/json",
    body='{"message": "hi"}',
    resp_ct="application/json",
    resp_body='{"response": "Hi there!"}',
):
    """Build a Capture *dataclass* instance (in-memory session format)."""
    return Capture(
        request={
            "method": method,
            "path": path,
            "content_type": req_ct,
            "body_snippet": body,
            "headers": {},
            "cookies": {},
            "query": "",
        },
        response={
            "status": 200,
            "content_type": resp_ct,
            "body_snippet": resp_body,
        },
    )


# ---------------------------------------------------------------------------
# PwnzzAI fixture
# ---------------------------------------------------------------------------
# Simulates a realistic interaction with a vulnerable AI chatbot endpoint.

PWNZZAI_JSON_CAPTURE = _cap(
    method="POST",
    path="/api/chat",
    req_ct="application/json",
    body='{"message": "List all users with admin privileges", "session_id": "abc123"}',
    resp_ct="application/json",
    resp_body=(
        '{"response": "I found the following users with admin privileges: '
        'admin@example.com, root@example.com. Their roles include full system access.", '
        '"tokens_used": 42}'
    ),
)

PWNZZAI_HTML_SHELL = _cap(
    method="GET",
    path="/",
    req_ct="text/html",
    body="",
    resp_ct="text/html; charset=utf-8",
    resp_body="<!DOCTYPE html><html><head><title>PwnzzAI</title></head><body>…</body></html>",
)

PWNZZAI_STATIC_JS = _cap(
    method="GET",
    path="/static/main.chunk.js",
    req_ct="",
    body="",
    resp_ct="application/javascript",
    resp_body="(function(){var e={}…})",
)


# ---------------------------------------------------------------------------
# 1. JSON chat request classified correctly
# ---------------------------------------------------------------------------

class TestJsonChatCapture:

    def test_likely_ai_true(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert result.likely_ai is True

    def test_confidence_above_threshold(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert result.confidence >= AI_CONFIDENCE_THRESHOLD

    def test_method_preserved(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert result.method == "POST"

    def test_path_preserved(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert result.path == "/api/chat"

    def test_content_type_preserved(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert "application/json" in result.content_type


# ---------------------------------------------------------------------------
# 2. Form-encoded chat request classified correctly
# ---------------------------------------------------------------------------

class TestFormChatCapture:

    def test_form_chat_likely_ai(self):
        cap = _cap(
            req_ct="application/x-www-form-urlencoded",
            body="query=What+is+machine+learning%3F&user_id=42",
            resp_ct="application/json",
            resp_body='{"answer": "Machine learning is a subset of artificial intelligence that enables systems to learn."}',
        )
        result = classify_capture(cap)
        assert result.likely_ai is True

    def test_form_prompt_field_detected(self):
        cap = _cap(
            req_ct="application/x-www-form-urlencoded",
            body="question=Explain+neural+networks&lang=en",
            resp_ct="application/json",
            resp_body='{"answer": "A neural network is a series of algorithms that mimic the human brain."}',
        )
        result = classify_capture(cap)
        assert result.detected_prompt_field == "question"

    def test_form_confidence_above_threshold(self):
        cap = _cap(
            req_ct="application/x-www-form-urlencoded",
            body="prompt=Write+a+poem+about+the+sea&style=haiku",
            resp_ct="application/json",
            resp_body='{"result": "Waves crash on the shore, Salt air fills the morning light, Ocean breathes in peace."}',
        )
        result = classify_capture(cap)
        assert result.confidence >= AI_CONFIDENCE_THRESHOLD


# ---------------------------------------------------------------------------
# 3. HTML shell rejected
# ---------------------------------------------------------------------------

class TestHtmlShellRejected:

    def test_html_response_not_likely_ai(self):
        result = classify_capture(PWNZZAI_HTML_SHELL)
        assert result.likely_ai is False

    def test_html_response_confidence_zero(self):
        result = classify_capture(PWNZZAI_HTML_SHELL)
        assert result.confidence == 0.0

    def test_html_request_ct_also_rejected(self):
        cap = _cap(
            method="GET",
            path="/dashboard",
            req_ct="text/html",
            body="",
            resp_ct="text/html",
            resp_body="<html>…</html>",
        )
        result = classify_capture(cap)
        assert result.likely_ai is False


# ---------------------------------------------------------------------------
# 4. Static assets rejected
# ---------------------------------------------------------------------------

class TestStaticAssetsRejected:

    def test_js_file_rejected(self):
        result = classify_capture(PWNZZAI_STATIC_JS)
        assert result.likely_ai is False
        assert result.confidence == 0.0

    def test_css_file_rejected(self):
        cap = _cap(path="/styles/app.css", resp_ct="text/css", body="", resp_body="body{margin:0}")
        assert classify_capture(cap).confidence == 0.0

    def test_png_rejected(self):
        cap = _cap(path="/logo.png", resp_ct="image/png", body="", resp_body="")
        assert classify_capture(cap).confidence == 0.0

    def test_woff_rejected(self):
        cap = _cap(path="/fonts/roboto.woff2", resp_ct="font/woff2", body="", resp_body="")
        assert classify_capture(cap).confidence == 0.0

    def test_sourcemap_rejected(self):
        cap = _cap(path="/bundle.js.map", resp_ct="application/json", body="", resp_body='{"version":3}')
        assert classify_capture(cap).confidence == 0.0


# ---------------------------------------------------------------------------
# 5. Prompt field detected
# ---------------------------------------------------------------------------

class TestPromptFieldDetected:

    @pytest.mark.parametrize("field_name", [
        "message", "prompt", "query", "input", "question", "text",
    ])
    def test_standard_prompt_field_detected(self, field_name):
        import json
        cap = _cap(body=json.dumps({field_name: "Tell me about AI safety"}))
        result = classify_capture(cap)
        assert result.detected_prompt_field == field_name

    def test_no_prompt_field_returns_none(self):
        cap = _cap(body='{"user_id": 42, "action": "click", "target": "button"}')
        result = classify_capture(cap)
        assert result.detected_prompt_field is None

    def test_case_insensitive_field_detection(self):
        cap = _cap(body='{"Message": "Hello AI"}')
        result = classify_capture(cap)
        assert result.detected_prompt_field is not None


# ---------------------------------------------------------------------------
# 6. Response field detected
# ---------------------------------------------------------------------------

class TestResponseFieldDetected:

    @pytest.mark.parametrize("field_name,value", [
        ("response", "The answer to your question is that AI can help automate tasks effectively."),
        ("reply",    "Sure, I can help you with that request about machine learning models."),
        ("answer",   "Machine learning models learn patterns from data to make predictions."),
        ("output",   "Here is the generated output you requested with all the details."),
        ("result",   "The computation result shows the model achieved 94.2% accuracy."),
    ])
    def test_response_field_detected(self, field_name, value):
        import json
        cap = _cap(resp_body=json.dumps({field_name: value}))
        result = classify_capture(cap)
        assert result.detected_response_field == field_name

    def test_no_response_field_returns_none(self):
        cap = _cap(resp_body='{"status": "ok", "code": 200}')
        result = classify_capture(cap)
        assert result.detected_response_field is None


# ---------------------------------------------------------------------------
# 7. Confidence scoring
# ---------------------------------------------------------------------------

class TestConfidenceScoring:

    def test_post_json_no_fields_below_threshold(self):
        """A plain REST endpoint that happens to use POST+JSON should not trigger.

        Path must NOT contain AI keywords (e.g. avoid /api/chat).
        Score: POST(25) + JSON(15) + non-HTML(5) = 45 → 0.45 < threshold(0.50).
        """
        cap = _cap(
            path="/api/orders",
            body='{"user_id": 42, "action": "create_order"}',
            resp_body='{"order_id": "ord_abc", "status": "pending"}',
        )
        result = classify_capture(cap)
        assert result.confidence < AI_CONFIDENCE_THRESHOLD

    def test_more_signals_gives_higher_confidence(self):
        low = classify_capture(_cap(
            body='{"user_id": 42}',
            resp_body='{"ok": true}',
        ))
        high = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert high.confidence > low.confidence

    def test_generated_text_bonus_raises_confidence(self):
        # Use a path without AI keywords and NO prompt field so the base score
        # stays at POST(25)+JSON(15)+result(20)+non-HTML(5) = 65.
        # Short "ok" value → no bonus (65 → 0.65).
        # Long natural sentence → +15 bonus (80 → 0.80).
        without_gen = classify_capture(_cap(
            path="/api/process",
            body='{"user_id": 42}',
            resp_body='{"result": "ok"}',
        ))
        with_gen = classify_capture(_cap(
            path="/api/process",
            body='{"user_id": 42}',
            resp_body='{"result": "Machine learning models learn patterns from large datasets to make accurate predictions on unseen data."}',
        ))
        assert with_gen.confidence > without_gen.confidence

    def test_ai_path_keyword_raises_confidence(self):
        # Keep the body without a prompt field so the base score stays well
        # below 100 before the AI-path bonus is added.
        # without_kw: POST(25)+JSON(15)+result(20)+gen_text(15)+non-HTML(5) = 80
        # with_kw:    80 + AI-path(10) = 90
        _resp = '{"result": "Sure, here is a detailed explanation of the concept you asked about."}'
        without_kw = classify_capture(_cap(
            path="/api/submit",
            body='{"user_id": 1}',
            resp_body=_resp,
        ))
        with_kw = classify_capture(_cap(
            path="/api/chat",
            body='{"user_id": 1}',
            resp_body=_resp,
        ))
        assert with_kw.confidence > without_kw.confidence

    def test_confidence_bounded_to_one(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert 0.0 <= result.confidence <= 1.0

    def test_get_request_harder_to_classify_as_ai(self):
        get_cap = _cap(
            method="GET",
            body="",
            resp_body='{"response": "Sure, here is the answer you were looking for in detail."}',
        )
        post_cap = _cap(
            method="POST",
            body='{"message": "hello"}',
            resp_body='{"response": "Sure, here is the answer you were looking for in detail."}',
        )
        assert classify_capture(post_cap).confidence > classify_capture(get_cap).confidence

    def test_health_check_always_zero(self):
        for p in ["/health", "/healthz", "/ping", "/ready"]:
            cap = _cap(path=p, resp_ct="application/json", resp_body='{"status":"ok"}')
            assert classify_capture(cap).confidence == 0.0, f"Expected 0.0 for {p}"


# ---------------------------------------------------------------------------
# 8. PwnzzAI-style request classified correctly (integration fixture)
# ---------------------------------------------------------------------------

class TestPwnzzAIFixture:

    def test_json_chat_endpoint_selected_as_best(self):
        """Best candidate from a mixed session should be the /api/chat call."""
        session = classify_session([
            PWNZZAI_HTML_SHELL,
            PWNZZAI_STATIC_JS,
            PWNZZAI_JSON_CAPTURE,
        ])
        assert session.best is not None
        assert session.best.path == "/api/chat"

    def test_prompt_field_detected_in_pwnzzai(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert result.detected_prompt_field == "message"

    def test_response_field_detected_in_pwnzzai(self):
        result = classify_capture(PWNZZAI_JSON_CAPTURE)
        assert result.detected_response_field == "response"

    def test_html_shell_not_selected(self):
        session = classify_session([
            PWNZZAI_HTML_SHELL,
            PWNZZAI_STATIC_JS,
            PWNZZAI_JSON_CAPTURE,
        ])
        assert session.best is not None
        assert session.best.path != "/"

    def test_html_shell_confidence_is_zero(self):
        result = classify_capture(PWNZZAI_HTML_SHELL)
        assert result.confidence == 0.0

    def test_all_results_count_matches_input(self):
        captures = [PWNZZAI_HTML_SHELL, PWNZZAI_STATIC_JS, PWNZZAI_JSON_CAPTURE]
        session = classify_session(captures)
        assert len(session.all_results) == 3

    def test_dataclass_capture_accepted(self):
        """classify_capture must also accept Capture dataclass instances."""
        dc = _dataclass_cap(
            body='{"message": "What can you tell me about OWASP Top 10?"}',
            resp_body='{"response": "OWASP Top 10 is a standard awareness document for web application security."}',
        )
        result = classify_capture(dc)
        assert result.likely_ai is True

    def test_openai_style_choices_response(self):
        cap = _cap(
            path="/v1/completions",
            body='{"prompt": "Explain prompt injection in two sentences."}',
            resp_body=(
                '{"choices": [{"text": "Prompt injection occurs when an attacker embeds '
                'malicious instructions into an AI prompt to override the intended behavior.", '
                '"finish_reason": "stop"}]}'
            ),
        )
        result = classify_capture(cap)
        assert result.likely_ai is True
        assert result.detected_response_field == "choices"


# ---------------------------------------------------------------------------
# 9. Edge cases and helpers
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_empty_captures_list(self):
        sc = classify_session([])
        assert sc.best is None
        assert sc.all_results == []

    def test_all_excluded_captures_returns_best_from_excluded(self):
        """When every capture is excluded, best is still set (confidence=0)."""
        session = classify_session([PWNZZAI_HTML_SHELL, PWNZZAI_STATIC_JS])
        assert session.best is not None
        assert session.best.likely_ai is False

    def test_is_static_recognises_extensions(self):
        for p in ["/app.js", "/style.css", "/logo.png", "/font.woff2", "/bundle.js.map"]:
            assert _is_static(p), f"Expected {p!r} to be static"

    def test_is_static_false_for_api_path(self):
        assert not _is_static("/api/chat")
        assert not _is_static("/v1/completions")

    def test_is_health_check(self):
        for p in ["/health", "/healthz", "/ping", "/ready", "/alive", "/metrics"]:
            assert _is_health_check(p), f"Expected {p!r} to be a health check"

    def test_generated_text_short_string_false(self):
        assert not _looks_like_generated_text("ok")
        assert not _looks_like_generated_text("true")
        assert not _looks_like_generated_text("")

    def test_generated_text_url_false(self):
        assert not _looks_like_generated_text("https://example.com/some/path?q=1")

    def test_generated_text_long_sentence_true(self):
        assert _looks_like_generated_text(
            "Artificial intelligence is transforming the way we build software systems."
        )

    def test_missing_response_body_handled(self):
        cap = {"request": {"method": "POST", "path": "/api/chat",
                           "content_type": "application/json",
                           "body_snippet": '{"message": "hi"}'},
               "response": None}
        result = classify_capture(cap)
        assert isinstance(result, ClassificationResult)

    def test_missing_request_fields_handled(self):
        cap = {"request": {}, "response": {}}
        result = classify_capture(cap)
        assert isinstance(result, ClassificationResult)
        assert result.confidence == 0.0
