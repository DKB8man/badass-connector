"""Local harness test executor.

Executes harness test step sequences against a local AI endpoint using the
runner's in-memory ``LocalAuthStore`` for authentication.  Produces turn dicts
in the same format as the cloud's ``send_message`` so the cloud can evaluate
PASS/FAIL using the identical ``assert_vulnerable`` logic.

This module intentionally reimplements the HTTP mechanics from the
BADASS Cloud harness runner — the connector is a standalone package with no
dependency on the BADASS Cloud codebase.  The evaluation logic (pattern
matching, PASS/FAIL decisions) is **not** duplicated here; it stays on
BADASS Cloud.
"""
import json
import time
from typing import Any, Dict, List, Optional

import httpx

from ..target.builder import LocalAuthStore
from ..logs import get_logger, log
from badass_runner_protocol import (
    _denial_code,
    deserialize_enforcement_probe,
)

logger = get_logger()

MAX_GET_MESSAGE_LEN = 500
DEFAULT_REQUEST_TIMEOUT = 15.0
DEFAULT_INTER_STEP_DELAY = 0.5
MAX_ENFORCEMENT_RESPONSE_BYTES = 4096

_HTML_MARKERS = ["@vite/client", "@react-refresh", "<head", "<body", "<!doctype html"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_html_shell(text: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    t = (text or "")[:2000].lower()
    return any(m in t for m in _HTML_MARKERS)


def _as_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, list):
        if val and isinstance(val[0], dict):
            first = val[0]
            return str(
                first.get("text")
                or first.get("content")
                or (first.get("message") or {}).get("content")
                or json.dumps(first)
            )
        return json.dumps(val)
    if isinstance(val, dict):
        return json.dumps(val)
    return str(val).strip()


def _extract_reply(resp_json: Any, response_field: str):
    """Return ``(reply_text, extraction_error)`` from a JSON response.

    Tries the configured field, case-insensitive fallback, common alternative
    field names, and standard nested paths (OpenAI, Anthropic).
    """
    if not isinstance(resp_json, dict):
        return "", "Response was not a JSON object"

    # Exact match
    val = resp_json.get(response_field)
    if val is not None:
        s = _as_str(val)
        if s:
            return s, None

    # Case-insensitive
    for k, v in resp_json.items():
        if k.lower() == response_field.lower() and v is not None:
            s = _as_str(v)
            if s:
                return s, None

    # Common fallbacks
    for field in ("reply", "message", "content", "text", "answer", "output", "result", "response"):
        if field == response_field:
            continue
        val = resp_json.get(field)
        if val is not None:
            s = _as_str(val)
            if s:
                return s, None

    # OpenAI choices
    choices = resp_json.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            msg = first.get("message") or {}
            if isinstance(msg, dict) and msg.get("content"):
                return str(msg["content"]), None
            if first.get("text"):
                return str(first["text"]), None

    # Anthropic content
    content = resp_json.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        text = content[0].get("text", "")
        if text:
            return str(text), None

    keys = list(resp_json.keys())
    return "", f"Field '{response_field}' not found. Available keys: {keys}"


# ---------------------------------------------------------------------------
# StepResult
# ---------------------------------------------------------------------------

class StepResult:
    """Result of executing a single harness step."""

    def __init__(
        self,
        request: str,
        response: str,
        raw_reply: str,
        status_code: int,
        elapsed_ms: int,
        extraction_error: Optional[str] = None,
        tool_calls_raw: Optional[list] = None,
        function_call_raw: Optional[dict] = None,
        html_shell: bool = False,
        content_type: str = "",
    ):
        self.request = request
        self.response = response
        self.raw_reply = raw_reply
        self.status_code = status_code
        self.elapsed_ms = elapsed_ms
        self.extraction_error = extraction_error
        self.tool_calls_raw = tool_calls_raw
        self.function_call_raw = function_call_raw
        self.html_shell = html_shell
        self.content_type = content_type

    def to_dict(self) -> Dict:
        d: Dict[str, Any] = {
            "request": self.request,
            "response": self.response,
            "raw_reply": self.raw_reply,
            "status_code": self.status_code,
            "elapsed_ms": self.elapsed_ms,
        }
        if self.extraction_error is not None:
            d["extraction_error"] = self.extraction_error
        if self.tool_calls_raw is not None:
            d["tool_calls_raw"] = self.tool_calls_raw
        if self.function_call_raw is not None:
            d["function_call_raw"] = self.function_call_raw
        if self.html_shell:
            d["html_shell"] = True
        if self.content_type:
            d["content_type"] = self.content_type
        return d


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------

class LocalTestExecutor:
    """Executes harness test step sequences against a local AI target.

    Auth credentials come from ``LocalAuthStore`` (never from the job payload).
    The executor makes real HTTP requests to ``base_url + message_path``; the
    target must be reachable from the local machine.

    Parameters
    ----------
    base_url:
        Root URL of the AI service, e.g. ``http://localhost:8000``.
    message_path:
        Endpoint path, e.g. ``/api/chat``.
    method:
        HTTP method string (``POST``, ``GET``, …).
    request_message_field:
        JSON body key used to send the prompt, e.g. ``message``.
    response_message_field:
        JSON response key used to extract the AI reply, e.g. ``reply``.
    auth_store:
        Optional :class:`~badass_runner.target.builder.LocalAuthStore`.
        Credentials are injected at request time and never stored in results.
    request_timeout:
        HTTP timeout per individual request in seconds.
    inter_step_delay:
        Pause between consecutive steps (seconds) to avoid rate-limiting.
    """

    def __init__(
        self,
        base_url: str,
        message_path: str,
        method: str,
        request_message_field: str,
        response_message_field: str,
        auth_store: Optional[LocalAuthStore] = None,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        inter_step_delay: float = DEFAULT_INTER_STEP_DELAY,
        extra_body_fields: Optional[Dict] = None,
        body_format: str = "flat",
        can_cause_side_effects: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.message_path = message_path
        self.method = (method or "POST").split(",")[0].strip().upper()
        self.request_message_field = request_message_field
        self.response_message_field = response_message_field
        self.auth_store = auth_store
        self.request_timeout = request_timeout
        self.inter_step_delay = inter_step_delay
        self.extra_body_fields: Dict = extra_body_fields if isinstance(extra_body_fields, dict) else {}
        self.body_format = body_format or "flat"
        self.can_cause_side_effects = bool(can_cause_side_effects)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> Dict[str, str]:
        if self.auth_store:
            return self.auth_store.apply_to_headers({})
        return {}

    def _url(self, path_override: Optional[str] = None) -> str:
        path = (path_override or self.message_path).lstrip("/")
        return self.base_url + "/" + path

    def execute_surface_probe(self, paths: List[str]) -> List[Dict[str, Any]]:
        """GET passive routes without auth and return observations, never verdicts."""
        observations: List[Dict[str, Any]] = []
        with httpx.Client(timeout=self.request_timeout, follow_redirects=False) as client:
            for path in paths:
                started = time.monotonic()
                try:
                    response = client.get(self._url(path))
                    observations.append({
                        "path": path,
                        "status_code": response.status_code,
                        "response_excerpt": (response.text or "")[:1000],
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": None,
                    })
                except Exception as exc:
                    observations.append({
                        "path": path,
                        "status_code": 0,
                        "response_excerpt": "",
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "error": str(exc)[:300],
                    })
                if self.inter_step_delay:
                    time.sleep(self.inter_step_delay)
        return observations

    def execute_enforcement_probe(self, payload: dict) -> List[Dict[str, Any]]:
        """Execute probe legs and return raw observations, never a verdict."""
        probe = deserialize_enforcement_probe(payload)
        method = (probe["method"] or self.method or "POST").upper()
        if method in {"PUT", "PATCH", "DELETE"} and (
            probe["non_mutating"]
            or not self.can_cause_side_effects
            or not probe["requires_isolated_fixture"]
            or not probe["isolated_fixture"]
        ):
            return [
                {
                    "variant": variant["name"],
                    "authorized": authorized,
                    "status_code": 0,
                    "response_headers": {},
                    "response_body": "",
                    "error": (
                        "destructive enforcement probe requires explicit side-effect "
                        "opt-in and a verified isolated fixture"
                    ),
                }
                for variant in probe["unauthorized_variants"]
                for authorized in (True, False)
            ]

        observations = []
        for variant in probe["unauthorized_variants"]:
            variant_mutating = (
                probe["non_mutating"]
                if variant["non_mutating"] is None
                else variant["non_mutating"]
            )
            variant_fixture = (
                probe["requires_isolated_fixture"]
                if variant["requires_isolated_fixture"] is None
                else variant["requires_isolated_fixture"]
            )
            if not variant_mutating and (
                not self.can_cause_side_effects
                or not variant_fixture
                or not probe["isolated_fixture"]
            ):
                error = (
                    "mutating enforcement probe requires explicit side-effect "
                    "opt-in and a verified isolated fixture"
                )
                for authorized in (True, False):
                    observations.append(
                        {
                            "variant": variant["name"],
                            "authorized": authorized,
                            "status_code": 0,
                            "response_headers": {},
                            "response_body": "",
                            "error": error,
                        }
                    )
                continue

            body = dict(variant["request_body"] or probe["request_body"])
            if "message" in body:
                message = body.pop("message")
                if self.body_format == "openai_messages":
                    body["messages"] = [{"role": "user", "content": message}]
                else:
                    body[self.request_message_field] = message
            body = {**self.extra_body_fields, **body}
            authorized_headers = dict(probe["authorized_headers"] or {})
            authorized_headers = self.auth_store.apply_to_headers(
                authorized_headers
            ) if self.auth_store else authorized_headers
            for authorized, headers in (
                (True, authorized_headers),
                (False, dict(variant["headers"])),
            ):
                try:
                    request_kwargs = {
                        "method": method,
                        "url": self._url(probe["path"]),
                        "headers": dict(headers),
                    }
                    if method in {"GET", "HEAD"}:
                        request_kwargs["params"] = body
                    else:
                        request_kwargs["json"] = body
                        request_kwargs["headers"]["Content-Type"] = "application/json"
                    with httpx.Client(
                        timeout=self.request_timeout, follow_redirects=False
                    ) as client:
                        with client.stream(**request_kwargs) as response:
                            body_bytes = bytearray()
                            for chunk in response.iter_bytes():
                                remaining = (
                                    MAX_ENFORCEMENT_RESPONSE_BYTES - len(body_bytes)
                                )
                                if remaining <= 0:
                                    break
                                body_bytes.extend(chunk[:remaining])
                            response_body = bytes(body_bytes).decode(
                                "utf-8", errors="replace"
                            )
                            response_status = response.status_code
                            response_headers = dict(response.headers)
                    observations.append(
                        {
                            "variant": variant["name"],
                            "authorized": authorized,
                            "status_code": response_status,
                            "response_headers": response_headers,
                            "response_body": response_body,
                            "denial_code": _denial_code(response_body),
                            "error": None,
                        }
                    )
                except httpx.TimeoutException:
                    observations.append(
                        {
                            "variant": variant["name"],
                            "authorized": authorized,
                            "status_code": 0,
                            "response_headers": {},
                            "response_body": "",
                            "error": "Target unreachable or timed out",
                        }
                    )
                except Exception as exc:
                    observations.append(
                        {
                            "variant": variant["name"],
                            "authorized": authorized,
                            "status_code": 0,
                            "response_headers": {},
                            "response_body": "",
                            "error": f"Connection error: {exc}",
                        }
                    )
        return observations

    # ------------------------------------------------------------------
    # Single-step execution
    # ------------------------------------------------------------------

    def send_step(
        self,
        message: str,
        path_override: Optional[str] = None,
    ) -> StepResult:
        """Send *message* to the target and return a :class:`StepResult`.

        Always uses ``follow_redirects=False`` — redirects are reported as
        errors so the cloud evaluator can classify them correctly.
        """
        url = self._url(path_override)
        auth_hdrs = self._auth_headers()
        start = time.time()

        try:
            if self.method in ("GET", "HEAD", "DELETE"):
                msg_truncated = message[:MAX_GET_MESSAGE_LEN]
                with httpx.Client(timeout=self.request_timeout, follow_redirects=False) as c:
                    resp = c.request(
                        method=self.method,
                        url=url,
                        params={self.request_message_field: msg_truncated},
                        headers=auth_hdrs,
                    )
            else:
                body = {**self.extra_body_fields, self.request_message_field: message}
                with httpx.Client(timeout=self.request_timeout, follow_redirects=False) as c:
                    resp = c.request(
                        method=self.method,
                        url=url,
                        json=body,
                        headers={**auth_hdrs, "Content-Type": "application/json"},
                    )
        except httpx.TimeoutException:
            elapsed_ms = int((time.time() - start) * 1000)
            return StepResult(
                request=message,
                response="[TIMEOUT]",
                raw_reply="",
                status_code=0,
                elapsed_ms=elapsed_ms,
                extraction_error="Target unreachable or timed out",
            )
        except Exception as exc:
            elapsed_ms = int((time.time() - start) * 1000)
            return StepResult(
                request=message,
                response=f"[ERROR] {exc}",
                raw_reply="",
                status_code=0,
                elapsed_ms=elapsed_ms,
                extraction_error=f"Connection error: {exc}",
            )

        elapsed_ms = int((time.time() - start) * 1000)
        status_code = resp.status_code
        content_type = resp.headers.get("content-type", "")

        # 3xx — report and stop; the cloud evaluator classifies this
        if 300 <= status_code < 400:
            location = resp.headers.get("location", "")
            return StepResult(
                request=message,
                response=f"[REDIRECT {status_code}]",
                raw_reply="",
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                extraction_error=f"Redirect received ({status_code}) Location: {location}",
            )

        # 4xx / 5xx
        if status_code >= 400:
            allow = resp.headers.get("allow", "")
            allow_note = f" Allow: {allow}" if allow else ""
            try:
                snippet = resp.text[:500]
            except Exception:
                snippet = ""
            return StepResult(
                request=message,
                response=f"[HTTP {status_code}]{allow_note}",
                raw_reply="",
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                extraction_error=f"HTTP error {status_code}{allow_note}. Body: {snippet}",
            )

        # HTML shell detection
        if _is_html_shell(resp.text, content_type):
            return StepResult(
                request=message,
                response="[HTML SHELL]",
                raw_reply="",
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                extraction_error=(
                    f"Endpoint returned HTML shell instead of AI response "
                    f"(HTTP {status_code}, type={content_type or 'unknown'})"
                ),
                html_shell=True,
                content_type=content_type,
            )

        # Parse JSON + extract reply
        tool_calls_raw = None
        function_call_raw = None
        try:
            resp_json = resp.json()
            reply, ext_err = _extract_reply(resp_json, self.response_message_field)
            # Structured tool calls (OpenAI + Anthropic)
            _msg = ((resp_json.get("choices") or [{}])[0]).get("message", {})
            tool_calls_raw = _msg.get("tool_calls") or resp_json.get("tool_calls") or None
            function_call_raw = _msg.get("function_call") or resp_json.get("function_call") or None
            _anthropic_tools = [
                {"name": i.get("name", ""), "arguments": i.get("input", {})}
                for i in (resp_json.get("content") or [])
                if isinstance(i, dict) and i.get("type") == "tool_use"
            ]
            if _anthropic_tools:
                tool_calls_raw = (list(tool_calls_raw) if tool_calls_raw else []) + _anthropic_tools
        except Exception:
            reply = resp.text[:2000].strip()
            ext_err = None

        if not reply:
            return StepResult(
                request=message,
                response="[EXTRACTION FAILED]",
                raw_reply="",
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                extraction_error=ext_err or f"Field '{self.response_message_field}' not found",
                tool_calls_raw=tool_calls_raw,
                function_call_raw=function_call_raw,
                content_type=content_type,
            )

        return StepResult(
            request=message,
            response=reply,
            raw_reply=reply,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            tool_calls_raw=tool_calls_raw,
            function_call_raw=function_call_raw,
            content_type=content_type,
        )

    # ------------------------------------------------------------------
    # Multi-step execution
    # ------------------------------------------------------------------

    def execute_test(
        self,
        test_id: str,
        steps: List[str],
        max_turns: int = 5,
        new_session_before: Optional[List[int]] = None,
        path_override: Optional[str] = None,
    ) -> List[Dict]:
        """Execute all *steps* for one test and return a list of turn dicts.

        Parameters
        ----------
        test_id:
            Used only for logging.
        steps:
            Prompt strings to send in order.
        max_turns:
            Hard cap on the number of steps executed (guardrail limit).
        new_session_before:
            Step indices before which a new session should be started.
            For the runner, this is informational only (no server-side
            session management is performed).
        path_override:
            If supplied, use this path instead of ``self.message_path``.

        Returns
        -------
        list[dict]
            Turn dicts compatible with the cloud's ``HarnessTranscript``
            format.
        """
        turns: List[Dict] = []
        capped = steps[:max_turns]

        for i, step in enumerate(capped):
            log(logger, "debug", "Executing step",
                test_id=test_id, step=i, total=len(capped))
            turn = self.send_step(step, path_override=path_override)
            turns.append(turn.to_dict())

            # Stop on connection failure — subsequent steps will also fail
            if turn.status_code == 0:
                log(logger, "warning", "Connection failure at step — aborting test",
                    test_id=test_id, step=i)
                break

            if i < len(capped) - 1:
                time.sleep(self.inter_step_delay)

        return turns
