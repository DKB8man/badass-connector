"""Sanitize harness turns before uploading to the cloud.

Strips locally-held credentials and common secret patterns from turn data so
that no authentication material is ever uploaded.  Called by JobPoller before
POSTing to /api/runners/jobs/{run_id}/complete.

Design principles
-----------------
* Credential values from LocalAuthStore are stripped by exact string match —
  these are the highest-priority secrets because they are known precisely.
* A pattern-based pass removes common token shapes (JWTs, sk-* API keys,
  Bearer tokens) in case a credential appears inside a JSON response or request
  body that the exact-match pass missed.
* Auth-bearing HTTP header *keys* (Authorization, Cookie, X-API-Key) are
  removed entirely from any ``step_headers_used`` sub-dicts that the executor
  might have captured.
* The sanitizer is intentionally conservative: it never modifies status codes,
  elapsed_ms, or tool call *structure* — only string values.
"""
import re
from typing import Any, Dict, List, Optional

_REDACTED = "[REDACTED]"

_SECRET_PATTERN = re.compile(
    r'('
    r'sk-[A-Za-z0-9_\-]{8,}|'                  # OpenAI / Anthropic-style key
    r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|'  # JWT
    r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-]{8,}'  # Authorization header value
    r')',
    re.IGNORECASE,
)

_AUTH_HEADER_KEYS = {"authorization", "cookie", "x-api-key", "x-auth-token"}


def _redact_str(text: str, known_secrets: List[str]) -> str:
    """Remove known secrets and common pattern-matched secrets from *text*."""
    for secret in known_secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, _REDACTED)
    text = _SECRET_PATTERN.sub(_REDACTED, text)
    return text


def _redact_value(obj: Any, known_secrets: List[str]) -> Any:
    """Recursively redact string values in *obj*; drop auth header keys from dicts."""
    if isinstance(obj, str):
        return _redact_str(obj, known_secrets)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in _AUTH_HEADER_KEYS:
                out[k] = _REDACTED
            else:
                out[k] = _redact_value(v, known_secrets)
        return out
    if isinstance(obj, list):
        return [_redact_value(item, known_secrets) for item in obj]
    return obj


def sanitize_turns(
    turns: List[Dict],
    auth_secrets: Optional[List[str]] = None,
) -> List[Dict]:
    """Return a sanitized copy of *turns* safe to upload to the cloud.

    Parameters
    ----------
    turns:
        Raw turn dicts produced by :class:`~badass_runner.harness.executor.LocalTestExecutor`.
    auth_secrets:
        Credential string values from ``LocalAuthStore`` (bearer token value,
        API key value, etc.) that must never leave the runner.  Values shorter
        than 4 characters are ignored to avoid false-positive redaction.

    Returns
    -------
    list[dict]
        A new list of turn dicts with all credential material replaced by
        ``"[REDACTED]"``.  The original *turns* list is never mutated.
    """
    known = [s for s in (auth_secrets or []) if s and len(s) >= 4]

    sanitized = []
    for turn in turns:
        safe: Dict[str, Any] = {
            "request": _redact_str(str(turn.get("request", "")), known),
            "response": _redact_str(str(turn.get("response", "")), known),
            "raw_reply": _redact_str(str(turn.get("raw_reply") or ""), known),
            "status_code": turn.get("status_code", 0),
            "elapsed_ms": turn.get("elapsed_ms", 0),
        }

        if turn.get("extraction_error"):
            safe["extraction_error"] = _redact_str(str(turn["extraction_error"]), known)

        if turn.get("tool_calls_raw") is not None:
            safe["tool_calls_raw"] = _redact_value(turn["tool_calls_raw"], known)

        if turn.get("function_call_raw") is not None:
            safe["function_call_raw"] = _redact_value(turn["function_call_raw"], known)

        if turn.get("html_shell"):
            safe["html_shell"] = True

        if turn.get("content_type"):
            safe["content_type"] = str(turn["content_type"])

        if turn.get("step_headers_used") is not None:
            safe["step_headers_used"] = _redact_value(turn["step_headers_used"], known)

        sanitized.append(safe)

    return sanitized
