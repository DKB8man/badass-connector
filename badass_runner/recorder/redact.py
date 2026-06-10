"""Credential redaction for the local recorder proxy.

Rules
-----
- Headers whose name is in the sensitive set or matches a sensitive pattern
  have their value replaced with ``[REDACTED]``.
- Cookie header values are replaced per-key (keys are preserved for debugging).
- Body text is scanned for Bearer/Basic auth tokens and they are redacted.
"""

import re
from typing import Dict

REDACTED = "[REDACTED]"

# Header names that are always redacted (lower-cased for comparison)
_ALWAYS_REDACT_HEADERS: frozenset = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-secret",
        "api-key",
    }
)

# Header names matching this pattern are also redacted
_SENSITIVE_HEADER_RE = re.compile(
    r"(token|secret|key|password|passwd|credential|auth)", re.IGNORECASE
)

# Body patterns
_BEARER_RE = re.compile(r"(?i)Bearer\s+\S+")
_BASIC_RE = re.compile(r"(?i)Basic\s+\S+")

# CSRF / form-body patterns
# Matches both URL-encoded (csrf_token=<val>) and JSON ("csrf_token": "<val>") forms.
# The value capture stops at whitespace, quote, or ampersand.
_CSRF_NAMES = r"(?:csrf[_\-]?token|csrfmiddlewaretoken|_token|x-csrf-token)"
_CSRF_URLENC_RE = re.compile(
    rf"(?i)({_CSRF_NAMES})=([^&\s\"']+)",
)
_CSRF_JSON_RE = re.compile(
    rf'(?i)"{_CSRF_NAMES}"\s*:\s*"([^"]+)"',
)

# API-key / secret field patterns (both URL-encoded and JSON forms)
# Covers: x-api-key, api_key, api-key, api_secret, access_token, auth_token, secret_key
_API_KEY_NAMES = r"(?:x-api-key|api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)"
_API_KEY_URLENC_RE = re.compile(
    rf"(?i)({_API_KEY_NAMES})=([^&\s\"']+)",
)
_API_KEY_JSON_RE = re.compile(
    rf'(?i)"{_API_KEY_NAMES}"\s*:\s*"([^"]+)"',
)

# Cookie / Set-Cookie header lines in log output or tracebacks
_COOKIE_LINE_RE = re.compile(
    r"(?i)((?:Set-)?Cookie:\s*)([^\n\r]+)",
)

# Quoted-assignment form: api_key = 'value' or csrf_token = "value"
# Catches the common Python/debug-log pattern for sensitive field assignments.
_SENSITIVE_ASSIGN_NAMES = (
    r"(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|"
    r"secret[_\-]?key|csrf[_\-]?token|x-csrf-token|csrfmiddlewaretoken|"
    r"_token|bearer[_\-]?token|runner[_\-]?token|password|passwd)"
)
_QUOTED_ASSIGN_RE = re.compile(
    rf"(?i)({_SENSITIVE_ASSIGN_NAMES})\s*=\s*['\"]([^'\"\n\r]+)['\"]",
)


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of *headers* with sensitive values replaced."""
    result: Dict[str, str] = {}
    for name, value in headers.items():
        lower = name.lower()
        if lower in _ALWAYS_REDACT_HEADERS or _SENSITIVE_HEADER_RE.search(lower):
            result[name] = REDACTED
        else:
            result[name] = value
    return result


def redact_cookies(cookie_header: str) -> str:
    """Redact all cookie values, preserving keys.

    Input:  ``session=abc123; _ga=GA1.1``
    Output: ``session=[REDACTED]; _ga=[REDACTED]``
    """
    if not cookie_header:
        return ""
    parts = [p.strip() for p in cookie_header.split(";")]
    redacted_parts: list = []
    for part in parts:
        if "=" in part:
            key = part.split("=", 1)[0].strip()
            redacted_parts.append(f"{key}={REDACTED}")
        elif part:
            redacted_parts.append(part)
    return "; ".join(redacted_parts)


def _redact_cookie_line(m: re.Match) -> str:
    """Replace all cookie values in a Cookie/Set-Cookie header line."""
    return m.group(1) + redact_cookies(m.group(2))


def redact_body(body: str) -> str:
    """Redact auth tokens and CSRF secrets embedded in a body snippet.

    Handles:
    * ``Bearer <token>`` and ``Basic <token>`` auth values.
    * URL-encoded CSRF fields: ``csrf_token=<val>``, ``_token=<val>``,
      ``csrfmiddlewaretoken=<val>``, ``x-csrf-token=<val>``.
    * JSON CSRF fields: ``"csrf_token": "<val>"``, ``"_token": "<val>"``, etc.
    * URL-encoded API-key fields: ``x-api-key=<val>``, ``api_key=<val>``, etc.
    * JSON API-key fields: ``"x-api-key": "<val>"``, ``"api_key": "<val>"``, etc.
    """
    body = _BEARER_RE.sub(f"Bearer {REDACTED}", body)
    body = _BASIC_RE.sub(f"Basic {REDACTED}", body)
    body = _CSRF_URLENC_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", body)
    body = _CSRF_JSON_RE.sub(lambda m: m.group(0).split(":")[0] + f': "{REDACTED}"', body)
    body = _API_KEY_URLENC_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", body)
    body = _API_KEY_JSON_RE.sub(lambda m: m.group(0).split(":")[0] + f': "{REDACTED}"', body)
    return body


def redact_text(text: str) -> str:
    """Redact secrets from arbitrary text strings (log lines, tracebacks, debug output).

    Extends :func:`redact_body` with additional patterns for:

    * ``Cookie: key=value; ...`` and ``Set-Cookie: key=value; ...`` header lines
      embedded in log/traceback text.
    * Quoted Python-style assignments: ``api_key = 'value'``,
      ``csrf_token = "value"``, ``bearer_token = 'value'``, etc.

    Use this when sanitising diagnostic strings that are not HTTP body snippets,
    such as exception tracebacks, log lines, or debug output that may contain
    credential fragments.
    """
    text = redact_body(text)
    text = _COOKIE_LINE_RE.sub(_redact_cookie_line, text)
    text = _QUOTED_ASSIGN_RE.sub(lambda m: f"{m.group(1)} = '{REDACTED}'", text)
    return text
