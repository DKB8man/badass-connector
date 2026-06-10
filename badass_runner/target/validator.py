"""ValidationPreview — sends a harmless probe to a LocalTarget.

The validator fires a single, low-risk prompt at the recorded endpoint and
extracts the AI response field from the reply.  This gives the user immediate
confirmation that:

  1. The target URL is reachable.
  2. The prompt field name is correct.
  3. The response field name extracts a meaningful value.

No auth credentials are logged or stored after the request completes.
The probe text is deliberately innocuous (arithmetic question) to avoid
triggering any content-policy filters on the target system.

Origin allowlisting
-------------------
Probes are restricted to the origin (scheme + host + port) declared in
``LocalTarget.base_url``.  Two attack vectors are blocked:

1. **Malformed path override** — ``endpoint_path`` values that contain a URL
   scheme (``://``) or start with ``//`` are rejected before the request is
   built.  This prevents a crafted ``path_override`` from silently redirecting
   the probe to an arbitrary host.

2. **Server-issued redirects** — ``follow_redirects`` is disabled.  Any 3xx
   response from the target app is examined: if the ``Location`` header points
   to a different origin the probe is terminated with a
   :class:`TargetOriginError`; if it points to the *same* origin the redirect
   is followed once; if there is no ``Location`` header the 3xx is returned as-
   is with ``success=False``.

Validation is *optional* — running it sends one real HTTP request to the
target app, which must be reachable from the local machine.
"""

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse

import httpx

from .builder import LocalAuthStore, LocalTarget

DEFAULT_PROBE = "What is 2+2?"
DEFAULT_TIMEOUT = 10  # seconds

_SAFE_PROBE_HINT = (
    "Probe text should be short and innocuous — the intent is connectivity "
    "and field-name verification, not adversarial testing."
)


# ---------------------------------------------------------------------------
# Origin allowlist helpers
# ---------------------------------------------------------------------------

class TargetOriginError(ValueError):
    """Raised when a request or redirect would leave the registered target origin."""


def _normalise_origin(url: str) -> str:
    """Return ``scheme://host:port`` for *url*, lower-cased and normalised.

    Default ports (80 for http, 443 for https) are made explicit so that
    ``http://host`` and ``http://host:80`` compare equal.
    """
    p = urlparse(url.lower().strip())
    scheme = p.scheme
    host = p.hostname or ""
    port = p.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port}"


def _assert_same_origin(url: str, base_url: str) -> None:
    """Raise :class:`TargetOriginError` if *url* has a different origin than *base_url*."""
    req_origin = _normalise_origin(url)
    allowed = _normalise_origin(base_url)
    if req_origin != allowed:
        raise TargetOriginError(
            f"Request origin {req_origin!r} does not match the registered "
            f"target origin {allowed!r}."
        )


def _validate_endpoint_path(path: str) -> None:
    """Raise :class:`TargetOriginError` if *path* could bypass origin allowlisting.

    Rejected patterns:
    * Anything containing ``://``  (absolute URL smuggled as a path)
    * Anything starting with ``//`` (protocol-relative URL)
    """
    if "://" in path:
        raise TargetOriginError(
            f"Endpoint path {path!r} contains a URL scheme ('://').  "
            "Only relative paths (e.g. '/api/chat') are allowed."
        )
    if path.startswith("//"):
        raise TargetOriginError(
            f"Endpoint path {path!r} starts with '//' (protocol-relative URL).  "
            "Use an absolute path instead (e.g. '/api/chat')."
        )


# ---------------------------------------------------------------------------
# Output type
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Outcome of a single validation probe."""

    success: bool
    probe_sent: str
    status_code: int
    raw_response: Dict[str, Any]
    extracted_response: Optional[str]
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Field extractor
# ---------------------------------------------------------------------------

def _extract_field(raw: Dict[str, Any], field_name: str) -> Optional[str]:
    """Extract *field_name* from *raw*, returning a string value or None.

    Handles:
    * Direct key lookup (exact match).
    * Case-insensitive fallback.
    * OpenAI-style ``choices`` array: unwraps ``choices[0].text``,
      ``choices[0].content``, or ``choices[0].message.content``.
    * Arbitrary list: ``str(list[0])``.
    """
    if not raw or not field_name:
        return None

    val = raw.get(field_name)
    if val is None:
        for k, v in raw.items():
            if k.lower() == field_name.lower():
                val = v
                break

    if val is None:
        return None

    if isinstance(val, str):
        return val

    if isinstance(val, list):
        if not val:
            return None
        first = val[0]
        if isinstance(first, dict):
            return (
                first.get("text")
                or first.get("content")
                or (first.get("message") or {}).get("content")
                or json.dumps(first)
            )
        return str(first)

    return str(val)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class ValidationPreview:
    """Sends a single harmless probe to a :class:`~badass_runner.target.LocalTarget`
    and returns a :class:`ValidationResult`.

    Parameters
    ----------
    probe_text:
        The prompt string to send.  Defaults to :data:`DEFAULT_PROBE`.
    timeout:
        HTTP request timeout in seconds.  Defaults to 10.
    """

    def __init__(
        self,
        probe_text: str = DEFAULT_PROBE,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.probe_text = probe_text
        self.timeout = timeout

    def run(
        self,
        target: LocalTarget,
        auth: Optional[LocalAuthStore] = None,
    ) -> ValidationResult:
        """Fire the probe and return a :class:`ValidationResult`.

        Parameters
        ----------
        target:
            The :class:`LocalTarget` to probe.
        auth:
            Optional :class:`LocalAuthStore` providing credentials.
            Credentials are injected into request headers at call time
            and are not stored in the result.

        Raises
        ------
        TargetOriginError
            If ``target.endpoint_path`` contains a URL scheme or starts with
            ``//``, which would allow the probe to escape the registered origin.
        """
        # ---- origin allowlist: path validation --------------------------
        try:
            _validate_endpoint_path(target.endpoint_path)
        except TargetOriginError as exc:
            return ValidationResult(
                success=False,
                probe_sent=self.probe_text,
                status_code=0,
                raw_response={},
                extracted_response=None,
                error=str(exc),
            )

        url = target.base_url.rstrip("/") + target.endpoint_path

        # ---- origin allowlist: constructed-URL check --------------------
        try:
            _assert_same_origin(url, target.base_url)
        except TargetOriginError as exc:
            return ValidationResult(
                success=False,
                probe_sent=self.probe_text,
                status_code=0,
                raw_response={},
                extracted_response=None,
                error=str(exc),
            )

        payload: Dict[str, Any] = {target.prompt_field: self.probe_text}

        headers: Dict[str, str] = dict(target.safe_headers)
        if auth is not None:
            headers = auth.apply_to_headers(headers)

        ct = (target.content_type or "").lower()
        if "form" in ct:
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            body = urlencode(payload).encode()
        else:
            headers.setdefault("Content-Type", "application/json")
            body = json.dumps(payload).encode()

        try:
            resp = httpx.request(
                method=target.method,
                url=url,
                headers=headers,
                content=body,
                timeout=self.timeout,
                follow_redirects=False,   # redirects handled explicitly below
            )
        except Exception as exc:
            return ValidationResult(
                success=False,
                probe_sent=self.probe_text,
                status_code=0,
                raw_response={},
                extracted_response=None,
                error=str(exc),
            )

        # ---- origin allowlist: redirect interception --------------------
        if 300 <= resp.status_code < 400:
            location = resp.headers.get("location", "")
            if not location:
                return ValidationResult(
                    success=False,
                    probe_sent=self.probe_text,
                    status_code=resp.status_code,
                    raw_response={},
                    extracted_response=None,
                    error=f"Redirect ({resp.status_code}) with no Location header.",
                )

            # Resolve relative Location against base_url
            if not location.startswith(("http://", "https://")):
                location = target.base_url.rstrip("/") + "/" + location.lstrip("/")

            try:
                _assert_same_origin(location, target.base_url)
            except TargetOriginError:
                return ValidationResult(
                    success=False,
                    probe_sent=self.probe_text,
                    status_code=resp.status_code,
                    raw_response={},
                    extracted_response=None,
                    error=(
                        f"Redirect ({resp.status_code}) to {location!r} blocked — "
                        f"destination is outside the registered target origin "
                        f"({_normalise_origin(target.base_url)}).  "
                        f"Update the endpoint path directly instead of relying on redirects."
                    ),
                )

            # Same-origin redirect — follow once (no further redirect allowed)
            try:
                resp = httpx.request(
                    method=target.method,
                    url=location,
                    headers=headers,
                    content=body,
                    timeout=self.timeout,
                    follow_redirects=False,
                )
            except Exception as exc:
                return ValidationResult(
                    success=False,
                    probe_sent=self.probe_text,
                    status_code=0,
                    raw_response={},
                    extracted_response=None,
                    error=f"Error following same-origin redirect to {location!r}: {exc}",
                )

        raw: Dict[str, Any] = {}
        try:
            raw = resp.json()
        except Exception:
            raw = {"_raw_text": resp.text[:500]}

        extracted = _extract_field(raw, target.response_field)

        return ValidationResult(
            success=200 <= resp.status_code < 300,
            probe_sent=self.probe_text,
            status_code=resp.status_code,
            raw_response=raw,
            extracted_response=extracted,
        )
