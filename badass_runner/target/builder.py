"""TargetBuilder — converts a ClassificationResult into a LocalTarget.

Auth safety contract
--------------------
* ``extra_headers`` passed to ``from_classification`` have every credential-
  bearing header stripped before being stored in ``LocalTarget.safe_headers``.
* ``LocalAuthStore`` holds the raw credential in memory only — it is never
  serialised to disk and never included in ``to_cloud_payload()``.
* ``to_cloud_payload()`` contains only structural metadata (base URL, path,
  method, content-type, field names, runner_required flag).  No tokens, no
  cookies, no credential values ever reach the cloud payload.

Override support
----------------
* ``TargetBuilder.from_classification`` accepts ``prompt_field_override``,
  ``response_field_override``, and ``path_override`` at build time.
* ``TargetBuilder.apply_overrides`` returns a modified copy of an existing
  LocalTarget — use this for interactive corrections after inspection.
"""

import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Dict, Optional

from ..classifier.classifier import ClassificationResult

# ---------------------------------------------------------------------------
# Auth-header detection (mirrors recorder/redact.py but kept self-contained)
# ---------------------------------------------------------------------------

_AUTH_HEADER_EXACT: frozenset = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-secret",
    "api-key",
})

_AUTH_SUBSTRINGS: tuple = (
    "token", "secret", "key", "password", "passwd", "credential", "auth",
)


def _is_auth_header(name: str) -> bool:
    """Return True if *name* looks like an authentication / credential header."""
    low = name.lower()
    if low in _AUTH_HEADER_EXACT:
        return True
    return any(sub in low for sub in _AUTH_SUBSTRINGS)


def _strip_auth_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of *headers* with every auth-bearing header removed."""
    return {k: v for k, v in headers.items() if not _is_auth_header(k)}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LocalTarget:
    """Local (runner-side) representation of an AI endpoint target.

    ``runner_required`` is always ``True`` — this target was discovered
    locally and can only be tested via a Local Runner.
    """

    target_id: str
    name: str
    base_url: str
    endpoint_path: str
    method: str
    content_type: str
    prompt_field: str
    response_field: str
    safe_headers: Dict[str, str]
    runner_required: bool
    created_at: datetime
    source_session_id: Optional[str] = None

    def to_cloud_payload(self) -> dict:
        """Return a dict safe to send to BADASS Cloud.

        Credential-bearing headers are excluded.  ``safe_headers`` has already
        had auth stripped at build time, so this method simply omits any
        local-only fields and serialises the rest.
        """
        return {
            "target_id": self.target_id,
            "name": self.name,
            "base_url": self.base_url,
            "endpoint_path": self.endpoint_path,
            "method": self.method,
            "content_type": self.content_type,
            "prompt_field": self.prompt_field,
            "response_field": self.response_field,
            "safe_headers": dict(self.safe_headers),
            "runner_required": self.runner_required,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class LocalAuthStore:
    """Stores authentication credentials for a target — never leaves the runner.

    Supported auth types:
        none       — no authentication required
        bearer     — Authorization: Bearer <credential_value>
        basic      — Authorization: Basic <credential_value>  (pre-encoded)
        api_key    — <header_name>: <credential_value>
        cookie     — Cookie: <credential_value>
    """

    target_id: str
    auth_type: str = "none"
    credential_value: Optional[str] = None
    header_name: Optional[str] = None

    def apply_to_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return a copy of *headers* with the credential injected."""
        out = dict(headers)
        if self.auth_type == "bearer" and self.credential_value:
            out["Authorization"] = f"Bearer {self.credential_value}"
        elif self.auth_type == "basic" and self.credential_value:
            out["Authorization"] = f"Basic {self.credential_value}"
        elif self.auth_type == "api_key" and self.header_name and self.credential_value:
            out[self.header_name] = self.credential_value
        elif self.auth_type == "cookie" and self.credential_value:
            out["Cookie"] = self.credential_value
        return out

    def to_safe_summary(self) -> dict:
        """Cloud-safe summary: auth type flag only, no credential value."""
        return {
            "auth_type": self.auth_type,
            "has_auth": self.auth_type != "none",
        }


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class InvalidClassificationError(ValueError):
    """Raised when a ClassificationResult cannot be used to build a target."""


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class TargetBuilder:
    """Converts a :class:`~badass_runner.classifier.ClassificationResult`
    into a :class:`LocalTarget`."""

    @staticmethod
    def from_classification(
        result: ClassificationResult,
        base_url: str,
        name: Optional[str] = None,
        source_session_id: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        prompt_field_override: Optional[str] = None,
        response_field_override: Optional[str] = None,
        path_override: Optional[str] = None,
    ) -> LocalTarget:
        """Build a :class:`LocalTarget` from a ``ClassificationResult``.

        Parameters
        ----------
        result:
            Must have ``likely_ai = True``; raises
            :class:`InvalidClassificationError` otherwise.
        base_url:
            Scheme + host of the target (e.g. ``http://localhost:8000``).
            Must not include a path.
        name:
            Human-readable target name.  Defaults to ``"METHOD /path"``.
        source_session_id:
            Recorder session this target was derived from (stored for
            traceability, not uploaded to cloud).
        extra_headers:
            Additional headers observed during recording (e.g. ``Accept``,
            ``X-Request-ID``).  Auth-bearing headers are stripped
            automatically before storage.
        prompt_field_override / response_field_override / path_override:
            Manual corrections applied at build time.
        """
        if result is None or not result.likely_ai:
            conf = getattr(result, "confidence", 0.0) if result is not None else 0.0
            raise InvalidClassificationError(
                f"Cannot build target from a non-AI classification result "
                f"(confidence={conf:.2f}, likely_ai=False)."
            )

        prompt_field = prompt_field_override or result.detected_prompt_field or "message"
        response_field = response_field_override or result.detected_response_field or "response"
        endpoint_path = path_override or result.path

        safe_headers = _strip_auth_headers(extra_headers or {})

        return LocalTarget(
            target_id=uuid.uuid4().hex[:12],
            name=name or f"{result.method} {endpoint_path}",
            base_url=base_url.rstrip("/"),
            endpoint_path=endpoint_path,
            method=result.method,
            content_type=result.content_type,
            prompt_field=prompt_field,
            response_field=response_field,
            safe_headers=safe_headers,
            runner_required=True,
            created_at=datetime.now(timezone.utc),
            source_session_id=source_session_id,
        )

    @staticmethod
    def apply_overrides(
        target: LocalTarget,
        prompt_field: Optional[str] = None,
        response_field: Optional[str] = None,
        path: Optional[str] = None,
        name: Optional[str] = None,
    ) -> LocalTarget:
        """Return a new :class:`LocalTarget` with the specified fields overridden.

        Fields not provided are copied unchanged from *target*.
        """
        kwargs: dict = {}
        if prompt_field is not None:
            kwargs["prompt_field"] = prompt_field
        if response_field is not None:
            kwargs["response_field"] = response_field
        if path is not None:
            kwargs["endpoint_path"] = path
        if name is not None:
            kwargs["name"] = name
        return replace(target, **kwargs) if kwargs else target
