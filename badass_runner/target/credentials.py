"""Runner-local, keyring-backed credentials for protected target contexts.

The JSON index deliberately contains metadata only.  Credential values are
stored under their opaque reference in the operating system keyring and are
only fetched by :meth:`get_by_ref` (which R5-C will consume).
"""

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Optional

try:
    import keyring
except ImportError:  # Allows a clear operational error rather than plaintext.
    keyring = None

from ..config import CONFIG_DIR

KEYRING_SERVICE = "badass-runner.credentials.v1"
DEFAULT_INDEX_FILE = CONFIG_DIR / "credentials.json"
_REF_DOMAIN = b"badass.runner.enforcement.context-ref.v1\0"
_SECURE_OS_KEYRING_MODULES = (
    "keyring.backends.secretservice",
    "keyring.backends.libsecret",
    "keyring.backends.kwallet",
    "keyring.backends.macos",
    "keyring.backends.windows",
)
_AUTH_TYPE_ALIASES = {"api-key": "api_key", "header": "api_key"}
_SUPPORTED_AUTH_TYPES = {"bearer", "basic", "api_key", "cookie"}


def _canonical_auth_type(auth_type: Any) -> str:
    """Normalize legacy CLI spellings before they reach the credential index."""
    if not isinstance(auth_type, str):
        raise ValueError("unsupported credential auth type")
    normalized = _AUTH_TYPE_ALIASES.get(auth_type, auth_type)
    if normalized not in _SUPPORTED_AUTH_TYPES:
        raise ValueError("unsupported credential auth type")
    return normalized


class CredentialStorageError(RuntimeError):
    """The host secure credential backend could not safely be used."""


def _is_secure_os_keyring_backend(backend: Any) -> bool:
    """Accept only OS-backed keyrings whose security model we explicitly know."""
    backend_module = type(backend).__module__.lower()
    return backend_module in _SECURE_OS_KEYRING_MODULES


def credential_ref(target_ref: str, context_key: str) -> str:
    """Return the R5-A target/context-bound opaque credential reference."""
    if not target_ref or not context_key:
        raise ValueError("target_ref and context_key are required")
    digest = hashlib.sha256(
        _REF_DOMAIN + target_ref.encode("utf-8") + b"\0" + context_key.encode("utf-8")
    ).digest()
    return "credref_" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass
class LocalCredential:
    """A credential loaded locally; its value is never serialized or uploaded."""

    target_ref: str
    context_key: str
    auth_type: str
    header_name: Optional[str] = None
    credential_value: Optional[str] = None

    @property
    def ref(self) -> str:
        return credential_ref(self.target_ref, self.context_key)

    def to_safe_summary(self) -> dict[str, Any]:
        return {
            "target_ref": self.target_ref,
            "context_key": self.context_key,
            "credential_ref": self.ref,
            "auth_type": self.auth_type,
            "header_name": self.header_name,
            "has_credential": self.credential_value is not None,
        }

    def to_cloud_payload(self) -> dict[str, Any]:
        """Compatibility-safe serialization: credential values never cross it."""
        return self.to_safe_summary()


class MultiContextCredentialStore:
    """Metadata index plus OS-keyring secrets keyed by ``(target, context)``.

    Constructing/loading this store reads only metadata.  It intentionally
    does not resolve keyring entries at runner startup.
    """

    def __init__(self, index_path: Path | None = None, keyring_backend: Any = None) -> None:
        self.index_path = Path(index_path or DEFAULT_INDEX_FILE)
        self._keyring = keyring_backend if keyring_backend is not None else keyring
        self._metadata: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        if not self.index_path.exists():
            self._metadata = {}
            return
        try:
            with self.index_path.open(encoding="utf-8") as fh:
                records = json.load(fh)
            if not isinstance(records, list):
                raise ValueError("credential index must be a list")
            self._metadata = {}
            for record in records:
                if not isinstance(record, dict) or "credential_value" in record:
                    raise ValueError("credential index contains invalid or secret data")
                required = {"target_ref", "context_key", "credential_ref", "auth_type", "header_name"}
                if set(record) != required:
                    raise ValueError("credential index has invalid metadata fields")
                expected = credential_ref(record["target_ref"], record["context_key"])
                if record["credential_ref"] != expected:
                    raise ValueError("credential index reference does not match target/context")
                if expected in self._metadata:
                    raise ValueError("credential index contains ambiguous duplicate reference")
                self._metadata[expected] = record
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise CredentialStorageError(f"Cannot load credential metadata index: {exc}") from exc

    def _require_keyring(self) -> Any:
        if self._keyring is None:
            raise CredentialStorageError(
                "No OS keyring backend is available; refusing to store credentials in plaintext."
            )
        try:
            backend = self._keyring.get_keyring() if hasattr(self._keyring, "get_keyring") else self._keyring
            if getattr(backend, "priority", 1) <= 0:
                raise CredentialStorageError(
                    "No usable OS keyring backend is available; refusing plaintext storage."
                )
            if not _is_secure_os_keyring_backend(backend):
                raise CredentialStorageError(
                    "The configured keyring backend is not an approved secure OS "
                    "store; refusing plaintext storage."
                )
            return backend
        except CredentialStorageError:
            raise
        except Exception:
            raise CredentialStorageError(
                "OS keyring is unavailable; refusing plaintext storage."
            ) from None

    def _save_metadata(self) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".credentials-", dir=self.index_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(list(self._metadata.values()), fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.chmod(name, 0o600)
            os.replace(name, self.index_path)
            os.chmod(self.index_path, 0o600)
        except OSError as exc:
            try:
                os.unlink(name)
            except OSError:
                pass
            raise CredentialStorageError(f"Cannot save credential metadata index: {exc}") from exc

    def set(self, credential: LocalCredential) -> None:
        if not credential.credential_value:
            raise ValueError("credential value is required")
        auth_type = _canonical_auth_type(credential.auth_type)
        if auth_type == "api_key" and not credential.header_name:
            raise ValueError("header_name is required for api_key credentials")
        credential = replace(credential, auth_type=auth_type)
        ref = credential.ref
        backend = self._require_keyring()
        try:
            backend.set_password(KEYRING_SERVICE, ref, credential.credential_value)
        except Exception:
            raise CredentialStorageError(
                "Cannot save credential to the OS keyring."
            ) from None
        # Persist only after the secret is secure.  No value is copied into index.
        self._metadata[ref] = {
            "target_ref": credential.target_ref,
            "context_key": credential.context_key,
            "credential_ref": ref,
            "auth_type": credential.auth_type,
            "header_name": credential.header_name,
        }
        self._save_metadata()

    def get_by_ref(self, ref: str) -> Optional[LocalCredential]:
        """Load one secret only when a future executor explicitly requests it."""
        metadata = self._metadata.get(ref)
        if metadata is None:
            return None
        backend = self._require_keyring()
        try:
            secret = backend.get_password(KEYRING_SERVICE, ref)
        except Exception:
            raise CredentialStorageError(
                "Cannot read credential from the OS keyring."
            ) from None
        if secret is None:
            return None
        return LocalCredential(
            target_ref=metadata["target_ref"], context_key=metadata["context_key"],
            auth_type=_canonical_auth_type(metadata["auth_type"]),
            header_name=metadata["header_name"],
            credential_value=secret,
        )

    def get(self, target_ref: str, context_key: str) -> Optional[LocalCredential]:
        return self.get_by_ref(credential_ref(target_ref, context_key))

    def list_metadata(self) -> list[dict[str, Any]]:
        """Return safe metadata; this method never contacts the keyring."""
        return [
            {**record, "has_credential": True}
            for record in sorted(self._metadata.values(), key=lambda item: item["credential_ref"])
        ]

    def to_cloud_payload(self) -> list[dict[str, Any]]:
        """Return metadata only; secrets remain in the OS keyring."""
        return self.list_metadata()

    def remove(self, target_ref: str, context_key: str) -> bool:
        ref = credential_ref(target_ref, context_key)
        if ref not in self._metadata:
            return False
        backend = self._require_keyring()
        try:
            backend.delete_password(KEYRING_SERVICE, ref)
        except Exception:
            raise CredentialStorageError(
                "Cannot delete credential from the OS keyring."
            ) from None
        del self._metadata[ref]
        self._save_metadata()
        return True