from typing import List, Optional

import httpx

from . import __version__ as RUNNER_VERSION
from .recorder.redact import redact_text


class CloudAPIError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class RunnerClient:
    """Thin HTTP client for the BADASS Cloud runner endpoints."""

    def __init__(
        self,
        server_url: str,
        runner_token: Optional[str] = None,
        timeout: int = 15,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.runner_token = runner_token
        self.timeout = timeout

    def _auth_headers(self) -> dict:
        if not self.runner_token:
            return {}
        return {"Authorization": f"Bearer {self.runner_token}"}

    def register(self, registration_token: str) -> dict:
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/register",
                json={
                    "registration_token": registration_token,
                    "runner_version": RUNNER_VERSION,
                },
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Cannot reach cloud: {exc}") from exc

        if not resp.is_success:
            detail = _extract_detail(resp)
            raise CloudAPIError(resp.status_code, detail)

        return resp.json()

    def heartbeat(self) -> dict:
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/heartbeat",
                json={"runner_version": RUNNER_VERSION},
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Heartbeat request failed: {exc}") from exc

        if not resp.is_success:
            detail = _extract_detail(resp)
            raise CloudAPIError(resp.status_code, detail)

        return resp.json()

    # ------------------------------------------------------------------
    # Job lifecycle (Phase 6 — runner-based harness execution)
    # ------------------------------------------------------------------

    def poll_jobs(self) -> list:
        """Poll for pending harness jobs assigned to this runner."""
        try:
            resp = httpx.get(
                f"{self.server_url}/api/runners/jobs",
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Job poll request failed: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json().get("jobs", [])

    def claim_job(self, run_id: str) -> dict:
        """Claim a job, setting its status to RUNNING on the cloud."""
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/jobs/{run_id}/claim",
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Claim request failed: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()

    def complete_job(self, run_id: str, results: List[dict]) -> dict:
        """Upload sanitized test results and trigger cloud-side evaluation."""
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/jobs/{run_id}/complete",
                json={"results": results},
                headers=self._auth_headers(),
                timeout=max(self.timeout, 120),
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Complete request failed: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()

    def fail_job(self, run_id: str, error: str) -> dict:
        """Mark a job as failed on the cloud side.

        The error string is passed through ``redact_text`` before upload so
        that secrets accidentally captured in exception messages (e.g. Bearer
        tokens from HTTP responses) are never sent to the cloud.
        """
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/jobs/{run_id}/fail",
                json={"error": redact_text(error)},
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Fail request failed: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()

    def check_version(self) -> dict:
        """Fetch version compatibility information from the cloud.

        Unauthenticated — safe to call before login.

        Returns a dict with keys:
            ``minimum_runner_version``     — connectors below this must upgrade.
            ``recommended_runner_version`` — connectors below this receive a warning.
            ``api_contract_version``       — integer; increments on breaking changes.

        Raises:
            ConnectionError  — network unreachable.
            CloudAPIError    — non-2xx response (e.g. old cloud without the endpoint).
        """
        try:
            resp = httpx.get(
                f"{self.server_url}/api/runners/version",
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Version check request failed: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()

    def upload_capture(self, capture_data: dict) -> dict:
        """Upload a classified recorder capture to the cloud for wizard polling."""
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/recorder/sessions",
                json=capture_data,
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Cannot reach cloud: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()

    # ------------------------------------------------------------------
    # Phase 8 — Zero-config pairing (login flow)
    # ------------------------------------------------------------------

    def pair_start(self, device_id: str, runner_name: Optional[str] = None) -> dict:
        """Start a pairing session (anonymous).

        Returns pairing_code, browser_pair_url, polling_token, expires_in_seconds.
        """
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/pair/start",
                json={
                    "device_id": device_id,
                    "runner_version": RUNNER_VERSION,
                    "runner_name": runner_name,
                },
                headers={"X-Badass-Server-Url": self.server_url},
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Cannot reach cloud: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()

    def pair_poll(self, polling_token: str) -> dict:
        """Poll for pairing approval.

        Returns {status: 'pending'} or {status: 'approved', runner_token, runner_id}.
        Raises CloudAPIError with status 410 when expired/consumed.
        Raises CloudAPIError with status 429 when rate-limited.
        """
        try:
            resp = httpx.post(
                f"{self.server_url}/api/runners/pair/poll",
                headers={"Authorization": f"Bearer {polling_token}"},
                timeout=self.timeout,
            )
        except httpx.RequestError as exc:
            raise ConnectionError(f"Poll request failed: {exc}") from exc

        if not resp.is_success:
            raise CloudAPIError(resp.status_code, _extract_detail(resp))

        return resp.json()


def _extract_detail(resp: httpx.Response) -> str:
    try:
        return resp.json().get("detail", resp.text)
    except Exception:
        return resp.text
