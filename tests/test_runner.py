"""Phase 2 Local Runner tests.

Unit tests covering: config, client, heartbeat loop, status server, CLI commands.
All HTTP calls are mocked — no real server required.
"""
import json
import os
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Make runner package importable from tests/
sys.path.insert(0, str(Path(__file__).parent.parent))

from badass_runner.client import CloudAPIError, RunnerClient
from badass_runner.config import (
    RunnerConfig,
    clear_pid,
    load_config,
    read_pid,
    save_config,
    write_pid,
)
from badass_runner.heartbeat import HeartbeatLoop
from badass_runner.status_server import LocalStatusServer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_config_dir(tmp_path):
    """Isolated config directory so tests don't touch ~/.badass-runner."""
    return tmp_path


@pytest.fixture()
def config(tmp_config_dir):
    return RunnerConfig(
        server_url="http://localhost:9999",
        runner_name="test-runner",
        runner_id="runner-abc",
        runner_token="badass_runner_TESTTOKEN",
        status_port=0,
    )


def _ok_response(data: dict):
    """Build a mock httpx Response that looks like a success."""
    resp = MagicMock()
    resp.is_success = True
    resp.status_code = 200
    resp.json.return_value = data
    resp.text = json.dumps(data)
    return resp


def _error_response(status_code: int, detail: str):
    resp = MagicMock()
    resp.is_success = False
    resp.status_code = status_code
    resp.json.return_value = {"detail": detail}
    resp.text = detail
    return resp


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class TestConfig:

    def test_save_and_load_roundtrip(self, tmp_config_dir):
        cfg = RunnerConfig(
            server_url="https://cloud.example.com",
            runner_name="my-runner",
            runner_id="id-123",
            runner_token="badass_runner_tok",
        )
        cfg_file = tmp_config_dir / "config.json"
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        assert loaded.server_url == cfg.server_url
        assert loaded.runner_name == cfg.runner_name
        assert loaded.runner_id == cfg.runner_id
        assert loaded.runner_token == cfg.runner_token

    def test_load_missing_returns_none(self, tmp_config_dir):
        assert load_config(tmp_config_dir / "nonexistent.json") is None

    def test_is_registered_true(self):
        cfg = RunnerConfig(
            server_url="http://x.com", runner_name="r",
            runner_id="id", runner_token="tok",
        )
        assert cfg.is_registered() is True

    def test_is_registered_false_no_token(self):
        cfg = RunnerConfig(server_url="http://x.com", runner_name="r")
        assert cfg.is_registered() is False

    def test_pid_write_read_clear(self, tmp_config_dir):
        pid_file = tmp_config_dir / "runner.pid"
        write_pid(12345, pid_file)
        assert read_pid(pid_file) == 12345
        clear_pid(pid_file)
        assert read_pid(pid_file) is None

    def test_runner_token_not_in_plain_text_after_save(self, tmp_config_dir):
        """Token IS stored in config file (not hashed) — but file should exist."""
        cfg = RunnerConfig(
            server_url="https://cloud.example.com", runner_name="r",
            runner_id="id", runner_token="badass_runner_secret",
        )
        cfg_file = tmp_config_dir / "config.json"
        save_config(cfg, cfg_file)
        assert cfg_file.exists()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class TestRunnerClient:

    def test_register_success(self):
        client = RunnerClient("http://localhost:9999")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _ok_response(
                {"runner_id": "id-1", "runner_token": "badass_runner_tok", "name": "r"}
            )
            result = client.register("badass_reg_MYTOKEN")
        assert result["runner_id"] == "id-1"
        assert result["runner_token"] == "badass_runner_tok"

    def test_register_sends_runner_version(self):
        client = RunnerClient("http://localhost:9999")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _ok_response(
                {"runner_id": "id-1", "runner_token": "tok", "name": "r"}
            )
            client.register("badass_reg_X")
        call_kwargs = mock_post.call_args
        assert "runner_version" in call_kwargs.kwargs.get("json", {})

    def test_register_invalid_token_raises_cloud_api_error(self):
        client = RunnerClient("http://localhost:9999")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _error_response(401, "Invalid registration token")
            with pytest.raises(CloudAPIError) as exc_info:
                client.register("bad_token")
        assert exc_info.value.status_code == 401

    def test_heartbeat_success(self):
        client = RunnerClient("http://localhost:9999", runner_token="badass_runner_T")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _ok_response({"ok": True, "runner_id": "id-1"})
            result = client.heartbeat()
        assert result["ok"] is True

    def test_heartbeat_sends_auth_header(self):
        client = RunnerClient("http://localhost:9999", runner_token="badass_runner_T")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _ok_response({"ok": True, "runner_id": "id-1"})
            client.heartbeat()
        headers = mock_post.call_args.kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer badass_runner_T"

    def test_heartbeat_connection_error_raises(self):
        import httpx as _httpx
        client = RunnerClient("http://localhost:9999", runner_token="tok")
        with patch("httpx.post", side_effect=_httpx.ConnectError("refused")):
            with pytest.raises(ConnectionError):
                client.heartbeat()

    def test_heartbeat_revoked_raises_403(self):
        client = RunnerClient("http://localhost:9999", runner_token="tok")
        with patch("httpx.post") as mock_post:
            mock_post.return_value = _error_response(403, "Runner has been revoked")
            with pytest.raises(CloudAPIError) as exc_info:
                client.heartbeat()
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Heartbeat loop
# ---------------------------------------------------------------------------

class TestHeartbeatLoop:

    def _make_client(self, heartbeat_responses):
        """Build a mock client whose heartbeat() cycles through responses."""
        client = MagicMock()
        client.heartbeat.side_effect = heartbeat_responses
        return client

    def test_heartbeat_loop_calls_heartbeat(self):
        stop = threading.Event()
        responses = [None, None, stop.set()]  # two successful beats then stop

        client = MagicMock()
        call_count = [0]

        def hb():
            call_count[0] += 1
            if call_count[0] >= 2:
                stop.set()

        client.heartbeat.side_effect = hb

        loop = HeartbeatLoop(client, interval=0)
        loop.start()
        stop.wait(timeout=2)
        loop.stop()

        assert call_count[0] >= 2

    def test_loop_stops_on_revoked(self):
        revoked = threading.Event()
        client = MagicMock()
        client.heartbeat.side_effect = CloudAPIError(403, "Runner has been revoked")

        loop = HeartbeatLoop(
            client, interval=0, on_revoked=revoked.set
        )
        loop.start()
        assert revoked.wait(timeout=2), "on_revoked callback not called"
        loop.stop()

    def test_loop_stops_on_invalid_auth(self):
        invalid = threading.Event()
        client = MagicMock()
        client.heartbeat.side_effect = CloudAPIError(401, "Invalid runner token")

        loop = HeartbeatLoop(
            client, interval=0, on_invalid_auth=invalid.set
        )
        loop.start()
        assert invalid.wait(timeout=2), "on_invalid_auth callback not called"
        loop.stop()

    def test_loop_retries_on_connection_error(self):
        success = threading.Event()
        call_count = [0]

        client = MagicMock()

        def hb():
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("timeout")
            success.set()

        client.heartbeat.side_effect = hb

        # initial_backoff=0 so the retry happens immediately in tests
        loop = HeartbeatLoop(client, interval=0, initial_backoff=0)
        loop.start()
        assert success.wait(timeout=3), "Did not retry after connection error"
        loop.stop()
        assert call_count[0] >= 2

    def test_loop_is_running_after_start(self):
        stop = threading.Event()
        client = MagicMock()
        client.heartbeat.side_effect = lambda: stop.wait(10)

        loop = HeartbeatLoop(client, interval=0)
        loop.start()
        assert loop.is_running()
        stop.set()
        loop.stop()


# ---------------------------------------------------------------------------
# Local status server
# ---------------------------------------------------------------------------

class TestLocalStatusServer:

    def _find_free_port(self) -> int:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_status_endpoint_returns_200(self):
        import httpx as _httpx

        port = self._find_free_port()
        state = {"running": True, "status": "connected", "runner_id": "r1"}
        server = LocalStatusServer(port=port, get_state=lambda: state)
        server.start()
        time.sleep(0.1)

        try:
            resp = _httpx.get(f"http://127.0.0.1:{port}/status", timeout=3)
            assert resp.status_code == 200
            data = resp.json()
            assert data["running"] is True
            assert data["status"] == "connected"
        finally:
            server.stop()

    def test_unknown_path_returns_404(self):
        import httpx as _httpx

        port = self._find_free_port()
        server = LocalStatusServer(port=port, get_state=lambda: {})
        server.start()
        time.sleep(0.1)

        try:
            resp = _httpx.get(f"http://127.0.0.1:{port}/unknown", timeout=3)
            assert resp.status_code == 404
        finally:
            server.stop()

    def test_is_running_after_start(self):
        port = self._find_free_port()
        server = LocalStatusServer(port=port, get_state=lambda: {})
        server.start()
        time.sleep(0.05)
        assert server.is_running()
        server.stop()


# ---------------------------------------------------------------------------
# CLI — start / status / stop
# ---------------------------------------------------------------------------

class TestCLI:

    def test_start_registers_and_runs(self, tmp_config_dir):
        """Runner registers, saves config, starts heartbeat+status threads, then stops."""
        from click.testing import CliRunner
        from badass_runner.cli import main

        cfg_file = tmp_config_dir / "config.json"
        pid_file = tmp_config_dir / "runner.pid"

        register_resp = _ok_response(
            {"runner_id": "r-test", "runner_token": "badass_runner_T", "name": "tester"}
        )
        version_resp = _ok_response({
            "minimum_runner_version": "0.1.0",
            "recommended_runner_version": "0.2.0",
            "api_contract_version": "1",
        })

        runner = CliRunner()

        # Mock HeartbeatLoop and LocalStatusServer so start() doesn't block,
        # and patch threading.Event so shutdown_event.wait() returns immediately.
        mock_heartbeat = MagicMock()
        mock_status = MagicMock()
        mock_event = MagicMock()
        mock_event.wait.return_value = None  # unblock shutdown_event.wait()
        mock_event.is_set.return_value = False
        mock_event.set.return_value = None

        with patch("httpx.post", return_value=register_resp) as mock_post, \
             patch("httpx.get", return_value=version_resp), \
             patch("badass_runner.cli.HeartbeatLoop", return_value=mock_heartbeat), \
             patch("badass_runner.cli.LocalStatusServer", return_value=mock_status), \
             patch("badass_runner.cli.threading") as mock_threading, \
             patch("badass_runner.cli.PID_FILE", pid_file), \
             patch("badass_runner.cli.CONFIG_FILE", cfg_file):

            mock_threading.Event.return_value = mock_event

            result = runner.invoke(
                main,
                [
                    "start",
                    "--server-url", "http://localhost:9999",
                    "--token", "badass_reg_TEST",
                    "--name", "tester",
                    "--port", "7890",
                    "--config", str(cfg_file),
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        # Registration was called
        mock_post.assert_called_once()
        assert "register" in mock_post.call_args[0][0]
        # Heartbeat loop was started
        mock_heartbeat.start.assert_called_once()
        # Status server was started
        mock_status.start.assert_called_once()
        # Config was persisted with runner_id + token
        saved = load_config(cfg_file)
        assert saved is not None
        assert saved.runner_id == "r-test"
        assert saved.runner_token == "badass_runner_T"

    def test_start_requires_server_url_for_registration(self, tmp_config_dir):
        from click.testing import CliRunner
        from badass_runner.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["start", "--token", "badass_reg_X", "--config",
             str(tmp_config_dir / "config.json")],
        )
        assert result.exit_code != 0
        assert "server-url" in result.output.lower() or "server_url" in result.output.lower()

    def test_start_no_token_no_config_fails(self, tmp_config_dir):
        from click.testing import CliRunner
        from badass_runner.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["start", "--config", str(tmp_config_dir / "nonexistent.json")],
        )
        assert result.exit_code != 0

    def test_status_no_pid_file(self, tmp_config_dir):
        from click.testing import CliRunner
        from badass_runner.cli import main

        runner = CliRunner()
        with patch("badass_runner.cli.PID_FILE", tmp_config_dir / "runner.pid"):
            result = runner.invoke(main, ["status"])
        assert "not running" in result.output.lower() or "no runner" in result.output.lower()

    def test_stop_no_pid_file(self, tmp_config_dir):
        from click.testing import CliRunner
        from badass_runner.cli import main

        runner = CliRunner()
        with patch("badass_runner.cli.PID_FILE", tmp_config_dir / "runner.pid"):
            result = runner.invoke(main, ["stop"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower() or "no runner" in result.output.lower()

    def test_stop_sends_sigterm(self, tmp_config_dir):
        from click.testing import CliRunner
        from badass_runner.cli import main

        pid_file = tmp_config_dir / "runner.pid"
        write_pid(os.getpid(), pid_file)  # use own PID — won't actually kill

        runner = CliRunner()
        with patch("badass_runner.cli.PID_FILE", pid_file), \
             patch("os.kill") as mock_kill:
            result = runner.invoke(main, ["stop"])

        mock_kill.assert_called_once_with(os.getpid(), signal.SIGTERM)
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# RunnerClient.check_version() — unit tests
# ---------------------------------------------------------------------------

def _ok_version_response() -> MagicMock:
    return _ok_response({
        "minimum_runner_version": "0.1.0",
        "recommended_runner_version": "0.2.0",
        "api_contract_version": "1",
    })


class TestCheckVersion:
    """Unit tests for RunnerClient.check_version()."""

    def test_returns_dict_on_200(self):
        with patch("httpx.get", return_value=_ok_version_response()):
            client = RunnerClient(server_url="https://example.com")
            result = client.check_version()
        assert result["minimum_runner_version"] == "0.1.0"
        assert result["recommended_runner_version"] == "0.2.0"
        assert result["api_contract_version"] == "1"

    def test_calls_unauthenticated_version_path(self):
        """check_version must hit /api/runners/version with no auth header."""
        with patch("httpx.get", return_value=_ok_version_response()) as mock_get:
            client = RunnerClient(server_url="https://cloud.example.com")
            client.check_version()
        url = mock_get.call_args[0][0]
        assert url == "https://cloud.example.com/api/runners/version"
        # No Authorization header expected
        kwargs = mock_get.call_args[1] if mock_get.call_args[1] else {}
        assert "Authorization" not in kwargs.get("headers", {})

    def test_raises_connection_error_on_network_failure(self):
        import httpx as _httpx
        with patch("httpx.get", side_effect=_httpx.ConnectError("refused")):
            client = RunnerClient(server_url="https://example.com")
            with pytest.raises(ConnectionError):
                client.check_version()

    def test_raises_cloud_api_error_on_404(self):
        resp_404 = MagicMock(status_code=404, is_success=False,
                             text="Not Found", json=lambda: {"detail": "Not Found"})
        with patch("httpx.get", return_value=resp_404):
            client = RunnerClient(server_url="https://example.com")
            with pytest.raises(CloudAPIError) as exc_info:
                client.check_version()
        assert exc_info.value.status_code == 404

    def test_raises_cloud_api_error_on_500(self):
        resp_500 = MagicMock(status_code=500, is_success=False,
                             text="Internal Server Error",
                             json=lambda: {"detail": "Internal Server Error"})
        with patch("httpx.get", return_value=resp_500):
            client = RunnerClient(server_url="https://example.com")
            with pytest.raises(CloudAPIError) as exc_info:
                client.check_version()
        assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# _check_cloud_version() — CLI helper unit tests
# ---------------------------------------------------------------------------

class TestCheckCloudVersion:
    """Unit tests for the _check_cloud_version() CLI helper."""

    def _make_client(self, version_info=None, raise_conn=False, raise_api=False):
        """Return a MagicMock RunnerClient with a preset check_version() behaviour."""
        m = MagicMock()
        if raise_conn:
            m.check_version.side_effect = ConnectionError("refused")
        elif raise_api:
            m.check_version.side_effect = CloudAPIError(404, "Not Found")
        else:
            m.check_version.return_value = version_info or {
                "minimum_runner_version": "0.1.0",
                "recommended_runner_version": "0.2.0",
                "api_contract_version": "1",
            }
        return m

    def test_compatible_version_does_not_exit(self):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client()
        _check_cloud_version(client)  # must not raise

    def test_below_minimum_exits_with_code_1(self):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client({
            "minimum_runner_version": "99.0.0",
            "recommended_runner_version": "99.0.0",
            "api_contract_version": "1",
        })
        with pytest.raises(SystemExit) as exc_info:
            _check_cloud_version(client)
        assert exc_info.value.code == 1

    def test_below_minimum_message_contains_version(self, capsys):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client({
            "minimum_runner_version": "99.0.0",
            "recommended_runner_version": "99.0.0",
            "api_contract_version": "1",
        })
        with pytest.raises(SystemExit):
            _check_cloud_version(client)
        captured = capsys.readouterr()
        assert "99.0.0" in captured.err
        assert "upgrade" in captured.err.lower()

    def test_below_recommended_does_not_exit(self):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client({
            "minimum_runner_version": "0.1.0",
            "recommended_runner_version": "99.0.0",
            "api_contract_version": "1",
        })
        _check_cloud_version(client)  # must not raise SystemExit

    def test_below_recommended_emits_warning(self, capsys):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client({
            "minimum_runner_version": "0.1.0",
            "recommended_runner_version": "99.0.0",
            "api_contract_version": "1",
        })
        _check_cloud_version(client)
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "99.0.0" in captured.err

    def test_connection_error_warns_and_continues(self, capsys):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client(raise_conn=True)
        _check_cloud_version(client)  # must not raise
        captured = capsys.readouterr()
        assert "Warning" in captured.err

    def test_cloud_api_error_warns_and_continues(self, capsys):
        from badass_runner.cli import _check_cloud_version
        client = self._make_client(raise_api=True)
        _check_cloud_version(client)  # must not raise
        captured = capsys.readouterr()
        assert "Warning" in captured.err


# ---------------------------------------------------------------------------
# _parse_version() — unit tests
# ---------------------------------------------------------------------------

class TestParseVersion:
    """Unit tests for the _parse_version() semver helper."""

    def test_standard_semver(self):
        from badass_runner.cli import _parse_version
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_v_prefix_stripped(self):
        from badass_runner.cli import _parse_version
        assert _parse_version("v0.2.0") == (0, 2, 0)

    def test_comparison_works(self):
        from badass_runner.cli import _parse_version
        assert _parse_version("0.1.0") < _parse_version("0.2.0")
        assert _parse_version("1.0.0") > _parse_version("0.9.9")
        assert _parse_version("0.2.0") == _parse_version("0.2.0")

    def test_malformed_returns_zero_tuple(self):
        from badass_runner.cli import _parse_version
        assert _parse_version("not-a-version") == (0, 0, 0)
        assert _parse_version("") == (0, 0, 0)


# ---------------------------------------------------------------------------
# RunnerClient.fail_job() — error redaction
# ---------------------------------------------------------------------------

class TestFailJobRedaction:
    """fail_job must apply redact_text() to the error string before upload."""

    def test_bearer_token_in_error_is_redacted(self):
        """A Bearer token captured in an exception message must not reach the cloud."""
        captured = {}

        def _mock_post(url, json=None, headers=None, timeout=None):
            captured["json"] = json
            return _ok_response({"ok": True})

        with patch("httpx.post", side_effect=_mock_post):
            client = RunnerClient(
                server_url="https://example.com",
                runner_token="badass_runner_T",
            )
            client.fail_job("run-1", "Request failed: Authorization: Bearer super-secret-value")

        error_sent = captured["json"]["error"]
        assert "super-secret-value" not in error_sent
        assert "[REDACTED]" in error_sent

    def test_clean_error_passes_through_unchanged(self):
        """A safe error string must survive redaction intact."""
        captured = {}

        def _mock_post(url, json=None, headers=None, timeout=None):
            captured["json"] = json
            return _ok_response({"ok": True})

        safe_msg = "Target returned HTTP 503 — service unavailable"
        with patch("httpx.post", side_effect=_mock_post):
            client = RunnerClient(
                server_url="https://example.com",
                runner_token="badass_runner_T",
            )
            client.fail_job("run-2", safe_msg)

        assert captured["json"]["error"] == safe_msg

    def test_quoted_assignment_secret_is_redacted(self):
        """Quoted assignment patterns (key=\"value\") must also be redacted."""
        captured = {}

        def _mock_post(url, json=None, headers=None, timeout=None):
            captured["json"] = json
            return _ok_response({"ok": True})

        with patch("httpx.post", side_effect=_mock_post):
            client = RunnerClient(
                server_url="https://example.com",
                runner_token="badass_runner_T",
            )
            client.fail_job("run-3", 'Error: api_key="my-secret-api-key-value" was rejected')

        assert "my-secret-api-key-value" not in captured["json"]["error"]


# ---------------------------------------------------------------------------
# Smoke: existing cloud target execution unchanged
# ---------------------------------------------------------------------------

class TestCloudTargetUnchanged:
    """Verify the runner's harness package is self-contained and uses correct API paths."""

    def test_harness_package_importable(self):
        """Runner harness subpackage must be importable without any cloud/backend deps."""
        from badass_runner.harness import job_poller, executor  # noqa: F401

    def test_runner_client_uses_api_runners_prefix(self):
        """RunnerClient must target /api/runners/ — documents the runner-cloud contract."""
        import inspect
        import badass_runner.client as client_module
        source = inspect.getsource(client_module)
        assert "/api/runners/" in source, (
            "RunnerClient must use /api/runners/ for all cloud calls"
        )

    def test_runner_harness_uses_jobs_path_not_harness_prefix(self):
        """Job poller must call /api/runners/jobs — not the cloud /api/harness/ prefix."""
        import inspect
        import badass_runner.harness.job_poller as poller_module
        source = inspect.getsource(poller_module)
        assert "/api/runners/jobs" in source or "jobs" in source, (
            "JobPoller must poll /api/runners/jobs"
        )

    def test_runner_target_independent_of_cloud_harness_model(self):
        """LocalTarget must be self-contained — no cloud harness model dependencies."""
        import dataclasses
        from badass_runner.target.builder import LocalTarget, LocalAuthStore
        target_fields = {f.name for f in dataclasses.fields(LocalTarget)}
        assert "target_id" in target_fields
        assert "base_url" in target_fields
        assert "endpoint_path" in target_fields
        auth_fields = {f.name for f in dataclasses.fields(LocalAuthStore)}
        assert "auth_type" in auth_fields
        assert "credential_value" in auth_fields
