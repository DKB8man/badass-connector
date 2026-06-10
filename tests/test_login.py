"""Phase 8 runner CLI login tests.

Tests the badass-runner login flow:
  - pair_start / pair_poll client methods
  - config persistence after successful login
  - browser open is attempted
  - fallback URL is shown if browser launch fails
  - polling succeeds and stores credentials
  - polling timeout is handled cleanly
  - start works after login (config has runner_id + runner_token)
  - existing --token flow still works (regression)
"""
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest
from click.testing import CliRunner

from badass_runner.cli import main
from badass_runner.client import CloudAPIError, RunnerClient
from badass_runner.config import CONFIG_FILE, RunnerConfig, load_config, save_config


# ---------------------------------------------------------------------------
# RunnerClient pairing methods
# ---------------------------------------------------------------------------

class TestPairStart:
    def test_pair_start_sends_correct_fields(self):
        client = RunnerClient("https://example.com")
        payload = {}

        def mock_post(url, json=None, headers=None, timeout=None):
            payload.update(json or {})
            resp = MagicMock()
            resp.is_success = True
            resp.json.return_value = {
                "pairing_code": "ABCDEF",
                "browser_pair_url": "https://example.com/pair/ABCDEF",
                "polling_token": "badass_poll_abc123",
                "expires_in_seconds": 600,
            }
            return resp

        with patch("httpx.post", side_effect=mock_post):
            result = client.pair_start(device_id="test-device", runner_name="My Machine")

        assert payload["device_id"] == "test-device"
        assert payload["runner_name"] == "My Machine"
        assert "runner_version" in payload
        assert result["pairing_code"] == "ABCDEF"

    def test_pair_start_connection_error(self):
        client = RunnerClient("https://unreachable.local")
        import httpx
        with patch("httpx.post", side_effect=httpx.RequestError("no route")):
            with pytest.raises(ConnectionError):
                client.pair_start(device_id="dev")


class TestPairPoll:
    def test_pair_poll_pending(self):
        client = RunnerClient("https://example.com")

        def mock_post(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.is_success = True
            resp.json.return_value = {"status": "pending"}
            return resp

        with patch("httpx.post", side_effect=mock_post):
            result = client.pair_poll("badass_poll_abc")

        assert result["status"] == "pending"

    def test_pair_poll_approved_returns_token(self):
        client = RunnerClient("https://example.com")

        def mock_post(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.is_success = True
            resp.json.return_value = {
                "status": "approved",
                "runner_token": "badass_runner_xyz",
                "runner_id": "runner-123",
                "runner_name": "My Machine",
            }
            return resp

        with patch("httpx.post", side_effect=mock_post):
            result = client.pair_poll("badass_poll_abc")

        assert result["status"] == "approved"
        assert result["runner_token"] == "badass_runner_xyz"

    def test_pair_poll_rate_limited(self):
        client = RunnerClient("https://example.com")

        def mock_post(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.is_success = False
            resp.status_code = 429
            resp.json.return_value = {"detail": "Poll too fast"}
            resp.text = "Poll too fast"
            return resp

        with patch("httpx.post", side_effect=mock_post):
            with pytest.raises(CloudAPIError) as exc:
                client.pair_poll("badass_poll_abc")
        assert exc.value.status_code == 429

    def test_pair_poll_expired(self):
        client = RunnerClient("https://example.com")

        def mock_post(url, headers=None, timeout=None):
            resp = MagicMock()
            resp.is_success = False
            resp.status_code = 410
            resp.json.return_value = {"detail": "Pairing expired"}
            resp.text = "Pairing expired"
            return resp

        with patch("httpx.post", side_effect=mock_post):
            with pytest.raises(CloudAPIError) as exc:
                client.pair_poll("badass_poll_abc")
        assert exc.value.status_code == 410


# ---------------------------------------------------------------------------
# CLI: login command
# ---------------------------------------------------------------------------

def _mock_start_resp():
    return {
        "pairing_code": "TEST12",
        "browser_pair_url": "https://example.com/pair/TEST12",
        "polling_token": "badass_poll_mock",
        "expires_in_seconds": 600,
    }


def _mock_approved_resp():
    return {
        "status": "approved",
        "runner_token": "badass_runner_mock_token",
        "runner_id": "runner-mock-id",
        "runner_name": "Test Machine",
    }


class TestLoginCommand:
    def test_login_stores_config_on_success(self):
        runner = CliRunner()
        call_count = {"n": 0}

        def mock_pair_start(self_client, device_id, runner_name=None):
            return _mock_start_resp()

        def mock_pair_poll(self_client, polling_token):
            call_count["n"] += 1
            if call_count["n"] < 2:
                return {"status": "pending"}
            return _mock_approved_resp()

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            with (
                patch.object(RunnerClient, "pair_start", mock_pair_start),
                patch.object(RunnerClient, "pair_poll", mock_pair_poll),
                patch("webbrowser.open", return_value=True),
                patch("time.sleep"),
            ):
                result = runner.invoke(main, [
                    "login",
                    "--server-url", "https://example.com",
                    "--name", "Test Machine",
                    "--config", str(cfg_path),
                ])

            # Must check cfg INSIDE the tempdir context — it's deleted on exit
            assert result.exit_code == 0, result.output
            cfg = load_config(cfg_path)
            assert cfg is not None
            assert cfg.runner_id == "runner-mock-id"
            assert cfg.runner_token == "badass_runner_mock_token"
            assert cfg.server_url == "https://example.com"

    def test_login_opens_browser(self):
        runner = CliRunner()
        browser_urls = []

        def mock_pair_start(self_client, device_id, runner_name=None):
            return _mock_start_resp()

        def mock_pair_poll(self_client, polling_token):
            return _mock_approved_resp()

        def mock_browser_open(url, new=0, autoraise=True):
            browser_urls.append(url)
            return True

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            with (
                patch.object(RunnerClient, "pair_start", mock_pair_start),
                patch.object(RunnerClient, "pair_poll", mock_pair_poll),
                patch("webbrowser.open", side_effect=mock_browser_open),
                patch("time.sleep"),
            ):
                runner.invoke(main, [
                    "login", "--server-url", "https://example.com",
                    "--config", str(cfg_path),
                ])

        assert any("TEST12" in url for url in browser_urls)

    def test_login_shows_fallback_url_if_browser_fails(self):
        runner = CliRunner()

        def mock_pair_start(self_client, device_id, runner_name=None):
            return _mock_start_resp()

        def mock_pair_poll(self_client, polling_token):
            return _mock_approved_resp()

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            with (
                patch.object(RunnerClient, "pair_start", mock_pair_start),
                patch.object(RunnerClient, "pair_poll", mock_pair_poll),
                patch("webbrowser.open", return_value=False),
                patch("time.sleep"),
            ):
                result = runner.invoke(main, [
                    "login", "--server-url", "https://example.com",
                    "--config", str(cfg_path),
                ])

        assert "https://example.com/pair/TEST12" in result.output

    def test_login_handles_polling_timeout(self):
        runner = CliRunner()

        def mock_pair_start(self_client, device_id, runner_name=None):
            return {**_mock_start_resp(), "expires_in_seconds": 1}

        def mock_pair_poll(self_client, polling_token):
            return {"status": "pending"}

        elapsed = [0]

        def mock_sleep(secs):
            elapsed[0] += secs

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            with (
                patch.object(RunnerClient, "pair_start", mock_pair_start),
                patch.object(RunnerClient, "pair_poll", mock_pair_poll),
                patch("webbrowser.open", return_value=True),
                patch("time.sleep", side_effect=mock_sleep),
                patch("time.monotonic", side_effect=[0, 0, 2, 2]),
            ):
                result = runner.invoke(main, [
                    "login", "--server-url", "https://example.com",
                    "--config", str(cfg_path),
                ])

        assert result.exit_code != 0

    def test_login_handles_rate_limit_gracefully(self):
        runner = CliRunner()
        call_count = {"n": 0}

        def mock_pair_start(self_client, device_id, runner_name=None):
            return _mock_start_resp()

        def mock_pair_poll(self_client, polling_token):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise CloudAPIError(429, "Poll too fast")
            return _mock_approved_resp()

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            with (
                patch.object(RunnerClient, "pair_start", mock_pair_start),
                patch.object(RunnerClient, "pair_poll", mock_pair_poll),
                patch("webbrowser.open", return_value=True),
                patch("time.sleep"),
            ):
                result = runner.invoke(main, [
                    "login", "--server-url", "https://example.com",
                    "--config", str(cfg_path),
                ])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# CLI: start after login (regression — token flow still works)
# ---------------------------------------------------------------------------

class TestStartAfterLogin:
    def test_start_uses_saved_config(self):
        """start should work without --token when config has runner_id + runner_token."""
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg = RunnerConfig(
                server_url="https://example.com",
                runner_name="Test Runner",
                runner_id="runner-123",
                runner_token="badass_runner_abc",
                device_id="dev-123",
            )
            save_config(cfg, cfg_path)

            with (
                patch("badass_runner.heartbeat.HeartbeatLoop") as _hl,
                patch("badass_runner.status_server.LocalStatusServer") as _ss,
                patch("badass_runner.cli.write_pid"),
                patch("badass_runner.cli.clear_pid"),
                patch("os.getpid", return_value=12345),
                patch("threading.Event") as mock_ev,
            ):
                ev_instance = MagicMock()
                ev_instance.wait.side_effect = KeyboardInterrupt
                mock_ev.return_value = ev_instance

                result = runner.invoke(main, [
                    "start",
                    "--config", str(cfg_path),
                ])

        # Should not fail with "no credentials" error
        assert "No runner credentials" not in (result.output or "")

    def test_start_fails_without_config_and_token(self):
        """start without any credentials should give a clear error."""
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            result = runner.invoke(main, [
                "start",
                "--server-url", "https://example.com",
                "--config", str(cfg_path),
            ])

        assert result.exit_code != 0
        assert "No runner credentials" in (result.output + (result.exception and str(result.exception) or ""))

    def test_existing_token_flow_still_works(self):
        """--token flag should still register via the old token endpoint (regression)."""
        runner = CliRunner()

        def mock_register(self_client, registration_token):
            return {
                "runner_id": "runner-reg-123",
                "runner_token": "badass_runner_reg_abc",
                "name": "Token Runner",
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            with (
                patch.object(RunnerClient, "register", mock_register),
                patch("badass_runner.heartbeat.HeartbeatLoop") as _hl,
                patch("badass_runner.status_server.LocalStatusServer") as _ss,
                patch("badass_runner.cli.write_pid"),
                patch("badass_runner.cli.clear_pid"),
                patch("os.getpid", return_value=12345),
                patch("threading.Event") as mock_ev,
            ):
                ev_instance = MagicMock()
                ev_instance.wait.side_effect = KeyboardInterrupt
                mock_ev.return_value = ev_instance

                result = runner.invoke(main, [
                    "start",
                    "--server-url", "https://example.com",
                    "--token", "badass_reg_faketoken",
                    "--config", str(cfg_path),
                ])

            # Must check INSIDE the tmpdir context — it's deleted on exit
            saved = load_config(cfg_path)
            assert saved is not None
            assert saved.runner_id == "runner-reg-123"


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

class TestConfigPersistence:
    def test_device_id_preserved_across_login(self):
        """A stable device_id should persist between login calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg = RunnerConfig(
                server_url="https://example.com",
                runner_name="Test",
                device_id="stable-device-id",
            )
            save_config(cfg, cfg_path)

            loaded = load_config(cfg_path)
            assert loaded.device_id == "stable-device-id"

    def test_config_file_permissions(self):
        """Config file should be created with 0o600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = Path(tmpdir) / "config.json"
            cfg = RunnerConfig(server_url="https://x.com", runner_name="r")
            save_config(cfg, cfg_path)
            mode = oct(cfg_path.stat().st_mode)
            assert mode.endswith("600")
