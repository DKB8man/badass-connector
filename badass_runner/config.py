import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


CONFIG_DIR = Path(os.environ.get("BADASS_RUNNER_HOME", Path.home() / ".badass-runner"))
CONFIG_FILE = CONFIG_DIR / "config.json"
PID_FILE = CONFIG_DIR / "runner.pid"

DEFAULT_STATUS_PORT = 7890
DEFAULT_HEARTBEAT_INTERVAL = 30


@dataclass
class RunnerConfig:
    server_url: str
    runner_name: str
    runner_id: Optional[str] = None
    runner_token: Optional[str] = None
    device_id: Optional[str] = None
    status_port: int = DEFAULT_STATUS_PORT
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL

    def is_registered(self) -> bool:
        return bool(self.runner_id and self.runner_token)


def load_config(config_path: Path = CONFIG_FILE) -> Optional[RunnerConfig]:
    if not config_path.exists():
        return None
    try:
        with open(config_path) as fh:
            data = json.load(fh)
        valid_keys = RunnerConfig.__dataclass_fields__.keys()
        return RunnerConfig(**{k: v for k, v in data.items() if k in valid_keys})
    except Exception:
        return None


def save_config(cfg: RunnerConfig, config_path: Path = CONFIG_FILE) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as fh:
        json.dump(asdict(cfg), fh, indent=2)
    os.chmod(config_path, 0o600)


def write_pid(pid: int, pid_path: Path = PID_FILE) -> None:
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(pid))


def read_pid(pid_path: Path = PID_FILE) -> Optional[int]:
    if not pid_path.exists():
        return None
    try:
        return int(pid_path.read_text().strip())
    except Exception:
        return None


def clear_pid(pid_path: Path = PID_FILE) -> None:
    if pid_path.exists():
        try:
            pid_path.unlink()
        except Exception:
            pass
