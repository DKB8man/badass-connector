"""Local capture storage — persists recorder sessions as JSONL files.

Each line in the file is a JSON object representing one captured request/response
pair.  Files are stored at::

    ~/.badass-runner/sessions/<session_id>.jsonl

This allows ``recorder show`` to display captures even after the proxy has
stopped, and allows real-time append so captures are not lost if the process
crashes.
"""

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from ..config import CONFIG_DIR
from .session import Capture, RecorderSession

SESSIONS_DIR = CONFIG_DIR / "sessions"


def _session_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.jsonl"


def append_capture(session_id: str, capture: Capture) -> None:
    """Append a single capture to the session JSONL file."""
    path = _session_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "request": capture.request,
        "response": capture.response,
    }
    with open(path, "a") as fh:
        fh.write(json.dumps(entry) + "\n")
    # Restrict to owner-only (contains sanitised metadata, still sensitive)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_captures(session_id: str) -> List[dict]:
    """Load all captures for *session_id* from disk. Returns empty list if not found."""
    path = _session_path(session_id)
    if not path.exists():
        return []
    captures: List[dict] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    captures.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return captures


def list_session_files() -> List[str]:
    """Return all session IDs that have a storage file on disk."""
    if not SESSIONS_DIR.exists():
        return []
    return [
        p.stem
        for p in sorted(SESSIONS_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    ]


def delete_session_file(session_id: str) -> None:
    path = _session_path(session_id)
    if path.exists():
        path.unlink()
