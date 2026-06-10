import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

DEFAULT_TTL = 3600  # seconds
MAX_CAPTURES = 1000


@dataclass
class Capture:
    request: dict
    response: Optional[dict] = None


@dataclass
class RecorderSession:
    session_id: str
    target_url: str
    port: int
    created_at: datetime
    expires_at: datetime
    captures: List[Capture] = field(default_factory=list)

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def add_capture(self, capture: Capture) -> bool:
        """Add capture, respecting MAX_CAPTURES cap. Returns False if cap reached."""
        if len(self.captures) >= MAX_CAPTURES:
            return False
        self.captures.append(capture)
        return True

    def to_info(self) -> dict:
        return {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "port": self.port,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "capture_count": len(self.captures),
            "expired": self.is_expired(),
        }


class SessionStore:
    """In-memory store for recorder sessions (per-process singleton)."""

    def __init__(self) -> None:
        self._sessions: Dict[str, RecorderSession] = {}

    def create(
        self,
        target_url: str,
        port: int,
        ttl: int = DEFAULT_TTL,
    ) -> RecorderSession:
        session_id = uuid.uuid4().hex[:8]
        now = datetime.now(timezone.utc)
        session = RecorderSession(
            session_id=session_id,
            target_url=target_url.rstrip("/"),
            port=port,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
        )
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Optional[RecorderSession]:
        return self._sessions.get(session_id)

    def get_active(self, session_id: str) -> Optional[RecorderSession]:
        """Return session only if it exists and has not expired."""
        s = self._sessions.get(session_id)
        if s is None or s.is_expired():
            return None
        return s

    def remove(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def list_active(self) -> List[RecorderSession]:
        return [s for s in self._sessions.values() if not s.is_expired()]


# Process-level singleton — used by proxy handlers and CLI commands
store = SessionStore()
