from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class SSEEvent:
    id: int
    data: str


@dataclass
class SSESession:
    session_id: str
    events: deque[SSEEvent]
    next_id: int = 1
    last_active: float = field(default_factory=time.time)


class SSESessionManager:
    """Per-session SSE event buffer with reconnect replay (MCP 2025-03-26)."""

    def __init__(self, buffer_size: int = 512, idle_seconds: int = 300) -> None:
        self._buffer_size = buffer_size
        self._idle_seconds = idle_seconds
        self._sessions: dict[str, SSESession] = {}
        self._lock = asyncio.Lock()

    async def append(self, session_id: str, data: str) -> int:
        async with self._lock:
            sess = self._sessions.get(session_id)
            if sess is None:
                sess = SSESession(session_id=session_id, events=deque(maxlen=self._buffer_size))
                self._sessions[session_id] = sess
            event_id = sess.next_id
            sess.next_id += 1
            sess.events.append(SSEEvent(id=event_id, data=data))
            sess.last_active = time.time()
            return event_id

    async def replay_after(self, session_id: str, last_event_id: int) -> list[SSEEvent]:
        async with self._lock:
            sess = self._sessions.get(session_id)
            if not sess:
                return []
            sess.last_active = time.time()
            return [event for event in sess.events if event.id > last_event_id]

    async def evict_idle(self) -> int:
        now = time.time()
        removed = 0
        async with self._lock:
            stale = [
                sid
                for sid, sess in self._sessions.items()
                if now - sess.last_active > self._idle_seconds
            ]
            for sid in stale:
                del self._sessions[sid]
                removed += 1
        return removed

    def session_count(self) -> int:
        return len(self._sessions)
