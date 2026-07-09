from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field


@dataclass
class TaintStore:
    min_length: int = 12
    marks: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)


class SessionStore:
    def __init__(self, min_length: int = 12, scope: str = "session") -> None:
        self._min_length = min_length
        self._scope = scope
        self._sessions: dict[str, TaintStore] = {}
        self._process_store = TaintStore(min_length=min_length)
        self._lock = threading.Lock()

    def _store_for(self, session_id: str) -> TaintStore:
        if self._scope == "process":
            return self._process_store
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = TaintStore(min_length=self._min_length)
            return self._sessions[session_id]

    def mark(self, session_id: str, value: str) -> None:
        if len(value) < self._min_length:
            return
        store = self._store_for(session_id)
        store.marks.add(value)
        store.hashes.add(hashlib.sha256(value.encode()).hexdigest())

    def mark_from_hits(self, session_id: str, values: list[str]) -> None:
        for value in values:
            self.mark(session_id, value)

    def check(self, session_id: str, text: str) -> str | None:
        store = self._store_for(session_id)
        for value in store.marks:
            if value in text:
                return value
        return None

    def clear(self, session_id: str | None = None) -> None:
        with self._lock:
            if session_id is None:
                self._sessions.clear()
                self._process_store.marks.clear()
                self._process_store.hashes.clear()
            elif session_id in self._sessions:
                del self._sessions[session_id]

    def session_count(self) -> int:
        return len(self._sessions)
