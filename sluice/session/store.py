from __future__ import annotations

import threading
from dataclasses import dataclass, field

from sluice.session.provenance import TaintMark, paths_for_value, value_hash


@dataclass
class TaintStore:
    min_length: int = 12
    marks: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    provenance: dict[str, TaintMark] = field(default_factory=dict)


class SessionStore:
    def __init__(self, min_length: int = 12, scope: str = "session", provenance: bool = True) -> None:
        self._min_length = min_length
        self._scope = scope
        self._provenance_enabled = provenance
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

    def mark(
        self,
        session_id: str,
        value: str,
        *,
        json_paths: list[str] | None = None,
        source_tool: str | None = None,
        source_upstream: str | None = None,
        source_method: str | None = None,
    ) -> None:
        if len(value) < self._min_length:
            return
        store = self._store_for(session_id)
        store.marks.add(value)
        digest = value_hash(value)
        store.hashes.add(digest)
        if self._provenance_enabled:
            existing = store.provenance.get(digest)
            paths = json_paths or []
            if existing:
                merged_paths = sorted(set(existing.json_paths + paths))
                store.provenance[digest] = TaintMark(
                    value=value,
                    value_hash=digest,
                    json_paths=merged_paths,
                    source_tool=existing.source_tool or source_tool,
                    source_upstream=existing.source_upstream or source_upstream,
                    source_method=existing.source_method or source_method,
                )
            else:
                store.provenance[digest] = TaintMark(
                    value=value,
                    value_hash=digest,
                    json_paths=paths,
                    source_tool=source_tool,
                    source_upstream=source_upstream,
                    source_method=source_method,
                )

    def mark_from_hits(
        self,
        session_id: str,
        values: list[str],
        *,
        raw_json: str | None = None,
        source_tool: str | None = None,
        source_upstream: str | None = None,
        source_method: str | None = None,
    ) -> None:
        parsed = None
        if raw_json and self._provenance_enabled:
            from sluice.session.provenance import parse_json_safe

            parsed = parse_json_safe(raw_json)

        for value in values:
            paths: list[str] = []
            if parsed is not None:
                paths = paths_for_value(parsed, value, self._min_length)
            self.mark(
                session_id,
                value,
                json_paths=paths,
                source_tool=source_tool,
                source_upstream=source_upstream,
                source_method=source_method,
            )

    def check(self, session_id: str, text: str) -> str | None:
        store = self._store_for(session_id)
        for value in store.marks:
            if value in text:
                return value
        return None

    def provenance_for_leak(self, session_id: str, leaked_value: str) -> TaintMark | None:
        store = self._store_for(session_id)
        digest = value_hash(leaked_value)
        return store.provenance.get(digest)

    def list_marks(self, session_id: str) -> list[TaintMark]:
        store = self._store_for(session_id)
        return list(store.provenance.values())

    def mark_count(self, session_id: str) -> int:
        store = self._store_for(session_id)
        return len(store.marks)

    def clear(self, session_id: str | None = None) -> None:
        with self._lock:
            if session_id is None:
                self._sessions.clear()
                self._process_store.marks.clear()
                self._process_store.hashes.clear()
                self._process_store.provenance.clear()
            elif session_id in self._sessions:
                del self._sessions[session_id]

    def session_count(self) -> int:
        return len(self._sessions)
