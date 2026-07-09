from __future__ import annotations

import json
import time
from pathlib import Path

import aiosqlite
import structlog

from sluice.audit.sink import AuditFilter, AuditSink
from sluice.config.schema import SqliteAuditConfig
from sluice.proxy.models import AuditEvent

log = structlog.get_logger()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    upstream TEXT NOT NULL,
    direction TEXT NOT NULL,
    method TEXT,
    tool TEXT,
    action TEXT NOT NULL,
    detectors TEXT,
    rule TEXT,
    redacted_preview TEXT,
    latency_us INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_upstream_ts ON events(upstream, ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""


class SqliteSink(AuditSink):
    def __init__(self, cfg: SqliteAuditConfig) -> None:
        self._path = Path(cfg.path).expanduser()
        self._retention_days = cfg.retention_days
        self._db: aiosqlite.Connection | None = None

    async def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._db = await aiosqlite.connect(self._path)
            await self._db.executescript(_SCHEMA)
        return self._db

    async def write(self, event: AuditEvent) -> None:
        db = await self._conn()
        now_ms = int(time.time() * 1000)
        await db.execute(
            """
            INSERT INTO events (
                ts, session_id, upstream, direction, method, tool,
                action, detectors, rule, redacted_preview, latency_us
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_ms,
                event.session_id,
                event.upstream,
                event.direction,
                event.method,
                event.tool,
                event.action,
                json.dumps(event.detectors),
                event.rule,
                event.redacted_preview,
                event.latency_us,
            ),
        )
        await db.commit()
        await self._maybe_prune(db, now_ms)

    async def _maybe_prune(self, db: aiosqlite.Connection, now_ms: int) -> None:
        cutoff = now_ms - self._retention_days * 86_400_000
        await db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        await db.commit()

    async def query(self, filter: AuditFilter):
        db = await self._conn()
        clauses = ["1=1"]
        params: list[object] = []
        if filter.since_ms is not None:
            clauses.append("ts >= ?")
            params.append(filter.since_ms)
        if filter.upstream:
            clauses.append("upstream = ?")
            params.append(filter.upstream)
        if filter.action:
            clauses.append("action = ?")
            params.append(filter.action)
        if filter.session_id:
            clauses.append("session_id = ?")
            params.append(filter.session_id)

        sql = (
            f"SELECT session_id, upstream, direction, method, tool, action, "
            f"detectors, rule, redacted_preview, latency_us, ts "
            f"FROM events WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?"
        )
        params.append(filter.limit)

        async with db.execute(sql, params) as cursor:
            async for row in cursor:
                yield AuditEvent(
                    session_id=row[0],
                    upstream=row[1],
                    direction=row[2],
                    method=row[3],
                    tool=row[4],
                    action=row[5],
                    detectors=json.loads(row[6] or "[]"),
                    rule=row[7],
                    redacted_preview=row[8],
                    latency_us=row[9],
                )

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None
