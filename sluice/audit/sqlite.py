from __future__ import annotations

import json
import time
from pathlib import Path

import aiosqlite
import structlog

from sluice.audit.sink import AuditFilter, AuditSink
from sluice.config.schema import SqliteAuditConfig
from sluice.proxy.models import AuditEvent
from sluice.session.provenance import PropagationEdge

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
    latency_us INTEGER,
    preset_source TEXT,
    client_ip TEXT,
    propagation TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_upstream_ts ON events(upstream, ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

CREATE TABLE IF NOT EXISTS propagation_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    event_id INTEGER,
    source_path TEXT,
    source_tool TEXT,
    sink_tool TEXT,
    sink_upstream TEXT,
    value_hash TEXT NOT NULL,
    rule TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prop_session ON propagation_edges(session_id);
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
            await self._migrate(self._db)
        return self._db

    async def _migrate(self, db: aiosqlite.Connection) -> None:
        async with db.execute("PRAGMA table_info(events)") as cursor:
            cols = {row[1] async for row in cursor}
        migrations = {
            "preset_source": "ALTER TABLE events ADD COLUMN preset_source TEXT",
            "client_ip": "ALTER TABLE events ADD COLUMN client_ip TEXT",
            "propagation": "ALTER TABLE events ADD COLUMN propagation TEXT",
        }
        for col, sql in migrations.items():
            if col not in cols:
                await db.execute(sql)
        await db.commit()

    async def write(self, event: AuditEvent) -> None:
        db = await self._conn()
        now_ms = int(time.time() * 1000)
        cursor = await db.execute(
            """
            INSERT INTO events (
                ts, session_id, upstream, direction, method, tool,
                action, detectors, rule, redacted_preview, latency_us,
                preset_source, client_ip, propagation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                event.preset_source,
                event.client_ip,
                json.dumps(event.propagation) if event.propagation else None,
            ),
        )
        event_id = cursor.lastrowid
        await db.commit()
        await self._maybe_prune(db, now_ms)

        if event.propagation:
            for edge in event.propagation:
                await self.write_propagation(
                    PropagationEdge(
                        session_id=event.session_id,
                        value_hash=edge.get("value_hash") or "",
                        source_path=edge.get("source_path"),
                        source_tool=edge.get("source_tool"),
                        sink_tool=edge.get("sink_tool"),
                        sink_upstream=edge.get("sink_upstream") or event.upstream,
                        rule=edge.get("rule") or "taint_leak",
                    ),
                    event_id=event_id,
                )

    async def write_propagation(self, edge: PropagationEdge, event_id: int | None = None) -> None:
        db = await self._conn()
        now_ms = int(time.time() * 1000)
        await db.execute(
            """
            INSERT INTO propagation_edges (
                ts, session_id, event_id, source_path, source_tool,
                sink_tool, sink_upstream, value_hash, rule
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_ms,
                edge.session_id,
                event_id,
                edge.source_path,
                edge.source_tool,
                edge.sink_tool,
                edge.sink_upstream,
                edge.value_hash,
                edge.rule,
            ),
        )
        await db.commit()

    async def _maybe_prune(self, db: aiosqlite.Connection, now_ms: int) -> None:
        cutoff = now_ms - self._retention_days * 86_400_000
        await db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        await db.execute("DELETE FROM propagation_edges WHERE ts < ?", (cutoff,))
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
            f"SELECT id, ts, session_id, upstream, direction, method, tool, action, "
            f"detectors, rule, redacted_preview, latency_us, preset_source, client_ip, propagation "
            f"FROM events WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?"
        )
        params.append(filter.limit)

        async with db.execute(sql, params) as cursor:
            async for row in cursor:
                yield AuditEvent(
                    event_id=row[0],
                    ts=row[1],
                    session_id=row[2],
                    upstream=row[3],
                    direction=row[4],
                    method=row[5],
                    tool=row[6],
                    action=row[7],
                    detectors=json.loads(row[8] or "[]"),
                    rule=row[9],
                    redacted_preview=row[10],
                    latency_us=row[11],
                    preset_source=row[12],
                    client_ip=row[13],
                    propagation=json.loads(row[14]) if row[14] else None,
                )

    async def stats_last_24h(self) -> dict[str, object]:
        db = await self._conn()
        since = int(time.time() * 1000) - 86_400_000
        stats: dict[str, object] = {"actions": {}, "detectors": {}, "total": 0}
        async with db.execute(
            "SELECT action, COUNT(*) FROM events WHERE ts >= ? GROUP BY action",
            (since,),
        ) as cursor:
            async for action, count in cursor:
                stats["actions"][action] = count
                stats["total"] = int(stats["total"]) + count
        async with db.execute(
            "SELECT detectors FROM events WHERE ts >= ?",
            (since,),
        ) as cursor:
            detector_counts: dict[str, int] = {}
            async for (raw,) in cursor:
                for det in json.loads(raw or "[]"):
                    detector_counts[det] = detector_counts.get(det, 0) + 1
            stats["detectors"] = detector_counts
        return stats

    async def list_sessions(self, limit: int = 50) -> list[dict[str, object]]:
        db = await self._conn()
        since = int(time.time() * 1000) - 86_400_000
        rows: list[dict[str, object]] = []
        async with db.execute(
            """
            SELECT session_id, COUNT(*) as events, MAX(ts) as last_ts
            FROM events WHERE ts >= ?
            GROUP BY session_id
            ORDER BY last_ts DESC
            LIMIT ?
            """,
            (since, limit),
        ) as cursor:
            async for session_id, events, last_ts in cursor:
                rows.append(
                    {
                        "session_id": session_id,
                        "events": events,
                        "last_ts": last_ts,
                    }
                )
        return rows

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None
