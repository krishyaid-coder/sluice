from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sluice.audit.sink import AuditFilter
from sluice.audit.sqlite import SqliteSink
from sluice.config.schema import SluiceConfig
from sluice.session import taint

if TYPE_CHECKING:
    from sluice.audit.sink import AuditSink

_DASHBOARD_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(_DASHBOARD_DIR / "templates"))


def _sqlite_sink(audit: AuditSink | None) -> SqliteSink | None:
    if isinstance(audit, SqliteSink):
        return audit
    chained = getattr(audit, "_sinks", None)
    if chained:
        for sink in chained:
            found = _sqlite_sink(sink)
            if found:
                return found
    return None


def create_dashboard(cfg: SluiceConfig, audit: AuditSink | None) -> FastAPI:
    app = FastAPI(title="Sluice Dashboard", docs_url=None, redoc_url=None)
    sqlite = _sqlite_sink(audit)
    static_dir = _DASHBOARD_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _auth(request: Request) -> None:
        token = cfg.dashboard.token
        if not token:
            return
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {token}":
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        _auth(request)
        stats = await sqlite.stats_last_24h() if sqlite else {"actions": {}, "detectors": {}, "total": 0}
        sessions = taint.store().session_count() if taint.store() else 0
        return templates.TemplateResponse(
            request,
            "overview.html",
            {
                "stats": stats,
                "active_sessions": sessions,
                "version": cfg.version,
            },
        )

    @app.get("/events", response_class=HTMLResponse)
    async def events(
        request: Request,
        upstream: str | None = None,
        action: str | None = None,
        session_id: str | None = None,
    ):
        _auth(request)
        since_ms = int(time.time() * 1000) - 86_400_000
        rows = []
        if sqlite:
            async for event in sqlite.query(
                AuditFilter(
                    since_ms=since_ms,
                    upstream=upstream,
                    action=action,
                    session_id=session_id,
                    limit=cfg.dashboard.page_size,
                )
            ):
                rows.append(event)
        return templates.TemplateResponse(
            request,
            "events.html",
            {"events": rows, "upstream": upstream, "action": action, "session_id": session_id},
        )

    @app.get("/sessions", response_class=HTMLResponse)
    async def sessions(request: Request):
        _auth(request)
        session_rows = await sqlite.list_sessions(cfg.dashboard.page_size) if sqlite else []
        for row in session_rows:
            row["marks"] = taint.mark_count(str(row["session_id"]))
        return templates.TemplateResponse(request, "sessions.html", {"sessions": session_rows})

    @app.get("/health")
    async def health():
        return {"status": "ok", "dashboard": True}

    return app
