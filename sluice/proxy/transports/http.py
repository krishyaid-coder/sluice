from __future__ import annotations

import json

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from sluice.proxy.models import JSONRPCRequest, JSONRPCResponse
from sluice.proxy.pipeline import Pipeline
from sluice.proxy.router import Router, new_session_id

log = structlog.get_logger()


def create_app(pipeline: Pipeline, router: Router) -> FastAPI:
    app = FastAPI(title="Sluice", version="0.1.0", description="Local MCP gate.")

    async def _handle_proxy(upstream_name: str, request: Request) -> JSONResponse:
        session_id = request.headers.get("Mcp-Session-Id") or new_session_id()
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON")

        rpc = JSONRPCRequest.model_validate(body)
        raw = json.dumps(body)

        clean_raw, violation = await pipeline.inspect_request(
            raw, session_id=session_id, upstream=router.resolve_upstream(upstream_name)
        )

        if violation and violation.action == "block":
            return JSONResponse(
                content=JSONRPCResponse(
                    id=rpc.id,
                    error={"code": -32600, "message": violation.detail},
                ).model_dump(exclude_none=True),
                headers={"Mcp-Session-Id": session_id},
            )

        if violation and violation.action == "redact":
            body = json.loads(clean_raw)
            rpc = JSONRPCRequest.model_validate(body)

        try:
            upstream_response = await router.dispatch(
                upstream_name, rpc, session_id
            )
        except Exception as e:
            log.error("forward_failed", error=str(e), upstream=upstream_name)
            raise HTTPException(status_code=502, detail="Upstream MCP server unreachable")

        resp_raw = json.dumps(upstream_response.model_dump(exclude_none=True))
        clean_resp, resp_violation = await pipeline.inspect_response(
            resp_raw,
            session_id=session_id,
            upstream=router.resolve_upstream(upstream_name),
            method=rpc.method,
        )

        if resp_violation and resp_violation.action == "block":
            return JSONResponse(
                content=JSONRPCResponse(
                    id=rpc.id,
                    error={"code": -32600, "message": "Upstream response failed policy."},
                ).model_dump(exclude_none=True),
                headers={"Mcp-Session-Id": session_id},
            )

        content = json.loads(clean_resp) if resp_violation and resp_violation.action == "redact" else upstream_response.model_dump(exclude_none=True)
        return JSONResponse(content=content, headers={"Mcp-Session-Id": session_id})

    @app.post("/")
    async def proxy_default(request: Request) -> JSONResponse:
        return await _handle_proxy("", request)

    @app.post("/u/{upstream_name}")
    async def proxy_upstream(upstream_name: str, request: Request) -> JSONResponse:
        if not router.has(upstream_name):
            raise HTTPException(status_code=404, detail=f"Unknown upstream: {upstream_name}")
        return await _handle_proxy(upstream_name, request)

    @app.get("/u/{upstream_name}")
    async def proxy_sse(upstream_name: str, request: Request):
        session_id = request.headers.get("Mcp-Session-Id") or new_session_id()

        async def event_stream():
            yield f"data: {json.dumps({'type': 'session', 'session_id': session_id})}\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Mcp-Session-Id": session_id, "Cache-Control": "no-cache"},
        )

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "sluice"}

    return app


class HTTPTransport:
    def __init__(self, host: str, port: int, pipeline: Pipeline, router: Router):
        self._host = host
        self._port = port
        self._pipeline = pipeline
        self._router = router
        self._server = None

    async def run(self, pipeline: Pipeline, router: Router) -> None:
        import uvicorn

        app = create_app(pipeline, router)
        config = uvicorn.Config(app, host=self._host, port=self._port, log_level="info")
        server = uvicorn.Server(config)
        self._server = server
        await server.serve()

    async def shutdown(self) -> None:
        if self._server:
            self._server.should_exit = True
        await self._router.aclose()
