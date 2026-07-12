from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import structlog

from sluice.config.schema import UpstreamConfig
from sluice.proxy.models import JSONRPCRequest, JSONRPCResponse

log = structlog.get_logger()

MCP_ACCEPT = "application/json, text/event-stream"
MCP_PROTOCOL = "2025-03-26"


class HTTPUpstream:
    def __init__(self, cfg: UpstreamConfig):
        self._cfg = cfg
        self._client = httpx.AsyncClient(timeout=60.0, headers=cfg.headers)
        self._session_urls: dict[str, str] = {}

    @property
    def name(self) -> str:
        return self._cfg.name

    @property
    def is_streamable(self) -> bool:
        return self._cfg.transport == "streamable_http"

    def _base_headers(self, session_id: str | None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": MCP_ACCEPT,
            "MCP-Protocol-Version": MCP_PROTOCOL,
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return headers

    async def forward(
        self, request: JSONRPCRequest, session_id: str | None = None
    ) -> JSONRPCResponse:
        url = self._cfg.url
        if not url:
            raise ValueError(f"upstream {self._cfg.name} has no url")

        headers = self._base_headers(session_id)
        try:
            resp = await self._client.post(
                url,
                json=request.model_dump(exclude_none=True),
                headers=headers,
            )
            resp.raise_for_status()

            if session_id and "Mcp-Session-Id" in resp.headers:
                self._session_urls[session_id] = url

            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                return self._parse_sse_json_response(resp.text)

            return JSONRPCResponse.model_validate(resp.json())
        except httpx.HTTPStatusError as e:
            log.error("upstream_http_error", status=e.response.status_code, upstream=self._cfg.name)
            raise
        except httpx.RequestError as e:
            log.error("upstream_unreachable", error=str(e), upstream=self._cfg.name)
            raise

    def _parse_sse_json_response(self, body: str) -> JSONRPCResponse:
        for line in body.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    return JSONRPCResponse.model_validate(json.loads(payload))
        raise ValueError(f"upstream {self._cfg.name} returned SSE without JSON data")

    async def stream_events(
        self, session_id: str, *, last_event_id: int = 0
    ) -> AsyncIterator[str]:
        url = self._cfg.url
        if not url:
            raise ValueError(f"upstream {self._cfg.name} has no url")

        headers = self._base_headers(session_id)
        if last_event_id:
            headers["Last-Event-Id"] = str(last_event_id)
        try:
            async with self._client.stream("GET", url, headers=headers) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.startswith("data:"):
                        yield line[5:].strip()
        except httpx.HTTPError as e:
            log.error("upstream_sse_error", error=str(e), upstream=self._cfg.name)
            raise

    async def aclose(self) -> None:
        await self._client.aclose()
