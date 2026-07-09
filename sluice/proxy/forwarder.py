from __future__ import annotations

import httpx
import structlog

from sluice.config.schema import UpstreamConfig
from sluice.proxy.models import JSONRPCRequest, JSONRPCResponse

log = structlog.get_logger()


class HTTPUpstream:
    def __init__(self, cfg: UpstreamConfig):
        self._cfg = cfg
        self._client = httpx.AsyncClient(timeout=60.0, headers=cfg.headers)

    @property
    def name(self) -> str:
        return self._cfg.name

    async def forward(
        self, request: JSONRPCRequest, session_id: str | None = None
    ) -> JSONRPCResponse:
        url = self._cfg.url
        if not url:
            raise ValueError(f"upstream {self._cfg.name} has no url")

        headers = {"Content-Type": "application/json"}
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        try:
            resp = await self._client.post(
                url,
                json=request.model_dump(exclude_none=True),
                headers=headers,
            )
            resp.raise_for_status()
            return JSONRPCResponse.model_validate(resp.json())
        except httpx.HTTPStatusError as e:
            log.error("upstream_http_error", status=e.response.status_code, upstream=self._cfg.name)
            raise
        except httpx.RequestError as e:
            log.error("upstream_unreachable", error=str(e), upstream=self._cfg.name)
            raise

    async def aclose(self) -> None:
        await self._client.aclose()
