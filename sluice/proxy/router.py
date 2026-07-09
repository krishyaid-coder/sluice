from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid
from typing import TYPE_CHECKING

import structlog

from sluice.config.schema import SluiceConfig, UpstreamConfig
from sluice.proxy.forwarder import HTTPUpstream
from sluice.proxy.models import JSONRPCRequest, JSONRPCResponse

if TYPE_CHECKING:
    pass

log = structlog.get_logger()


class StdioUpstream:
    def __init__(self, cfg: UpstreamConfig):
        self._cfg = cfg
        self._proc: subprocess.Popen[str] | None = None
        self._lock = asyncio.Lock()

    @property
    def name(self) -> str:
        return self._cfg.name

    def _ensure_proc(self) -> subprocess.Popen[str]:
        if self._proc and self._proc.poll() is None:
            return self._proc
        if not self._cfg.command:
            raise ValueError(f"upstream {self._cfg.name} has no command")
        env = {**dict(**__import__("os").environ), **self._cfg.env}
        self._proc = subprocess.Popen(
            [self._cfg.command, *self._cfg.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
            env=env,
        )
        log.info("stdio_upstream_spawned", upstream=self._cfg.name, command=self._cfg.command)
        return self._proc

    async def forward(
        self, request: JSONRPCRequest, session_id: str | None = None
    ) -> JSONRPCResponse:
        async with self._lock:
            proc = self._ensure_proc()
            assert proc.stdin and proc.stdout
            line = json.dumps(request.model_dump(exclude_none=True))
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
            resp_line = await asyncio.to_thread(proc.stdout.readline)
            if not resp_line:
                raise RuntimeError(f"upstream {self._cfg.name} closed stdout")
            return JSONRPCResponse.model_validate(json.loads(resp_line.strip()))

    async def aclose(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()


class Router:
    def __init__(self, cfg: SluiceConfig):
        self._cfg = cfg
        self._http: dict[str, HTTPUpstream] = {}
        self._stdio: dict[str, StdioUpstream] = {}
        for upstream in cfg.upstreams:
            if upstream.transport == "stdio":
                self._stdio[upstream.name] = StdioUpstream(upstream)
            else:
                self._http[upstream.name] = HTTPUpstream(upstream)

    def resolve_upstream(self, name: str | None) -> str:
        if name and self.has(name):
            return name
        return self._cfg.routing.default

    def has(self, name: str) -> bool:
        return name in self._http or name in self._stdio

    def http_upstream(self, name: str) -> HTTPUpstream | None:
        return self._http.get(name)

    async def dispatch(
        self,
        upstream_name: str,
        request: JSONRPCRequest,
        session_id: str,
    ) -> JSONRPCResponse:
        name = self.resolve_upstream(upstream_name)
        if name in self._stdio:
            return await self._stdio[name].forward(request, session_id)
        if name in self._http:
            return await self._http[name].forward(request, session_id)
        raise KeyError(f"unknown upstream: {name}")

    async def aclose(self) -> None:
        for upstream in self._http.values():
            await upstream.aclose()
        for upstream in self._stdio.values():
            await upstream.aclose()

    async def health_check(self) -> dict[str, str]:
        results: dict[str, str] = {}
        for upstream in self._cfg.upstreams:
            if upstream.transport == "stdio":
                results[upstream.name] = "ok" if upstream.command else "missing command"
            else:
                results[upstream.name] = "ok" if upstream.url else "missing url"
        return results


def new_session_id() -> str:
    return str(uuid.uuid4())
