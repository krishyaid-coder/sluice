from __future__ import annotations

import asyncio
import json
import os
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

# Wait budget for a single forward() to receive its correlated response.
# Long enough to survive real MCP servers doing slow work, short enough that
# a broken server surfaces as an error instead of a silent hang.
STDIO_FORWARD_TIMEOUT_SECONDS = 30.0

# How long we give the upstream process to exit gracefully after terminate().
STDIO_TERMINATE_TIMEOUT_SECONDS = 5.0


class StdioUpstream:
    """MCP stdio upstream with proper JSON-RPC id correlation.

    Prior implementation did one readline() per request under a lock and
    assumed that line was the response. Any stray stdout (server logging,
    notifications, out-of-order responses) would desync request/response
    pairing silently — a wrong response could get returned to the agent
    without being scanned against the correct request's context.

    This implementation runs a persistent reader task, dispatches each
    inbound line by its JSON-RPC id to a pending-request map, and treats
    notifications and non-JSON lines as observability events, not responses.
    """

    def __init__(self, cfg: UpstreamConfig):
        self._cfg = cfg
        self._proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._pending: dict[int | str, asyncio.Future[JSONRPCResponse]] = {}
        self._start_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._closed = False

    @property
    def name(self) -> str:
        return self._cfg.name

    async def _ensure_proc(self) -> asyncio.subprocess.Process:
        async with self._start_lock:
            if self._proc and self._proc.returncode is None:
                return self._proc
            if not self._cfg.command:
                raise ValueError(f"upstream {self._cfg.name} has no command")
            env = {**os.environ, **self._cfg.env}
            self._proc = await asyncio.create_subprocess_exec(
                self._cfg.command,
                *self._cfg.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=sys.stderr,
                env=env,
            )
            self._reader_task = asyncio.create_task(
                self._reader_loop(), name=f"stdio-reader-{self._cfg.name}"
            )
            log.info(
                "stdio_upstream_spawned",
                upstream=self._cfg.name,
                command=self._cfg.command,
                pid=self._proc.pid,
            )
            return self._proc

    async def _reader_loop(self) -> None:
        assert self._proc and self._proc.stdout is not None
        try:
            while not self._closed:
                line = await self._proc.stdout.readline()
                if not line:
                    # EOF — process closed stdout, likely exited.
                    log.info("stdio_upstream_eof", upstream=self._cfg.name)
                    break
                self._dispatch_line(line)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — log and drain, don't crash
            log.error("stdio_reader_crashed", upstream=self._cfg.name, error=str(exc))
        finally:
            self._fail_pending(
                RuntimeError(f"upstream {self._cfg.name} stdout closed")
            )

    def _dispatch_line(self, line: bytes) -> None:
        stripped = line.strip()
        if not stripped:
            return
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            # Server likely logged plain text to stdout. Not our response.
            preview = stripped[:200].decode(errors="replace")
            log.warning(
                "stdio_non_json_line", upstream=self._cfg.name, preview=preview
            )
            return
        if not isinstance(payload, dict):
            log.warning(
                "stdio_unexpected_payload",
                upstream=self._cfg.name,
                payload_type=type(payload).__name__,
            )
            return

        msg_id = payload.get("id")
        if msg_id is None:
            # Server-initiated notification (no id, no response expected).
            log.info(
                "stdio_server_notification",
                upstream=self._cfg.name,
                method=payload.get("method"),
            )
            return

        fut = self._pending.pop(msg_id, None)
        if fut is None:
            log.warning(
                "stdio_orphan_response", upstream=self._cfg.name, message_id=msg_id
            )
            return
        if fut.done():
            return
        try:
            response = JSONRPCResponse.model_validate(payload)
        except Exception as exc:  # noqa: BLE001 — surface via future
            fut.set_exception(exc)
            return
        fut.set_result(response)

    def _fail_pending(self, exc: BaseException) -> None:
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    async def forward(
        self, request: JSONRPCRequest, session_id: str | None = None
    ) -> JSONRPCResponse:
        if request.id is None:
            raise ValueError(
                f"upstream {self._cfg.name}: cannot forward a notification "
                f"(id is None) via forward(); notifications expect no response"
            )
        proc = await self._ensure_proc()
        assert proc.stdin is not None

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[JSONRPCResponse] = loop.create_future()
        if request.id in self._pending:
            # Duplicate id in flight — this is a client bug we surface loudly
            # rather than let the second request steal the first's response.
            raise RuntimeError(
                f"upstream {self._cfg.name}: request id {request.id!r} already in flight"
            )
        self._pending[request.id] = fut

        line = json.dumps(request.model_dump(exclude_none=True)) + "\n"
        try:
            async with self._write_lock:
                proc.stdin.write(line.encode())
                await proc.stdin.drain()
            return await asyncio.wait_for(fut, timeout=STDIO_FORWARD_TIMEOUT_SECONDS)
        except TimeoutError as exc:
            self._pending.pop(request.id, None)
            raise RuntimeError(
                f"upstream {self._cfg.name}: timed out waiting for response to "
                f"id {request.id!r} after {STDIO_FORWARD_TIMEOUT_SECONDS}s"
            ) from exc
        except Exception:
            self._pending.pop(request.id, None)
            raise

    async def aclose(self) -> None:
        self._closed = True
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(
                    self._proc.wait(), timeout=STDIO_TERMINATE_TIMEOUT_SECONDS
                )
            except TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        self._fail_pending(
            RuntimeError(f"upstream {self._cfg.name} closed")
        )


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
