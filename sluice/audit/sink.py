from __future__ import annotations

from dataclasses import dataclass
from typing import AsyncIterator, Protocol

from sluice.proxy.models import AuditEvent


@dataclass
class AuditFilter:
    since_ms: int | None = None
    upstream: str | None = None
    action: str | None = None
    session_id: str | None = None
    limit: int = 100


class AuditSink(Protocol):
    async def write(self, event: AuditEvent) -> None: ...
    async def query(self, filter: AuditFilter) -> AsyncIterator[AuditEvent]: ...
    async def close(self) -> None: ...
