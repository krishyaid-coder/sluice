from __future__ import annotations

import structlog

from sluice.audit.sink import AuditFilter, AuditSink
from sluice.proxy.models import AuditEvent

log = structlog.get_logger()


class StdoutSink(AuditSink):
    async def write(self, event: AuditEvent) -> None:
        log.info(
            "audit_event",
            session_id=event.session_id,
            upstream=event.upstream,
            direction=event.direction,
            method=event.method,
            tool=event.tool,
            action=event.action,
            detectors=event.detectors,
            rule=event.rule,
        )

    async def query(self, filter: AuditFilter):
        if False:
            yield AuditEvent(
                session_id="",
                upstream="",
                direction="",
                action="",
            )

    async def close(self) -> None:
        return None


class ChainedSink(AuditSink):
    def __init__(self, sinks: list[AuditSink]) -> None:
        self._sinks = sinks

    async def write(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            await sink.write(event)

    async def query(self, filter: AuditFilter):
        for sink in self._sinks:
            if hasattr(sink, "query"):
                async for event in sink.query(filter):
                    yield event
                return

    async def close(self) -> None:
        for sink in self._sinks:
            await sink.close()
