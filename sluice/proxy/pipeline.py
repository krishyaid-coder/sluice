from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import structlog

from sluice.detectors.base import ScanContext
from sluice.policy.engine import bootstrap_detectors, evaluate
from sluice.proxy.models import AuditEvent, PolicyViolation
from sluice.session import taint

if TYPE_CHECKING:
    from sluice.audit.sink import AuditSink
    from sluice.config.schema import SluiceConfig

log = structlog.get_logger()


class Pipeline:
    def __init__(self, cfg: SluiceConfig, audit: AuditSink | None = None) -> None:
        self._cfg = cfg
        self._audit = audit
        bootstrap_detectors()
        taint.configure(cfg)

    def _tool_from_raw(self, raw: str) -> str | None:
        try:
            payload = json.loads(raw)
            if payload.get("method") == "tools/call":
                return payload.get("params", {}).get("name")
        except (json.JSONDecodeError, AttributeError):
            pass
        return None

    def _method_from_raw(self, raw: str) -> str | None:
        try:
            return json.loads(raw).get("method")
        except (json.JSONDecodeError, AttributeError):
            return None

    def _preview(self, raw: str, violation: PolicyViolation | None) -> str:
        if violation and violation.action == "redact":
            return raw[:200]
        if len(raw) > 200:
            return raw[:200] + "…"
        return raw

    async def _audit_write(
        self,
        *,
        session_id: str,
        upstream: str,
        direction: str,
        raw: str,
        violation: PolicyViolation | None,
        latency_us: int,
        client_ip: str | None = None,
    ) -> None:
        if not self._audit:
            return
        action = violation.action if violation else "pass"
        await self._audit.write(
            AuditEvent(
                session_id=session_id,
                upstream=upstream,
                direction=direction,
                method=self._method_from_raw(raw),
                tool=self._tool_from_raw(raw),
                action=action,
                detectors=violation.detectors if violation else [],
                rule=violation.rule if violation else None,
                redacted_preview=self._preview(raw, violation),
                latency_us=latency_us,
                preset_source=violation.preset_source if violation else None,
                client_ip=client_ip,
                propagation=violation.propagation if violation else None,
            )
        )

    async def inspect_request(
        self,
        raw: str,
        *,
        session_id: str,
        upstream: str,
        client_ip: str | None = None,
    ) -> tuple[str, PolicyViolation | None]:
        start = time.perf_counter_ns()
        method = self._method_from_raw(raw)
        tool = self._tool_from_raw(raw)
        context = ScanContext("request", method, tool, upstream, session_id)

        leak = taint.check(session_id, raw)
        if leak:
            edge = taint.propagation_edge_for_leak(
                session_id,
                leak,
                sink_tool=tool,
                sink_upstream=upstream,
            )
            propagation = None
            if edge:
                propagation = [
                    {
                        "value_hash": edge.value_hash[:16],
                        "source_path": edge.source_path,
                        "source_tool": edge.source_tool,
                        "sink_tool": edge.sink_tool,
                        "sink_upstream": edge.sink_upstream,
                        "rule": edge.rule,
                    }
                ]
            violation = PolicyViolation(
                rule="taint_leak",
                detail="This value already appeared in an earlier tool response.",
                action="block",
                detectors=["taint_leak"],
                propagation=propagation,
            )
            latency = (time.perf_counter_ns() - start) // 1000
            await self._audit_write(
                session_id=session_id,
                upstream=upstream,
                direction="request",
                raw=raw,
                violation=violation,
                latency_us=latency,
                client_ip=client_ip,
            )
            log.warning("taint_leak_blocked", upstream=upstream, session_id=session_id)
            return raw, violation

        body, violation, hits = evaluate(raw, context, self._cfg)
        latency = (time.perf_counter_ns() - start) // 1000
        await self._audit_write(
            session_id=session_id,
            upstream=upstream,
            direction="request",
            raw=body,
            violation=violation,
            latency_us=latency,
            client_ip=client_ip,
        )
        return body, violation

    async def inspect_response(
        self,
        raw: str,
        *,
        session_id: str,
        upstream: str,
        method: str | None = None,
        client_ip: str | None = None,
    ) -> tuple[str, PolicyViolation | None]:
        start = time.perf_counter_ns()
        tool = self._tool_from_raw(raw) if method == "tools/call" else None
        context = ScanContext("response", method, tool, upstream, session_id)

        body, violation, hits = evaluate(raw, context, self._cfg)
        if violation is None or violation.action in ("flag", "redact"):
            taint.mark_from_hits(
                session_id,
                [h.matched for h in hits],
                raw_json=body,
                source_tool=tool,
                source_upstream=upstream,
                source_method=method,
            )

        latency = (time.perf_counter_ns() - start) // 1000
        await self._audit_write(
            session_id=session_id,
            upstream=upstream,
            direction="response",
            raw=body,
            violation=violation,
            latency_us=latency,
            client_ip=client_ip,
        )
        return body, violation

    @staticmethod
    def block_response(request_id: int | str | None, message: str) -> str:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": message},
            }
        )

    @staticmethod
    def request_id_from_raw(raw: str) -> int | str | None:
        try:
            return json.loads(raw).get("id")
        except (json.JSONDecodeError, AttributeError):
            return None
