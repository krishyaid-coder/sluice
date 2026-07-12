from __future__ import annotations

import json

import structlog

from sluice.audit.sink import AuditFilter, AuditSink
from sluice.config.schema import OtelConfig
from sluice.proxy.models import AuditEvent

log = structlog.get_logger()


class OtelSink(AuditSink):
    """Lightweight OpenTelemetry trace exporter for audit events."""

    def __init__(self, cfg: OtelConfig) -> None:
        self._cfg = cfg
        self._tracer = None
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({"service.name": cfg.service_name})
            provider = TracerProvider(resource=resource)
            exporter = OTLPSpanExporter(endpoint=cfg.endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer("sluice.audit")
        except Exception as e:
            log.warning("otel_init_failed", error=str(e))

    async def write(self, event: AuditEvent) -> None:
        if not self._tracer:
            return
        with self._tracer.start_as_current_span("sluice.audit_event") as span:
            span.set_attribute("sluice.session_id", event.session_id)
            span.set_attribute("sluice.upstream", event.upstream)
            span.set_attribute("sluice.direction", event.direction)
            span.set_attribute("sluice.action", event.action)
            if event.method:
                span.set_attribute("sluice.method", event.method)
            if event.tool:
                span.set_attribute("sluice.tool", event.tool)
            if event.rule:
                span.set_attribute("sluice.rule", event.rule)
            if event.detectors:
                span.set_attribute("sluice.detectors", json.dumps(event.detectors))
            if event.latency_us is not None:
                span.set_attribute("sluice.latency_us", event.latency_us)
            if event.preset_source:
                span.set_attribute("sluice.preset_source", event.preset_source)
            if event.propagation:
                span.set_attribute("sluice.propagation", json.dumps(event.propagation))

    async def query(self, filter: AuditFilter):
        if False:  # pragma: no cover
            yield AuditEvent(
                session_id="",
                upstream="",
                direction="",
                action="pass",
            )

    async def close(self) -> None:
        try:
            from opentelemetry import trace

            provider = trace.get_tracer_provider()
            if hasattr(provider, "shutdown"):
                provider.shutdown()
        except Exception:
            pass
