from __future__ import annotations

from sluice.audit.otel import OtelSink
from sluice.audit.sink import AuditSink
from sluice.audit.sqlite import SqliteSink
from sluice.audit.stdout import ChainedSink, StdoutSink
from sluice.config.schema import AuditConfig, SluiceConfig


def build_audit_sink(cfg: SluiceConfig) -> AuditSink | None:
    audit_cfg: AuditConfig = cfg.audit
    sinks: list[AuditSink] = []

    if audit_cfg.sink in ("sqlite", "both", "all"):
        sinks.append(SqliteSink(audit_cfg.sqlite))
    if audit_cfg.sink in ("stdout", "both", "all"):
        sinks.append(StdoutSink())
    if cfg.otel.enabled or audit_cfg.sink in ("otel", "all"):
        sinks.append(OtelSink(cfg.otel))

    if not sinks:
        return None
    if len(sinks) == 1:
        return sinks[0]
    return ChainedSink(sinks)
