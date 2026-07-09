from __future__ import annotations

from sluice.audit.sink import AuditSink
from sluice.audit.sqlite import SqliteSink
from sluice.audit.stdout import ChainedSink, StdoutSink
from sluice.config.schema import AuditConfig, SluiceConfig


def build_audit_sink(cfg: SluiceConfig) -> AuditSink | None:
    audit_cfg: AuditConfig = cfg.audit
    sinks: list[AuditSink] = []

    if audit_cfg.sink in ("sqlite", "both"):
        sinks.append(SqliteSink(audit_cfg.sqlite))
    if audit_cfg.sink in ("stdout", "both"):
        sinks.append(StdoutSink())

    if not sinks:
        return None
    if len(sinks) == 1:
        return sinks[0]
    return ChainedSink(sinks)
