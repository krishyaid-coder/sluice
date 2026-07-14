from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class ProxyConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 4444


class UpstreamConfig(BaseModel):
    name: str
    transport: Literal["stdio", "http", "streamable_http"] = "http"
    url: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def valid_name(cls, v: str) -> str:
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("upstream name must be alphanumeric with - or _")
        return v


class RoutingConfig(BaseModel):
    default: str = "default"


class DetectorToggle(BaseModel):
    enabled: bool = True
    redaction: bool = True
    severity_threshold: Literal["low", "medium", "high", "critical"] = "medium"


class DetectorsConfig(BaseModel):
    secrets: DetectorToggle = Field(default_factory=DetectorToggle)
    pii: DetectorToggle = Field(default_factory=DetectorToggle)
    tool_poisoning: DetectorToggle = Field(default_factory=DetectorToggle)
    prompt_injection: DetectorToggle = Field(default_factory=DetectorToggle)


class PolicyRule(BaseModel):
    detector: str
    action: Literal["block", "redact", "flag", "pass"]
    upstream: str | None = None
    tool: str | None = None
    preset_source: str | None = None


_TAINT_RULE_PATTERNS = frozenset({"taint_leak", "taint.*", "taint_*"})


class PolicyConfig(BaseModel):
    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: Literal["block", "redact", "flag", "pass"] = "flag"

    @model_validator(mode="after")
    def reject_redact_for_taint(self) -> PolicyConfig:
        for i, rule in enumerate(self.rules):
            if rule.action == "redact" and rule.detector in _TAINT_RULE_PATTERNS:
                raise ValueError(
                    f"policy.rules[{i}]: action 'redact' is not valid for detector "
                    f"{rule.detector!r}. A taint leak is triggered by the whole flagged "
                    f"value; partial masking is not meaningful. Use 'block' or 'flag'."
                )
        return self


class TaintConfig(BaseModel):
    enabled: bool = True
    min_length: int = 12
    scope: Literal["session", "process"] = "session"
    provenance: bool = True


class StreamableHttpConfig(BaseModel):
    session_buffer: int = 512
    session_idle_seconds: int = 300


class TransportsConfig(BaseModel):
    streamable_http: StreamableHttpConfig = Field(default_factory=StreamableHttpConfig)


class DashboardConfig(BaseModel):
    enabled: bool = True
    path: str = "/_sluice"
    token: str | None = None
    page_size: int = 50


class OtelConfig(BaseModel):
    enabled: bool = False
    endpoint: str = "http://localhost:4318/v1/traces"
    service_name: str = "sluice"


class SqliteAuditConfig(BaseModel):
    path: str = "~/.sluice/audit.db"
    retention_days: int = 30


class AuditConfig(BaseModel):
    sink: Literal["sqlite", "stdout", "both", "otel", "all"] = "sqlite"
    sqlite: SqliteAuditConfig = Field(default_factory=SqliteAuditConfig)


class LoggingConfig(BaseModel):
    level: Literal["debug", "info", "warn", "error"] = "info"
    format: Literal["json", "console"] = "json"


class SluiceConfig(BaseModel):
    version: int = 1
    include: list[str] = Field(default_factory=list)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    upstreams: list[UpstreamConfig] = Field(default_factory=list)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    transports: TransportsConfig = Field(default_factory=TransportsConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    otel: OtelConfig = Field(default_factory=OtelConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("upstreams")
    @classmethod
    def at_least_one_upstream(cls, v: list[UpstreamConfig]) -> list[UpstreamConfig]:
        if not v:
            raise ValueError("at least one upstream is required")
        names = [u.name for u in v]
        if len(names) != len(set(names)):
            raise ValueError("upstream names must be unique")
        return v

    @model_validator(mode="after")
    def validate_dashboard_security(self) -> SluiceConfig:
        host = self.proxy.host
        non_loopback = host not in ("127.0.0.1", "localhost", "::1")
        if self.dashboard.enabled and non_loopback and not self.dashboard.token:
            raise ValueError(
                "dashboard requires dashboard.token when proxy.host is not loopback"
            )
        return self


def default_config() -> SluiceConfig:
    return SluiceConfig(
        include=["preset:filesystem"],
        upstreams=[
            UpstreamConfig(
                name="filesystem",
                transport="stdio",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            )
        ],
        policy=PolicyConfig(
            rules=[
                PolicyRule(detector="secrets.*", action="block"),
                PolicyRule(detector="pii.*", action="redact"),
                PolicyRule(detector="tool_poisoning.*", action="flag"),
                PolicyRule(detector="prompt_injection.*", action="flag"),
            ]
        ),
    )


def config_to_yaml_dict(cfg: SluiceConfig) -> dict[str, Any]:
    return cfg.model_dump(mode="json")
