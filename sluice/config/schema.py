from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


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


class PolicyRule(BaseModel):
    detector: str
    action: Literal["block", "redact", "flag", "pass"]
    upstream: str | None = None
    tool: str | None = None


class PolicyConfig(BaseModel):
    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: Literal["block", "redact", "flag", "pass"] = "flag"


class TaintConfig(BaseModel):
    enabled: bool = True
    min_length: int = 12
    scope: Literal["session", "process"] = "session"


class SqliteAuditConfig(BaseModel):
    path: str = "~/.sluice/audit.db"
    retention_days: int = 30


class AuditConfig(BaseModel):
    sink: Literal["sqlite", "stdout", "both"] = "sqlite"
    sqlite: SqliteAuditConfig = Field(default_factory=SqliteAuditConfig)


class LoggingConfig(BaseModel):
    level: Literal["debug", "info", "warn", "error"] = "info"
    format: Literal["json", "console"] = "json"


class SluiceConfig(BaseModel):
    version: int = 1
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    upstreams: list[UpstreamConfig] = Field(default_factory=list)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    taint: TaintConfig = Field(default_factory=TaintConfig)
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


def default_config() -> SluiceConfig:
    return SluiceConfig(
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
            ]
        ),
    )


def config_to_yaml_dict(cfg: SluiceConfig) -> dict[str, Any]:
    return cfg.model_dump(mode="json")
