from typing import Any

from pydantic import BaseModel, Field


class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] | None = None


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None


class PolicyViolation(BaseModel):
    rule: str
    detail: str
    action: str
    detectors: list[str] = Field(default_factory=list)
    preset_source: str | None = None
    propagation: list[dict[str, str | None]] | None = None


class AuditEvent(BaseModel):
    session_id: str
    upstream: str
    direction: str
    method: str | None = None
    tool: str | None = None
    action: str
    detectors: list[str] = Field(default_factory=list)
    rule: str | None = None
    redacted_preview: str | None = None
    latency_us: int | None = None
    preset_source: str | None = None
    client_ip: str | None = None
    propagation: list[dict[str, str | None]] | None = None
    event_id: int | None = None
    ts: int | None = None
