from __future__ import annotations

import json
import re

from sluice.detectors.base import Hit, ScanContext, register

INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (
        "tool_poisoning.ignore_instructions",
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        "ignore-previous-instructions phrase",
    ),
    (
        "tool_poisoning.system_override",
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(a\s+)?(system|admin|root)",
        "system-role override phrase",
    ),
    (
        "tool_poisoning.hidden_markup",
        r"<!--.*?-->",
        "HTML comment in tool description",
    ),
    (
        "tool_poisoning.zero_width",
        r"[\u200b-\u200f\ufeff]",
        "zero-width / invisible characters",
    ),
    (
        "tool_poisoning.exfil_phrase",
        r"(?i)(send|post|email|upload).{0,40}(all|every|full).{0,20}(file|data|content|secret)",
        "exfiltration instruction in tool metadata",
    ),
]


def _scan_text_field(text: str, field_name: str) -> list[Hit]:
    hits: list[Hit] = []
    for detector_id, pattern, label in INJECTION_PATTERNS:
        for match in re.finditer(pattern, text):
            hits.append(
                Hit(
                    detector_id=detector_id,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group()[:80],
                    label=f"{label} in {field_name}",
                    severity="high",
                )
            )
    return hits


class ToolPoisoningDetector:
    id = "tool_poisoning"
    category = "tool_poisoning"
    severity = "high"

    def scan(self, text: str, context: ScanContext) -> list[Hit]:
        if context.method != "tools/list" or context.direction != "response":
            return []

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return _scan_text_field(text, "raw")

        hits: list[Hit] = []
        tools = payload.get("result", {}).get("tools", [])
        if not isinstance(tools, list):
            tools = payload.get("tools", [])

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "unknown")
            for field in ("description", "name"):
                value = tool.get(field, "")
                if isinstance(value, str) and value:
                    hits.extend(_scan_text_field(value, f"tool:{name}.{field}"))
            schema = tool.get("inputSchema", {})
            if isinstance(schema, dict):
                schema_text = json.dumps(schema)
                hits.extend(_scan_text_field(schema_text, f"tool:{name}.inputSchema"))
        return hits


register(ToolPoisoningDetector())
