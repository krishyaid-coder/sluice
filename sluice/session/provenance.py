from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaintMark:
    value: str
    value_hash: str
    json_paths: list[str] = field(default_factory=list)
    source_tool: str | None = None
    source_upstream: str | None = None
    source_method: str | None = None


@dataclass
class PropagationEdge:
    session_id: str
    value_hash: str
    source_path: str | None
    source_tool: str | None
    sink_tool: str | None
    sink_upstream: str | None
    rule: str = "taint_leak"


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def extract_string_paths(obj: Any, prefix: str = "$") -> list[tuple[str, str]]:
    """Walk JSON and return (json_path, string_value) pairs."""
    pairs: list[tuple[str, str]] = []
    if isinstance(obj, str) and obj:
        pairs.append((prefix, obj))
    elif isinstance(obj, dict):
        for key, val in obj.items():
            child = f"{prefix}.{key}" if prefix != "$" else f"$.{key}"
            pairs.extend(extract_string_paths(val, child))
    elif isinstance(obj, list):
        for idx, val in enumerate(obj):
            pairs.extend(extract_string_paths(val, f"{prefix}[{idx}]"))
    return pairs


def paths_for_value(obj: Any, needle: str, min_length: int = 12) -> list[str]:
    if len(needle) < min_length:
        return []
    return [path for path, val in extract_string_paths(obj) if needle in val]


def parse_json_safe(text: str) -> Any | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
