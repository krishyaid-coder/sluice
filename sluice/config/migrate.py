from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sluice.config.schema import UpstreamConfig


def is_legacy_config(raw: dict[str, Any]) -> bool:
    return "upstreams" not in raw and "upstream" in raw


def migrate_legacy_config(raw: dict[str, Any]) -> dict[str, Any]:
    if "upstreams" in raw:
        return raw

    migrated = dict(raw)
    migrated.setdefault("version", 1)

    upstream_block = migrated.pop("upstream", {})
    transport = migrated.pop("transport", "http")

    upstream = UpstreamConfig(
        name="default",
        transport=transport if transport in ("stdio", "http", "streamable_http") else "http",
        url=upstream_block.get("url"),
        command=upstream_block.get("command"),
        args=upstream_block.get("args", []),
        env=upstream_block.get("env", {}),
        headers=upstream_block.get("headers", {}),
    )
    migrated["upstreams"] = [upstream.model_dump()]
    migrated.setdefault("routing", {"default": "default"})
    return migrated


def write_upgraded_config(path: Path, migrated: dict[str, Any]) -> Path:
    upgraded_path = path.parent / f"{path.name}.upgraded"
    upgraded_path.write_text(yaml.safe_dump(migrated, sort_keys=False))
    return upgraded_path
