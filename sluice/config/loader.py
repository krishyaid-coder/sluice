from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from sluice.config.schema import SluiceConfig, UpstreamConfig

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _expand_env(value: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in os.environ:
            raise ValueError(f"environment variable not set: {var}")
        return os.environ[var]

    return _ENV_PATTERN.sub(replacer, value)


def _expand_env_recursive(obj: Any) -> Any:
    if isinstance(obj, str):
        if "${" in obj:
            return _expand_env(obj)
        return obj
    if isinstance(obj, dict):
        return {k: _expand_env_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_recursive(v) for v in obj]
    return obj


def _expand_paths(obj: Any) -> Any:
    if isinstance(obj, str) and obj.startswith("~"):
        return str(Path(obj).expanduser())
    if isinstance(obj, dict):
        return {k: _expand_paths(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_paths(v) for v in obj]
    return obj


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


def load_config(path: str | Path) -> SluiceConfig:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"config not found: {path}")

    with path.open() as f:
        raw = yaml.safe_load(f) or {}

    raw = migrate_legacy_config(raw)
    raw = _expand_env_recursive(raw)
    raw = _expand_paths(raw)

    cfg = SluiceConfig.model_validate(raw)

    default_name = cfg.routing.default
    if not any(u.name == default_name for u in cfg.upstreams):
        cfg.routing.default = cfg.upstreams[0].name

    return cfg


def find_config(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    local = Path("config.yaml")
    if local.exists():
        return local
    home = Path.home() / ".sluice" / "config.yaml"
    if home.exists():
        return home
    return local
