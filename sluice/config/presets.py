from __future__ import annotations

import copy
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

PRESET_PREFIX = "preset:"


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        elif key in result and isinstance(result[key], list) and isinstance(value, list):
            result[key] = result[key] + value
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_preset_file(name: str) -> dict[str, Any]:
    pkg = resources.files("sluice.policy.presets")
    path = pkg / f"{name}.yaml"
    if not path.is_file():
        raise ValueError(f"unknown preset: {name}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _annotate_preset_rules(data: dict[str, Any], preset_name: str) -> None:
    rules = data.get("policy", {}).get("rules", [])
    for rule in rules:
        if isinstance(rule, dict):
            rule.setdefault("preset_source", preset_name)


def resolve_includes(raw: dict[str, Any], config_path: Path) -> dict[str, Any]:
    """Merge include list into config. Later includes and the main file win."""
    includes = raw.pop("include", []) or []
    merged: dict[str, Any] = {}

    for item in includes:
        if not isinstance(item, str):
            continue
        if item.startswith(PRESET_PREFIX):
            preset_name = item[len(PRESET_PREFIX) :]
            preset = _load_preset_file(preset_name)
            _annotate_preset_rules(preset, preset_name)
            merged = _deep_merge(merged, preset)
        else:
            local_path = (config_path.parent / item).resolve()
            if not local_path.exists():
                raise FileNotFoundError(f"include not found: {local_path}")
            with local_path.open(encoding="utf-8") as f:
                included = yaml.safe_load(f) or {}
            merged = _deep_merge(merged, included)

    return _deep_merge(merged, raw)


def list_presets() -> list[str]:
    pkg = resources.files("sluice.policy.presets")
    return sorted(p.name.removesuffix(".yaml") for p in pkg.iterdir() if p.name.endswith(".yaml"))


def preset_yaml(name: str) -> str:
    data = _load_preset_file(name)
    return yaml.safe_dump(data, sort_keys=False)
