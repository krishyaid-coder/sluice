from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Literal, Protocol

Severity = Literal["low", "medium", "high", "critical"]
Direction = Literal["request", "response"]


@dataclass(frozen=True)
class ScanContext:
    direction: Direction
    method: str | None
    tool: str | None
    upstream: str
    session_id: str = "default"


@dataclass(frozen=True)
class Hit:
    detector_id: str
    start: int
    end: int
    matched: str
    label: str
    severity: Severity = "medium"


class Detector(Protocol):
    id: str
    category: str
    severity: Severity

    def scan(self, text: str, context: ScanContext) -> list[Hit]: ...


_REGISTRY: dict[str, Detector] = {}


def register(detector: Detector) -> Detector:
    _REGISTRY[detector.id] = detector
    return detector


def get_registry() -> dict[str, Detector]:
    return dict(_REGISTRY)


def load_entry_point_detectors() -> None:
    eps = entry_points().select(group="sluice.detectors")
    for ep in eps:
        detector = ep.load()
        if callable(detector):
            detector = detector()
        register(detector)


def scan_all(text: str, context: ScanContext) -> list[Hit]:
    hits: list[Hit] = []
    for detector in _REGISTRY.values():
        hits.extend(detector.scan(text, context))
    return hits


def match_detector_pattern(pattern: str, detector_id: str) -> bool:
    if pattern == "*":
        return True
    if "." in pattern:
        return fnmatch.fnmatch(detector_id, pattern)
    return fnmatch.fnmatch(detector_id.split(".", 1)[-1], pattern) or fnmatch.fnmatch(
        detector_id, pattern
    )


@dataclass
class DetectorConfig:
    enabled: bool = True
    options: dict = field(default_factory=dict)
