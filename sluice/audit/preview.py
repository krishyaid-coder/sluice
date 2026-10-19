from __future__ import annotations

from sluice.detectors.base import Hit
from sluice.proxy.models import PolicyViolation
from sluice.session.provenance import value_hash

_PREVIEW_MAX = 200


def hash_prefix(value: str, length: int = 4) -> str:
    return value_hash(value)[:length] + "…"


def _add_part(parts: list[str], seen: set[str], detector_id: str, value: str) -> None:
    if not value:
        return
    token = f"{detector_id}={hash_prefix(value)}"
    if token not in seen:
        seen.add(token)
        parts.append(token)


def safe_preview(
    *,
    method: str | None,
    tool: str | None,
    hits: list[Hit] | None = None,
    violation: PolicyViolation | None = None,
    extra_values: list[tuple[str, str]] | None = None,
    propagation_hashes: list[str] | None = None,
) -> str:
    """Build an audit preview that never contains raw matched values.

    Shape: ``secrets.aws_access_key=ab8f… taint_leak=1a5d…``
    If nothing sensitive was observed, fall back to ``method tool``.
    """
    parts: list[str] = []
    seen: set[str] = set()
    for hit in hits or []:
        _add_part(parts, seen, hit.detector_id, hit.matched)
    for detector_id, value in extra_values or []:
        _add_part(parts, seen, detector_id, value)
    for digest in propagation_hashes or []:
        if not digest:
            continue
        token = f"taint_leak={digest[:4]}…"
        if token not in seen:
            seen.add(token)
            parts.append(token)
    if violation and not parts:
        for det in violation.detectors:
            token = det
            if token not in seen:
                seen.add(token)
                parts.append(token)
    if parts:
        return " ".join(parts)[:_PREVIEW_MAX]
    if method and tool:
        return f"{method} {tool}"
    return method or tool or "-"
