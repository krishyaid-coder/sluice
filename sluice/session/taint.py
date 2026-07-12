from __future__ import annotations

from sluice.config.schema import SluiceConfig, TaintConfig
from sluice.session.provenance import PropagationEdge, TaintMark
from sluice.session.store import SessionStore

_store: SessionStore | None = None
_enabled = False


def configure(cfg: SluiceConfig | TaintConfig) -> None:
    global _store, _enabled
    taint_cfg = cfg.taint if isinstance(cfg, SluiceConfig) else cfg
    _enabled = taint_cfg.enabled
    _store = SessionStore(
        min_length=taint_cfg.min_length,
        scope=taint_cfg.scope,
        provenance=taint_cfg.provenance,
    )


def mark(
    session_id: str,
    value: str,
    *,
    raw_json: str | None = None,
    source_tool: str | None = None,
    source_upstream: str | None = None,
    source_method: str | None = None,
) -> None:
    mark_from_hits(
        session_id,
        [value],
        raw_json=raw_json,
        source_tool=source_tool,
        source_upstream=source_upstream,
        source_method=source_method,
    )


def mark_from_hits(
    session_id: str,
    values: list[str],
    *,
    raw_json: str | None = None,
    source_tool: str | None = None,
    source_upstream: str | None = None,
    source_method: str | None = None,
) -> None:
    if _enabled and _store:
        _store.mark_from_hits(
            session_id,
            values,
            raw_json=raw_json,
            source_tool=source_tool,
            source_upstream=source_upstream,
            source_method=source_method,
        )


def check(session_id: str, text: str) -> str | None:
    if not _enabled or not _store:
        return None
    return _store.check(session_id, text)


def provenance_for_leak(session_id: str, leaked_value: str) -> TaintMark | None:
    if not _enabled or not _store:
        return None
    return _store.provenance_for_leak(session_id, leaked_value)


def propagation_edge_for_leak(
    session_id: str,
    leaked_value: str,
    *,
    sink_tool: str | None,
    sink_upstream: str,
) -> PropagationEdge | None:
    mark = provenance_for_leak(session_id, leaked_value)
    if not mark:
        return None
    source_path = mark.json_paths[0] if mark.json_paths else None
    return PropagationEdge(
        session_id=session_id,
        value_hash=mark.value_hash,
        source_path=source_path,
        source_tool=mark.source_tool,
        sink_tool=sink_tool,
        sink_upstream=sink_upstream,
    )


def list_marks(session_id: str) -> list[TaintMark]:
    if not _store:
        return []
    return _store.list_marks(session_id)


def mark_count(session_id: str) -> int:
    if not _store:
        return 0
    return _store.mark_count(session_id)


def clear(session_id: str | None = None) -> None:
    if _store:
        _store.clear(session_id)


def store() -> SessionStore | None:
    return _store
