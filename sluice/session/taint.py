from __future__ import annotations

from sluice.config.schema import SluiceConfig, TaintConfig
from sluice.session.store import SessionStore

_store: SessionStore | None = None
_enabled = False


def configure(cfg: SluiceConfig | TaintConfig) -> None:
    global _store, _enabled
    taint_cfg = cfg.taint if isinstance(cfg, SluiceConfig) else cfg
    _enabled = taint_cfg.enabled
    _store = SessionStore(min_length=taint_cfg.min_length, scope=taint_cfg.scope)


def mark(session_id: str, value: str) -> None:
    if _enabled and _store:
        _store.mark(session_id, value)


def mark_from_hits(session_id: str, values: list[str]) -> None:
    if _enabled and _store:
        _store.mark_from_hits(session_id, values)


def check(session_id: str, text: str) -> str | None:
    if not _enabled or not _store:
        return None
    return _store.check(session_id, text)


def clear(session_id: str | None = None) -> None:
    if _store:
        _store.clear(session_id)


def store() -> SessionStore | None:
    return _store
