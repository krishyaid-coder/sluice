"""Session-scoped stable pseudonymization of PII values.

The registry maintains a bidirectional map inside each session:

- forward:  real value  -> pseudonym  (e.g. jane@corp.com -> EMAIL_A)
- reverse:  pseudonym   -> real value

Naming scheme is deterministic within a session and starts fresh in each new
session. First email seen becomes EMAIL_A, next EMAIL_B, and so on through Z,
then AA, AB, ... The type prefix comes from the detector id (pii.email ->
EMAIL, pii.phone_us -> PHONE, etc.).

Design decisions this module encodes:
- Session-scoped only. No cross-session persistence in v1.
- PII only. Secrets are handled by the redact path, not here.
- Bidirectional. Sluice replaces values on tool responses and restores them
  on outbound tool calls before they reach the tool server.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from sluice.config.schema import PseudonymConfig, SluiceConfig

# Map detector ids to the human-readable type prefix used in pseudonyms.
_DETECTOR_TYPE_MAP: dict[str, str] = {
    "pii.email": "EMAIL",
    "pii.phone_us": "PHONE",
    "pii.phone_sg": "PHONE",
    "pii.nric_sg": "NRIC",
    "pii.passport": "PASSPORT",
    "pii.credit_card": "CARD",
    "pii.ssn_us": "SSN",
    "pii.ip_private": "IP",
}

_DEFAULT_TYPE_PREFIX = "PII"

# Matches tokens of the form TYPE_LETTERS (e.g. EMAIL_A, PHONE_AB).
# Deliberately constrained to uppercase-and-underscore. The regex is just a
# shape filter; only tokens whose TYPE half is in KNOWN_TYPE_PREFIXES are
# treated as pseudonyms — otherwise a natural-language constant like
# ``CONSTANT_VALUE`` would look like a pseudonym and trip fail-closed on
# legitimate content.
_PSEUDONYM_RE = re.compile(r"\b([A-Z][A-Z0-9]{1,11})_([A-Z]{1,5})\b")

# Type prefixes that we recognize as pseudonyms. Comes from the mapped values
# plus the fallback. Any TYPE_X token whose TYPE is not in this set is treated
# as ordinary content and left alone.
KNOWN_TYPE_PREFIXES: frozenset[str] = frozenset(_DETECTOR_TYPE_MAP.values()) | {_DEFAULT_TYPE_PREFIX}


def _type_for_detector(detector_id: str) -> str:
    """Map a detector id to its pseudonym type prefix."""
    if detector_id in _DETECTOR_TYPE_MAP:
        return _DETECTOR_TYPE_MAP[detector_id]
    if detector_id.startswith("pii."):
        # Fallback for a pii.* detector we haven't explicitly mapped.
        suffix = detector_id.split(".", 1)[1].upper()
        return re.sub(r"[^A-Z0-9]", "", suffix) or _DEFAULT_TYPE_PREFIX
    return _DEFAULT_TYPE_PREFIX


def _alphabet_index(idx: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA, 27 -> AB, ..., 51 -> AZ, 52 -> BA."""
    if idx < 0:
        raise ValueError("alphabet index must be non-negative")
    letters: list[str] = []
    n = idx
    while True:
        letters.append(chr(ord("A") + n % 26))
        n = n // 26 - 1
        if n < 0:
            break
    return "".join(reversed(letters))


@dataclass
class PseudonymRegistry:
    """Bidirectional per-session mapping of real values to pseudonyms."""

    forward: dict[str, str] = field(default_factory=dict)  # real -> pseudonym
    reverse: dict[str, str] = field(default_factory=dict)  # pseudonym -> real
    counters: dict[str, int] = field(default_factory=dict)  # type_prefix -> next_idx

    def assign(self, value: str, detector_id: str) -> str:
        """Return the pseudonym for value, assigning a new one if needed."""
        if not value:
            return value
        existing = self.forward.get(value)
        if existing is not None:
            return existing
        type_prefix = _type_for_detector(detector_id)
        idx = self.counters.get(type_prefix, 0)
        # Skip any pseudonym that would collide with an existing pseudonym for
        # a different value under the same type prefix. In practice this never
        # fires (counter is monotonic per prefix), but keep the loop for safety.
        while True:
            candidate = f"{type_prefix}_{_alphabet_index(idx)}"
            if candidate not in self.reverse:
                break
            idx += 1
        self.forward[value] = candidate
        self.reverse[candidate] = value
        self.counters[type_prefix] = idx + 1
        return candidate

    def lookup(self, pseudonym: str) -> str | None:
        """Return the real value for a pseudonym, or None if unknown."""
        return self.reverse.get(pseudonym)

    def mappings(self) -> dict[str, str]:
        """Snapshot of forward mappings (real -> pseudonym). Copy, not view."""
        return dict(self.forward)

    def is_empty(self) -> bool:
        return not self.forward


def find_pseudonym_tokens(
    text: str, known_prefixes: frozenset[str] | set[str] | None = None
) -> list[str]:
    """Return distinct pseudonym tokens found in text, in order of first appearance.

    Only tokens whose TYPE half is in ``known_prefixes`` count. Default is
    the built-in pii type prefixes plus the generic fallback. Pass a wider
    set to include per-session-observed prefixes if needed.
    """
    if not text:
        return []
    prefixes = known_prefixes if known_prefixes is not None else KNOWN_TYPE_PREFIXES
    seen: list[str] = []
    for match in _PSEUDONYM_RE.finditer(text):
        if match.group(1) not in prefixes:
            continue
        token = match.group(0)
        if token not in seen:
            seen.append(token)
    return seen


class PseudonymStore:
    """Container for per-session PseudonymRegistry instances."""

    def __init__(self, enabled: bool = True, fail_closed_on_reverse: bool = True) -> None:
        self._enabled = enabled
        self._fail_closed = fail_closed_on_reverse
        self._sessions: dict[str, PseudonymRegistry] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def fail_closed_on_reverse(self) -> bool:
        return self._fail_closed

    def registry(self, session_id: str) -> PseudonymRegistry:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = PseudonymRegistry()
            return self._sessions[session_id]

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def clear(self, session_id: str | None = None) -> None:
        with self._lock:
            if session_id is None:
                self._sessions.clear()
            elif session_id in self._sessions:
                del self._sessions[session_id]

    def session_count(self) -> int:
        return len(self._sessions)


# Module-level singleton, following the pattern used by session/taint.py.
_store: PseudonymStore | None = None


def configure(cfg: SluiceConfig | PseudonymConfig) -> None:
    global _store
    pcfg = cfg.pseudonym if isinstance(cfg, SluiceConfig) else cfg
    _store = PseudonymStore(
        enabled=pcfg.enabled,
        fail_closed_on_reverse=pcfg.fail_closed_on_reverse,
    )


def store() -> PseudonymStore | None:
    return _store


def enabled() -> bool:
    return _store is not None and _store.enabled


def registry_for(session_id: str) -> PseudonymRegistry | None:
    if _store is None or not _store.enabled:
        return None
    return _store.registry(session_id)


def assign(session_id: str, value: str, detector_id: str) -> str | None:
    """Assign or return a pseudonym for value. Returns None if disabled."""
    registry = registry_for(session_id)
    if registry is None:
        return None
    return registry.assign(value, detector_id)


def lookup(session_id: str, pseudonym: str) -> str | None:
    registry = registry_for(session_id)
    if registry is None:
        return None
    return registry.lookup(pseudonym)


def mappings_for(session_id: str) -> dict[str, str]:
    registry = registry_for(session_id)
    if registry is None:
        return {}
    return registry.mappings()


def clear(session_id: str | None = None) -> None:
    if _store is not None:
        _store.clear(session_id)
