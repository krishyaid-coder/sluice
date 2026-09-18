from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sluice.audit.sink import AuditSink
from sluice.audit.sqlite import SqliteSink
from sluice.audit.stdout import ChainedSink
from sluice.proxy.models import AuditEvent
from sluice.session.provenance import extract_string_paths, parse_json_safe, value_hash

_MIN_VALUE_LEN = 12

# Hash prefixes as stored in redacted_preview: four hex chars plus an ellipsis.
_HASH_RE = re.compile(r"\b([0-9a-fA-F]{4})(?:[0-9a-fA-F]*)?(?:…|\.{3})")
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class InvalidSessionId(ValueError):
    """Session id failed the allowed format check."""


@dataclass
class EventRef:
    ts: str
    upstream: str
    tool: str | None
    event_id: int | None


@dataclass
class SensitiveOutcome:
    attempted_at: EventRef
    action: str
    rule: str | None


@dataclass
class SensitiveValue:
    hash_prefix: str
    first_seen: EventRef
    outcome: SensitiveOutcome | None = None


@dataclass
class ActionCounts:
    blocked: int = 0
    redacted: int = 0
    pseudonymized: int = 0
    flagged: int = 0
    passed: int = 0


@dataclass
class SessionSummary:
    requests_inspected: int = 0
    sensitive_values_seen: int = 0
    actions: ActionCounts = field(default_factory=ActionCounts)


@dataclass
class SessionReport:
    session_id: str
    started_at: str | None = None
    ended_at: str | None = None
    duration_seconds: int = 0
    upstreams: list[str] = field(default_factory=list)
    summary: SessionSummary = field(default_factory=SessionSummary)
    sensitive_values: list[SensitiveValue] = field(default_factory=list)
    detectors_fired: dict[str, int] = field(default_factory=dict)
    injections_detected: int = 0
    empty: bool = False


def validate_session_id(session_id: str) -> str:
    value = session_id.strip()
    if not _SESSION_ID_RE.fullmatch(value):
        raise InvalidSessionId(f"invalid session id: {session_id!r}")
    return value


def sqlite_sink(audit: AuditSink | None) -> SqliteSink | None:
    if isinstance(audit, SqliteSink):
        return audit
    if isinstance(audit, ChainedSink):
        return audit.find(SqliteSink)
    return None


def extract_hash_prefixes(preview: str | None) -> list[str]:
    if not preview:
        return []
    seen: list[str] = []
    for match in _HASH_RE.finditer(preview):
        prefix = match.group(1).lower()
        if prefix not in seen:
            seen.append(prefix)
    return seen


def _add_prefix(seen: list[str], prefix: str) -> None:
    prefix = prefix.lower()
    if len(prefix) >= 4 and prefix[:4] not in seen:
        seen.append(prefix[:4])


def event_hash_prefixes(event: AuditEvent) -> list[str]:
    """Safe 4-char prefixes for grouping. Never returns raw matched text."""
    found: list[str] = []
    for prefix in extract_hash_prefixes(event.redacted_preview):
        _add_prefix(found, prefix)
    if event.propagation:
        for edge in event.propagation:
            raw_hash = edge.get("value_hash") or ""
            if raw_hash:
                _add_prefix(found, raw_hash)
    if event.detectors:
        parsed = parse_json_safe(event.redacted_preview)
        if parsed is not None:
            for _, value in extract_string_paths(parsed):
                if len(value) >= _MIN_VALUE_LEN:
                    _add_prefix(found, value_hash(value))
    return found


def _iso_utc(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_ref(event: AuditEvent) -> EventRef:
    ts = _iso_utc(event.ts or 0)
    return EventRef(
        ts=ts,
        upstream=event.upstream,
        tool=event.tool,
        event_id=event.event_id,
    )


def _outcome_rule(event: AuditEvent) -> str | None:
    if event.rule:
        return event.rule
    if not event.detectors:
        return None
    if len(event.detectors) == 1:
        return event.detectors[0]
    for preferred in ("taint_leak",):
        if preferred in event.detectors:
            return preferred
    return event.detectors[0]


def build_session_report(session_id: str, events: list[AuditEvent]) -> SessionReport:
    if not events:
        return SessionReport(session_id=session_id, empty=True)

    timestamps = [e.ts or 0 for e in events]
    started_ms = min(timestamps)
    ended_ms = max(timestamps)
    duration = max(0, (ended_ms - started_ms) // 1000)

    upstreams: list[str] = []
    for event in events:
        if event.upstream and event.upstream not in upstreams:
            upstreams.append(event.upstream)

    actions = ActionCounts()
    requests = 0
    detector_counts: Counter[str] = Counter()
    injections = 0

    by_hash: dict[str, list[AuditEvent]] = {}
    hash_order: list[str] = []

    for event in events:
        if event.direction == "request":
            requests += 1
        if event.action == "block":
            actions.blocked += 1
        elif event.action == "redact":
            actions.redacted += 1
        elif event.action == "pseudonymize":
            actions.pseudonymized += 1
        elif event.action == "flag":
            actions.flagged += 1
        else:
            actions.passed += 1

        for det in event.detectors:
            detector_counts[det] += 1
            if det.startswith("prompt_injection."):
                injections += 1

        for prefix in event_hash_prefixes(event):
            if prefix not in by_hash:
                hash_order.append(prefix)
                by_hash[prefix] = []
            by_hash[prefix].append(event)

    sensitive: list[SensitiveValue] = []
    for prefix in hash_order:
        group = by_hash[prefix]
        first = group[0]
        outcome: SensitiveOutcome | None = None
        for follow in group[1:]:
            if follow.action in {"block", "redact", "flag"}:
                outcome = SensitiveOutcome(
                    attempted_at=_event_ref(follow),
                    action=follow.action,
                    rule=_outcome_rule(follow),
                )
                break
        sensitive.append(
            SensitiveValue(
                hash_prefix=prefix,
                first_seen=_event_ref(first),
                outcome=outcome,
            )
        )

    detectors = dict(sorted(detector_counts.items(), key=lambda item: (-item[1], item[0])))

    return SessionReport(
        session_id=session_id,
        started_at=_iso_utc(started_ms),
        ended_at=_iso_utc(ended_ms),
        duration_seconds=duration,
        upstreams=upstreams,
        summary=SessionSummary(
            requests_inspected=requests,
            sensitive_values_seen=len(sensitive),
            actions=actions,
        ),
        sensitive_values=sensitive,
        detectors_fired=detectors,
        injections_detected=injections,
        empty=False,
    )


async def load_session_report(sink: SqliteSink, session_id: str) -> SessionReport:
    session_id = validate_session_id(session_id)
    events = await sink.events_for_session(session_id)
    return build_session_report(session_id, events)


async def load_recent_reports(sink: SqliteSink, last: int) -> list[SessionReport]:
    ids = await sink.recent_session_ids(last)
    reports: list[SessionReport] = []
    for session_id in ids:
        reports.append(await load_session_report(sink, session_id))
    return reports


def report_to_json_dict(report: SessionReport) -> dict[str, Any]:
    def ref_dict(ref: EventRef) -> dict[str, Any]:
        return {
            "ts": ref.ts,
            "upstream": ref.upstream,
            "tool": ref.tool,
            "event_id": ref.event_id,
        }

    values: list[dict[str, Any]] = []
    for item in report.sensitive_values:
        entry: dict[str, Any] = {
            "hash_prefix": item.hash_prefix,
            "first_seen": ref_dict(item.first_seen),
            "outcome": None,
        }
        if item.outcome:
            entry["outcome"] = {
                "attempted_at": ref_dict(item.outcome.attempted_at),
                "action": item.outcome.action,
                "rule": item.outcome.rule,
            }
        values.append(entry)

    return {
        "session_id": report.session_id,
        "started_at": report.started_at,
        "ended_at": report.ended_at,
        "duration_seconds": report.duration_seconds,
        "upstreams": list(report.upstreams),
        "summary": {
            "requests_inspected": report.summary.requests_inspected,
            "sensitive_values_seen": report.summary.sensitive_values_seen,
            "actions": {
                "blocked": report.summary.actions.blocked,
                "redacted": report.summary.actions.redacted,
                "pseudonymized": report.summary.actions.pseudonymized,
                "flagged": report.summary.actions.flagged,
                "passed": report.summary.actions.passed,
            },
        },
        "sensitive_values": values,
        "detectors_fired": dict(report.detectors_fired),
        "injections_detected": report.injections_detected,
    }
