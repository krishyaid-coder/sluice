from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import typer

from sluice.audit import build_audit_sink
from sluice.audit.report import (
    InvalidSessionId,
    SensitiveValue,
    SessionReport,
    load_recent_reports,
    load_session_report,
    report_to_json_dict,
    sqlite_sink,
)
from sluice.config.loader import find_config, load_config

FormatName = Literal["human", "markdown", "json"]

_LABEL_WIDTH = 22
_FOLLOW_LABEL_WIDTH = 9
_OUTCOME_VERB = {
    "block": "blocked",
    "redact": "redacted",
    "flag": "flagged",
}


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _format_duration(seconds: int) -> str:
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if hours:
        parts.append(f"{hours}h")
    if minutes or hours:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def _tool_label(upstream: str, tool: str | None) -> str:
    return f"{upstream}/{tool or '-'}"


def _clock(ts: str) -> str:
    dt = _parse_iso(ts)
    if not dt:
        return "--:--:--"
    return dt.strftime("%H:%M:%S")


def _header_times(report: SessionReport) -> str:
    start = _parse_iso(report.started_at)
    end = _parse_iso(report.ended_at)
    if not start or not end:
        return ""
    start_s = start.strftime("%Y-%m-%d %H:%M:%S")
    if start.date() == end.date():
        end_s = end.strftime("%H:%M:%S")
    else:
        end_s = end.strftime("%Y-%m-%d %H:%M:%S")
    duration = _format_duration(report.duration_seconds)
    upstreams = ", ".join(report.upstreams) if report.upstreams else "-"
    return f"{start_s} → {end_s}  ({duration})  •  upstreams: {upstreams}"


def _actions_phrase(report: SessionReport) -> str:
    counts = report.summary.actions
    parts = [f"{counts.blocked} blocked", f"{counts.redacted} redacted"]
    if counts.flagged:
        parts.append(f"{counts.flagged} flagged")
    parts.append(f"{counts.passed} passed")
    return ", ".join(parts)


def _outcome_line(item: SensitiveValue) -> str | None:
    if item.outcome is None:
        return "         no reuse observed"
    verb = _OUTCOME_VERB.get(item.outcome.action, item.outcome.action)
    label = item.outcome.action.upper()
    if item.outcome.action == "block":
        label = "BLOCKED"
    elif item.outcome.action == "redact":
        label = "REDACTED"
    elif item.outcome.action == "flag":
        label = "FLAGGED"
    rule = f" ({item.outcome.rule})" if item.outcome.rule else ""
    loc = _tool_label(item.outcome.attempted_at.upstream, item.outcome.attempted_at.tool)
    return (
        f"         {verb.ljust(_FOLLOW_LABEL_WIDTH)} "
        f"{_clock(item.outcome.attempted_at.ts)}  {loc}  →  {label}{rule}"
    )


def format_human(report: SessionReport) -> str:
    if report.empty:
        return f"Session {report.session_id} has no events."

    lines = [
        f"Sluice session report — {report.session_id}",
        _header_times(report),
        "",
        "Summary",
        f"  {'Requests inspected'.ljust(_LABEL_WIDTH)}{report.summary.requests_inspected}",
        f"  {'Sensitive values seen'.ljust(_LABEL_WIDTH)}{report.summary.sensitive_values_seen}",
        f"  {'Actions taken'.ljust(_LABEL_WIDTH)}{_actions_phrase(report)}",
        "",
    ]

    if report.sensitive_values:
        lines.append("Sensitive values (hashes only)")
        for item in report.sensitive_values:
            shown = f"{item.hash_prefix}…"
            loc = _tool_label(item.first_seen.upstream, item.first_seen.tool)
            lines.append(
                f"  {shown.ljust(6)}  {'first seen'.ljust(_FOLLOW_LABEL_WIDTH)} "
                f"{_clock(item.first_seen.ts)}  {loc}"
            )
            follow = _outcome_line(item)
            if follow:
                lines.append(follow)
        lines.append("")
    else:
        lines.append("No sensitive values seen in this session.")
        lines.append("")

    if report.detectors_fired:
        lines.append("Detectors that fired")
        width = max(len(name) for name in report.detectors_fired)
        for name, count in report.detectors_fired.items():
            lines.append(f"  {name.ljust(width)}      {count}")
        lines.append("")
    else:
        lines.append("No detectors fired.")
        lines.append("")

    if report.injections_detected:
        lines.append(f"Injections detected: {report.injections_detected}")
    else:
        lines.append("No injections detected in this session.")
    lines.append("")
    lines.append(f"Full detail: sluice logs --session {report.session_id}")
    return "\n".join(lines)


def format_markdown(report: SessionReport) -> str:
    if report.empty:
        return f"Session {report.session_id} has no events."

    lines = [
        f"## Sluice session report — {report.session_id}",
        "",
        _header_times(report),
        "",
        "### Summary",
        "",
        f"- Requests inspected: {report.summary.requests_inspected}",
        f"- Sensitive values seen: {report.summary.sensitive_values_seen}",
        f"- Actions taken: {_actions_phrase(report)}",
        "",
    ]

    if report.sensitive_values:
        lines.append("### Sensitive values (hashes only)")
        lines.append("")
        for item in report.sensitive_values:
            loc = _tool_label(item.first_seen.upstream, item.first_seen.tool)
            lines.append(f"- `{item.hash_prefix}…`")
            lines.append(f"  - first seen {_clock(item.first_seen.ts)} {loc}")
            if item.outcome is None:
                lines.append("  - no reuse observed")
            else:
                verb = _OUTCOME_VERB.get(item.outcome.action, item.outcome.action)
                label = item.outcome.action.upper()
                if item.outcome.action == "block":
                    label = "BLOCKED"
                elif item.outcome.action == "redact":
                    label = "REDACTED"
                elif item.outcome.action == "flag":
                    label = "FLAGGED"
                rule = f" ({item.outcome.rule})" if item.outcome.rule else ""
                oloc = _tool_label(item.outcome.attempted_at.upstream, item.outcome.attempted_at.tool)
                lines.append(
                    f"  - {verb} {_clock(item.outcome.attempted_at.ts)} {oloc} → {label}{rule}"
                )
        lines.append("")
    else:
        lines.append("No sensitive values seen in this session.")
        lines.append("")

    if report.detectors_fired:
        lines.append("### Detectors that fired")
        lines.append("")
        lines.append("| Detector | Count |")
        lines.append("| --- | --- |")
        for name, count in report.detectors_fired.items():
            lines.append(f"| {name} | {count} |")
        lines.append("")
    else:
        lines.append("No detectors fired.")
        lines.append("")

    if report.injections_detected:
        lines.append(f"Injections detected: {report.injections_detected}")
    else:
        lines.append("No injections detected in this session.")
    lines.append("")
    lines.append(f"Full detail: `sluice logs --session {report.session_id}`")
    return "\n".join(lines)


def format_json(reports: list[SessionReport], as_array: bool) -> str:
    payload: object
    if as_array:
        payload = [report_to_json_dict(r) for r in reports]
    elif reports:
        payload = report_to_json_dict(reports[0])
    else:
        payload = []
    return json.dumps(payload, indent=2)


def render(reports: list[SessionReport], fmt: FormatName, as_array: bool) -> str:
    if fmt == "json":
        return format_json(reports, as_array=as_array)
    if not reports:
        return "No sessions."
    formatter = format_markdown if fmt == "markdown" else format_human
    return "\n\n".join(formatter(r) for r in reports)


def register(app: typer.Typer) -> None:
    app.command("report")(report_cmd)


def report_cmd(
    session: str | None = typer.Option(
        None, "--session", help="Specific session ID. Mutually exclusive with --last."
    ),
    last: int = typer.Option(1, "--last", help="N most recent sessions. Ignored if --session is set."),
    fmt: str = typer.Option("human", "--format", help="human, markdown, or json"),
    config: Path | None = typer.Option(None, "--config", help="Path to config.yaml"),
    log_level: str = typer.Option("info", "--log-level"),
) -> None:
    """Summarize what Sluice caught in one or more sessions."""
    del log_level  # accepted for CLI consistency with serve/stdio
    fmt_norm = fmt.strip().lower()
    if fmt_norm not in {"human", "markdown", "json"}:
        typer.echo(f"invalid format: {fmt}", err=True)
        raise typer.Exit(2)
    if session is None and last < 1:
        typer.echo("--last must be >= 1", err=True)
        raise typer.Exit(2)

    config_path = find_config(str(config) if config else None)
    try:
        cfg = load_config(config_path)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1) from e
    except Exception as e:
        typer.echo(f"config error: {e}", err=True)
        raise typer.Exit(1) from e

    audit = build_audit_sink(cfg)
    sink = sqlite_sink(audit)
    if sink is None:
        typer.echo("No audit sink configured", err=True)
        raise typer.Exit(1)

    async def _run() -> list[SessionReport]:
        try:
            if session is not None:
                return [await load_session_report(sink, session)]
            return await load_recent_reports(sink, last)
        finally:
            await sink.close()
            if audit is not None:
                await audit.close()

    try:
        reports = asyncio.run(_run())
    except InvalidSessionId as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(2) from e
    except (OSError, sqlite3.OperationalError) as e:
        typer.echo(f"audit database unreachable: {e}", err=True)
        raise typer.Exit(1) from e
    except Exception as e:
        typer.echo(f"query error: {e}", err=True)
        raise typer.Exit(2) from e

    as_array = session is None
    typer.echo(render(reports, fmt_norm, as_array=as_array))  # type: ignore[arg-type]
