from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sluice.audit.report import (
    InvalidSessionId,
    build_session_report,
    extract_hash_prefixes,
    report_to_json_dict,
    validate_session_id,
)
from sluice.audit.sqlite import SqliteSink
from sluice.cli.main import app
from sluice.config.schema import SqliteAuditConfig
from sluice.proxy.models import AuditEvent

SECRET = "AKIAIOSFODNN7EXAMPLE"
RUNNER = CliRunner()

T0 = int(datetime(2026, 9, 9, 14, 22, 3, tzinfo=UTC).timestamp() * 1000)
T1 = int(datetime(2026, 9, 9, 14, 24, 0, tzinfo=UTC).timestamp() * 1000)
T2 = int(datetime(2026, 9, 9, 14, 28, 0, tzinfo=UTC).timestamp() * 1000)
T3 = int(datetime(2026, 9, 9, 14, 31, 0, tzinfo=UTC).timestamp() * 1000)
T5 = int(datetime(2026, 9, 9, 14, 47, 19, tzinfo=UTC).timestamp() * 1000)


def _cfg(tmp_path: Path, db_path: Path, sink: str = "sqlite") -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        "\n".join(
            [
                "version: 1",
                "upstreams:",
                "  - name: demo",
                "    transport: http",
                "    url: http://127.0.0.1:9",
                "audit:",
                f"  sink: {sink}",
                "  sqlite:",
                f"    path: {db_path}",
            ]
        )
        + "\n"
    )
    return path


async def _open_db(db_path: Path) -> SqliteSink:
    sink = SqliteSink(SqliteAuditConfig(path=str(db_path)))
    await sink._conn()
    return sink


async def _insert(
    sink: SqliteSink,
    *,
    session_id: str,
    ts: int,
    upstream: str,
    tool: str,
    action: str,
    detectors: list[str],
    rule: str | None,
    preview: str | None,
    direction: str = "request",
    method: str = "tools/call",
) -> None:
    db = await sink._conn()
    await db.execute(
        """
        INSERT INTO events (
            ts, session_id, upstream, direction, method, tool,
            action, detectors, rule, redacted_preview, latency_us
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            session_id,
            upstream,
            direction,
            method,
            tool,
            action,
            json.dumps(detectors),
            rule,
            preview,
            100,
        ),
    )
    await db.commit()


def _event(**kwargs) -> AuditEvent:
    defaults = dict(
        session_id="sess-a3f9b2c1",
        upstream="filesystem",
        direction="request",
        method="tools/call",
        tool="read_file",
        action="pass",
        detectors=[],
        rule=None,
        redacted_preview=None,
        event_id=1,
        ts=T0,
    )
    defaults.update(kwargs)
    return AuditEvent(**defaults)


def test_validate_session_id():
    assert validate_session_id("sess-a3f9b2c1") == "sess-a3f9b2c1"
    with pytest.raises(InvalidSessionId):
        validate_session_id("bad id")
    with pytest.raises(InvalidSessionId):
        validate_session_id("../etc/passwd")


def test_extract_hash_prefixes_ignores_raw_secret():
    assert extract_hash_prefixes("ab8f…") == ["ab8f"]
    assert extract_hash_prefixes(f"ab8f… {SECRET}") == ["ab8f"]
    assert extract_hash_prefixes(SECRET) == []


def test_pass_only_session_skips_sensitive_section():
    from sluice.cli.report import format_human

    report = build_session_report(
        "sess-pass",
        [
            _event(action="pass", event_id=1),
            _event(action="pass", event_id=2, ts=T5, tool="list_dir"),
        ],
    )
    assert report.summary.requests_inspected == 2
    assert report.summary.actions.passed == 2
    assert report.sensitive_values == []
    assert report.detectors_fired == {}
    text = format_human(report)
    assert "No sensitive values seen in this session." in text
    assert "No detectors fired." in text
    assert "Sensitive values (hashes only)" not in text


def test_taint_leak_block_pairs_first_seen_and_outcome():
    from sluice.cli.report import format_human

    events = [
        _event(
            event_id=42,
            ts=T0,
            action="flag",
            detectors=["secrets.aws_access_key"],
            rule="secrets.aws_access_key",
            redacted_preview="ab8f…",
            direction="response",
        ),
        _event(
            event_id=51,
            ts=T3,
            upstream="github",
            tool="create_issue",
            action="block",
            detectors=["taint_leak"],
            rule="taint_leak",
            redacted_preview="ab8f…",
        ),
    ]
    report = build_session_report("sess-a3f9b2c1", events)
    assert report.summary.sensitive_values_seen == 1
    value = report.sensitive_values[0]
    assert value.hash_prefix == "ab8f"
    assert value.first_seen.tool == "read_file"
    assert value.outcome is not None
    assert value.outcome.action == "block"
    assert value.outcome.rule == "taint_leak"
    assert value.outcome.attempted_at.tool == "create_issue"
    text = format_human(report)
    assert "BLOCKED (taint_leak)" in text
    assert "blocked" in text
    assert "attempted" not in text
    assert "first seen" in text


def test_live_audit_preview_groups_taint_without_leaking_secret():
    from sluice.cli.report import format_human
    from sluice.session.provenance import value_hash

    expected = value_hash(SECRET)[:4]
    flag_preview = json.dumps(
        {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": SECRET}]}}
    )
    block_preview = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "send_email", "arguments": {"body": SECRET}},
        }
    )
    report = build_session_report(
        "demo-session-1",
        [
            _event(
                event_id=3,
                ts=T0,
                action="flag",
                detectors=["secrets.aws_access_key"],
                rule="secrets.aws_access_key",
                redacted_preview=flag_preview,
                direction="response",
                tool=None,
            ),
            _event(
                event_id=4,
                ts=T3,
                tool="send_email",
                action="block",
                detectors=["taint_leak"],
                rule="taint_leak",
                redacted_preview=block_preview,
                propagation=[{"value_hash": value_hash(SECRET)[:16], "rule": "taint_leak"}],
            ),
        ],
    )
    assert report.summary.sensitive_values_seen == 1
    assert report.sensitive_values[0].hash_prefix == expected
    assert report.sensitive_values[0].outcome is not None
    assert report.sensitive_values[0].outcome.action == "block"
    text = format_human(report)
    assert SECRET not in text
    assert "BLOCKED (taint_leak)" in text


def test_pii_redact_pairs_first_seen_and_redacted():
    from sluice.cli.report import format_human

    events = [
        _event(
            event_id=10,
            ts=T1,
            redacted_preview="2c1e…",
            action="pass",
        ),
        _event(
            event_id=11,
            ts=T2,
            upstream="email",
            tool="send",
            action="redact",
            detectors=["pii.email"],
            rule="pii.email",
            redacted_preview="2c1e…",
        ),
    ]
    report = build_session_report("sess-pii", events)
    value = report.sensitive_values[0]
    assert value.hash_prefix == "2c1e"
    assert value.outcome is not None
    assert value.outcome.action == "redact"
    assert "REDACTED (pii.email)" in format_human(report)


def test_json_is_parseable_and_omits_raw_secret():
    from sluice.cli.report import format_human, format_markdown

    report = build_session_report(
        "sess-a3f9b2c1",
        [
            _event(
                redacted_preview=f"ab8f… contains {SECRET}",
                action="flag",
                detectors=["secrets.aws_access_key"],
                rule="secrets.aws_access_key",
            )
        ],
    )
    payload = report_to_json_dict(report)
    dumped = json.dumps(payload)
    json.loads(dumped)
    assert SECRET not in dumped
    assert payload["sensitive_values"][0]["hash_prefix"] == "ab8f"
    assert SECRET not in format_human(report)
    md = format_markdown(report)
    assert SECRET not in md
    assert md.startswith("## Sluice session report")
    assert "- Requests inspected:" in md


def test_empty_session_message():
    from sluice.cli.report import format_human

    report = build_session_report("sess-xxx", [])
    assert format_human(report) == "Session sess-xxx has no events."


@pytest.mark.asyncio
async def test_last_n_reverse_chronological(tmp_path: Path):
    from sluice.audit.report import load_recent_reports

    db_path = tmp_path / "audit.db"
    sink = await _open_db(db_path)
    await _insert(
        sink,
        session_id="sess-old",
        ts=T0,
        upstream="filesystem",
        tool="read_file",
        action="pass",
        detectors=[],
        rule=None,
        preview=None,
    )
    await _insert(
        sink,
        session_id="sess-new",
        ts=T5,
        upstream="github",
        tool="list_issues",
        action="pass",
        detectors=[],
        rule=None,
        preview=None,
    )
    reports = await load_recent_reports(sink, 2)
    await sink.close()
    assert [r.session_id for r in reports] == ["sess-new", "sess-old"]


def test_cli_empty_db_no_sessions(tmp_path: Path):
    db_path = tmp_path / "audit.db"
    cfg = _cfg(tmp_path, db_path)
    result = RUNNER.invoke(app, ["report", "--config", str(cfg)])
    assert result.exit_code == 0
    assert "no sessions" in result.stdout.lower()


def test_cli_formats_and_session_lookup(tmp_path: Path):
    db_path = tmp_path / "audit.db"
    cfg = _cfg(tmp_path, db_path)

    async def _seed() -> None:
        sink = await _open_db(db_path)
        await _insert(
            sink,
            session_id="sess-a3f9b2c1",
            ts=T0,
            upstream="filesystem",
            tool="read_file",
            action="flag",
            detectors=["secrets.aws_access_key"],
            rule="secrets.aws_access_key",
            preview=f"ab8f… {SECRET}",
            direction="response",
        )
        await _insert(
            sink,
            session_id="sess-a3f9b2c1",
            ts=T3,
            upstream="github",
            tool="create_issue",
            action="block",
            detectors=["taint_leak"],
            rule="taint_leak",
            preview="ab8f…",
        )
        await sink.close()

    asyncio.run(_seed())

    human = RUNNER.invoke(app, ["report", "--config", str(cfg), "--session", "sess-a3f9b2c1"])
    assert human.exit_code == 0
    assert "Sluice session report — sess-a3f9b2c1" in human.stdout
    assert SECRET not in human.stdout
    assert "BLOCKED (taint_leak)" in human.stdout

    md = RUNNER.invoke(
        app,
        ["report", "--config", str(cfg), "--session", "sess-a3f9b2c1", "--format", "markdown"],
    )
    assert md.exit_code == 0
    assert md.stdout.startswith("## Sluice session report")
    assert "- Requests inspected:" in md.stdout

    js = RUNNER.invoke(
        app,
        ["report", "--config", str(cfg), "--session", "sess-a3f9b2c1", "--format", "json"],
    )
    assert js.exit_code == 0
    payload = json.loads(js.stdout)
    assert payload["session_id"] == "sess-a3f9b2c1"
    assert payload["summary"]["actions"]["blocked"] == 1
    assert SECRET not in js.stdout

    array = RUNNER.invoke(app, ["report", "--config", str(cfg), "--last", "1", "--format", "json"])
    assert array.exit_code == 0
    parsed = json.loads(array.stdout)
    assert isinstance(parsed, list)
    assert parsed[0]["session_id"] == "sess-a3f9b2c1"


def test_cli_invalid_session_and_missing_sink(tmp_path: Path):
    db_path = tmp_path / "audit.db"
    cfg = _cfg(tmp_path, db_path)
    bad = RUNNER.invoke(app, ["report", "--config", str(cfg), "--session", "not a valid id"])
    assert bad.exit_code == 2

    stdout_dir = tmp_path / "stdout"
    stdout_dir.mkdir()
    stdout_cfg = _cfg(stdout_dir, tmp_path / "unused.db", sink="stdout")
    missing = RUNNER.invoke(app, ["report", "--config", str(stdout_cfg)])
    assert missing.exit_code == 1
    assert "No audit sink configured" in missing.stderr
