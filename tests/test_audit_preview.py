"""Audit preview must never retain matched secrets."""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite
import pytest
from typer.testing import CliRunner

from sluice.audit.preview import hash_prefix, safe_preview
from sluice.audit.report import extract_hash_prefixes, load_session_report
from sluice.audit.sqlite import SqliteSink
from sluice.cli.main import app
from sluice.cli.report import format_human
from sluice.config.schema import (
    AuditConfig,
    PolicyConfig,
    PolicyRule,
    SluiceConfig,
    SqliteAuditConfig,
    TaintConfig,
)
from sluice.detectors.base import Hit
from sluice.policy.engine import bootstrap_detectors
from sluice.proxy.pipeline import Pipeline
from sluice.session import taint
from sluice.session.provenance import value_hash

SECRET = "AKIAIOSFODNN7EXAMPLE"
RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def _reset_taint():
    taint.clear()
    bootstrap_detectors()
    taint.configure(TaintConfig(enabled=True, min_length=8))


def _cfg(db_path: Path) -> SluiceConfig:
    return SluiceConfig(
        upstreams=[{"name": "test", "transport": "http", "url": "http://localhost:1"}],
        policy=PolicyConfig(
            rules=[PolicyRule(detector="secrets.*", action="block")],
        ),
        taint=TaintConfig(enabled=True, min_length=8),
        audit=AuditConfig(sink="sqlite", sqlite=SqliteAuditConfig(path=str(db_path))),
    )


def _yaml(tmp_path: Path, db_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        "\n".join(
            [
                "version: 1",
                "upstreams:",
                "  - name: test",
                "    transport: http",
                "    url: http://127.0.0.1:9",
                "audit:",
                "  sink: sqlite",
                "  sqlite:",
                f"    path: {db_path}",
                "policy:",
                "  rules:",
                "    - detector: secrets.*",
                "      action: block",
            ]
        )
        + "\n"
    )
    return path


def _tool_call(tool: str, body: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {"body": body}},
        }
    )


def test_safe_preview_never_includes_matched_value():
    hit = Hit(
        detector_id="secrets.aws_access_key",
        start=0,
        end=len(SECRET),
        matched=SECRET,
        label="aws access key",
        severity="critical",
    )
    preview = safe_preview(
        method="tools/call",
        tool="send_email",
        hits=[hit],
        extra_values=[("taint_leak", SECRET)],
    )
    assert SECRET not in preview
    assert "AKIA" not in preview
    prefix = hash_prefix(SECRET)
    assert f"secrets.aws_access_key={prefix}" in preview
    assert f"taint_leak={prefix}" in preview
    assert extract_hash_prefixes(preview) == [value_hash(SECRET)[:4]]


def test_safe_preview_pass_is_method_and_tool():
    assert (
        safe_preview(method="tools/call", tool="send_email") == "tools/call send_email"
    )


async def _run_leak_and_pass(db_path: Path, session_id: str) -> None:
    cfg = _cfg(db_path)
    sink = SqliteSink(cfg.audit.sqlite)
    pipeline = Pipeline(cfg, audit=sink)
    taint.mark(
        session_id,
        SECRET,
        raw_json=_tool_call("read_file", SECRET),
        source_tool="read_file",
    )
    await pipeline.inspect_request(
        _tool_call("send_email", SECRET),
        session_id=session_id,
        upstream="test",
    )
    await pipeline.inspect_request(
        _tool_call("send_email", "hello, thanks"),
        session_id=session_id,
        upstream="test",
    )
    await sink.close()


def test_pipeline_does_not_store_secret_in_db_logs_or_report(tmp_path: Path):
    import asyncio

    db_path = tmp_path / "audit.db"
    session_id = "sess-preview-1"
    yaml_path = _yaml(tmp_path, db_path)
    asyncio.run(_run_leak_and_pass(db_path, session_id))

    events = asyncio.run(_all_text(db_path))
    assert SECRET not in events

    async def _stored():
        sink = SqliteSink(_cfg(db_path).audit.sqlite)
        rows = await sink.events_for_session(session_id)
        report = await load_session_report(sink, session_id)
        await sink.close()
        return rows, report

    stored, report = asyncio.run(_stored())
    leak_previews = [e.redacted_preview or "" for e in stored if e.rule == "taint_leak"]
    assert leak_previews
    assert any("taint_leak=" in p for p in leak_previews)
    prefix = value_hash(SECRET)[:4]
    assert any(prefix in (e.redacted_preview or "") for e in stored)
    dumped = "\n".join(e.model_dump_json() for e in stored)
    assert SECRET not in dumped
    assert SECRET not in format_human(report)
    assert "taint_leak" in format_human(report)

    logs = RUNNER.invoke(
        app, ["logs", "--config", str(yaml_path), "--json", "--since", "24h"]
    )
    assert logs.exit_code == 0, logs.stdout or logs.stderr
    assert SECRET not in logs.stdout

    cli_report = RUNNER.invoke(
        app, ["report", "--config", str(yaml_path), "--session", session_id]
    )
    assert cli_report.exit_code == 0, cli_report.stdout or cli_report.stderr
    assert SECRET not in cli_report.stdout
    assert "taint_leak" in cli_report.stdout


@pytest.mark.asyncio
async def test_secret_hit_preview_hashes_without_raw_body(tmp_path: Path):
    db_path = tmp_path / "audit.db"
    cfg = _cfg(db_path)
    sink = SqliteSink(cfg.audit.sqlite)
    pipeline = Pipeline(cfg, audit=sink)
    session_id = "sess-preview-2"
    await pipeline.inspect_request(
        _tool_call("send_email", SECRET),
        session_id=session_id,
        upstream="test",
    )
    await sink.close()

    sink = SqliteSink(cfg.audit.sqlite)
    events = await sink.events_for_session(session_id)
    await sink.close()
    assert events
    preview = events[0].redacted_preview or ""
    assert SECRET not in preview
    assert "{" not in preview
    assert f"secrets.aws_access_key={hash_prefix(SECRET)}" in preview
    blob = await _all_text(db_path)
    assert SECRET not in blob


async def _all_text(db_path: Path) -> str:
    chunks: list[str] = []
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT * FROM events") as cursor:
            async for row in cursor:
                chunks.append(" ".join("" if v is None else str(v) for v in row))
        async with db.execute("SELECT * FROM propagation_edges") as cursor:
            async for row in cursor:
                chunks.append(" ".join("" if v is None else str(v) for v in row))
    return "\n".join(chunks)
