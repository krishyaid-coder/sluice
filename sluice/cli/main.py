from __future__ import annotations

import asyncio
import json
from pathlib import Path

import structlog
import typer
import yaml

from sluice import __version__
from sluice.audit import build_audit_sink
from sluice.audit.sink import AuditFilter
from sluice.config.loader import find_config, load_config
from sluice.config.schema import default_config
from sluice.proxy.pipeline import Pipeline
from sluice.proxy.router import Router
from sluice.proxy.transports.http import HTTPTransport
from sluice.proxy.transports.stdio import StdioTransport

log = structlog.get_logger()
app = typer.Typer(
    name="sluice",
    help="Local MCP gate with cross-call memory for sensitive values.",
    no_args_is_help=True,
)


def _setup_logging(level: str = "info") -> None:
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(__import__("logging"), level.upper(), 20)
        ),
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )


def _build_runtime(config_path: Path) -> tuple[Pipeline, Router]:
    cfg = load_config(config_path)
    audit = build_audit_sink(cfg)
    pipeline = Pipeline(cfg, audit)
    router = Router(cfg)
    return pipeline, router


@app.command("init")
def init_cmd(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config.yaml"),
    path: Path = typer.Option(Path("config.yaml"), "--path", help="Config output path"),
) -> None:
    """Write a starter config.yaml."""
    if path.exists() and not force:
        typer.echo(f"config already exists: {path} (use --force to overwrite)", err=True)
        raise typer.Exit(1)
    cfg = default_config()
    path.write_text(yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False))
    typer.echo(f"Wrote {path}")


@app.command("serve")
def serve_cmd(
    config: Path | None = typer.Option(None, "--config", help="Path to config.yaml"),
    host: str | None = typer.Option(None, "--host"),
    port: int | None = typer.Option(None, "--port"),
    log_level: str = typer.Option("info", "--log-level"),
) -> None:
    """Run the HTTP proxy."""
    _setup_logging(log_level)
    config_path = find_config(str(config) if config else None)
    cfg = load_config(config_path)
    pipeline, router = _build_runtime(config_path)
    bind_host = host or cfg.proxy.host
    bind_port = port or cfg.proxy.port
    typer.echo(f"Sluice listening on http://{bind_host}:{bind_port}")
    transport = HTTPTransport(bind_host, bind_port, pipeline, router)
    asyncio.run(transport.run(pipeline, router))


@app.command("stdio")
def stdio_cmd(
    config: Path | None = typer.Option(None, "--config", help="Path to config.yaml"),
    upstream: str | None = typer.Option(None, "--upstream", help="Upstream name"),
    log_level: str = typer.Option("warn", "--log-level"),
) -> None:
    """Run as a stdio bridge for Claude Desktop / Cursor."""
    _setup_logging(log_level)
    config_path = find_config(str(config) if config else None)
    pipeline, router = _build_runtime(config_path)
    name = upstream or load_config(config_path).routing.default
    transport = StdioTransport(name)
    asyncio.run(transport.run(pipeline, router))


@app.command("logs")
def logs_cmd(
    config: Path | None = typer.Option(None, "--config"),
    since: str = typer.Option("1h", "--since", help="Duration like 1h, 30m"),
    upstream: str | None = typer.Option(None, "--upstream"),
    action: str | None = typer.Option(None, "--action"),
    json_out: bool = typer.Option(False, "--json"),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """Query the audit log."""
    config_path = find_config(str(config) if config else None)
    cfg = load_config(config_path)
    audit = build_audit_sink(cfg)
    if audit is None:
        typer.echo("No audit sink configured", err=True)
        raise typer.Exit(1)

    since_ms = _parse_since(since)

    async def _run():
        count = 0
        async for event in audit.query(
            AuditFilter(since_ms=since_ms, upstream=upstream, action=action, limit=limit)
        ):
            count += 1
            if json_out:
                typer.echo(event.model_dump_json())
            else:
                typer.echo(
                    f"{event.action:6} {event.upstream:12} {event.direction:8} "
                    f"{event.method or '-':16} detectors={event.detectors}"
                )
        await audit.close()
        if count == 0:
            typer.echo("No events found.")

    asyncio.run(_run())


def _parse_since(since: str) -> int | None:
    import re
    import time

    m = re.fullmatch(r"(\d+)([hms])", since.strip())
    if not m:
        return None
    value, unit = int(m.group(1)), m.group(2)
    mult = {"h": 3_600_000, "m": 60_000, "s": 1_000}[unit]
    return int(time.time() * 1000) - value * mult


@app.command("doctor")
def doctor_cmd(
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    """Validate config and check upstream definitions."""
    config_path = find_config(str(config) if config else None)
    try:
        cfg = load_config(config_path)
    except Exception as e:
        typer.echo(f"config error: {e}", err=True)
        raise typer.Exit(2)

    typer.echo(f"config: {config_path} (version {cfg.version})")
    typer.echo(f"upstreams: {len(cfg.upstreams)}")
    router = Router(cfg)

    async def _check():
        health = await router.health_check()
        for name, status in health.items():
            typer.echo(f"  {name}: {status}")
        await router.aclose()

    asyncio.run(_check())
    from sluice.session import taint

    store = taint.store()
    sessions = store.session_count() if store else 0
    typer.echo(f"taint sessions in memory: {sessions}")
    typer.echo("doctor: ok")


@app.command("version")
def version_cmd(json_out: bool = typer.Option(False, "--json")) -> None:
    """Print version info."""
    import platform
    import sys

    info = {
        "version": __version__,
        "python": sys.version,
        "platform": platform.platform(),
    }
    if json_out:
        typer.echo(json.dumps(info))
    else:
        typer.echo(f"sluice {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
