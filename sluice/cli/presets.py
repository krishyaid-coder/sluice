from __future__ import annotations

from pathlib import Path

import typer
import yaml

from sluice.config.presets import list_presets, preset_yaml

presets_app = typer.Typer(help="Bundled policy presets for common MCP servers.")


@presets_app.command("list")
def presets_list() -> None:
    """List bundled preset names."""
    for name in list_presets():
        typer.echo(name)


@presets_app.command("show")
def presets_show(name: str) -> None:
    """Print a preset YAML file."""
    try:
        typer.echo(preset_yaml(name))
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)


@presets_app.command("apply")
def presets_apply(
    name: str,
    path: Path = typer.Option(Path("config.yaml"), "--path", help="Config file to update"),
) -> None:
    """Append include: preset:<name> to an existing config."""
    if not path.exists():
        typer.echo(f"config not found: {path}", err=True)
        raise typer.Exit(1)
    data = yaml.safe_load(path.read_text()) or {}
    includes = data.setdefault("include", [])
    token = f"preset:{name}"
    if token not in includes:
        includes.append(token)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    typer.echo(f"Added {token} to {path}")
