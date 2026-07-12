# ADR 0001: Typer for CLI framework

Status: Accepted
Date: 2026-06-01 (backfilled 2026-07-11)
Deciders: krishna, colleague

## Context

Sluice needs a real subcommand-based CLI (`init`, `serve`, `stdio`, `logs`, `doctor`, `version`), not just `python -m sluice`. The choice of CLI framework shapes every command file, help output, testing pattern, and how contributors add new commands. We wanted:

- Type-annotated command signatures so IDEs and mypy catch errors
- Zero-boilerplate subcommand registration
- Good `--help` output out of the box
- No heavy runtime cost or transitive dependency footprint
- Reasonable adoption in Python OSS so contributors recognize it

The two credible options were Click (mature, imperative, decorator-heavy) and Typer (built on Click, type-annotation-driven, thin).

## Decision

Adopt **Typer** for the CLI. Every subcommand lives as a Typer app or function under `sluice/cli/`.

## Consequences

- Command signatures read as normal Python functions with type hints; contributors don't have to learn a decorator vocabulary.
- We inherit Click's ecosystem (rich, prompt-toolkit integration) if we ever need it — Typer is a thin wrapper.
- Slightly less battle-tested than raw Click; a handful of edge cases (rich help formatting on some terminals, autocompletion install) are more fragile.
- Adds `typer` as a direct dependency. Small footprint, no worry.
- Testing pattern: `typer.testing.CliRunner`, same shape as `click.testing.CliRunner`.

## Alternatives considered

- **Click.** More mature, more common. Rejected because decorator-heavy signatures don't play well with type checkers, and we didn't want to duplicate type info between decorators and function bodies.
- **argparse.** Zero dependency, standard library. Rejected because subcommand ergonomics are painful past three commands, and help output is dated.
- **Fire.** Terse but under-specified. Rejected — help output is poor and it invites accidental exposure of internals.
