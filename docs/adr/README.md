# Architecture Decision Records

Short, immutable records of the significant technical decisions made in Sluice.

Each ADR captures the *context* at the time (what problem, what constraints), the *decision* itself, and the *consequences* we accepted. ADRs are not documentation of current state — they are records of *why* current state is the way it is.

## Rules

- **Immutable once accepted.** If a decision changes, write a new ADR that supersedes the old one. Never edit the old one except to add a "Superseded by ADR NNNN" line at the top.
- **Numbered sequentially.** `0001-*.md`, `0002-*.md`, no gaps.
- **Short.** Michael Nygard format. Context / Decision / Consequences / Alternatives. Under one page.
- **Written when the decision is made**, not backfilled later. (We violated this for 0001–0006; won't again.)

## Index

| # | Title | Status |
|---|---|---|
| 0001 | Typer for CLI framework | Accepted |
| 0002 | First-match semantics for policy rules | Accepted |
| 0003 | aiosqlite for the audit store | Accepted |
| 0004 | Per-process session ID for stdio transport | Accepted (revisit for multi-tenant) |
| 0005 | Publish as `sluice-taint` on PyPI | Accepted |
| 0006 | Tool-poisoning detector scans names, descriptions, and param schemas | Accepted |
| 0007 | Jinja + vanilla CSS for v0.2 dashboard | Accepted (v0.2 pre-implementation) |
| 0008 | Preset override precedence by list position | Accepted (v0.2 pre-implementation) |
| 0009 | `python:3.12-slim` as the Docker base image | Accepted (v0.2 pre-implementation) |

## Format template

New ADRs should start from this skeleton:

```markdown
# ADR NNNN: Title

Status: Proposed / Accepted / Superseded by ADR MMMM
Date: YYYY-MM-DD
Deciders: <names>

## Context
What problem, what constraints, what forces are at play.

## Decision
What we picked. One paragraph.

## Consequences
What follows from this choice — good, bad, and neutral.

## Alternatives considered
What else was on the table and why we didn't pick it.
```
