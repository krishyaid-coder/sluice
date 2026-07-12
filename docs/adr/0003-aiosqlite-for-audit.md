# ADR 0003: aiosqlite for the audit store

Status: Accepted
Date: 2026-06-05 (backfilled 2026-07-11)
Deciders: krishna, colleague

## Context

The audit store writes on every JSON-RPC message and is queried from `sluice logs`. The rest of Sluice is async (FastAPI, `httpx.AsyncClient`, async transports). Blocking calls into a sync SQLite driver from an async context would either need a thread pool wrapper or would stall the event loop under load.

Choices:
- **`sqlite3` (stdlib), sync, called from a thread pool executor.** No new dep; one more failure mode (executor tuning, backpressure).
- **`aiosqlite`.** Thin async wrapper around `sqlite3` in a background thread. One extra dep; naturally awaitable.
- **Something bigger** (`sqlmodel`, `SQLAlchemy` async). Rejected on weight — the audit table is nine columns and one index.

## Decision

Use **`aiosqlite`** for the SQLite audit sink. Wrap it behind the `AuditSink` protocol so a synchronous or Postgres backend can slot in later without touching call sites.

## Consequences

- One extra dependency (`aiosqlite`, ~200 lines of Python, no C deps).
- Awaitable API matches the rest of the codebase; no `run_in_executor` boilerplate at every call site.
- Under the hood `aiosqlite` still uses a single background thread; write throughput is bounded by that thread. For our scale (< 10k events/sec ceiling), fine. If we hit the ceiling, we batch writes.
- `sluice logs` remains queryable while `serve` is running because SQLite supports concurrent readers with WAL mode. We enable WAL on init.

## Alternatives considered

- **`sqlite3` + `loop.run_in_executor`.** Same behavior in practice, more boilerplate at every site. Would have leaked "this is a blocking call" into every caller. Rejected on ergonomics.
- **DuckDB.** Better for analytical queries. Rejected — we're doing point writes and time-range scans, not analytics.
- **Postgres (via `asyncpg`).** Overkill for a local dev tool. May become an optional sink in v0.3 for team deployments.
